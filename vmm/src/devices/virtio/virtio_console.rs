use std::borrow::{Borrow, BorrowMut};
use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_bindings::virtio_ring::VRING_DESC_F_WRITE;
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::{Queue, QueueOwnedT, QueueT};

use vm_memory::{Bytes, GuestMemoryMmap};

use crate::devices::pic::Pic;
use crate::devices::virtio::{DeviceType, default_signal_interrupt};
use crate::system::backend::HypervisorBackend;
use crate::system::vmachine::vcpu::VcpuInjector;

#[repr(C, packed)]
#[derive(Default, Clone, Copy, Debug)]
pub struct VirtioConsoleConfig {
    pub cols: u16,
    pub rows: u16,
    pub max_nr_ports: u16,
    pub emerg_wr: u16,
}

/// TX request: data to write to stdout.
struct TxRequest {
    head_index: u16,
    data: Vec<u8>,
}

enum WorkerMessage {
    Tx(TxRequest),
}

/// Shared state for Console device.
struct SharedState {
    config: VirtioConfig<Queue>,
    guest_mem: Option<GuestMemoryMmap>,
    pic: Option<Arc<Mutex<Pic>>>,
    irq_line: u8,
    rx_buffer: VecDeque<u8>,
}

/// `VirtIO` Console Device with worker thread for TX.
pub struct ConsoleDevice<B: HypervisorBackend> {
    state: Arc<Mutex<SharedState>>,
    injector: Option<VcpuInjector<B>>,
    tx_sender: Option<Sender<WorkerMessage>>,
    worker_thread: Option<JoinHandle<()>>,
    worker_stop: Arc<AtomicBool>,
}

impl<B: HypervisorBackend> ConsoleDevice<B> {
    pub fn new() -> anyhow::Result<Self> {
        let mut queues = Vec::new();
        queues.push(
            Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create RX queue: {e:?}"))?,
        );
        queues.push(
            Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create TX queue: {e:?}"))?,
        );

        let console_config = VirtioConsoleConfig {
            cols: 80,
            rows: 24,
            max_nr_ports: 1,
            emerg_wr: 0,
        };

        let config_space = unsafe {
            std::slice::from_raw_parts(
                (&raw const console_config).cast::<u8>(),
                std::mem::size_of::<VirtioConsoleConfig>(),
            )
            .to_vec()
        };

        let mut device_features = 0u64;
        device_features |= 1 << VIRTIO_F_VERSION_1;

        let state = SharedState {
            config: VirtioConfig::new(device_features, queues, config_space),
            guest_mem: None,
            pic: None,
            irq_line: 0,
            rx_buffer: VecDeque::new(),
        };

        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            injector: None,
            tx_sender: None,
            worker_thread: None,
            worker_stop: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn set_memory(&mut self, mem: GuestMemoryMmap) {
        self.state.lock().unwrap().guest_mem = Some(mem);
    }

    pub fn set_injector(&mut self, injector: VcpuInjector<B>, pic: Arc<Mutex<Pic>>, line: u8) {
        self.injector = Some(injector);
        let mut state = self.state.lock().unwrap();
        state.pic = Some(pic);
        state.irq_line = line;
    }

    /// Queue input data from Host to be sent to Guest.
    pub fn queue_input(&mut self, data: &[u8]) {
        let mut state = self.state.lock().unwrap();
        state.rx_buffer.extend(data);
        // Try to process RX immediately
        let mem_opt = state.guest_mem.clone();
        let pic = state.pic.clone();
        let irq_line = state.irq_line;
        if mem_opt.is_some_and(|mem| Self::process_rx_inner(&mut state, &mem)) {
            default_signal_interrupt(&mut state.config, pic.as_ref(), irq_line);
        }
    }

    fn spawn_worker(&mut self) {
        let (tx, rx) = mpsc::channel::<WorkerMessage>();
        self.tx_sender = Some(tx);
        self.worker_stop.store(false, Ordering::SeqCst);

        let state = Arc::clone(&self.state);
        let stop_flag = Arc::clone(&self.worker_stop);

        let handle = thread::spawn(move || {
            log::info!("VirtIO Console Worker: Started");

            loop {
                let Ok(msg) = rx.recv() else {
                    log::info!("VirtIO Console Worker: Channel closed, exiting");
                    break;
                };

                if stop_flag.load(Ordering::SeqCst) {
                    log::info!("VirtIO Console Worker: Stop flag set, exiting");
                    break;
                }

                match msg {
                    WorkerMessage::Tx(req) => {
                        // Write to stdout
                        let _ = io::stdout().write_all(&req.data);
                        let _ = io::stdout().flush();

                        // Update used ring (TX used.len = 0)
                        let mut state_guard = state.lock().unwrap();
                        let mem_opt = state_guard.guest_mem.clone();
                        let pic = state_guard.pic.clone();
                        let irq_line = state_guard.irq_line;

                        if mem_opt.is_some_and(|mem| {
                            state_guard.config.queues.get_mut(1).is_some_and(|queue| {
                                queue.add_used(&mem, req.head_index, 0).is_ok()
                                    && queue.needs_notification(&mem).unwrap_or(true)
                            })
                        }) {
                            default_signal_interrupt(
                                &mut state_guard.config,
                                pic.as_ref(),
                                irq_line,
                            );
                        }
                    }
                }
            }

            log::info!("VirtIO Console Worker: Exited");
        });

        self.worker_thread = Some(handle);
    }

    fn stop_worker(&mut self) {
        self.worker_stop.store(true, Ordering::SeqCst);
        self.tx_sender = None;
        if let Some(handle) = self.worker_thread.take() {
            let _ = handle.join();
        }
    }

    /// Process RX queue synchronously.
    fn process_rx_inner(state: &mut SharedState, mem: &GuestMemoryMmap) -> bool {
        let queue = match state.config.queues.first_mut() {
            Some(q) => q,
            None => return false,
        };

        if state.rx_buffer.is_empty() {
            return false;
        }

        let mut used_any = false;

        while let Some(chain) = queue.iter(mem).ok().and_then(|mut i| i.next()) {
            if state.rx_buffer.is_empty() {
                break;
            }

            let head_index = chain.head_index();
            let mut total_written = 0;

            for desc in chain {
                if (desc.flags() & VRING_DESC_F_WRITE as u16) == 0 {
                    continue;
                }

                let desc_len = desc.len() as usize;
                let available = std::cmp::min(desc_len, state.rx_buffer.len());
                if available == 0 {
                    break;
                }

                let mut chunk = Vec::with_capacity(available);
                for _ in 0..available {
                    if let Some(b) = state.rx_buffer.pop_front() {
                        chunk.push(b);
                    } else {
                        break;
                    }
                }

                if !chunk.is_empty() && mem.write_slice(&chunk, desc.addr()).is_ok() {
                    total_written += chunk.len();
                }
            }

            if total_written > 0 {
                let _ = queue.add_used(mem, head_index, total_written as u32);
                used_any = true;
            }
        }

        used_any
    }
}

impl<B: HypervisorBackend> VirtioDeviceType for ConsoleDevice<B> {
    fn device_type(&self) -> u32 {
        DeviceType::Console as u32
    }
}

impl<B: HypervisorBackend> VirtioDeviceActions for ConsoleDevice<B> {
    type E = anyhow::Error;

    fn activate(&mut self) -> anyhow::Result<()> {
        log::debug!("VirtIO Console Activated - spawning worker");
        self.spawn_worker();
        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        log::debug!("VirtIO Console Reset - stopping worker");
        self.stop_worker();
        self.state.lock().unwrap().rx_buffer.clear();
        Ok(())
    }
}

impl<B: HypervisorBackend> Borrow<VirtioConfig<Queue>> for ConsoleDevice<B> {
    fn borrow(&self) -> &VirtioConfig<Queue> {
        unsafe {
            let guard = self.state.lock().unwrap();
            let ptr = &raw const guard.config;
            &*ptr
        }
    }
}

impl<B: HypervisorBackend> BorrowMut<VirtioConfig<Queue>> for ConsoleDevice<B> {
    fn borrow_mut(&mut self) -> &mut VirtioConfig<Queue> {
        unsafe {
            let mut guard = self.state.lock().unwrap();
            let ptr = &raw mut guard.config;
            &mut *ptr
        }
    }
}

impl<B: HypervisorBackend> VirtioMmioDevice for ConsoleDevice<B> {
    fn queue_notify(&mut self, val: u32) {
        log::debug!("VirtIO Console Notify: queue={val}");

        let mut state = self.state.lock().unwrap();
        let Some(mem) = state.guest_mem.clone() else {
            return;
        };

        // Extract values for interrupt signaling
        let pic = state.pic.clone();
        let irq_line = state.irq_line;

        match val {
            0 => {
                // RX: Process synchronously
                if Self::process_rx_inner(&mut state, &mem) {
                    default_signal_interrupt(&mut state.config, pic.as_ref(), irq_line);
                }
            }
            1 => {
                // TX: Send to worker for async stdout writes
                let Some(queue) = state.config.queues.get_mut(1) else {
                    return;
                };

                while let Some(chain) = queue.iter(&mem).ok().and_then(|mut i| i.next()) {
                    let head_index = chain.head_index();
                    let mut data = Vec::new();

                    for desc in chain {
                        if (desc.flags() & VRING_DESC_F_WRITE as u16) != 0 {
                            continue;
                        }

                        let len = desc.len() as usize;
                        let mut buf = vec![0u8; len];
                        if mem.read_slice(&mut buf, desc.addr()).is_ok() {
                            data.extend(buf);
                        }
                    }

                    if let Some(sender) = &self.tx_sender {
                        let msg = WorkerMessage::Tx(TxRequest { head_index, data });
                        if sender.send(msg).is_err() {
                            log::error!("Failed to send to console worker");
                        }
                    } else {
                        // Fallback: write synchronously
                        let _ = io::stdout().write_all(&data);
                        let _ = io::stdout().flush();
                        let _ = queue.add_used(&mem, head_index, 0);
                    }
                }

                // Signal interrupt if needed (for sync fallback path)
                if self.tx_sender.is_none()
                    && state
                        .config
                        .queues
                        .get_mut(1)
                        .is_some_and(|queue| queue.needs_notification(&mem).unwrap_or(true))
                {
                    default_signal_interrupt(&mut state.config, pic.as_ref(), irq_line);
                }
            }
            _ => {}
        }
    }
}
