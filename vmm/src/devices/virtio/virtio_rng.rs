use std::borrow::{Borrow, BorrowMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::{Queue, QueueOwnedT, QueueT};

use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

use crate::devices::pic::Pic;
use crate::devices::virtio::{DeviceType, default_signal_interrupt};
use crate::system::backend::HypervisorBackend;
use crate::system::vmachine::vcpu::VcpuInjector;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

const CHUNK_SIZE: usize = 64;

/// Parsed RNG request for the worker thread.
struct RngRequest {
    head_index: u16,
    segments: Vec<(GuestAddress, u32)>,
}

/// Message sent to the RNG worker thread.
struct WorkerMessage {
    request: RngRequest,
}

/// Shared state for RNG device.
struct SharedState {
    config: VirtioConfig<Queue>,
    guest_mem: Option<GuestMemoryMmap>,
    pic: Option<Arc<Mutex<Pic>>>,
    irq_line: u8,
}

/// `VirtIO` RNG Device with pipelined worker thread.
pub struct RngDevice<B: HypervisorBackend> {
    state: Arc<Mutex<SharedState>>,
    injector: Option<VcpuInjector<B>>,
    worker_sender: Option<Sender<WorkerMessage>>,
    worker_thread: Option<JoinHandle<()>>,
    worker_stop: Arc<AtomicBool>,
}

impl<B: HypervisorBackend> RngDevice<B> {
    pub fn new() -> anyhow::Result<Self> {
        let mut queues = Vec::new();
        queues.push(Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create queue: {e:?}"))?);

        let config_space = Vec::new();
        let mut device_features = 0u64;
        device_features |= 1 << VIRTIO_F_VERSION_1;

        let state = SharedState {
            config: VirtioConfig::new(device_features, queues, config_space),
            guest_mem: None,
            pic: None,
            irq_line: 0,
        };

        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            injector: None,
            worker_sender: None,
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

    fn spawn_worker(&mut self) {
        let (tx, rx) = mpsc::channel::<WorkerMessage>();
        self.worker_sender = Some(tx);
        self.worker_stop.store(false, Ordering::SeqCst);

        let state = Arc::clone(&self.state);
        let stop_flag = Arc::clone(&self.worker_stop);

        let handle = thread::spawn(move || {
            log::info!("VirtIO RNG Worker: Started");
            let mut rng = StdRng::from_os_rng();
            let mut buf = [0u8; CHUNK_SIZE];

            loop {
                let Ok(msg) = rx.recv() else {
                    log::info!("VirtIO RNG Worker: Channel closed, exiting");
                    break;
                };

                if stop_flag.load(Ordering::SeqCst) {
                    log::info!("VirtIO RNG Worker: Stop flag set, exiting");
                    break;
                }

                let mut state_guard = state.lock().unwrap();
                let Some(mem) = state_guard.guest_mem.clone() else {
                    log::error!("RNG Worker: No guest memory");
                    continue;
                };

                // Extract values before queue borrow
                let pic = state_guard.pic.clone();
                let irq_line = state_guard.irq_line;

                // Fill random data for each segment
                let mut total_written = 0u32;
                for (addr, len) in &msg.request.segments {
                    let mut offset = 0usize;
                    let len = *len as usize;
                    while offset < len {
                        let chunk_len = std::cmp::min(len - offset, buf.len());
                        rng.fill_bytes(&mut buf[..chunk_len]);
                        let write_addr = addr.checked_add(offset as u64).unwrap();
                        if let Err(e) = mem.write_slice(&buf[..chunk_len], write_addr) {
                            log::error!("RNG: Failed to write: {e:?}");
                            break;
                        }
                        offset += chunk_len;
                        total_written += chunk_len as u32;
                    }
                }

                // Update used ring
                let needs_interrupt = if let Some(queue) = state_guard.config.queues.first_mut() {
                    queue
                        .add_used(&mem, msg.request.head_index, total_written)
                        .is_ok()
                        && queue.needs_notification(&mem).unwrap_or(true)
                } else {
                    false
                };

                if needs_interrupt {
                    default_signal_interrupt(&mut state_guard.config, pic.as_ref(), irq_line);
                }
            }

            log::info!("VirtIO RNG Worker: Exited");
        });

        self.worker_thread = Some(handle);
    }

    fn stop_worker(&mut self) {
        self.worker_stop.store(true, Ordering::SeqCst);
        self.worker_sender = None;
        if let Some(handle) = self.worker_thread.take() {
            let _ = handle.join();
        }
    }
}

impl<B: HypervisorBackend> VirtioDeviceType for RngDevice<B> {
    fn device_type(&self) -> u32 {
        DeviceType::Rng as u32
    }
}

impl<B: HypervisorBackend> VirtioDeviceActions for RngDevice<B> {
    type E = anyhow::Error;

    fn activate(&mut self) -> anyhow::Result<()> {
        log::debug!("VirtIO RNG Activated - spawning worker");
        self.spawn_worker();
        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        log::debug!("VirtIO RNG Reset - stopping worker");
        self.stop_worker();
        Ok(())
    }
}

impl<B: HypervisorBackend> Borrow<VirtioConfig<Queue>> for RngDevice<B> {
    fn borrow(&self) -> &VirtioConfig<Queue> {
        unsafe {
            let guard = self.state.lock().unwrap();
            let ptr = &raw const guard.config;
            &*ptr
        }
    }
}

impl<B: HypervisorBackend> BorrowMut<VirtioConfig<Queue>> for RngDevice<B> {
    fn borrow_mut(&mut self) -> &mut VirtioConfig<Queue> {
        unsafe {
            let mut guard = self.state.lock().unwrap();
            let ptr = &raw mut guard.config;
            &mut *ptr
        }
    }
}

impl<B: HypervisorBackend> VirtioMmioDevice for RngDevice<B> {
    fn queue_notify(&mut self, _val: u32) {
        log::debug!("VirtIO RNG Notify (pipelined)");

        let mut state = self.state.lock().unwrap();
        let Some(mem) = state.guest_mem.clone() else {
            return;
        };

        // Extract values for interrupt signaling
        let pic = state.pic.clone();
        let irq_line = state.irq_line;

        // Collect all requests first
        let mut requests = Vec::new();
        if let Some(queue) = state.config.queues.first_mut() {
            while let Some(chain) = queue.iter(&mem).ok().and_then(|mut i| i.next()) {
                let head_index = chain.head_index();
                let mut segments = Vec::new();

                for desc in chain {
                    if (desc.flags() & virtio_bindings::virtio_ring::VRING_DESC_F_WRITE as u16) == 0
                    {
                        continue;
                    }
                    segments.push((desc.addr(), desc.len()));
                }

                requests.push(RngRequest {
                    head_index,
                    segments,
                });
            }
        }

        // Send requests to worker or process sync
        for request in requests {
            if let Some(sender) = &self.worker_sender {
                let msg = WorkerMessage { request };
                if sender.send(msg).is_err() {
                    log::error!("Failed to send to RNG worker");
                }
            } else {
                // Fallback: process synchronously
                let mut rng = StdRng::from_os_rng();
                let mut buf = [0u8; CHUNK_SIZE];
                let mut total_written = 0u32;

                for (addr, len) in &request.segments {
                    let mut offset = 0usize;
                    let len = *len as usize;
                    while offset < len {
                        let chunk_len = std::cmp::min(len - offset, buf.len());
                        rng.fill_bytes(&mut buf[..chunk_len]);
                        let write_addr = addr.checked_add(offset as u64).unwrap();
                        if mem.write_slice(&buf[..chunk_len], write_addr).is_err() {
                            break;
                        }
                        offset += chunk_len;
                        total_written += chunk_len as u32;
                    }
                }

                let needs_interrupt = if let Some(queue) = state.config.queues.first_mut() {
                    queue
                        .add_used(&mem, request.head_index, total_written)
                        .is_ok()
                        && queue.needs_notification(&mem).unwrap_or(true)
                } else {
                    false
                };

                if needs_interrupt {
                    default_signal_interrupt(&mut state.config, pic.as_ref(), irq_line);
                }
            }
        }
    }
}
