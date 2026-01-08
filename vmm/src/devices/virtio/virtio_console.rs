use std::borrow::{Borrow, BorrowMut};
use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_bindings::virtio_ring::VRING_DESC_F_WRITE;
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::{Queue, QueueOwnedT, QueueT};

use vm_memory::{Address, Bytes, GuestMemoryMmap};

use crate::devices::pic::Pic;
use crate::devices::virtio::{DeviceType, default_signal_interrupt};
use crate::system::backend::HypervisorBackend;
use crate::system::vmachine::vcpu::VcpuInjector;

// Config layout
#[repr(C, packed)]
#[derive(Default, Clone, Copy, Debug)]
pub struct VirtioConsoleConfig {
    pub cols: u16,
    pub rows: u16,
    pub max_nr_ports: u16,
    pub emerg_wr: u16,
}

/// VirtIO Console Device
pub struct ConsoleDevice<B: HypervisorBackend> {
    config: VirtioConfig<Queue>,
    guest_mem: Option<GuestMemoryMmap>,
    injector: Option<VcpuInjector<B>>,
    pic: Option<Arc<Mutex<Pic>>>,
    irq_line: u8,

    // Buffer for input data (Host -> Guest)
    rx_buffer: VecDeque<u8>,
}

impl<B: HypervisorBackend> ConsoleDevice<B> {
    pub fn new() -> anyhow::Result<Self> {
        // Console has 2 queues: RX (0), TX (1)
        let mut queues = Vec::new();
        queues.push(
            Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create RX queue: {:?}", e))?,
        );
        queues.push(
            Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create TX queue: {:?}", e))?,
        );

        // Config Space
        let console_config = VirtioConsoleConfig {
            cols: 80,
            rows: 24,
            max_nr_ports: 1,
            emerg_wr: 0,
        };

        // Serialize config
        let config_space = unsafe {
            std::slice::from_raw_parts(
                &console_config as *const _ as *const u8,
                std::mem::size_of::<VirtioConsoleConfig>(),
            )
            .to_vec()
        };

        // Features
        let mut device_features = 0u64;
        device_features |= 1 << VIRTIO_F_VERSION_1;

        Ok(Self {
            config: VirtioConfig::new(device_features, queues, config_space),
            guest_mem: None,
            injector: None,
            pic: None,
            irq_line: 0,
            rx_buffer: VecDeque::new(),
        })
    }

    pub fn set_memory(&mut self, mem: GuestMemoryMmap) {
        self.guest_mem = Some(mem);
    }

    pub fn set_injector(&mut self, injector: VcpuInjector<B>, pic: Arc<Mutex<Pic>>, line: u8) {
        self.injector = Some(injector);
        self.pic = Some(pic);
        self.irq_line = line;
    }

    /// Queue input data from Host (Stdin) to be sent to Guest
    pub fn queue_input(&mut self, data: &[u8]) {
        self.rx_buffer.extend(data);
        // Try to process RX queue immediately if buffers are available
        match self.process_rx() {
            Ok(true) => self.signal_interrupt(),
            Ok(false) => {}
            Err(e) => log::error!("Failed to process RX on input: {:?}", e),
        }
    }

    fn signal_interrupt(&mut self) {
        default_signal_interrupt(&mut self.config, self.pic.as_ref(), self.irq_line)
    }

    // Process RX Queue (0): Host -> Guest
    // Driver provides emptry buffers for us to fill with input data.
    fn process_rx(&mut self) -> anyhow::Result<bool> {
        let mem = match self.guest_mem.as_ref() {
            Some(m) => m,
            None => return Ok(false),
        };

        let mut used_any = false;

        // Scope for queue borrow
        {
            let queue = match self.config.queues.get_mut(0) {
                Some(q) => q,
                None => return Ok(false),
            };

            // If we have no data, we can't do anything
            if self.rx_buffer.is_empty() {
                return Ok(false);
            }

            while let Some(mut chain) = queue.iter(mem).ok().and_then(|mut i| i.next()) {
                if self.rx_buffer.is_empty() {
                    break;
                }

                let mut total_written = 0;
                for desc in chain.by_ref() {
                    // RX buffers must be writeable (Device writes to them)
                    if (desc.flags() & VRING_DESC_F_WRITE as u16) == 0 {
                        continue;
                    }

                    let mut desc_offset = 0;
                    let desc_len = desc.len() as usize;

                    while desc_offset < desc_len && !self.rx_buffer.is_empty() {
                        // Pop needed bytes
                        let needed = desc_len - desc_offset;
                        // We can't slice VecDeque easily, so pop one by one or collect?
                        // Optimization: drain a chunk?
                        // Let's just pop loop for simplicity for now.
                        let mut chunk = Vec::with_capacity(needed);
                        for _ in 0..needed {
                            if let Some(b) = self.rx_buffer.pop_front() {
                                chunk.push(b);
                            } else {
                                break;
                            }
                        }

                        let n = chunk.len();
                        if n > 0 {
                            let addr = desc.addr().checked_add(desc_offset as u64).unwrap();
                            mem.write_slice(&chunk, addr)?;
                            total_written += n;
                            desc_offset += n;
                        }
                    }
                }

                if total_written > 0 {
                    queue.add_used(mem, chain.head_index(), total_written as u32)?;
                    used_any = true;
                }
            }
        }

        Ok(used_any)
    }

    // Process TX Queue (1): Guest -> Host
    // Driver fills buffers with data for us to print.
    fn process_tx(&mut self) -> anyhow::Result<bool> {
        let mem = match self.guest_mem.as_ref() {
            Some(m) => m,
            None => return Ok(false),
        };

        let queue = match self.config.queues.get_mut(1) {
            Some(q) => q,
            None => return Ok(false),
        };

        let mut used_any = false;

        while let Some(mut chain) = queue.iter(mem).ok().and_then(|mut i| i.next()) {
            let mut _total_read = 0;

            for desc in chain.by_ref() {
                // TX buffers are read-only for device (Device reads them)
                if (desc.flags() & VRING_DESC_F_WRITE as u16) != 0 {
                    continue;
                }

                let len = desc.len() as usize;
                let addr = desc.addr();

                let mut buf = vec![0u8; len];
                match mem.read_slice(&mut buf, addr) {
                    Ok(_) => {
                        // Write to stdout
                        let _ = io::stdout().write(&buf);
                        let _ = io::stdout().flush();
                        // total_read += len; unused
                    }
                    Err(e) => log::error!("Failed to read TX guest mem: {:?}", e),
                }
            }

            // Should we return used length? Usually yes, 0 for TX?
            // VIRTIO spec: "The driver adds a descriptor chain to the receiveq... The device consumes the chain..."
            // For TX, "The driver adds a descriptor chain to the transmitq... The device consumes the chain..."
            // "The used.len field is set to 0." for Console TX?
            // Checking spec: "For transmitq, used.len is 0."
            queue.add_used(mem, chain.head_index(), 0)?;
            used_any = true;
        }

        Ok(used_any)
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
        log::debug!("VirtIO Console Activated");
        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        log::debug!("VirtIO Console Reset");
        self.rx_buffer.clear();
        Ok(())
    }
}

impl<B: HypervisorBackend> Borrow<VirtioConfig<Queue>> for ConsoleDevice<B> {
    fn borrow(&self) -> &VirtioConfig<Queue> {
        &self.config
    }
}

impl<B: HypervisorBackend> BorrowMut<VirtioConfig<Queue>> for ConsoleDevice<B> {
    fn borrow_mut(&mut self) -> &mut VirtioConfig<Queue> {
        &mut self.config
    }
}

impl<B: HypervisorBackend> VirtioMmioDevice for ConsoleDevice<B> {
    fn queue_notify(&mut self, val: u32) {
        println!("VirtIO Console Notify: {}", val);
        let res = match val {
            0 => self.process_rx(),
            1 => self.process_tx(),
            _ => Ok(false),
        };
        println!("VirtIO Console Notify Result: {:?}", res);
        match res {
            Ok(needs_irq) => {
                if needs_irq {
                    self.signal_interrupt();
                }
            }
            Err(e) => log::error!("Console queue error: {:?}", e),
        }
    }
}
