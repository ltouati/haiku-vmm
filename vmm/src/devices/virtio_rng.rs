use std::borrow::{Borrow, BorrowMut};
use std::fs::File;
use std::io::Read;
use std::sync::{Arc, Mutex};

use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::{Queue, QueueOwnedT, QueueT};

use vm_device::MutDeviceMmio;
use vm_memory::{Address, Bytes, GuestMemoryMmap}; // Added Address trait // For trait implementation

use crate::VcpuInjector;
use crate::devices::pic::Pic;

/// VirtIO RNG Device
pub struct RngDevice {
    config: VirtioConfig<Queue>,
    rng_source: File,
    guest_mem: Option<GuestMemoryMmap>,
    injector: Option<VcpuInjector>,
    pic: Option<Arc<Mutex<Pic>>>,
    irq_line: u8,
}

impl RngDevice {
    pub fn new() -> anyhow::Result<Self> {
        // RNG has 1 queue.
        let mut queues = Vec::new();
        queues
            .push(Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create queue: {:?}", e))?);

        // No config space for RNG
        let config_space = Vec::new();

        // Features
        let mut device_features = 0u64;
        device_features |= 1 << VIRTIO_F_VERSION_1;

        let rng_source = File::open("/dev/urandom")
            .map_err(|e| anyhow::anyhow!("Failed to open /dev/urandom: {:?}", e))?;

        Ok(Self {
            config: VirtioConfig::new(device_features, queues, config_space),
            rng_source,
            guest_mem: None,
            injector: None,
            pic: None,
            irq_line: 0,
        })
    }

    pub fn set_memory(&mut self, mem: GuestMemoryMmap) {
        self.guest_mem = Some(mem);
    }

    pub fn set_injector(&mut self, injector: VcpuInjector, pic: Arc<Mutex<Pic>>, line: u8) {
        self.injector = Some(injector);
        self.pic = Some(pic);
        self.irq_line = line;
    }

    fn process_queue(&mut self) -> anyhow::Result<bool> {
        let mem = match self.guest_mem.as_ref() {
            Some(m) => m,
            None => return Ok(false),
        };

        let queue = match self.config.queues.get_mut(0) {
            Some(q) => q,
            None => return Ok(false),
        };

        let mut used_any = false;

        while let Some(mut chain) = queue
            .iter(mem)
            .map_err(|e| {
                log::error!("Failed to get queue iterator: {:?}", e);
                e
            })
            .ok()
            .and_then(|mut i| i.next())
        {
            let mut total_written = 0;
            let mut buf = [0u8; 64];

            for desc in chain.by_ref() {
                // Fix: Cast VRING_DESC_F_WRITE to u16
                if (desc.flags() & virtio_bindings::virtio_ring::VRING_DESC_F_WRITE as u16) == 0 {
                    continue;
                }

                let mut desc_offset = 0;
                let desc_len = desc.len() as usize;

                while desc_offset < desc_len {
                    let chunk_len = std::cmp::min(desc_len - desc_offset, buf.len());
                    match self.rng_source.read(&mut buf[..chunk_len]) {
                        Ok(n) if n > 0 => {
                            // Fix: checked_add provided by Address trait
                            let addr = desc.addr().checked_add(desc_offset as u64).unwrap();
                            match mem.write_slice(&buf[..n], addr) {
                                Ok(_) => {
                                    total_written += n;
                                    desc_offset += n;
                                }
                                Err(e) => {
                                    log::error!("Failed to write to guest: {:?}", e);
                                    break;
                                }
                            }
                        }
                        _ => break,
                    }
                }
            }

            if total_written > 0 {
                // Fix: add_used needs mem
                queue
                    .add_used(mem, chain.head_index(), total_written as u32)
                    .unwrap();
                used_any = true;
            }
        }

        Ok(used_any)
    }
}

// Fix: Implement MutDeviceMmio for Mutex<RngDevice>
// Note: rust-vmm `vm-device` expects the implementation on the device struct itself if using `register_mmio`.
// Wait, `linux.rs` wraps it in `Arc<Mutex<T>>`. `register_mmio` takes `Arc<Mutex<dyn MutDeviceMmio>>`.
// So `RngDevice` must implement `MutDeviceMmio`.

impl MutDeviceMmio for RngDevice {
    fn mmio_read(&mut self, _base: vm_device::bus::MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data);
    }

    fn mmio_write(&mut self, _base: vm_device::bus::MmioAddress, offset: u64, data: &[u8]) {
        self.write(offset, data);
    }
}

impl VirtioDeviceType for RngDevice {
    fn device_type(&self) -> u32 {
        4 // RNG
    }
}

impl VirtioDeviceActions for RngDevice {
    type E = anyhow::Error;

    fn activate(&mut self) -> anyhow::Result<()> {
        log::debug!("VirtIO RNG Activated");
        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        log::debug!("VirtIO RNG Reset");
        Ok(())
    }
}

impl Borrow<VirtioConfig<Queue>> for RngDevice {
    fn borrow(&self) -> &VirtioConfig<Queue> {
        &self.config
    }
}

impl BorrowMut<VirtioConfig<Queue>> for RngDevice {
    fn borrow_mut(&mut self) -> &mut VirtioConfig<Queue> {
        &mut self.config
    }
}

impl VirtioMmioDevice for RngDevice {
    fn queue_notify(&mut self, _val: u32) {
        match self.process_queue() {
            Ok(needs_irq) => {
                if needs_irq {
                    // Fix: Injector needs to be mutable.
                    // Option iter gives ref implicitly if using &self.injector.
                    // We need `as_mut` or structure change.
                    // VcpuInjector::inject_interrupt is likely `&self` though?
                    // Let's check `VcpuInjector` definition.
                    // Assuming for now `inject_interrupt` takes `&mut self`.
                    // If so, we need `if let (Some(injector), ...)` binding to match mutable reference?
                    // No, we need `as_mut`.

                    if let (Some(injector), Some(pic)) = (self.injector.as_mut(), &self.pic) {
                        let mut pic_lock = pic.lock().unwrap();
                        pic_lock.set_irq(self.irq_line, true);

                        let _ = injector.inject_interrupt(self.irq_line);
                    }
                }
            }
            Err(e) => log::error!("RNG queue processing error: {:?}", e),
        }
    }
}
