use std::borrow::{Borrow, BorrowMut};
use std::io::Stdout;

use virtio_console::console::Console;
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::{Queue, QueueOwnedT, QueueT};
use vm_device::MutDeviceMmio;
use vm_device::bus::MmioAddress;
use vm_memory::GuestMemoryMmap;

/// VirtIO Console Device using rust-vmm components.
pub struct ConsoleDevice {
    config: VirtioConfig<Queue>,
    console: Console<Stdout>,
    guest_mem: Option<GuestMemoryMmap>,
}

impl ConsoleDevice {
    pub fn new() -> anyhow::Result<Self> {
        // Console usually has 2 queues: receive and transmit.
        let mut queues = Vec::new();
        queues.push(
            Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create Rx queue: {:?}", e))?,
        );
        queues.push(
            Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create Tx queue: {:?}", e))?,
        );

        // Device features: VERSION_1 is mandatory for modern virtio.
        let device_features = 1u64 << 32;

        // Config space: none for now.
        let config_space = Vec::new();

        Ok(Self {
            config: VirtioConfig::new(device_features, queues, config_space),
            console: Console::default(),
            guest_mem: None,
        })
    }

    pub fn set_memory(&mut self, mem: GuestMemoryMmap) {
        self.guest_mem = Some(mem);
    }
}

impl VirtioDeviceType for ConsoleDevice {
    fn device_type(&self) -> u32 {
        3 // Console
    }
}

impl VirtioDeviceActions for ConsoleDevice {
    type E = anyhow::Error;

    fn activate(&mut self) -> anyhow::Result<()> {
        log::info!("VirtIO Console Activated");
        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        log::info!("VirtIO Console Reset");
        Ok(())
    }
}

impl Borrow<VirtioConfig<Queue>> for ConsoleDevice {
    fn borrow(&self) -> &VirtioConfig<Queue> {
        &self.config
    }
}

impl BorrowMut<VirtioConfig<Queue>> for ConsoleDevice {
    fn borrow_mut(&mut self) -> &mut VirtioConfig<Queue> {
        &mut self.config
    }
}

// Implement VirtioMmioDevice explicitly to provide queue_notify.
impl VirtioMmioDevice for ConsoleDevice {
    fn queue_notify(&mut self, val: u32) {
        log::debug!("VirtIO Console Notify: {}", val);

        let mem = match self.guest_mem.as_ref() {
            Some(m) => m,
            None => return,
        };

        if let Some(queue) = self.config.queues.get_mut(val as usize) {
            // Process the queue
            // Queue 0: Receive (Device -> Driver)
            // Queue 1: Transmit (Driver -> Device)

            while let Some(mut chain) = queue
                .iter(mem)
                .map_err(|e| {
                    log::error!("Failed to get queue iterator: {:?}", e);
                    e
                })
                .ok()
                .and_then(|mut i| i.next())
            {
                if val == 1 {
                    // Transmit Queue: read from guest and write to stdout
                    if let Err(e) = self.console.process_transmitq_chain(&mut chain) {
                        log::error!("Console transmit failed: {}", e);
                    }
                } else if val == 0 {
                    // Receive Queue: read from stdin (or buffer) and write to guest
                }

                // Acknowledge the buffers as used.
                if let Err(e) = queue.add_used(mem, chain.head_index(), 0) {
                    log::error!("Failed to add used buffer: {:?}", e);
                }
            }
        }
    }
}

// Finally, implement MutDeviceMmio by delegating to VirtioMmioDevice.
impl MutDeviceMmio for ConsoleDevice {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data);
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        self.write(offset, data);
    }
}

impl Default for ConsoleDevice {
    fn default() -> Self {
        Self::new().expect("Failed to create ConsoleDevice")
    }
}
