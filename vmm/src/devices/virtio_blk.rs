use std::borrow::{Borrow, BorrowMut};
use std::fs::File;
use std::os::unix::fs::FileExt;

use virtio_bindings::virtio_blk::*;
use virtio_blk::defs::SECTOR_SHIFT;
use virtio_blk::request::{Request, RequestType};
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::{Queue, QueueOwnedT, QueueT};

use vm_device::MutDeviceMmio;
use vm_device::bus::MmioAddress;
use vm_memory::{Bytes, GuestMemoryMmap};

use crate::VcpuInjector;

/// VirtIO Block Device using rust-vmm components.
pub struct BlockDevice {
    config: VirtioConfig<Queue>,
    disk_file: File,
    guest_mem: Option<GuestMemoryMmap>,
    injector: Option<VcpuInjector>,
    irq_vector: u8,
}

impl BlockDevice {
    pub fn new(disk_file: File) -> anyhow::Result<Self> {
        // Block device usually has 1 queue.

        let mut queues = Vec::new();
        queues
            .push(Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create queue: {:?}", e))?);

        let metadata = disk_file.metadata()?;
        let disk_size = metadata.len();

        // Device features
        let device_features = (1u64 << VIRTIO_BLK_F_FLUSH) | (1u64 << 32); // VIRTIO_F_VERSION_1

        // Config space: contains capacity (u64 in sectors)
        let capacity_sectors = disk_size >> SECTOR_SHIFT;
        let mut config_space = Vec::with_capacity(8);
        config_space.extend_from_slice(&capacity_sectors.to_le_bytes());

        Ok(Self {
            config: VirtioConfig::new(device_features, queues, config_space),
            disk_file,
            guest_mem: None,
            injector: None,
            irq_vector: 0,
        })
    }

    pub fn set_memory(&mut self, mem: GuestMemoryMmap) {
        self.guest_mem = Some(mem);
    }

    pub fn set_injector(&mut self, injector: VcpuInjector, vector: u8) {
        self.injector = Some(injector);
        self.irq_vector = vector;
    }
}

impl VirtioDeviceType for BlockDevice {
    fn device_type(&self) -> u32 {
        2 // Block
    }
}

impl VirtioDeviceActions for BlockDevice {
    type E = anyhow::Error;

    fn activate(&mut self) -> anyhow::Result<()> {
        log::info!("VirtIO Block Activated");
        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        log::info!("VirtIO Block Reset");
        Ok(())
    }
}

impl Borrow<VirtioConfig<Queue>> for BlockDevice {
    fn borrow(&self) -> &VirtioConfig<Queue> {
        &self.config
    }
}

impl BorrowMut<VirtioConfig<Queue>> for BlockDevice {
    fn borrow_mut(&mut self) -> &mut VirtioConfig<Queue> {
        &mut self.config
    }
}

impl VirtioMmioDevice for BlockDevice {
    fn queue_notify(&mut self, val: u32) {
        log::debug!("VirtIO Block Notify: {}", val);

        let mem = match self.guest_mem.as_ref() {
            Some(m) => m,
            None => return,
        };

        let mut needs_interrupt = false;
        if let Some(queue) = self.config.queues.get_mut(val as usize) {
            while let Some(mut chain) = queue
                .iter(mem)
                .map_err(|e| {
                    log::error!("Failed to get queue iterator: {:?}", e);
                    e
                })
                .ok()
                .and_then(|mut i| i.next())
            {
                let request = match Request::parse(&mut chain) {
                    Ok(r) => r,
                    Err(e) => {
                        log::error!("Failed to parse block request: {}", e);
                        continue;
                    }
                };

                // Process Request:
                // Process Request:
                let used_len = Self::process_request(&mut self.disk_file, &request, &mut chain);

                if queue.add_used(mem, chain.head_index(), used_len).is_ok() {
                    needs_interrupt |= queue.needs_notification(mem).unwrap_or(true);
                }
            }
        }

        if needs_interrupt && let Some(injector) = &mut self.injector {
            injector.inject_interrupt(self.irq_vector).ok();
            log::debug!("Injected IRQ {}", self.irq_vector);
        }
    }
}

impl MutDeviceMmio for BlockDevice {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data);
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        self.write(offset, data);
    }
}

impl BlockDevice {
    fn process_request(
        disk_file: &mut std::fs::File,
        request: &Request,
        chain: &mut virtio_queue::DescriptorChain<&GuestMemoryMmap>,
    ) -> u32 {
        match request.request_type() {
            RequestType::In => {
                // Read from file
                let sector = request.sector();
                let offset = sector << SECTOR_SHIFT;
                let mut total_read = 0;
                for (addr, len) in request.data() {
                    let mut buf = vec![0u8; *len as usize]; // Inefficient but simple
                    if let Err(e) = disk_file.read_exact_at(&mut buf, offset + total_read) {
                        log::error!("Read failed: {}", e);
                        break;
                    }
                    // Write to guest
                    if let Err(e) = chain.memory().write_slice(&buf, *addr) {
                        log::error!("Guest write failed: {:?}", e);
                        break;
                    }
                    total_read += *len as u64;
                }
                // Status
                chain
                    .memory()
                    .write_obj(VIRTIO_BLK_S_OK as u8, request.status_addr())
                    .ok();

                total_read as u32
            }
            RequestType::Out => {
                let sector = request.sector();
                let offset = sector << SECTOR_SHIFT;
                let mut total_written = 0;
                for (addr, len) in request.data() {
                    let mut buf = vec![0u8; *len as usize];
                    if let Err(e) = chain.memory().read_slice(&mut buf, *addr) {
                        log::error!("Guest read failed: {:?}", e);
                        break;
                    }
                    if let Err(e) = disk_file.write_all_at(&buf, offset + total_written) {
                        log::error!("Write failed: {}", e);
                        break;
                    }
                    total_written += *len as u64;
                }
                chain
                    .memory()
                    .write_obj(VIRTIO_BLK_S_OK as u8, request.status_addr())
                    .ok();
                0
            }
            RequestType::Flush => {
                disk_file.sync_all().ok();
                chain
                    .memory()
                    .write_obj(VIRTIO_BLK_S_OK as u8, request.status_addr())
                    .ok();
                0
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempfile;

    #[test]
    fn test_block_device_new() {
        let file = tempfile().unwrap();
        file.set_len(1024 * 1024).unwrap(); // 1MB

        let dev = BlockDevice::new(file).unwrap();
        assert_eq!(dev.device_type(), 2);

        // 1MB = 2048 sectors (512 bytes each)
        let mut config = [0u8; 8];
        config.copy_from_slice(&dev.config.config_space[0..8]);
        let capacity = u64::from_le_bytes(config);
        assert_eq!(capacity, 2048);
    }
}
