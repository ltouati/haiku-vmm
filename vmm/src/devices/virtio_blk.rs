use std::borrow::{Borrow, BorrowMut};
use std::fs::File;
use std::os::unix::fs::FileExt;

use virtio_bindings::virtio_blk::*;
use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_blk::defs::SECTOR_SHIFT;
use virtio_blk::request::{Request, RequestType};
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::{Queue, QueueOwnedT, QueueT};

use vm_device::MutDeviceMmio;
use vm_device::bus::MmioAddress;
use vm_memory::{Bytes, GuestMemoryMmap};

use crate::VcpuInjector;
use crate::devices::pic::Pic;
use std::sync::{Arc, Mutex};

/// VirtIO Block Device using rust-vmm components.
pub struct BlockDevice {
    config: VirtioConfig<Queue>,
    disk_file: File,
    guest_mem: Option<GuestMemoryMmap>,
    injector: Option<VcpuInjector>,
    pic: Option<Arc<Mutex<Pic>>>,
    irq_line: u8,
}

impl BlockDevice {
    pub fn new(disk_file: File) -> anyhow::Result<Self> {
        // Block device usually has 1 queue.

        let mut queues = Vec::new();
        queues
            .push(Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create queue: {:?}", e))?);

        let metadata = disk_file.metadata()?;
        let disk_size = metadata.len();
        let capacity_sectors = disk_size >> SECTOR_SHIFT;

        // Populate Config Space
        let config = virtio_blk_config {
            capacity: capacity_sectors.to_le(),
            seg_max: 254u32.to_le(),
            blk_size: 512u32.to_le(),
            num_queues: 1u16.to_le(),
            ..Default::default()
        };

        // Features
        let mut device_features = 0u64;
        device_features |= 1 << VIRTIO_BLK_F_FLUSH;
        device_features |= 1 << VIRTIO_BLK_F_SEG_MAX;
        device_features |= 1 << VIRTIO_BLK_F_BLK_SIZE;
        device_features |= 1 << VIRTIO_BLK_F_MQ;

        device_features |= 1 << VIRTIO_F_VERSION_1; // Modern device

        // Serialize config to bytes
        let config_space = unsafe {
            std::slice::from_raw_parts(
                &config as *const _ as *const u8,
                std::mem::size_of::<virtio_blk_config>(),
            )
            .to_vec()
        };

        Ok(Self {
            config: VirtioConfig::new(device_features, queues, config_space),
            disk_file,
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
}

impl VirtioDeviceType for BlockDevice {
    fn device_type(&self) -> u32 {
        2 // Block
    }
}

impl VirtioDeviceActions for BlockDevice {
    type E = anyhow::Error;

    fn activate(&mut self) -> anyhow::Result<()> {
        log::debug!("VirtIO Block Activated");
        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        log::debug!("VirtIO Block Reset");
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

                let used_len = Self::process_request(&mut self.disk_file, &request, &mut chain);

                if queue.add_used(mem, chain.head_index(), used_len).is_ok() {
                    needs_interrupt |= queue.needs_notification(mem).unwrap_or(true);
                }
            }
        }

        if needs_interrupt && let Some(_injector) = &mut self.injector {
            self.config
                .interrupt_status
                .store(1, std::sync::atomic::Ordering::SeqCst);

            // Route through PIC (Pulse)
            if let Some(pic) = &self.pic {
                let mut p = pic.lock().unwrap();
                p.set_irq(self.irq_line, true);
                p.set_irq(self.irq_line, false);
            }

            // Manual Injection Removed - Handled by PIC Polling
            /* if let Some(inj) = &mut self.injector {
                let _ = inj.inject_interrupt(self.irq_line as u8);
            } */
        }
    }
}

impl MutDeviceMmio for BlockDevice {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        self.read(offset, data);

        // VIRTIO_MMIO_INTERRUPT_STATUS = 0x60
        // Reading this register returns the interrupt status and clears it.
        if offset == 0x60 {
            // Read Status - Do NOT clear. Spec says Write to ACK (0x64) clears it.
            // Just return data (already done by self.read above which copies from config space)
            log::debug!(
                "VirtIO Blk ISR Read. Status: {:#x}",
                self.config
                    .interrupt_status
                    .load(std::sync::atomic::Ordering::SeqCst)
            );
        }

        log::debug!(
            "VirtIO Blk MMIO Read: Offset {:#x}, Data {:?}, Len {}",
            offset,
            data,
            data.len()
        );
        if offset == 0x04 && data.len() >= 4 {
            let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
            log::debug!("VirtIO Blk Version Read: {}", version);
        }
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        log::debug!(
            "VirtIO Blk MMIO Write: Offset {:#x}, Data {:?}, Len {}",
            offset,
            data,
            data.len()
        );
        // Check legacy status access if possible, or just observe effects
        self.write(offset, data);
        if offset == 0x70 {
            // Status update
            log::debug!(
                "VirtIO Blk Status Write. New Status (from config): {:#x}",
                self.config.device_status
            );
        } else if offset == 0x64 {
            // VIRTIO_MMIO_INTERRUPT_ACK = 0x64
            // Writing a value with bits set clears the corresponding bits in the InterruptStatus register.
            let ack = if data.len() == 4 {
                u32::from_le_bytes(data.try_into().unwrap())
            } else {
                data[0] as u32 // Partial/byte write? Assume 32-bit usually.
            };

            // Clear bits
            // fetch_and with !ack (bitwise NAND?)
            // We want (status & !ack).
            // atomic.fetch_and takes the value to AND with. So passed value is !ack.
            self.config
                .interrupt_status
                .fetch_and(!(ack as u8), std::sync::atomic::Ordering::SeqCst);

            // If status is now 0, de-assert IRQ
            // We need to read it back OR check logic.
            // Simplified: If ACK matches Used Ring (bit 0) or Configuration (bit 1), de-assert?
            // Actually, if we clear the bits that CAUSED the interrupt, we should de-assert.
            // Since we only use bit 0 (Used Buffer) mostly.
            // Let's just Check current status.
            let current = self
                .config
                .interrupt_status
                .load(std::sync::atomic::Ordering::SeqCst);
            #[allow(clippy::collapsible_if)]
            if current == 0 {
                if let Some(pic) = &self.pic {
                    pic.lock().unwrap().set_irq(self.irq_line, false);
                    log::debug!("VirtIO Blk IRQ {} De-asserted via ACK", self.irq_line);
                }
            }
        }
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
