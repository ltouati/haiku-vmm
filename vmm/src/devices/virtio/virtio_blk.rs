use std::borrow::{Borrow, BorrowMut};
use std::fs::File;
use std::os::unix::fs::FileExt;

use virtio_bindings::virtio_blk::{
    VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_SEG_MAX,
    VIRTIO_BLK_S_OK, virtio_blk_config,
};
use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_blk::defs::SECTOR_SHIFT;
use virtio_blk::request::{Request, RequestType};
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::{Queue, QueueOwnedT, QueueT};

use vm_memory::{Bytes, GuestMemoryMmap};

use crate::devices::pic::Pic;
use crate::devices::virtio::{DeviceType, default_signal_interrupt};
use crate::system::backend::HypervisorBackend;
use crate::system::vmachine::vcpu::VcpuInjector;
use std::sync::{Arc, Mutex};

/// `VirtIO` Block Device using rust-vmm components.
pub struct BlockDevice<B: HypervisorBackend> {
    config: VirtioConfig<Queue>,
    disk_file: File,
    guest_mem: Option<GuestMemoryMmap>,
    injector: Option<VcpuInjector<B>>,
    pic: Option<Arc<Mutex<Pic>>>,
    irq_line: u8,
}

impl<B: HypervisorBackend> BlockDevice<B> {
    pub fn new(disk_file: File) -> anyhow::Result<Self> {
        // Block device usually has 1 queue.

        let mut queues = Vec::new();
        queues.push(Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create queue: {e:?}"))?);

        let metadata = disk_file.metadata()?;
        let disk_size = metadata.len();
        let capacity_sectors = disk_size >> SECTOR_SHIFT;

        // Populate Config Space
        let config = virtio_blk_config {
            capacity: capacity_sectors.to_le(),
            seg_max: 31u32.to_le(),
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
                (&raw const config).cast::<u8>(),
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

    pub fn set_injector(&mut self, injector: VcpuInjector<B>, pic: Arc<Mutex<Pic>>, line: u8) {
        self.injector = Some(injector);
        self.pic = Some(pic);
        self.irq_line = line;
    }
}

impl<B: HypervisorBackend> VirtioDeviceType for BlockDevice<B> {
    fn device_type(&self) -> u32 {
        DeviceType::Block as u32
    }
}

impl<B: HypervisorBackend> VirtioDeviceActions for BlockDevice<B> {
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

impl<B: HypervisorBackend> Borrow<VirtioConfig<Queue>> for BlockDevice<B> {
    fn borrow(&self) -> &VirtioConfig<Queue> {
        &self.config
    }
}

impl<B: HypervisorBackend> BorrowMut<VirtioConfig<Queue>> for BlockDevice<B> {
    fn borrow_mut(&mut self) -> &mut VirtioConfig<Queue> {
        &mut self.config
    }
}

impl<B: HypervisorBackend> VirtioMmioDevice for BlockDevice<B> {
    fn queue_notify(&mut self, val: u32) {
        println!("VirtIO Block Notify: {val}");
        log::debug!("VirtIO Block Notify: {val}");

        let mem = match self.guest_mem.as_ref() {
            Some(m) => m,
            None => return,
        };

        let mut needs_interrupt = false;
        if let Some(queue) = self.config.queues.get_mut(val as usize) {
            while let Some(mut chain) = queue
                .iter(mem)
                .map_err(|e| {
                    log::error!("Failed to get queue iterator: {e:?}");
                    e
                })
                .ok()
                .and_then(|mut i| i.next())
            {
                let request = match Request::parse(&mut chain) {
                    Ok(r) => r,
                    Err(e) => {
                        log::error!("Failed to parse block request: {e}");
                        continue;
                    }
                };

                let used_len = Self::process_request(&mut self.disk_file, &request, &mut chain);

                if queue.add_used(mem, chain.head_index(), used_len).is_ok()
                    && queue.needs_notification(mem).unwrap_or(true)
                {
                    needs_interrupt = true;
                }
            }
        }
        println!("Processing done, need interrupt={needs_interrupt}");
        if needs_interrupt {
            self.signal_interrupt();
        }
    }
}

impl<B: HypervisorBackend> BlockDevice<B> {
    fn signal_interrupt(&mut self) {
        default_signal_interrupt(&mut self.config, self.pic.as_ref(), self.irq_line);
    }

    fn process_request(
        disk_file: &mut std::fs::File,
        request: &Request,
        chain: &mut virtio_queue::DescriptorChain<&GuestMemoryMmap>,
    ) -> u32 {
        match request.request_type() {
            RequestType::In => {
                println!("In request");
                // Read from file
                let sector = request.sector();
                let offset = sector << SECTOR_SHIFT;
                let mut total_read = 0;
                for (addr, len) in request.data() {
                    let mut buf = vec![0u8; *len as usize]; // Inefficient but simple
                    if let Err(e) = disk_file.read_exact_at(&mut buf, offset + total_read) {
                        log::error!("Read failed: {e}");
                        break;
                    }
                    // Write to guest
                    if let Err(e) = chain.memory().write_slice(&buf, *addr) {
                        log::error!("Guest write failed: {e:?}");
                        break;
                    }
                    total_read += u64::from(*len);
                }
                // Status
                chain
                    .memory()
                    .write_obj(VIRTIO_BLK_S_OK as u8, request.status_addr())
                    .ok();

                println!("Read {total_read} bytes from disk file, sector {sector}");
                total_read as u32
            }
            RequestType::Out => {
                println!("Out request");
                let sector = request.sector();
                let offset = sector << SECTOR_SHIFT;
                let mut total_written = 0;
                for (addr, len) in request.data() {
                    let mut buf = vec![0u8; *len as usize];
                    if let Err(e) = chain.memory().read_slice(&mut buf, *addr) {
                        log::error!("Guest read failed: {e:?}");
                        break;
                    }
                    if let Err(e) = disk_file.write_all_at(&buf, offset + total_written) {
                        log::error!("Write failed: {e}");
                        break;
                    }
                    total_written += u64::from(*len);
                }
                chain
                    .memory()
                    .write_obj(VIRTIO_BLK_S_OK as u8, request.status_addr())
                    .ok();
                println!("Wrote {total_written} bytes to disk file, sector {sector}");
                total_written as u32
            }
            RequestType::Flush => {
                println!("Flush request");
                disk_file.sync_all().ok();
                chain
                    .memory()
                    .write_obj(VIRTIO_BLK_S_OK as u8, request.status_addr())
                    .ok();
                println!("Flushed disk file");
                0
            }
            e => {
                println!("Unsupported request type: {e:?}");
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::backend::MockBackend;
    use tempfile::tempfile;

    #[test]
    fn test_block_device_new() {
        let file = tempfile().unwrap();
        file.set_len(1024 * 1024).unwrap(); // 1MB

        let dev = BlockDevice::<MockBackend>::new(file).unwrap();
        assert_eq!(dev.device_type(), 2);

        // 1MB = 2048 sectors (512 bytes each)
        let mut config = [0u8; 8];
        config.copy_from_slice(&dev.config.config_space[0..8]);
        let capacity = u64::from_le_bytes(config);
        assert_eq!(capacity, 2048);
    }
}
