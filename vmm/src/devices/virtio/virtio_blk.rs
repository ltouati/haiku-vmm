use std::borrow::{Borrow, BorrowMut};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use virtio_bindings::virtio_blk::{
    VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_SEG_MAX,
    VIRTIO_BLK_S_OK, virtio_blk_config,
};
use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_blk::defs::SECTOR_SHIFT;
use virtio_blk::request::{Request, RequestType};
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::{Queue, QueueOwnedT, QueueT};

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::devices::pic::Pic;
use crate::devices::virtio::{DeviceType, default_signal_interrupt};
use crate::system::backend::HypervisorBackend;
use crate::system::vmachine::vcpu::VcpuInjector;

/// Parsed block request that can be sent to the worker thread.
struct ParsedRequest {
    request_type: RequestType,
    sector: u64,
    status_addr: GuestAddress,
    data_segments: Vec<DataSegment>,
}

enum DataSegment {
    Read { addr: GuestAddress, len: u32 },
    Write { data: Vec<u8> },
}

/// Message sent to the worker thread for pipelined I/O.
struct WorkerMessage {
    queue_idx: usize,
    request: ParsedRequest,
    head_index: u16,
}

/// Shared state between VCPU thread and worker thread.
struct SharedState {
    config: VirtioConfig<Queue>,
    pic: Option<Arc<Mutex<Pic>>>,
    irq_line: u8,
    guest_mem: Option<GuestMemoryMmap>,
}

/// `VirtIO` Block Device with fully pipelined I/O.
pub struct BlockDevice<B: HypervisorBackend> {
    state: Arc<Mutex<SharedState>>,
    disk_file: Arc<Mutex<File>>,
    injector: Option<VcpuInjector<B>>,
    worker_sender: Option<Sender<WorkerMessage>>,
    worker_thread: Option<JoinHandle<()>>,
    worker_stop: Arc<AtomicBool>,
}

impl<B: HypervisorBackend> BlockDevice<B> {
    pub fn new(disk_file: File) -> anyhow::Result<Self> {
        let mut queues = Vec::new();
        queues.push(Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create queue: {e:?}"))?);

        let metadata = disk_file.metadata()?;
        let disk_size = metadata.len();
        let capacity_sectors = disk_size >> SECTOR_SHIFT;

        let blk_config = virtio_blk_config {
            capacity: capacity_sectors.to_le(),
            seg_max: 31u32.to_le(),
            blk_size: 512u32.to_le(),
            num_queues: 1u16.to_le(),
            ..Default::default()
        };

        let mut device_features = 0u64;
        device_features |= 1 << VIRTIO_BLK_F_FLUSH;
        device_features |= 1 << VIRTIO_BLK_F_SEG_MAX;
        device_features |= 1 << VIRTIO_BLK_F_BLK_SIZE;
        device_features |= 1 << VIRTIO_BLK_F_MQ;
        device_features |= 1 << VIRTIO_F_VERSION_1;

        let config_space = unsafe {
            std::slice::from_raw_parts(
                (&raw const blk_config).cast::<u8>(),
                std::mem::size_of::<virtio_blk_config>(),
            )
            .to_vec()
        };

        let state = SharedState {
            config: VirtioConfig::new(device_features, queues, config_space),
            pic: None,
            irq_line: 0,
            guest_mem: None,
        };

        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            disk_file: Arc::new(Mutex::new(disk_file)),
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

        let disk_file = Arc::clone(&self.disk_file);
        let state = Arc::clone(&self.state);
        let stop_flag = Arc::clone(&self.worker_stop);

        let handle = thread::spawn(move || {
            log::info!("VirtIO Block Worker: Started (pipelined mode)");

            loop {
                let Ok(msg) = rx.recv() else {
                    log::info!("VirtIO Block Worker: Channel closed, exiting");
                    break;
                };

                if stop_flag.load(Ordering::SeqCst) {
                    log::info!("VirtIO Block Worker: Stop flag set, exiting");
                    break;
                }

                let mut file = disk_file.lock().unwrap();
                let mut state_guard = state.lock().unwrap();

                let Some(mem) = state_guard.guest_mem.clone() else {
                    log::error!("Block Worker: No guest memory");
                    continue;
                };

                // Extract pic/irq before queue borrow
                let pic = state_guard.pic.clone();
                let irq_line = state_guard.irq_line;

                let used_len = Self::process_parsed_request(&mut file, &msg.request, &mem);
                drop(file);

                // Update used ring and check if interrupt needed
                let needs_interrupt =
                    if let Some(queue) = state_guard.config.queues.get_mut(msg.queue_idx) {
                        queue.add_used(&mem, msg.head_index, used_len).is_ok()
                            && queue.needs_notification(&mem).unwrap_or(true)
                    } else {
                        false
                    };

                if needs_interrupt {
                    default_signal_interrupt(&mut state_guard.config, pic.as_ref(), irq_line);
                }
            }

            log::info!("VirtIO Block Worker: Exited");
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

    fn parse_request_from_chain(
        request: &Request,
        chain: &mut virtio_queue::DescriptorChain<&GuestMemoryMmap>,
    ) -> ParsedRequest {
        let mut data_segments = Vec::new();

        match request.request_type() {
            RequestType::In => {
                for (addr, len) in request.data() {
                    data_segments.push(DataSegment::Read {
                        addr: *addr,
                        len: *len,
                    });
                }
            }
            RequestType::Out => {
                for (addr, len) in request.data() {
                    let mut buf = vec![0u8; *len as usize];
                    if let Err(e) = chain.memory().read_slice(&mut buf, *addr) {
                        log::error!("Failed to read guest data for write: {e:?}");
                    }
                    data_segments.push(DataSegment::Write { data: buf });
                }
            }
            _ => {}
        }

        ParsedRequest {
            request_type: request.request_type(),
            sector: request.sector(),
            status_addr: request.status_addr(),
            data_segments,
        }
    }

    fn process_parsed_request(
        disk_file: &mut File,
        request: &ParsedRequest,
        mem: &GuestMemoryMmap,
    ) -> u32 {
        match request.request_type {
            RequestType::In => {
                let offset = request.sector << SECTOR_SHIFT;
                let mut total_read = 0u64;

                for segment in &request.data_segments {
                    if let DataSegment::Read { addr, len } = segment {
                        let mut buf = vec![0u8; *len as usize];
                        if let Err(e) = disk_file.read_exact_at(&mut buf, offset + total_read) {
                            log::error!("Read failed: {e}");
                            break;
                        }
                        if let Err(e) = mem.write_slice(&buf, *addr) {
                            log::error!("Guest write failed: {e:?}");
                            break;
                        }
                        total_read += u64::from(*len);
                    }
                }

                mem.write_obj(VIRTIO_BLK_S_OK as u8, request.status_addr)
                    .ok();
                log::debug!("Block Read: sector={}, bytes={total_read}", request.sector);
                total_read as u32
            }
            RequestType::Out => {
                let offset = request.sector << SECTOR_SHIFT;
                let mut total_written = 0u64;

                for segment in &request.data_segments {
                    if let DataSegment::Write { data } = segment {
                        if let Err(e) = disk_file.write_all_at(data, offset + total_written) {
                            log::error!("Write failed: {e}");
                            break;
                        }
                        total_written += data.len() as u64;
                    }
                }

                mem.write_obj(VIRTIO_BLK_S_OK as u8, request.status_addr)
                    .ok();
                log::debug!(
                    "Block Write: sector={}, bytes={total_written}",
                    request.sector
                );
                total_written as u32
            }
            RequestType::Flush => {
                disk_file.sync_all().ok();
                mem.write_obj(VIRTIO_BLK_S_OK as u8, request.status_addr)
                    .ok();
                log::debug!("Block Flush");
                0
            }
            _ => {
                log::warn!("Unsupported block request type: {:?}", request.request_type);
                0
            }
        }
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
        log::debug!("VirtIO Block Activated - spawning pipelined worker");
        self.spawn_worker();
        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        log::debug!("VirtIO Block Reset - stopping worker");
        self.stop_worker();
        Ok(())
    }
}

impl<B: HypervisorBackend> Borrow<VirtioConfig<Queue>> for BlockDevice<B> {
    fn borrow(&self) -> &VirtioConfig<Queue> {
        unsafe {
            let guard = self.state.lock().unwrap();
            let ptr = &raw const guard.config;
            &*ptr
        }
    }
}

impl<B: HypervisorBackend> BorrowMut<VirtioConfig<Queue>> for BlockDevice<B> {
    fn borrow_mut(&mut self) -> &mut VirtioConfig<Queue> {
        unsafe {
            let mut guard = self.state.lock().unwrap();
            let ptr = &raw mut guard.config;
            &mut *ptr
        }
    }
}

impl<B: HypervisorBackend> VirtioMmioDevice for BlockDevice<B> {
    fn queue_notify(&mut self, val: u32) {
        log::debug!("VirtIO Block Notify: queue={val} (pipelined)");

        let queue_idx = val as usize;
        let mut state = self.state.lock().unwrap();

        let Some(mem) = state.guest_mem.clone() else {
            return;
        };

        // Extract pic/irq before queue iteration
        let pic = state.pic.clone();
        let irq_line = state.irq_line;

        // Collect all requests first, then release queue borrow
        let mut requests = Vec::new();
        if let Some(queue) = state.config.queues.get_mut(queue_idx) {
            while let Some(mut chain) = queue
                .iter(&mem)
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

                let head_index = chain.head_index();
                let parsed = Self::parse_request_from_chain(&request, &mut chain);
                requests.push((head_index, parsed));
            }
        }

        // Send requests to worker (or process sync)
        for (head_index, parsed) in requests {
            if let Some(sender) = &self.worker_sender {
                let msg = WorkerMessage {
                    queue_idx,
                    request: parsed,
                    head_index,
                };
                if sender.send(msg).is_err() {
                    log::error!("Failed to send to block worker");
                }
            } else {
                // Fallback: process synchronously
                let used_len = {
                    let mut file = self.disk_file.lock().unwrap();
                    Self::process_parsed_request(&mut file, &parsed, &mem)
                };

                let needs_interrupt = if let Some(queue) = state.config.queues.get_mut(queue_idx) {
                    queue.add_used(&mem, head_index, used_len).is_ok()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::backend::MockBackend;
    use tempfile::tempfile;

    #[test]
    fn test_block_device_new() {
        let file = tempfile().unwrap();
        file.set_len(1024 * 1024).unwrap();

        let dev = BlockDevice::<MockBackend>::new(file).unwrap();
        assert_eq!(dev.device_type(), 2);

        let state = dev.state.lock().unwrap();
        let mut config = [0u8; 8];
        config.copy_from_slice(&state.config.config_space[0..8]);
        let capacity = u64::from_le_bytes(config);
        assert_eq!(capacity, 2048);
    }
}
