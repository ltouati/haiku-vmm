use virtio_queue::{Queue, QueueT};
use vm_device::bus::MmioAddress;
use vm_memory::GuestMemoryMmap;

// MMIO Constants (VirtIO Spec)
pub const VIRTIO_MMIO_MAGIC_VALUE: u64 = 0x000;
pub const VIRTIO_MMIO_VERSION: u64 = 0x004;
pub const VIRTIO_MMIO_DEVICE_ID: u64 = 0x008;
pub const VIRTIO_MMIO_VENDOR_ID: u64 = 0x00c;
pub const VIRTIO_MMIO_DEVICE_FEATURES: u64 = 0x010;
pub const VIRTIO_MMIO_DEVICE_FEATURES_SEL: u64 = 0x014;
pub const VIRTIO_MMIO_DRIVER_FEATURES: u64 = 0x020;
pub const VIRTIO_MMIO_DRIVER_FEATURES_SEL: u64 = 0x024;
pub const VIRTIO_MMIO_QUEUE_SEL: u64 = 0x030;
pub const VIRTIO_MMIO_QUEUE_NUM_MAX: u64 = 0x034;
pub const VIRTIO_MMIO_QUEUE_NUM: u64 = 0x038;
pub const VIRTIO_MMIO_QUEUE_READY: u64 = 0x044;
pub const VIRTIO_MMIO_QUEUE_NOTIFY: u64 = 0x050;
pub const VIRTIO_MMIO_INTERRUPT_STATUS: u64 = 0x060;
pub const VIRTIO_MMIO_INTERRUPT_ACK: u64 = 0x064;
pub const VIRTIO_MMIO_STATUS: u64 = 0x070;
pub const VIRTIO_MMIO_QUEUE_DESC_LOW: u64 = 0x080;
pub const VIRTIO_MMIO_QUEUE_DESC_HIGH: u64 = 0x084;
pub const VIRTIO_MMIO_QUEUE_AVAIL_LOW: u64 = 0x090;
pub const VIRTIO_MMIO_QUEUE_AVAIL_HIGH: u64 = 0x094;
pub const VIRTIO_MMIO_QUEUE_USED_LOW: u64 = 0x0a0;
pub const VIRTIO_MMIO_QUEUE_USED_HIGH: u64 = 0x0a4;
pub const VIRTIO_MMIO_CONFIG_GENERATION: u64 = 0x0fc;
pub const VIRTIO_MMIO_CONFIG: u64 = 0x100;

pub trait VirtioDevice: Send + Sync {
    fn device_type(&self) -> u32;
    fn queue_max_size(&self) -> u16;
    fn activate(&mut self, mem: GuestMemoryMmap);
    fn read_config(&self, offset: u64, size: u32) -> u64;
    fn write_config(&mut self, offset: u64, val: u64, size: u32);
}

pub struct ConsoleDevice;

impl ConsoleDevice {
    pub fn new() -> Self {
        ConsoleDevice
    }
}

impl Default for ConsoleDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioDevice for ConsoleDevice {
    fn device_type(&self) -> u32 {
        3 // Console
    }

    fn queue_max_size(&self) -> u16 {
        256
    }

    fn activate(&mut self, _mem: GuestMemoryMmap) {
        // Activation hook
    }

    fn read_config(&self, _offset: u64, _size: u32) -> u64 {
        0 // TODO: cols/rows
    }

    fn write_config(&mut self, _offset: u64, _val: u64, _size: u32) {
        // TODO
    }
}

pub struct MmioTransport {
    device: Box<dyn VirtioDevice>,

    // MMIO State
    status: u32,
    interrupt_status: u32,
    #[allow(dead_code)]
    driver_features_sel: u32,
    #[allow(dead_code)]
    device_features_sel: u32,
    queue_sel: u32,
    queues: Vec<Queue>,
    guest_mem: Option<GuestMemoryMmap>,
}

impl MmioTransport {
    pub fn new(device: Box<dyn VirtioDevice>) -> Self {
        let mut queues = Vec::new();
        for _ in 0..2 {
            queues.push(Queue::new(256).unwrap());
        }

        Self {
            device,
            status: 0,
            interrupt_status: 0,
            driver_features_sel: 0,
            device_features_sel: 0,
            queue_sel: 0,
            queues,
            guest_mem: None,
        }
    }

    pub fn set_memory(&mut self, mem: GuestMemoryMmap) {
        self.guest_mem = Some(mem);
    }

    pub fn read(&self, offset: u64) -> u32 {
        match offset {
            VIRTIO_MMIO_MAGIC_VALUE => 0x74726976, // "virt"
            VIRTIO_MMIO_VERSION => 2,
            VIRTIO_MMIO_DEVICE_ID => self.device.device_type(),
            VIRTIO_MMIO_VENDOR_ID => 0x554d4551, // "QEMU"
            VIRTIO_MMIO_STATUS => self.status,
            VIRTIO_MMIO_INTERRUPT_STATUS => self.interrupt_status,

            VIRTIO_MMIO_QUEUE_NUM_MAX => 256,
            VIRTIO_MMIO_QUEUE_NUM => {
                if let Some(q) = self.queues.get(self.queue_sel as usize) {
                    q.size() as u32
                } else {
                    0
                }
            }
            VIRTIO_MMIO_QUEUE_READY => {
                if let Some(mem) = self.guest_mem.as_ref() {
                    if let Some(q) = self.queues.get(self.queue_sel as usize) {
                        if q.is_valid(mem) { 1 } else { 0 }
                    } else {
                        0
                    }
                } else {
                    0
                }
            }
            VIRTIO_MMIO_CONFIG_GENERATION => 0,
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u64, val: u32) {
        match offset {
            VIRTIO_MMIO_STATUS => self.status = val,
            VIRTIO_MMIO_INTERRUPT_ACK => self.interrupt_status &= !val,
            VIRTIO_MMIO_QUEUE_SEL => self.queue_sel = val,

            VIRTIO_MMIO_QUEUE_NUM => {
                if let Some(q) = self.queues.get_mut(self.queue_sel as usize) {
                    q.set_size(val as u16);
                }
            }
            VIRTIO_MMIO_QUEUE_DESC_LOW => {
                if let Some(q) = self.queues.get_mut(self.queue_sel as usize) {
                    q.set_desc_table_address(Some(val), None);
                }
            }
            VIRTIO_MMIO_QUEUE_DESC_HIGH => {
                if let Some(q) = self.queues.get_mut(self.queue_sel as usize) {
                    q.set_desc_table_address(None, Some(val));
                }
            }

            VIRTIO_MMIO_QUEUE_AVAIL_LOW => {
                if let Some(q) = self.queues.get_mut(self.queue_sel as usize) {
                    q.set_avail_ring_address(Some(val), None);
                }
            }
            VIRTIO_MMIO_QUEUE_AVAIL_HIGH => {
                if let Some(q) = self.queues.get_mut(self.queue_sel as usize) {
                    q.set_avail_ring_address(None, Some(val));
                }
            }

            VIRTIO_MMIO_QUEUE_USED_LOW => {
                if let Some(q) = self.queues.get_mut(self.queue_sel as usize) {
                    q.set_used_ring_address(Some(val), None);
                }
            }
            VIRTIO_MMIO_QUEUE_USED_HIGH => {
                if let Some(q) = self.queues.get_mut(self.queue_sel as usize) {
                    q.set_used_ring_address(None, Some(val));
                }
            }

            VIRTIO_MMIO_QUEUE_READY => {
                if let Some(q) = self.queues.get_mut(self.queue_sel as usize) {
                    q.set_ready(val == 1);
                }
            }

            VIRTIO_MMIO_QUEUE_NOTIFY => {
                let _queue_idx = val;
                // debug!("VirtIO Notify Queue {}", queue_idx);
                // In a real device, we would process the queue here.
                // For now, just a stub acknowledgment.
                // self.interrupt_status |= 1; // Used Buffer Notification
            }

            _ => {}
        }
    }
}

use vm_device::MutDeviceMmio;

impl MutDeviceMmio for MmioTransport {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        if data.len() == 4 {
            let val = self.read(offset);
            data.copy_from_slice(&val.to_le_bytes());
        }
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        if data.len() == 4 {
            let mut val_bytes = [0u8; 4];
            val_bytes.copy_from_slice(data);
            let val = u32::from_le_bytes(val_bytes);
            self.write(offset, val);
        }
    }
}
