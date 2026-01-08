use std::borrow::{Borrow, BorrowMut};
use std::sync::atomic::Ordering;
use virtio_device::{VirtioConfig, VirtioMmioDevice};
use virtio_queue::Queue;
use vm_device::MutDeviceMmio;
use vm_device::bus::MmioAddress;

use std::ops::{Deref, DerefMut};
use virtio_bindings::virtio_mmio::VIRTIO_MMIO_QUEUE_PFN;

/// Generic wrapper for VirtIO devices to handle MMIO operations.
pub struct MmioVirtioDevice<T: VirtioMmioDevice>(pub T);

impl<T: VirtioMmioDevice> Deref for MmioVirtioDevice<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: VirtioMmioDevice> DerefMut for MmioVirtioDevice<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: VirtioMmioDevice> MutDeviceMmio for MmioVirtioDevice<T>
where
    T: BorrowMut<VirtioConfig<Queue>> + Borrow<VirtioConfig<Queue>>,
{
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        println!("MMIO read: offset = {:#x}, data = {:?}", offset, data);
        self.0.read(offset, data);
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        println!("MMIO write: offset = {:#x}, data = {:?}", offset, data);
        self.0.write(offset, data);

        if offset == VIRTIO_MMIO_QUEUE_PFN as u64 {
            // VIRTIO_MMIO_INTERRUPT_ACK = 0x64
            // Writing a value with bits set clears the corresponding bits in the InterruptStatus register.
            let ack = if data.len() == 4 {
                u32::from_le_bytes(data.try_into().unwrap_or([0; 4]))
            } else {
                data[0] as u32
            };

            // Clear bits in interrupt status
            let config: &mut VirtioConfig<Queue> = self.0.borrow_mut();
            config
                .interrupt_status
                .fetch_and(!(ack as u8), Ordering::SeqCst);
        }
    }
}
