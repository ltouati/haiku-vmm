use std::borrow::{Borrow, BorrowMut};
use std::sync::atomic::Ordering;
use virtio_device::{VirtioConfig, VirtioMmioDevice};
use virtio_queue::Queue;
use vm_device::MutDeviceMmio;
use vm_device::bus::MmioAddress;

use std::ops::{Deref, DerefMut};
use virtio_bindings::virtio_mmio::VIRTIO_MMIO_QUEUE_PFN;

/// Generic wrapper for `VirtIO` devices to handle MMIO operations.
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
        println!("MMIO read: offset = {offset:#x}, data = {data:?}");
        self.0.read(offset, data);
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        println!("MMIO write: offset = {offset:#x}, data = {data:?}");
        self.0.write(offset, data);

        if offset == u64::from(VIRTIO_MMIO_QUEUE_PFN) {
            // VIRTIO_MMIO_INTERRUPT_ACK = 0x64
            // Writing a value with bits set clears the corresponding bits in the InterruptStatus register.
            let ack = if data.len() == 4 {
                u32::from_le_bytes(data.try_into().unwrap_or([0; 4]))
            } else {
                u32::from(data[0])
            };

            // Clear bits in interrupt status
            let config: &mut VirtioConfig<Queue> = self.0.borrow_mut();
            config
                .interrupt_status
                .fetch_and(!(ack as u8), Ordering::SeqCst);
        }
    }
}
