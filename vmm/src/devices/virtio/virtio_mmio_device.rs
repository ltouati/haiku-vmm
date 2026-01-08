use std::borrow::{Borrow, BorrowMut};
use virtio_device::{VirtioConfig, VirtioMmioDevice};
use virtio_queue::Queue;
use vm_device::MutDeviceMmio;
use vm_device::bus::MmioAddress;

use std::ops::{Deref, DerefMut};

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
        self.0.read(offset, data);
        log::trace!("MMIO read: offset = {offset:#x}, data = {data:?}");
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        log::trace!("MMIO write: offset = {offset:#x}, data = {data:?}");
        self.0.write(offset, data);
    }
}
