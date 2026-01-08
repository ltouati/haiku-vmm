use crate::system::backend::HypervisorBackend;
use crate::system::nvmm::sys::NvmmCpuid;
use crate::system::vmachine::vcpu::Vcpu;
use anyhow::{Result, anyhow};
use log::debug;
use std::io;
use std::sync::{Arc, Mutex};
use vm_device::device_manager::IoManager;
use vm_memory::{
    Address, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion, MemoryRegionAddress,
};

/// A Virtual Machine instance.
pub struct Machine<B: HypervisorBackend> {
    pub(crate) raw: B::MachineHandle,
    pub device_mgr: Arc<Mutex<IoManager>>,
    pub(crate) backend: Arc<B>,
}

impl<B: HypervisorBackend> Drop for Machine<B> {
    fn drop(&mut self) {
        unsafe { self.backend.machine_destroy(&mut self.raw) };
    }
}

unsafe impl<B: HypervisorBackend> Send for Machine<B> {}

impl<B: HypervisorBackend> Machine<B> {
    pub fn create_vcpu(&mut self, id: u32) -> Result<Vcpu<'_, B>> {
        let mut vcpu_handle = self.backend.create_vcpu_handle();

        debug!("Calling nvmm_vcpu_create...");
        if unsafe {
            self.backend
                .vcpu_create(&mut self.raw, NvmmCpuid::default(), &mut vcpu_handle)
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Vcpu {
            _id: id,
            machine: self,
            raw: vcpu_handle,
            tid: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Maps memory regions defined in `GuestMemoryMmap` into the VM.
    pub fn map_guest_memory(&mut self, guest_memory: &GuestMemoryMmap) -> Result<()> {
        for region in guest_memory.iter() {
            let base = region.start_addr().raw_value();
            let size = region.len() as usize;

            // Get pointer to host memory
            let host_ptr = region
                .get_host_address(MemoryRegionAddress(0))
                .map_err(|e| anyhow!("{:?}", e))?;

            // Register HVA
            debug!("Calling nvmm_hva_map...");
            if unsafe { self.backend.hva_map(&mut self.raw, host_ptr as usize, size) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            // Map to GPA
            debug!("Calling nvmm_gpa_map...");
            if unsafe {
                self.backend
                    .gpa_map(&mut self.raw, host_ptr as usize, base, size, 7)
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
}
