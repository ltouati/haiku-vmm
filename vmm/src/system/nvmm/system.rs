use crate::system::backend::{NvmmBackend, NvmmMachineHandle};
use crate::system::nvmm::sys::{NvmmMachine, nvmm_init, nvmm_machine_create};
use crate::system::{Machine, VmmSystem};
use anyhow::Result;
use log::debug;
use std::io;
use std::sync::{Arc, Mutex};
use vm_device::device_manager::IoManager;

/// Represents the Global NVMM System.
pub struct NVMMSystem;

impl NVMMSystem {
    pub fn new() -> Result<Self> {
        unsafe {
            debug!("Calling nvmm_init...");
            let ret = nvmm_init();
            debug!("nvmm_init returned: {}", ret);
            if ret != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(NVMMSystem)
    }
}
impl VmmSystem for NVMMSystem {
    type Backend = NvmmBackend;

    fn create_machine(&self) -> Result<Machine<NvmmBackend>> {
        // Allocate zeroed NvmmMachine on heap/Box
        let mut raw_box = Box::new(unsafe { std::mem::zeroed::<NvmmMachine>() });

        unsafe {
            debug!("Calling nvmm_machine_create...");
            let ret = nvmm_machine_create(&mut *raw_box);
            debug!("nvmm_machine_create returned: {}", ret);
            if ret != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }

        Ok(Machine {
            raw: NvmmMachineHandle(raw_box),
            device_mgr: Arc::new(Mutex::new(IoManager::new())),
            backend: Arc::new(NvmmBackend),
        })
    }
}
