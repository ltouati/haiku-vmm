use crate::Machine;
use crate::nvmm::sys;
use anyhow::Result;
use log::debug;
use std::io;
use std::sync::{Arc, Mutex};
use vm_device::device_manager::IoManager;

/// Represents the Global NVMM System.
pub struct NvmmSystem;

impl NvmmSystem {
    pub fn new() -> Result<Self> {
        unsafe {
            debug!("Calling nvmm_init...");
            let ret = sys::nvmm_init();
            debug!("nvmm_init returned: {}", ret);
            if ret != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(NvmmSystem)
    }

    pub fn create_machine(&self) -> Result<Machine> {
        // Allocate zeroed NvmmMachine on heap/Box
        let mut raw_box = Box::new(unsafe { std::mem::zeroed::<sys::NvmmMachine>() });

        unsafe {
            debug!("Calling nvmm_machine_create...");
            let ret = sys::nvmm_machine_create(&mut *raw_box);
            debug!("nvmm_machine_create returned: {}", ret);
            if ret != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }

        Ok(Machine {
            raw: raw_box,
            device_mgr: Arc::new(Mutex::new(IoManager::new())),
            backend: Arc::new(crate::nvmm::backend::NvmmBackend),
        })
    }
}
