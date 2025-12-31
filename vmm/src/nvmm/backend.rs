use crate::nvmm::sys;
use std::ffi::c_void;

/// Trait to abstract NVMM hypervisor calls.
/// Trait to abstract NVMM hypervisor calls.
pub trait HypervisorBackend: Send + Sync {
    /// Destroy a machine.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn machine_destroy(&self, mach: *mut sys::NvmmMachine) -> i32;

    /// Map a host virtual address.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn hva_map(&self, mach: *mut sys::NvmmMachine, hva: usize, size: usize) -> i32;

    /// Map a guest physical address.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn gpa_map(
        &self,
        mach: *mut sys::NvmmMachine,
        hva: usize,
        gpa: u64,
        size: usize,
        flags: i32,
    ) -> i32;

    /// Create a VCPU.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn vcpu_create(
        &self,
        mach: *mut sys::NvmmMachine,
        cpuid: sys::NvmmCpuid,
        vcpu: *mut sys::NvmmVcpu,
    ) -> i32;

    /// Destroy a VCPU.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn vcpu_destroy(&self, mach: *mut sys::NvmmMachine, vcpu: *mut sys::NvmmVcpu) -> i32;

    /// Configure a VCPU.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn vcpu_configure(
        &self,
        mach: *mut sys::NvmmMachine,
        vcpu: *mut sys::NvmmVcpu,
        key: u64,
        value: *mut c_void,
    ) -> i32;

    /// Run a VCPU.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn vcpu_run(&self, mach: *mut sys::NvmmMachine, vcpu: *mut sys::NvmmVcpu) -> i32;

    /// Get VCPU state.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn vcpu_getstate(
        &self,
        mach: *mut sys::NvmmMachine,
        vcpu: *mut sys::NvmmVcpu,
        flags: u64,
    ) -> i32;

    /// Set VCPU state.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn vcpu_setstate(
        &self,
        mach: *mut sys::NvmmMachine,
        vcpu: *mut sys::NvmmVcpu,
        flags: u64,
    ) -> i32;

    /// Inject an event into a VCPU.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn vcpu_inject(&self, mach: *mut sys::NvmmMachine, vcpu: *mut sys::NvmmVcpu) -> i32;
}

/// Real NVMM backend implementation.
pub struct NvmmBackend;

impl HypervisorBackend for NvmmBackend {
    unsafe fn machine_destroy(&self, mach: *mut sys::NvmmMachine) -> i32 {
        unsafe { sys::nvmm_machine_destroy(mach) }
    }

    unsafe fn hva_map(&self, mach: *mut sys::NvmmMachine, hva: usize, size: usize) -> i32 {
        unsafe { sys::nvmm_hva_map(mach, hva, size) }
    }

    unsafe fn gpa_map(
        &self,
        mach: *mut sys::NvmmMachine,
        hva: usize,
        gpa: u64,
        size: usize,
        flags: i32,
    ) -> i32 {
        unsafe { sys::nvmm_gpa_map(mach, hva, gpa, size, flags) }
    }

    unsafe fn vcpu_create(
        &self,
        mach: *mut sys::NvmmMachine,
        cpuid: sys::NvmmCpuid,
        vcpu: *mut sys::NvmmVcpu,
    ) -> i32 {
        unsafe { sys::nvmm_vcpu_create(mach, cpuid, vcpu) }
    }

    unsafe fn vcpu_destroy(&self, mach: *mut sys::NvmmMachine, vcpu: *mut sys::NvmmVcpu) -> i32 {
        unsafe { sys::nvmm_vcpu_destroy(mach, vcpu) }
    }

    unsafe fn vcpu_configure(
        &self,
        mach: *mut sys::NvmmMachine,
        vcpu: *mut sys::NvmmVcpu,
        key: u64,
        value: *mut c_void,
    ) -> i32 {
        unsafe { sys::nvmm_vcpu_configure(mach, vcpu, key, value) }
    }

    unsafe fn vcpu_run(&self, mach: *mut sys::NvmmMachine, vcpu: *mut sys::NvmmVcpu) -> i32 {
        unsafe { sys::nvmm_vcpu_run(mach, vcpu) }
    }

    unsafe fn vcpu_getstate(
        &self,
        mach: *mut sys::NvmmMachine,
        vcpu: *mut sys::NvmmVcpu,
        flags: u64,
    ) -> i32 {
        unsafe { sys::nvmm_vcpu_getstate(mach, vcpu, flags) }
    }

    unsafe fn vcpu_setstate(
        &self,
        mach: *mut sys::NvmmMachine,
        vcpu: *mut sys::NvmmVcpu,
        flags: u64,
    ) -> i32 {
        unsafe { sys::nvmm_vcpu_setstate(mach, vcpu, flags) }
    }

    unsafe fn vcpu_inject(&self, mach: *mut sys::NvmmMachine, vcpu: *mut sys::NvmmVcpu) -> i32 {
        unsafe { sys::nvmm_vcpu_inject(mach, vcpu) }
    }
}

#[cfg(test)]
pub struct MockBackend {
    pub run_behaviors: std::sync::Mutex<
        std::collections::VecDeque<Box<dyn Fn(&mut sys::NvmmX64Exit) -> i32 + Send + Sync>>,
    >,
}

#[cfg(test)]
impl MockBackend {
    pub fn new() -> Self {
        Self {
            run_behaviors: std::sync::Mutex::new(std::collections::VecDeque::new()),
        }
    }

    pub fn queue_run_behavior<F>(&self, behavior: F)
    where
        F: Fn(&mut sys::NvmmX64Exit) -> i32 + Send + Sync + 'static,
    {
        self.run_behaviors
            .lock()
            .unwrap()
            .push_back(Box::new(behavior));
    }
}

#[cfg(test)]
impl HypervisorBackend for MockBackend {
    unsafe fn machine_destroy(&self, _mach: *mut sys::NvmmMachine) -> i32 {
        0
    }
    unsafe fn hva_map(&self, _mach: *mut sys::NvmmMachine, _hva: usize, _size: usize) -> i32 {
        0
    }
    unsafe fn gpa_map(
        &self,
        _mach: *mut sys::NvmmMachine,
        _hva: usize,
        _gpa: u64,
        _size: usize,
        _flags: i32,
    ) -> i32 {
        0
    }
    unsafe fn vcpu_create(
        &self,
        _mach: *mut sys::NvmmMachine,
        _cpuid: sys::NvmmCpuid,
        _vcpu: *mut sys::NvmmVcpu,
    ) -> i32 {
        0
    }
    unsafe fn vcpu_destroy(&self, _mach: *mut sys::NvmmMachine, _vcpu: *mut sys::NvmmVcpu) -> i32 {
        0
    }
    unsafe fn vcpu_configure(
        &self,
        _mach: *mut sys::NvmmMachine,
        _vcpu: *mut sys::NvmmVcpu,
        _key: u64,
        _value: *mut c_void,
    ) -> i32 {
        0
    }
    unsafe fn vcpu_run(&self, _mach: *mut sys::NvmmMachine, vcpu: *mut sys::NvmmVcpu) -> i32 {
        let mut behaviors = self.run_behaviors.lock().unwrap();
        if let Some(behavior) = behaviors.pop_front() {
            // Safe because we are in a test and vcpu pointer should be valid if machine is set up correctly
            // We need to access (*vcpu).exit which is a pointer to the exit struct
            unsafe {
                let exit_ptr = (*vcpu).exit;
                if !exit_ptr.is_null() {
                    behavior(&mut *exit_ptr)
                } else {
                    -1 // Error if exit ptr is null
                }
            }
        } else {
            0 // Default success (nop) if no behavior queued
        }
    }
    unsafe fn vcpu_getstate(
        &self,
        _mach: *mut sys::NvmmMachine,
        _vcpu: *mut sys::NvmmVcpu,
        _flags: u64,
    ) -> i32 {
        0
    }
    unsafe fn vcpu_setstate(
        &self,
        _mach: *mut sys::NvmmMachine,
        _vcpu: *mut sys::NvmmVcpu,
        _flags: u64,
    ) -> i32 {
        0
    }
    unsafe fn vcpu_inject(&self, _mach: *mut sys::NvmmMachine, _vcpu: *mut sys::NvmmVcpu) -> i32 {
        0
    }
}
