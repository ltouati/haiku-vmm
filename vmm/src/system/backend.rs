use crate::system::nvmm::sys::{
    NVMM_EXIT_HALTED, NVMM_EXIT_IO, NVMM_EXIT_MEMORY, NVMM_EXIT_RDMSR, NVMM_EXIT_SHUTDOWN,
    NVMM_EXIT_WRMSR, NVMM_VCPU_CONF_CPUID, NVMM_VCPU_EVENT_INTR, NvmmCpuid, NvmmCpuidSet,
    NvmmMachine, NvmmVcpu, NvmmVcpuConfCpuid, NvmmVcpuConfCpuidMask, NvmmVcpuConfCpuidUnion,
    NvmmX64Event, NvmmX64EventUnion, NvmmX64State, nvmm_gpa_map, nvmm_hva_map,
    nvmm_machine_destroy, nvmm_vcpu_configure, nvmm_vcpu_create, nvmm_vcpu_destroy, nvmm_vcpu_dump,
    nvmm_vcpu_getstate, nvmm_vcpu_inject, nvmm_vcpu_run, nvmm_vcpu_setstate,
};
use crate::system::vmachine::regs;
use crate::types::VmExit;
use anyhow::{Result, anyhow};
use iced_x86::{Decoder, DecoderOptions, OpKind, Register};
use log::debug;
use std::ffi::c_void;
use std::io;

/// Trait to abstract NVMM hypervisor calls.
pub trait HypervisorBackend: Send + Sync {
    type MachineHandle: Send;
    type VcpuHandle: Send;

    /// Allocate a new VCPU handle.
    fn create_vcpu_handle(&self) -> Self::VcpuHandle;

    /// Destroy a machine.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn machine_destroy(&self, mach: &mut Self::MachineHandle) -> i32;

    /// Map a host virtual address.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn hva_map(&self, mach: &mut Self::MachineHandle, hva: usize, size: usize) -> i32;

    /// Map a guest physical address.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn gpa_map(
        &self,
        mach: &mut Self::MachineHandle,
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
        mach: &mut Self::MachineHandle,
        cpuid: NvmmCpuid,
        vcpu: &mut Self::VcpuHandle,
    ) -> i32;

    /// Destroy a VCPU.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn vcpu_destroy(
        &self,
        mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
    ) -> i32;

    /// Run a VCPU.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn vcpu_run(
        &self,
        mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
    ) -> Result<VmExit>;

    /// Get VCPU state.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn get_vcpu_state(
        &self,
        mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
        flags: u64,
    ) -> Result<NvmmX64State>;

    /// Set VCPU state.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn set_vcpu_state(
        &self,
        mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
        state: &NvmmX64State,
        flags: u64,
    ) -> Result<()>;

    /// Configure CPUID.
    /// # Safety
    /// Dereferences raw pointers.
    #[allow(clippy::too_many_arguments)]
    unsafe fn configure_cpuid(
        &self,
        mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
        leaf: u32,
        set_eax: u32,
        set_ebx: u32,
        set_ecx: u32,
        set_edx: u32,
        del_eax: u32,
        del_ebx: u32,
        del_ecx: u32,
        del_edx: u32,
    ) -> Result<()>;

    /// Inject an event into a VCPU.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn vcpu_inject(
        &self,
        mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
        vector: u8,
    ) -> i32;

    /// Dump VCPU state.
    /// # Safety
    /// Dereferences raw pointers.
    unsafe fn vcpu_dump(&self, mach: &mut Self::MachineHandle, vcpu: &mut Self::VcpuHandle);
}

/// Real NVMM backend implementation.
pub struct NvmmBackend;

/// Wrapper for NvmmMachine to implement Send
pub struct NvmmMachineHandle(pub Box<NvmmMachine>);
unsafe impl Send for NvmmMachineHandle {}

/// Wrapper for NvmmVcpu to implement Send
pub struct NvmmVcpuHandle(pub Box<NvmmVcpu>);
unsafe impl Send for NvmmVcpuHandle {}

fn parse_nvmm_exit(
    exit: &crate::system::nvmm::sys::NvmmX64Exit,
    state: Option<&NvmmX64State>,
) -> Result<VmExit> {
    match exit.reason {
        NVMM_EXIT_IO => {
            let io_exit = unsafe { exit.u.io };

            let mut data = vec![];
            if !io_exit.in_
                && let Some(s) = state
            {
                let rax = s.gprs[regs::GPR_RAX];
                for i in 0..io_exit.operand_size {
                    data.push(((rax >> (i * 8)) & 0xFF) as u8);
                }
            }

            Ok(VmExit::Io {
                port: io_exit.port,
                is_in: io_exit.in_,
                data,
                op_size: io_exit.operand_size,
                npc: io_exit.npc,
            })
        }
        NVMM_EXIT_MEMORY => {
            let mut value = 0;
            let mem = unsafe { exit.u.mem };
            let is_write = (mem.prot & 2) != 0;
            if is_write {
                let inst_slice = &mem.inst_bytes[..mem.inst_len as usize];
                let mut decoder = Decoder::with_ip(64, inst_slice, 0, DecoderOptions::NONE);
                if let Some(instruction) = decoder.iter().next() {
                    let op1 = instruction.op1_kind();
                    if op1 == OpKind::Register {
                        let reg = instruction.op1_register();
                        if let Some(s) = state {
                            let gpr_idx = regs::reg_to_gpr(reg);
                            let full_val = s.gprs[gpr_idx];
                            match reg {
                                Register::AH | Register::CH | Register::DH | Register::BH => {
                                    value = (full_val >> 8) & 0xFF;
                                }
                                _ => value = full_val,
                            };
                        }
                    } else {
                        match op1 {
                            OpKind::Immediate8
                            | OpKind::Immediate16
                            | OpKind::Immediate32
                            | OpKind::Immediate64
                            | OpKind::Immediate8to16
                            | OpKind::Immediate8to32
                            | OpKind::Immediate8to64
                            | OpKind::Immediate32to64 => {
                                value = instruction.immediate(1);
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(VmExit::Memory {
                gpa: mem.gpa,
                is_write,
                inst_len: mem.inst_len,
                inst_bytes: mem.inst_bytes,
                value,
            })
        }
        NVMM_EXIT_RDMSR => {
            let msr_exit = unsafe { exit.u.rdmsr };
            Ok(VmExit::RdMsr {
                msr: msr_exit.msr,
                npc: msr_exit.npc,
            })
        }
        NVMM_EXIT_WRMSR => {
            let msr_exit = unsafe { exit.u.wrmsr };
            Ok(VmExit::WrMsr {
                msr: msr_exit.msr,
                val: msr_exit.val,
                npc: msr_exit.npc,
            })
        }
        NVMM_EXIT_SHUTDOWN => Ok(VmExit::Shutdown),
        NVMM_EXIT_HALTED => Ok(VmExit::Halted),
        0xffffffffffffffff => {
            let hw = unsafe { exit.u.inv.hwcode };
            debug!("NVMM_EXIT_INVALID: hwcode={:#x}", hw);
            Ok(VmExit::Unknown(0xffffffffffffffff))
        }
        r => Ok(VmExit::Unknown(r)),
    }
}

impl HypervisorBackend for NvmmBackend {
    type MachineHandle = NvmmMachineHandle;
    type VcpuHandle = NvmmVcpuHandle;

    fn create_vcpu_handle(&self) -> Self::VcpuHandle {
        NvmmVcpuHandle(Box::new(unsafe { std::mem::zeroed() }))
    }

    unsafe fn machine_destroy(&self, mach: &mut Self::MachineHandle) -> i32 {
        unsafe { nvmm_machine_destroy(&mut *mach.0) }
    }

    unsafe fn hva_map(&self, mach: &mut Self::MachineHandle, hva: usize, size: usize) -> i32 {
        unsafe { nvmm_hva_map(&mut *mach.0, hva, size) }
    }

    unsafe fn gpa_map(
        &self,
        mach: &mut Self::MachineHandle,
        hva: usize,
        gpa: u64,
        size: usize,
        flags: i32,
    ) -> i32 {
        unsafe { nvmm_gpa_map(&mut *mach.0, hva, gpa, size, flags) }
    }

    unsafe fn vcpu_create(
        &self,
        mach: &mut Self::MachineHandle,
        cpuid: NvmmCpuid,
        vcpu: &mut Self::VcpuHandle,
    ) -> i32 {
        unsafe { nvmm_vcpu_create(&mut *mach.0, cpuid, &mut *vcpu.0) }
    }

    unsafe fn vcpu_destroy(
        &self,
        mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
    ) -> i32 {
        unsafe { nvmm_vcpu_destroy(&mut *mach.0, &mut *vcpu.0) }
    }

    unsafe fn vcpu_run(
        &self,
        mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
    ) -> Result<VmExit> {
        let ret = unsafe { nvmm_vcpu_run(&mut *mach.0, &mut *vcpu.0) };
        if ret != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(4) {
                // EINTR
                return Ok(VmExit::Interrupted);
            }
            return Err(err.into());
        }

        let vcpu_ptr = &mut *vcpu.0;
        let exit_ptr = vcpu_ptr.exit;
        if exit_ptr.is_null() {
            return Err(anyhow!("Exit struct is null"));
        }
        let exit = unsafe { *exit_ptr };

        let state_ptr = vcpu_ptr.state;
        let state = if state_ptr.is_null() {
            None
        } else {
            Some(unsafe { &*state_ptr })
        };

        parse_nvmm_exit(&exit, state)
    }

    unsafe fn get_vcpu_state(
        &self,
        mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
        flags: u64,
    ) -> Result<NvmmX64State> {
        let ret = unsafe { nvmm_vcpu_getstate(&mut *mach.0, &mut *vcpu.0, flags) };
        if ret != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let vcpu_ptr = &mut *vcpu.0;
        let state_ptr = vcpu_ptr.state;
        if state_ptr.is_null() {
            return Err(anyhow!("State ptr is null"));
        }
        Ok(unsafe { *state_ptr })
    }

    unsafe fn set_vcpu_state(
        &self,
        mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
        state: &NvmmX64State,
        flags: u64,
    ) -> Result<()> {
        let vcpu_ptr = &mut *vcpu.0;
        let state_ptr = vcpu_ptr.state;
        if state_ptr.is_null() {
            return Err(anyhow!("State ptr is null"));
        }
        unsafe { *state_ptr = *state };
        let ret = unsafe { nvmm_vcpu_setstate(&mut *mach.0, &mut *vcpu.0, flags) };
        if ret != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    unsafe fn configure_cpuid(
        &self,
        mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
        leaf: u32,
        set_eax: u32,
        set_ebx: u32,
        set_ecx: u32,
        set_edx: u32,
        del_eax: u32,
        del_ebx: u32,
        del_ecx: u32,
        del_edx: u32,
    ) -> Result<()> {
        let conf = NvmmVcpuConfCpuid {
            mask: 1,
            leaf,
            u: NvmmVcpuConfCpuidUnion {
                mask: NvmmVcpuConfCpuidMask {
                    set: NvmmCpuidSet {
                        eax: set_eax,
                        ebx: set_ebx,
                        ecx: set_ecx,
                        edx: set_edx,
                    },
                    del: NvmmCpuidSet {
                        eax: del_eax,
                        ebx: del_ebx,
                        ecx: del_ecx,
                        edx: del_edx,
                    },
                },
            },
        };
        let ret = unsafe {
            nvmm_vcpu_configure(
                &mut *mach.0,
                &mut *vcpu.0,
                NVMM_VCPU_CONF_CPUID,
                &conf as *const _ as *mut c_void,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    unsafe fn vcpu_inject(
        &self,
        mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
        vector: u8,
    ) -> i32 {
        let vcpu_ptr = &mut *vcpu.0;
        let event_ptr = vcpu_ptr.event;
        if event_ptr.is_null() {
            return -1;
        }
        let event = NvmmX64Event {
            type_: NVMM_VCPU_EVENT_INTR,
            vector,
            u: NvmmX64EventUnion { pad: [0; 16] },
        };
        unsafe { *event_ptr = event };
        unsafe { nvmm_vcpu_inject(&mut *mach.0, &mut *vcpu.0) }
    }

    unsafe fn vcpu_dump(&self, mach: &mut Self::MachineHandle, vcpu: &mut Self::VcpuHandle) {
        unsafe { nvmm_vcpu_dump(&mut *mach.0, &mut *vcpu.0) }
    }
}

#[cfg(test)]
pub struct MockBackend {
    #[allow(clippy::type_complexity)]
    pub run_behaviors: std::sync::Mutex<
        std::collections::VecDeque<
            Box<dyn Fn(&mut crate::system::nvmm::sys::NvmmX64Exit) -> i32 + Send + Sync>,
        >,
    >,
}

#[cfg(test)]
impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
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
        F: Fn(&mut crate::system::nvmm::sys::NvmmX64Exit) -> i32 + Send + Sync + 'static,
    {
        self.run_behaviors
            .lock()
            .unwrap()
            .push_back(Box::new(behavior));
    }
}

#[cfg(test)]
impl HypervisorBackend for MockBackend {
    type MachineHandle = NvmmMachineHandle;
    type VcpuHandle = NvmmVcpuHandle;

    fn create_vcpu_handle(&self) -> Self::VcpuHandle {
        NvmmVcpuHandle(Box::new(unsafe { std::mem::zeroed() }))
    }

    unsafe fn machine_destroy(&self, _mach: &mut Self::MachineHandle) -> i32 {
        0
    }
    unsafe fn hva_map(&self, _mach: &mut Self::MachineHandle, _hva: usize, _size: usize) -> i32 {
        0
    }
    unsafe fn gpa_map(
        &self,
        _mach: &mut Self::MachineHandle,
        _hva: usize,
        _gpa: u64,
        _size: usize,
        _flags: i32,
    ) -> i32 {
        0
    }
    unsafe fn vcpu_create(
        &self,
        _mach: &mut Self::MachineHandle,
        _cpuid: NvmmCpuid,
        _vcpu: &mut Self::VcpuHandle,
    ) -> i32 {
        0
    }
    unsafe fn vcpu_destroy(
        &self,
        _mach: &mut Self::MachineHandle,
        _vcpu: &mut Self::VcpuHandle,
    ) -> i32 {
        0
    }
    unsafe fn vcpu_run(
        &self,
        _mach: &mut Self::MachineHandle,
        vcpu: &mut Self::VcpuHandle,
    ) -> Result<VmExit> {
        let mut behaviors = self.run_behaviors.lock().unwrap();
        if let Some(behavior) = behaviors.pop_front() {
            unsafe {
                let vcpu_ptr = &mut *vcpu.0;
                let exit_ptr = vcpu_ptr.exit;
                if !exit_ptr.is_null() {
                    let ret = behavior(&mut *exit_ptr);
                    if ret != 0 {
                        // For mock, returning error or interrupted
                        return Ok(VmExit::Interrupted); // Simplified
                    }
                    // For mock, we should interpret the exit struct set by behavior?
                    // But here behavior returns i32.
                    // Parse the exit struct
                    parse_nvmm_exit(&*exit_ptr, None)
                } else {
                    return Err(anyhow!("Exit ptr null in mock"));
                }
            }
        } else {
            Ok(VmExit::Unknown(0))
        }
    }
    unsafe fn get_vcpu_state(
        &self,
        _mach: &mut Self::MachineHandle,
        _vcpu: &mut Self::VcpuHandle,
        _flags: u64,
    ) -> Result<NvmmX64State> {
        Ok(NvmmX64State::default())
    }

    unsafe fn set_vcpu_state(
        &self,
        _mach: &mut Self::MachineHandle,
        _vcpu: &mut Self::VcpuHandle,
        _state: &NvmmX64State,
        _flags: u64,
    ) -> Result<()> {
        Ok(())
    }

    unsafe fn configure_cpuid(
        &self,
        _mach: &mut Self::MachineHandle,
        _vcpu: &mut Self::VcpuHandle,
        _leaf: u32,
        _set_eax: u32,
        _set_ebx: u32,
        _set_ecx: u32,
        _set_edx: u32,
        _del_eax: u32,
        _del_ebx: u32,
        _del_ecx: u32,
        _del_edx: u32,
    ) -> Result<()> {
        Ok(())
    }
    unsafe fn vcpu_inject(
        &self,
        _mach: &mut Self::MachineHandle,
        _vcpu: &mut Self::VcpuHandle,
        _vector: u8,
    ) -> i32 {
        0
    }
    unsafe fn vcpu_dump(&self, _mach: &mut Self::MachineHandle, _vcpu: &mut Self::VcpuHandle) {}
}
