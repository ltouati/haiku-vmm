pub mod regs;
pub mod runner;

pub use runner::{
    IoHandler, MemoryHandler, MsrHandler, ShutdownHandler, UnknownHandler, VcpuRunner,
};

use crate::Machine;
use crate::nvmm::sys;
use crate::types::VmExit;
use crate::utils::translate_gva;
use anyhow::{Result, anyhow};
use iced_x86::{Decoder, DecoderOptions, OpKind};
use log::debug;
use std::io;
use vm_memory::{Bytes, GuestAddress, GuestMemory};

/// A Virtual CPU.
pub struct Vcpu<'a> {
    pub(crate) _id: u32,
    pub machine: &'a mut Machine,
    pub(crate) raw: Box<sys::NvmmVcpu>,
}

impl<'a> Vcpu<'a> {
    /// Retrieve CPU State.
    pub fn get_state(&mut self, flags: u64) -> Result<sys::NvmmX64State> {
        unsafe {
            if sys::nvmm_vcpu_getstate(&mut *self.machine.raw, &mut *self.raw, flags) != 0 {
                return Err(io::Error::last_os_error().into());
            }
            let comm_ptr = self.raw.state;
            if comm_ptr.is_null() {
                return Err(anyhow!("Comm state is null"));
            }
            Ok(*comm_ptr)
        }
    }

    /// Configure VCPU (e.g. CPUID).
    #[allow(clippy::too_many_arguments)]
    pub fn configure_cpuid(
        &mut self,
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
        let mut conf = sys::NvmmVcpuConfCpuid {
            mask: 1, // mask=1 (set), exit=0
            leaf,
            u: sys::NvmmVcpuConfCpuidUnion {
                mask: sys::NvmmVcpuConfCpuidMask {
                    set: sys::NvmmCpuidSet {
                        eax: set_eax,
                        ebx: set_ebx,
                        ecx: set_ecx,
                        edx: set_edx,
                    },
                    del: sys::NvmmCpuidSet {
                        eax: del_eax,
                        ebx: del_ebx,
                        ecx: del_ecx,
                        edx: del_edx,
                    },
                },
            },
        };

        unsafe {
            if sys::nvmm_vcpu_configure(
                &mut *self.machine.raw,
                &mut *self.raw,
                sys::NVMM_VCPU_CONF_CPUID,
                &mut conf as *mut _ as *mut std::ffi::c_void,
            ) != 0
            {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    /// Set CPU State.
    pub fn set_state(&mut self, state: &sys::NvmmX64State, flags: u64) -> Result<()> {
        unsafe {
            let comm_ptr = self.raw.state;
            if comm_ptr.is_null() {
                return Err(anyhow!("Comm state is null"));
            }
            *comm_ptr = *state;

            if sys::nvmm_vcpu_setstate(&mut *self.machine.raw, &mut *self.raw, flags) != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    /// Inject an interrupt into the VCPU.
    pub fn inject_interrupt(&mut self, vector: u8) -> Result<()> {
        let mut injector = self.injector();
        injector.inject_interrupt(vector)
    }

    /// Create an injector that can be sent to other threads.
    pub fn injector(&self) -> VcpuInjector {
        let vcpu_ptr = &*self.raw as *const sys::NvmmVcpu as *mut sys::NvmmVcpu;
        let mach_ptr = &*self.machine.raw as *const sys::NvmmMachine as *mut sys::NvmmMachine;

        VcpuInjector {
            machine: mach_ptr,
            vcpu: vcpu_ptr,
        }
    }

    /// Internal function to run the CPU once.
    pub fn run(&mut self) -> Result<VmExit> {
        unsafe {
            let ret = sys::nvmm_vcpu_run(&mut *self.machine.raw, &mut *self.raw);
            if ret != 0 {
                let err = io::Error::last_os_error();
                let raw_err = err.raw_os_error();
                // println!("NVMM run returned {}, err: {:?}", ret, raw_err);
                if raw_err == Some(4) {
                    // EINTR
                    // println!("Converted to Interrupted");
                    return Ok(VmExit::Interrupted);
                }
                return Err(err.into());
            }

            let exit_ptr = self.raw.exit;
            if exit_ptr.is_null() {
                return Err(anyhow!("Exit struct is null"));
            }
            let exit = *exit_ptr;
            debug!("VM Exit Reason: {:#x}", exit.reason);

            Ok(match exit.reason {
                sys::NVMM_EXIT_IO => {
                    let io_exit = exit.u.io;

                    let mut data = vec![];
                    if !io_exit.in_ {
                        // For OUT, data is in RAX (AL)
                        // We must read state from comm page
                        let comm_ptr = self.raw.state;
                        // Assuming state is synced after run?
                        if !comm_ptr.is_null() {
                            let rax = (*comm_ptr).gprs[regs::GPR_RAX];

                            // Iterate bytes
                            for i in 0..io_exit.operand_size {
                                data.push(((rax >> (i * 8)) & 0xFF) as u8);
                            }
                        }
                    }

                    VmExit::Io {
                        port: io_exit.port,
                        is_in: io_exit.in_,
                        data,
                        op_size: io_exit.operand_size,
                        npc: io_exit.npc,
                    }
                }
                sys::NVMM_EXIT_MEMORY => {
                    let is_write = (exit.u.mem.prot & 2) != 0;
                    let mut value = 0;
                    if is_write {
                        // Decode source value
                        let inst_slice = &exit.u.mem.inst_bytes[..exit.u.mem.inst_len as usize];
                        let mut decoder = Decoder::with_ip(64, inst_slice, 0, DecoderOptions::NONE);
                        if let Some(instruction) = decoder.iter().next() {
                            // Op0 is memory (dst), Op1 is source (reg/imm)
                            let op1 = instruction.op1_kind();
                            if op1 == OpKind::Register {
                                let reg = instruction.op1_register();
                                let comm_ptr = self.raw.state;
                                if !comm_ptr.is_null() {
                                    let gpr_idx = regs::reg_to_gpr(reg);
                                    let full_val = (*comm_ptr).gprs[gpr_idx];

                                    // Handle high byte registers (AH, CH, DH, BH)
                                    // iced-x86: AH=4, CH=5, DH=6, BH=7
                                    use iced_x86::Register;
                                    value = match reg {
                                        Register::AH
                                        | Register::CH
                                        | Register::DH
                                        | Register::BH => (full_val >> 8) & 0xFF,
                                        _ => full_val,
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
                    VmExit::Memory {
                        gpa: exit.u.mem.gpa,
                        is_write,
                        inst_len: exit.u.mem.inst_len,
                        inst_bytes: exit.u.mem.inst_bytes,
                        value,
                    }
                }
                sys::NVMM_EXIT_RDMSR => {
                    let msr_exit = exit.u.rdmsr;
                    VmExit::RdMsr {
                        msr: msr_exit.msr,
                        npc: msr_exit.npc,
                    }
                }
                sys::NVMM_EXIT_WRMSR => {
                    let msr_exit = exit.u.wrmsr;
                    VmExit::WrMsr {
                        msr: msr_exit.msr,
                        val: msr_exit.val,
                        npc: msr_exit.npc,
                    }
                }
                sys::NVMM_EXIT_SHUTDOWN => VmExit::Shutdown,
                0xffffffffffffffff => {
                    let hw = exit.u.inv.hwcode;
                    debug!("NVMM_EXIT_INVALID: hwcode={:#x}", hw);
                    VmExit::Unknown(0xffffffffffffffff)
                }
                r => VmExit::Unknown(r),
            })
        }
    }

    pub fn get_rip(&mut self) -> Result<u64> {
        let _state = sys::NvmmX64State::default();
        self.get_state(regs::STATE_GPRS)
            .map(|s| s.gprs[regs::GPR_RIP])
    }

    pub fn runner(&mut self) -> VcpuRunner<'a, '_> {
        VcpuRunner::new(self)
    }

    pub fn advance_rip(&mut self, len: u64) -> Result<()> {
        let mut state = self.get_state(regs::STATE_GPRS)?;
        state.gprs[regs::GPR_RIP] += len;
        self.set_state(&state, regs::STATE_GPRS)
    }
}

/// A thread-safe injector for VCPU interrupts.
#[derive(Clone, Copy)]
pub struct VcpuInjector {
    machine: *mut sys::NvmmMachine,
    vcpu: *mut sys::NvmmVcpu,
}

unsafe impl Send for VcpuInjector {}
unsafe impl Sync for VcpuInjector {}

impl VcpuInjector {
    pub fn inject_interrupt(&mut self, vector: u8) -> Result<()> {
        unsafe {
            let event_ptr = (*self.vcpu).event;
            if event_ptr.is_null() {
                return Err(anyhow!("Event struct is null"));
            }

            let event = sys::NvmmX64Event {
                type_: sys::NVMM_VCPU_EVENT_INTR,
                vector,
                u: sys::NvmmX64EventUnion { pad: [0; 16] },
            };

            *event_ptr = event;

            if sys::nvmm_vcpu_inject(self.machine, self.vcpu) != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    /// Dump the VCPU state (to log/syslog).
    pub fn dump(&self) -> Result<()> {
        unsafe {
            sys::nvmm_vcpu_dump(self.machine, self.vcpu);
        }
        Ok(())
    }

    /// Retrieve CPU State (Thread-safe).
    pub fn get_state(&self, flags: u64) -> Result<sys::NvmmX64State> {
        unsafe {
            if sys::nvmm_vcpu_getstate(self.machine, self.vcpu, flags) != 0 {
                return Err(io::Error::last_os_error().into());
            }
            // The state is updated in the structure pointed to by vcpu->state
            let comm_ptr = (*self.vcpu).state;
            if comm_ptr.is_null() {
                return Err(anyhow!("Comm state is null"));
            }
            Ok(*comm_ptr)
        }
    }

    pub fn set_state(&self, state: &sys::NvmmX64State, flags: u64) -> Result<()> {
        unsafe {
            let comm_ptr = (*self.vcpu).state;
            if comm_ptr.is_null() {
                return Err(anyhow!("Comm state is null"));
            }
            *comm_ptr = *state;
            if sys::nvmm_vcpu_setstate(self.machine, self.vcpu, flags) != 0 {
                return Err(io::Error::last_os_error().into());
            }
            Ok(())
        }
    }

    /// Dump debug state with stack trace
    pub fn dump_debug_state<M: GuestMemory>(
        &self,
        mem: &M,
        kernel_path: Option<&std::path::Path>,
    ) -> Result<()> {
        let state = self.get_state(sys::NVMM_X64_STATE_ALL)?;

        let rip = state.gprs[regs::GPR_RIP];
        let rbp = state.gprs[regs::GPR_RBP];
        let cr3 = state.crs[2];

        println!("RIP: {:016x}", rip);
        println!("RBP: {:016x}", rbp);
        println!("CR3: {:016x}", cr3);

        // Walk Stack
        let mut stack_ips = Vec::new();
        stack_ips.push(rip);

        let mut current_rbp_gva = rbp;
        for _ in 0..20 {
            if current_rbp_gva == 0 || current_rbp_gva & 1 != 0 {
                break;
            }

            let current_rbp_gpa = match translate_gva(mem, cr3, current_rbp_gva) {
                Some(addr) => addr,
                None => break,
            };

            let next_rbp: u64 = match mem.read_obj(GuestAddress(current_rbp_gpa)) {
                Ok(val) => val,
                Err(_) => break,
            };

            let ret_addr_gpa = match translate_gva(mem, cr3, current_rbp_gva + 8) {
                Some(addr) => addr,
                None => break,
            };

            let ret_addr: u64 = match mem.read_obj(GuestAddress(ret_addr_gpa)) {
                Ok(val) => val,
                Err(_) => break,
            };

            if ret_addr == 0 {
                break;
            }

            stack_ips.push(ret_addr);
            current_rbp_gva = next_rbp;
        }

        if !stack_ips.is_empty() {
            // Only try addr2line if we have a kernel path
            if let Some(path) = kernel_path {
                println!("\nStack Trace:");
                let mut cmd = std::process::Command::new("addr2line");
                cmd.arg("-e").arg(path).arg("-f");

                for ip in &stack_ips {
                    cmd.arg(format!("{:x}", ip));
                }

                match cmd.output() {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let lines: Vec<&str> = stdout.lines().collect();
                        for (i, ip) in stack_ips.iter().enumerate() {
                            let func = lines.get(i * 2).unwrap_or(&"??");
                            let file = lines.get(i * 2 + 1).unwrap_or(&"??");
                            println!("#{:<2} {:#018x} in {} at {}", i, ip, func, file);
                        }
                    }
                    Err(e) => {
                        println!("Failed to run addr2line: {}", e);
                    }
                }
            } else {
                println!("\nStack Trace (IPs only):");
                for (i, ip) in stack_ips.iter().enumerate() {
                    println!("#{:<2} {:#018x}", i, ip);
                }
            }
        }

        let _ = self.dump(); // Also dump to kernel log
        Ok(())
    }
}
