use crate::system::Machine;
use crate::system::backend::HypervisorBackend;
use crate::system::nvmm::sys::{NVMM_X64_STATE_ALL, NVMM_X64_STATE_GPRS, NvmmX64State};
use crate::system::vmachine::regs;
use crate::system::vmachine::runner::VcpuRunner;
use crate::types::VmExit;
use crate::utils::translate_gva;
use anyhow::{Result, anyhow};
use log::debug;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use vm_memory::{Bytes, GuestAddress, GuestMemory};

/// A Virtual CPU.
pub struct Vcpu<'a, B: HypervisorBackend> {
    pub(crate) _id: u32,
    pub machine: &'a mut Machine<B>,
    pub(crate) raw: B::VcpuHandle,
    pub(crate) tid: Arc<AtomicUsize>,
}

unsafe impl<B: HypervisorBackend> Send for Vcpu<'_, B> {}

impl<'a, B: HypervisorBackend> Vcpu<'a, B> {
    /// Retrieve CPU State.
    pub fn get_state(&mut self, flags: u64) -> Result<NvmmX64State> {
        unsafe {
            self.machine
                .backend
                .get_vcpu_state(&mut self.machine.raw, &mut self.raw, flags)
        }
    }

    /// Check if Interrupts are enabled (RFLAGS.IF = 1).
    pub fn interrupts_enabled(&mut self) -> Result<bool> {
        let state = self.get_state(NVMM_X64_STATE_GPRS)?;
        Ok((state.gprs[regs::GPR_RFLAGS] & (1 << 9)) != 0)
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
        unsafe {
            self.machine.backend.configure_cpuid(
                &mut self.machine.raw,
                &mut self.raw,
                leaf,
                set_eax,
                set_ebx,
                set_ecx,
                set_edx,
                del_eax,
                del_ebx,
                del_ecx,
                del_edx,
            )
        }
    }

    /// Set CPU State.
    pub fn set_state(&mut self, state: &NvmmX64State, flags: u64) -> Result<()> {
        unsafe {
            self.machine
                .backend
                .set_vcpu_state(&mut self.machine.raw, &mut self.raw, state, flags)
        }
    }

    /// Inject an interrupt into the VCPU.
    pub fn inject_interrupt(&mut self, vector: u8) -> Result<()> {
        let mut injector = self.injector();
        injector.inject_interrupt(vector)
    }

    /// Create an injector that can be sent to other threads.
    pub fn injector(&self) -> VcpuInjector<B> {
        // Unsafe: Getting pointers to handles.
        // B::MachineHandle is owned by Machine. Machine is assumed pinned/stable during run.
        let mach_ptr = &self.machine.raw as *const B::MachineHandle as *mut B::MachineHandle;
        let vcpu_ptr = &self.raw as *const B::VcpuHandle as *mut B::VcpuHandle;

        VcpuInjector {
            machine: mach_ptr,
            vcpu: vcpu_ptr,
            backend: self.machine.backend.clone(),
            tid: self.tid.clone(),
        }
    }

    /// Internal function to run the CPU once.
    pub fn run(&mut self) -> Result<VmExit> {
        unsafe {
            // Update TID storage
            self.tid
                .store(libc::pthread_self() as usize, Ordering::Relaxed);

            let exit_result = self
                .machine
                .backend
                .vcpu_run(&mut self.machine.raw, &mut self.raw);

            match exit_result {
                Ok(exit) => {
                    debug!("VM Exit Reason: {:?}", exit);
                    Ok(exit)
                }
                Err(exit_result) => Err(anyhow!("VM Exit Reason: {:?}", exit_result)),
            }
        }
    }

    pub fn get_rip(&mut self) -> Result<u64> {
        // NvmmX64State::default isn't const, but safe to default.
        let _state = NvmmX64State::default();
        self.get_state(regs::STATE_GPRS)
            .map(|s| s.gprs[regs::GPR_RIP])
    }

    pub fn runner(&mut self) -> VcpuRunner<'a, '_, B> {
        VcpuRunner::new(self)
    }

    pub fn advance_rip(&mut self, len: u64) -> Result<()> {
        let mut state = self.get_state(regs::STATE_GPRS)?;
        state.gprs[regs::GPR_RIP] += len;
        self.set_state(&state, regs::STATE_GPRS)
    }
}

/// A thread-safe injector for VCPU interrupts.
pub struct VcpuInjector<B: HypervisorBackend> {
    machine: *mut B::MachineHandle,
    vcpu: *mut B::VcpuHandle,
    backend: Arc<B>,
    tid: Arc<AtomicUsize>,
}

impl<B: HypervisorBackend> Clone for VcpuInjector<B> {
    fn clone(&self) -> Self {
        Self {
            machine: self.machine,
            vcpu: self.vcpu,
            backend: self.backend.clone(),
            tid: self.tid.clone(),
        }
    }
}

unsafe impl<B: HypervisorBackend> Send for VcpuInjector<B> {}
unsafe impl<B: HypervisorBackend> Sync for VcpuInjector<B> {}

impl<B: HypervisorBackend> VcpuInjector<B> {
    pub fn inject_interrupt(&mut self, vector: u8) -> Result<()> {
        unsafe {
            if self
                .backend
                .vcpu_inject(&mut *self.machine, &mut *self.vcpu, vector)
                != 0
            {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    /// Stop the VCPU (kick).
    pub fn stop(&self) -> Result<()> {
        let tid = self.tid.load(Ordering::Relaxed);
        if tid != 0 {
            // Send SIGUSR1 to the VCPU thread
            unsafe {
                libc::pthread_kill(tid as libc::pthread_t, libc::SIGUSR1);
            }
        }
        Ok(())
    }

    /// Check if Interrupts are enabled (RFLAGS.IF = 1).
    pub fn interrupts_enabled(&self) -> Result<bool> {
        let state = self.get_state(NVMM_X64_STATE_GPRS)?;
        Ok((state.gprs[regs::GPR_RFLAGS] & (1 << 9)) != 0)
    }

    /// Dump the VCPU state (to log/syslog).
    pub fn dump(&self) -> Result<()> {
        unsafe {
            self.backend.vcpu_dump(&mut *self.machine, &mut *self.vcpu);
        }
        Ok(())
    }

    /// Retrieve CPU State (Thread-safe).
    pub fn get_state(&self, flags: u64) -> Result<NvmmX64State> {
        unsafe {
            self.backend
                .get_vcpu_state(&mut *self.machine, &mut *self.vcpu, flags)
        }
    }

    pub fn set_state(&self, state: &NvmmX64State, flags: u64) -> Result<()> {
        unsafe {
            self.backend
                .set_vcpu_state(&mut *self.machine, &mut *self.vcpu, state, flags)
        }
    }

    /// Dump debug state with stack trace
    pub fn dump_debug_state<M: GuestMemory>(
        &self,
        mem: &M,
        kernel_path: Option<&std::path::Path>,
    ) -> Result<()> {
        let state = self.get_state(NVMM_X64_STATE_ALL)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::backend::MockBackend;

    #[test]
    fn test_vcpu_run_mock() {
        let backend = Arc::new(MockBackend::new());
        // Set return value for vcpu_run
        // MockBackend vcpu_run returns result of behavior if queue set.
        // It passes &mut NvmmX64Exit.
        // We need to set up behavior to modify exit struct if valid?
        // But logic in backend.rs handles parsing.

        // Actually MockBackend behavior logic I implemented returns `i32`.
        // And `vcpu_run` in backend calls behavior, checks result.
        // If behavior returns 0, `vcpu_run` returns `Unknown(0)`.
        // If behavior returns non-zero, `vcpu_run` returns `Interrupted` (simplified).

        // I want to test clean exit.
        // backend logic: if exit_ptr !null, exit = *exit_ptr. Match reason.
        // Mock behavior has access to exit struct.
        // So behavior should WRITE to exit struct.

        backend.queue_run_behavior(|exit| {
            // Simulate IO exit
            exit.reason = crate::system::nvmm::sys::NVMM_EXIT_IO;
            exit.u.io.port = 0x80;
            exit.u.io.in_ = false;
            exit.u.io.operand_size = 1;
            exit.u.io.npc = 0x1234;
            0
        });

        // Machine and Vcpu creation needing mocked handles.
        // Machine<MockBackend>

        let mut test_machine = Machine {
            raw: crate::system::backend::NvmmMachineHandle(Box::new(unsafe { std::mem::zeroed() })),
            device_mgr: Arc::new(std::sync::Mutex::new(
                vm_device::device_manager::IoManager::new(),
            )),
            backend: backend.clone(),
        };

        // Create Vcpu
        let mut vcpu = test_machine.create_vcpu(0).expect("Failed to create vcpu");

        // Manually setup pointers for MockBackend expectations
        let mut exit_struct =
            Box::new(unsafe { std::mem::zeroed::<crate::system::nvmm::sys::NvmmX64Exit>() });
        // Need to set the pointer in the handle.
        // B::VcpuHandle is NvmmVcpuHandle(Box<NvmmVcpu>)
        // NvmmVcpu has fields exit: *mut NvmmX64Exit, etc.
        vcpu.raw.0.exit = &mut *exit_struct;

        let vm_exit = vcpu.run().expect("Vcpu run failed");

        match vm_exit {
            VmExit::Io { port, is_in, .. } => {
                assert_eq!(port, 0x80);
                assert!(!is_in);
            }
            _ => panic!("Expected Io exit, got {:?}", vm_exit),
        }
    }
}
