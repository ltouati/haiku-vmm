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
use std::sync::Arc;
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
            if self
                .machine
                .backend
                .vcpu_getstate(&mut *self.machine.raw, &mut *self.raw, flags)
                != 0
            {
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

        if unsafe {
            self.machine.backend.vcpu_configure(
                &mut *self.machine.raw,
                &mut *self.raw,
                sys::NVMM_VCPU_CONF_CPUID,
                &mut conf as *mut _ as *mut std::ffi::c_void,
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
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

            if self
                .machine
                .backend
                .vcpu_setstate(&mut *self.machine.raw, &mut *self.raw, flags)
                != 0
            {
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
            backend: self.machine.backend.clone(),
        }
    }

    /// Internal function to run the CPU once.
    pub fn run(&mut self) -> Result<VmExit> {
        unsafe {
            let ret = self
                .machine
                .backend
                .vcpu_run(&mut *self.machine.raw, &mut *self.raw);
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

            let comm_ptr = self.raw.state;
            let state = if comm_ptr.is_null() {
                None
            } else {
                Some(&*comm_ptr)
            };

            Ok(Self::handle_exit(&exit, state))
        }
    }

    fn handle_exit(exit: &sys::NvmmX64Exit, state: Option<&sys::NvmmX64State>) -> VmExit {
        unsafe {
            match exit.reason {
                sys::NVMM_EXIT_IO => {
                    let io_exit = exit.u.io;

                    let mut data = vec![];
                    if !io_exit.in_ {
                        // For OUT, data is in RAX (AL)
                        if let Some(s) = state {
                            let rax = s.gprs[regs::GPR_RAX];

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
                    let mut value = 0;
                    let is_write = (exit.u.mem.prot & 2) != 0;
                    if is_write {
                        // Decode source value
                        let inst_slice = &exit.u.mem.inst_bytes[..exit.u.mem.inst_len as usize];
                        let mut decoder = Decoder::with_ip(64, inst_slice, 0, DecoderOptions::NONE);
                        if let Some(instruction) = decoder.iter().next() {
                            // Op0 is memory (dst), Op1 is source (reg/imm)
                            let op1 = instruction.op1_kind();
                            if op1 == OpKind::Register {
                                let reg = instruction.op1_register();
                                if let Some(s) = state {
                                    let gpr_idx = regs::reg_to_gpr(reg);
                                    let full_val = s.gprs[gpr_idx];

                                    // Handle high byte registers (AH, CH, DH, BH)
                                    match reg {
                                        iced_x86::Register::AH
                                        | iced_x86::Register::CH
                                        | iced_x86::Register::DH
                                        | iced_x86::Register::BH => value = (full_val >> 8) & 0xFF,
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
            }
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
#[derive(Clone)]
pub struct VcpuInjector {
    machine: *mut sys::NvmmMachine,
    vcpu: *mut sys::NvmmVcpu,
    backend: Arc<dyn crate::nvmm::backend::HypervisorBackend>,
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

            if self.backend.vcpu_inject(self.machine, self.vcpu) != 0 {
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
            if self.backend.vcpu_getstate(self.machine, self.vcpu, flags) != 0 {
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
            if self.backend.vcpu_setstate(self.machine, self.vcpu, flags) != 0 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nvmm::sys;

    #[test]
    fn test_handle_exit_io() {
        let mut exit = sys::NvmmX64Exit {
            reason: sys::NVMM_EXIT_IO,
            u: unsafe { std::mem::zeroed() },
            exitstate: 0,
        };
        exit.u.io = sys::NvmmX64ExitIo {
            in_: false,
            port: 0x3f8,
            seg: 0,
            address_size: 4,
            operand_size: 1,
            rep: false,
            str_: false,
            npc: 0x1234,
        };

        let mut state = sys::NvmmX64State::default();
        state.gprs[regs::GPR_RAX] = 0x41; // 'A'

        let vm_exit = Vcpu::handle_exit(&exit, Some(&state));
        match vm_exit {
            VmExit::Io {
                port, is_in, data, ..
            } => {
                assert_eq!(port, 0x3f8);
                assert_eq!(is_in, false);
                assert_eq!(data, vec![0x41]);
            }
            _ => panic!("Expected Io exit"),
        }
    }

    #[test]
    fn test_handle_exit_io_in() {
        let mut exit = sys::NvmmX64Exit {
            reason: sys::NVMM_EXIT_IO,
            u: unsafe { std::mem::zeroed() },
            exitstate: 0,
        };
        exit.u.io = sys::NvmmX64ExitIo {
            in_: true,
            port: 0x60,
            seg: 0,
            address_size: 4,
            operand_size: 1,
            rep: false,
            str_: false,
            npc: 0x1234,
        };

        // For IN exits, data is not provided by guest state (it's what we need to return)
        // But the handle_exit function constructs a VmExit::Io which should capture the intent.
        let vm_exit = Vcpu::handle_exit(&exit, None);
        match vm_exit {
            VmExit::Io { port, is_in, .. } => {
                assert_eq!(port, 0x60);
                assert_eq!(is_in, true);
            }
            _ => panic!("Expected Io exit"),
        }
    }

    #[test]
    fn test_handle_exit_memory_read() {
        let mut exit = sys::NvmmX64Exit {
            reason: sys::NVMM_EXIT_MEMORY,
            u: unsafe { std::mem::zeroed() },
            exitstate: 0,
        };
        exit.u.mem = sys::NvmmX64ExitMemory {
            prot: 1, // Read (no write bit 2 set)
            gpa: 0x2000,
            inst_len: 0, // Instruction fetching might be skipped for read if not needed?
            // Actually handle_exit only decodes for Write to get the value.
            // For read, it just passes GPA.
            inst_bytes: [0u8; 15],
        };

        let vm_exit = Vcpu::handle_exit(&exit, None);
        match vm_exit {
            VmExit::Memory { gpa, is_write, .. } => {
                assert_eq!(gpa, 0x2000);
                assert_eq!(is_write, false);
            }
            _ => panic!("Expected Memory exit"),
        }
    }

    #[test]
    fn test_handle_exit_memory_write_imm() {
        let mut exit = sys::NvmmX64Exit {
            reason: sys::NVMM_EXIT_MEMORY,
            u: unsafe { std::mem::zeroed() },
            exitstate: 0,
        };
        // mov byte ptr [rax], 0x55
        // Bytes: C6 00 55
        let mut inst = [0u8; 15];
        inst[0] = 0xC6;
        inst[1] = 0x00;
        inst[2] = 0x55;

        exit.u.mem = sys::NvmmX64ExitMemory {
            prot: 2, // Write
            gpa: 0x1000,
            inst_len: 3,
            inst_bytes: inst,
        };

        let vm_exit = Vcpu::handle_exit(&exit, None);
        match vm_exit {
            VmExit::Memory {
                gpa,
                is_write,
                value,
                ..
            } => {
                assert_eq!(gpa, 0x1000);
                assert_eq!(is_write, true);
                assert_eq!(value, 0x55);
            }
            _ => panic!("Expected Memory exit"),
        }
    }

    #[test]
    fn test_handle_exit_memory_write_reg() {
        let mut exit = sys::NvmmX64Exit {
            reason: sys::NVMM_EXIT_MEMORY,
            u: unsafe { std::mem::zeroed() },
            exitstate: 0,
        };
        // mov [rax], rbx
        // Bytes: 48 89 18
        let mut inst = [0u8; 15];
        inst[0] = 0x48;
        inst[1] = 0x89;
        inst[2] = 0x18;

        exit.u.mem = sys::NvmmX64ExitMemory {
            prot: 2, // Write
            gpa: 0x1000,
            inst_len: 3,
            inst_bytes: inst,
        };

        let mut state = sys::NvmmX64State::default();
        state.gprs[regs::GPR_RBX] = 0xDEADBEEF;

        let vm_exit = Vcpu::handle_exit(&exit, Some(&state));
        match vm_exit {
            VmExit::Memory { value, .. } => {
                assert_eq!(value, 0xDEADBEEF);
            }
            _ => panic!("Expected Memory exit"),
        }
    }

    #[test]
    fn test_handle_exit_memory_write_high_byte() {
        let mut exit = sys::NvmmX64Exit {
            reason: sys::NVMM_EXIT_MEMORY,
            u: unsafe { std::mem::zeroed() },
            exitstate: 0,
        };
        // mov [rax], ah
        // Bytes: 88 20
        let mut inst = [0u8; 15];
        inst[0] = 0x88;
        inst[1] = 0x20;

        exit.u.mem = sys::NvmmX64ExitMemory {
            prot: 2, // Write
            gpa: 0x1000,
            inst_len: 2,
            inst_bytes: inst,
        };

        let mut state = sys::NvmmX64State::default();
        state.gprs[regs::GPR_RAX] = 0x12345678; // AH is 0x56

        let vm_exit = Vcpu::handle_exit(&exit, Some(&state));
        match vm_exit {
            VmExit::Memory { value, .. } => {
                assert_eq!(value, 0x56);
            }
            _ => panic!("Expected Memory exit"),
        }
    }

    #[test]
    fn test_handle_exit_rdmsr() {
        let mut exit = sys::NvmmX64Exit {
            reason: sys::NVMM_EXIT_RDMSR,
            u: unsafe { std::mem::zeroed() },
            exitstate: 0,
        };
        exit.u.rdmsr = sys::NvmmX64ExitRdMsr {
            msr: 0x1234,
            _pad: 0,
            npc: 0x5678,
        };
        let vm_exit = Vcpu::handle_exit(&exit, None);
        match vm_exit {
            VmExit::RdMsr { msr, npc } => {
                assert_eq!(msr, 0x1234);
                assert_eq!(npc, 0x5678);
            }
            _ => panic!("Expected RdMsr exit"),
        }
    }

    #[test]
    fn test_handle_exit_wrmsr() {
        let mut exit = sys::NvmmX64Exit {
            reason: sys::NVMM_EXIT_WRMSR,
            u: unsafe { std::mem::zeroed() },
            exitstate: 0,
        };
        exit.u.wrmsr = sys::NvmmX64ExitWrMsr {
            msr: 0x1234,
            _pad: 0,
            val: 0xDEADBEEF,
            npc: 0x5678,
        };
        let vm_exit = Vcpu::handle_exit(&exit, None);
        match vm_exit {
            VmExit::WrMsr { msr, val, npc } => {
                assert_eq!(msr, 0x1234);
                assert_eq!(val, 0xDEADBEEF);
                assert_eq!(npc, 0x5678);
            }
            _ => panic!("Expected WrMsr exit"),
        }
    }

    #[test]
    fn test_handle_exit_shutdown() {
        let exit = sys::NvmmX64Exit {
            reason: sys::NVMM_EXIT_SHUTDOWN,
            u: unsafe { std::mem::zeroed() },
            exitstate: 0,
        };
        let vm_exit = Vcpu::handle_exit(&exit, None);
        assert!(matches!(vm_exit, VmExit::Shutdown));
    }

    #[test]
    fn test_handle_exit_invalid() {
        let exit = sys::NvmmX64Exit {
            reason: 0xFFFFFFFF,
            u: unsafe { std::mem::zeroed() },
            exitstate: 0,
        };
        let vm_exit = Vcpu::handle_exit(&exit, None);
        if let VmExit::Unknown(reason) = vm_exit {
            assert_eq!(reason, 0xFFFFFFFF);
        } else {
            panic!("Expected Unknown exit");
        }
    }

    #[test]
    fn test_vcpu_run_mock() {
        let backend = Arc::new(crate::nvmm::backend::MockBackend::new());
        // Set return value for vcpu_run
        backend.queue_run_behavior(|_| 0);

        let machine = unsafe { std::mem::zeroed::<sys::NvmmMachine>() };
        let raw_machine = Box::new(machine);

        let mut test_machine = crate::nvmm::Machine {
            raw: raw_machine,
            device_mgr: Arc::new(std::sync::Mutex::new(
                vm_device::device_manager::IoManager::new(),
            )),
            backend: backend.clone(),
        };

        // Initialize fake VCPU struct
        let mut vcpu = crate::nvmm::Vcpu {
            _id: 0,
            machine: &mut test_machine,
            raw: Box::new(unsafe { std::mem::zeroed() }),
        };

        // Prepare Exit Struct
        let mut exit_struct = sys::NvmmX64Exit {
            reason: sys::NVMM_EXIT_IO,
            u: unsafe { std::mem::zeroed() },
            exitstate: 0,
        };
        exit_struct.u.io = sys::NvmmX64ExitIo {
            in_: false,
            port: 0x80,
            seg: 0,
            address_size: 4,
            operand_size: 1,
            rep: false,
            str_: false,
            npc: 0x1236,
        };

        // Prepare Event Struct
        let mut event_struct = sys::NvmmX64Event {
            type_: 0,
            vector: 0,
            u: unsafe { std::mem::zeroed() },
        };

        // Link raw pointers to our stack allocated structs
        // SAFETY: vcpu.raw is Boxed, so it's stable. exit_struct and event_struct must outlive vcpu.run() call.
        // Accessing/assigning to fields of NvmmVcpu is safe.
        (*vcpu.raw).exit = &mut exit_struct;
        (*vcpu.raw).event = &mut event_struct;

        // Run
        let exit = vcpu.run().unwrap();
        match exit {
            VmExit::Io { port, .. } => assert_eq!(port, 0x80),
            _ => panic!("Expected IO exit"),
        }
    }

    #[test]
    fn test_vcpu_inject_mock() {
        let backend = Arc::new(crate::nvmm::backend::MockBackend::new());
        // vcpu_inject returns 0 by default in mock

        let machine = unsafe { std::mem::zeroed::<sys::NvmmMachine>() };
        let raw_machine = Box::new(machine);

        let mut test_machine = crate::nvmm::Machine {
            raw: raw_machine,
            device_mgr: Arc::new(std::sync::Mutex::new(
                vm_device::device_manager::IoManager::new(),
            )),
            backend: backend.clone(),
        };

        let mut vcpu = crate::nvmm::Vcpu {
            _id: 0,
            machine: &mut test_machine,
            raw: Box::new(unsafe { std::mem::zeroed() }),
        };

        let mut event_struct = sys::NvmmX64Event {
            type_: 0,
            vector: 0,
            u: unsafe { std::mem::zeroed() },
        };

        (*vcpu.raw).event = &mut event_struct;

        let result = vcpu.inject_interrupt(0x20);
        assert!(result.is_ok());

        assert_eq!(event_struct.type_, sys::NVMM_VCPU_EVENT_INTR);
        assert_eq!(event_struct.vector, 0x20);
    }
}
