pub mod lapic;
pub mod linux;
pub mod pic;
pub mod pit;
pub mod regs;
pub mod serial;
pub mod sys;
pub mod virtio;

use anyhow::{Result, anyhow};
use futures::future::BoxFuture;
use log::debug;
use std::io;
use vm_memory::{Address, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, MemoryRegionAddress};

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
        Ok(Machine { raw: raw_box })
    }
}

/// A Virtual Machine instance.
pub struct Machine {
    raw: Box<sys::NvmmMachine>,
}

impl Drop for Machine {
    fn drop(&mut self) {
        unsafe {
            sys::nvmm_machine_destroy(&mut *self.raw);
        }
    }
}

impl Machine {
    pub fn create_vcpu(&mut self, id: u32) -> Result<Vcpu<'_>> {
        let mut vcpu_box = Box::new(unsafe { std::mem::zeroed::<sys::NvmmVcpu>() });

        unsafe {
            debug!("Calling nvmm_vcpu_create...");
            if sys::nvmm_vcpu_create(&mut *self.raw, id, &mut *vcpu_box) != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(Vcpu {
            _id: id,
            machine: self,
            raw: vcpu_box,
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

            unsafe {
                // Register HVA
                debug!("Calling nvmm_hva_map...");
                if sys::nvmm_hva_map(&mut *self.raw, host_ptr as usize, size) != 0 {
                    return Err(io::Error::last_os_error().into());
                }
                // Map to GPA
                debug!("Calling nvmm_gpa_map...");
                if sys::nvmm_gpa_map(&mut *self.raw, host_ptr as usize, base, size, 7) != 0 {
                    return Err(io::Error::last_os_error().into());
                }
            }
        }
        Ok(())
    }
}

/// A Virtual CPU.
pub struct Vcpu<'a> {
    _id: u32,
    machine: &'a mut Machine,
    raw: Box<sys::NvmmVcpu>,
}

#[derive(Debug)]
pub enum VmExit {
    Io {
        port: u16,
        is_in: bool,
        data: Vec<u8>,
        npc: u64,
    },
    Memory {
        gpa: u64,
        is_write: bool,
        inst_len: u8,
        value: u64,
    },
    RdMsr {
        msr: u32,
        npc: u64,
    },
    WrMsr {
        msr: u32,
        val: u64,
        npc: u64,
    },
    Shutdown,
    Unknown(u64),
}

#[derive(Debug, Clone)]
pub enum VmAction {
    Continue,
    AdvanceRip(u64),
    WriteRegAndContinue {
        reg: usize,
        val: u64,
        advance_rip: u64,
    },
    SetRip(u64),
    WriteRegMasked {
        reg: usize,
        val: u64,
        mask: u64,
        next_rip: u64,
    },
    Shutdown,
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
                return Err(io::Error::last_os_error().into());
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
                        npc: io_exit.npc,
                    }
                }
                sys::NVMM_EXIT_MEMORY => {
                    let is_write = (exit.u.mem.prot & 2) != 0;
                    let mut value = 0;
                    if is_write {
                        let comm_ptr = self.raw.state;
                        if !comm_ptr.is_null() {
                            value = (*comm_ptr).gprs[regs::GPR_RAX];
                        }
                    }
                    VmExit::Memory {
                        gpa: exit.u.mem.gpa,
                        is_write,
                        inst_len: exit.u.mem.inst_len,
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
}

/// A thread-safe injector for VCPU interrupts.
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
}

impl<'a> Vcpu<'a> {
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

pub type IoHandler<'b> = dyn FnMut(u16, bool, &[u8], u64) -> BoxFuture<'b, Result<VmAction>> + 'b;
pub type MemoryHandler<'b> = dyn FnMut(u64, bool, u8, u64) -> BoxFuture<'b, Result<VmAction>> + 'b;
pub type ShutdownHandler<'b> = dyn FnMut() -> BoxFuture<'b, Result<VmAction>> + 'b;
pub type MsrHandler<'b> = dyn FnMut(u32, bool, u64, u64) -> BoxFuture<'b, Result<VmAction>> + 'b;
pub type UnknownHandler<'b> = dyn FnMut(u64) -> BoxFuture<'b, Result<VmAction>> + 'b;

pub struct VcpuRunner<'a, 'b> {
    vcpu: &'b mut Vcpu<'a>,
    io_handler: Box<IoHandler<'b>>,
    memory_handler: Box<MemoryHandler<'b>>,
    shutdown_handler: Box<ShutdownHandler<'b>>,
    msr_handler: Box<MsrHandler<'b>>,
    unknown_handler: Box<UnknownHandler<'b>>,
}

impl<'a, 'b> VcpuRunner<'a, 'b> {
    pub fn new(vcpu: &'b mut Vcpu<'a>) -> Self {
        use log::{error, info};
        Self {
            vcpu,
            io_handler: Box::new(|port, is_in, _, _| {
                Box::pin(async move {
                    info!("Unhandled IO Exit: port={}, is_in={}", port, is_in);
                    Ok(VmAction::Continue)
                })
            }),
            memory_handler: Box::new(|gpa, is_write, _, _| {
                Box::pin(async move {
                    error!(
                        "Unhandled Memory Exit: gpa={:#x}, is_write={}",
                        gpa, is_write
                    );
                    Ok(VmAction::Shutdown)
                })
            }),
            shutdown_handler: Box::new(|| {
                Box::pin(async move {
                    info!("VM Shutdown");
                    Ok(VmAction::Shutdown)
                })
            }),
            msr_handler: Box::new(|msr, is_write, _, _| {
                Box::pin(async move {
                    info!("Unhandled MSR Exit: msr={:#x}, is_write={}", msr, is_write);
                    Ok(VmAction::Continue)
                })
            }),
            unknown_handler: Box::new(|reason| {
                Box::pin(async move {
                    error!("Unknown VM Exit Reason: {:#x}", reason);
                    Ok(VmAction::Shutdown)
                })
            }),
        }
    }

    pub fn on_io<F>(mut self, handler: F) -> Self
    where
        F: FnMut(u16, bool, &[u8], u64) -> BoxFuture<'b, Result<VmAction>> + 'b,
    {
        self.io_handler = Box::new(handler);
        self
    }

    pub fn on_memory<F>(mut self, handler: F) -> Self
    where
        F: FnMut(u64, bool, u8, u64) -> BoxFuture<'b, Result<VmAction>> + 'b,
    {
        self.memory_handler = Box::new(handler);
        self
    }

    pub fn on_shutdown<F>(mut self, handler: F) -> Self
    where
        F: FnMut() -> BoxFuture<'b, Result<VmAction>> + 'b,
    {
        self.shutdown_handler = Box::new(handler);
        self
    }

    pub fn on_msr<F>(mut self, handler: F) -> Self
    where
        F: FnMut(u32, bool, u64, u64) -> BoxFuture<'b, Result<VmAction>> + 'b,
    {
        self.msr_handler = Box::new(handler);
        self
    }

    pub fn on_unknown<F>(mut self, handler: F) -> Self
    where
        F: FnMut(u64) -> BoxFuture<'b, Result<VmAction>> + 'b,
    {
        self.unknown_handler = Box::new(handler);
        self
    }

    pub async fn run(mut self) -> Result<()> {
        use log::error;
        loop {
            let exit = self.vcpu.run()?;
            let action = match exit {
                VmExit::Io {
                    port,
                    is_in,
                    ref data,
                    npc,
                } => (self.io_handler)(port, is_in, data, npc).await?,
                VmExit::Memory {
                    gpa,
                    is_write,
                    inst_len,
                    value,
                } => (self.memory_handler)(gpa, is_write, inst_len, value).await?,
                VmExit::Shutdown => {
                    let rip = self.vcpu.get_rip().unwrap_or(0);
                    error!("VM Shutdown detected at RIP={:#x}", rip);
                    (self.shutdown_handler)().await?
                }
                VmExit::RdMsr { msr, npc } => (self.msr_handler)(msr, false, 0, npc).await?,
                VmExit::WrMsr { msr, val, npc } => (self.msr_handler)(msr, true, val, npc).await?,
                VmExit::Unknown(0) => VmAction::Continue,
                VmExit::Unknown(reason) => {
                    let rip = self.vcpu.get_rip().unwrap_or(0);
                    error!("Unknown Exit {:#x} at RIP={:#x}", reason, rip);
                    (self.unknown_handler)(reason).await?
                }
            };

            match action {
                VmAction::Continue => {}
                VmAction::Shutdown => break,
                VmAction::AdvanceRip(len) => self.vcpu.advance_rip(len)?,
                VmAction::SetRip(rip) => {
                    let mut state = self.vcpu.get_state(regs::STATE_GPRS)?;
                    state.gprs[regs::GPR_RIP] = rip;
                    self.vcpu.set_state(&state, regs::STATE_GPRS)?;
                }
                VmAction::WriteRegAndContinue {
                    reg,
                    val,
                    advance_rip,
                } => {
                    let mut state = self.vcpu.get_state(regs::STATE_GPRS)?;
                    state.gprs[reg] = val;
                    state.gprs[regs::GPR_RIP] = state.gprs[regs::GPR_RIP].wrapping_add(advance_rip);
                    self.vcpu.set_state(&state, regs::STATE_GPRS)?;
                }
                VmAction::WriteRegMasked {
                    reg,
                    val,
                    mask,
                    next_rip,
                } => {
                    let mut state = self.vcpu.get_state(regs::STATE_GPRS)?;
                    let old_val = state.gprs[reg];
                    state.gprs[reg] = (old_val & !mask) | (val & mask);
                    state.gprs[regs::GPR_RIP] = next_rip;
                    self.vcpu.set_state(&state, regs::STATE_GPRS)?;
                }
            }
        }
        Ok(())
    }
}
