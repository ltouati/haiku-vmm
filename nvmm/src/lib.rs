pub mod sys;
pub mod regs;
pub mod lapic;
pub mod pit;
pub mod serial;
pub mod pic;
pub mod linux;
pub mod virtio;

use std::io::{self, Error};
use log::debug;
use futures::future::BoxFuture;
use vm_memory::{
     Address, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, MemoryRegionAddress,
};

/// Represents the Global NVMM System.
pub struct NvmmSystem;

impl NvmmSystem {
    pub fn new() -> io::Result<Self> {
        unsafe {
            debug!("Calling nvmm_init...");
            let ret = sys::nvmm_init();
            debug!("nvmm_init returned: {}", ret);
            if ret != 0 {
                return Err(Error::last_os_error());
            }
        }
        Ok(NvmmSystem)
    }

    pub fn create_machine(&self) -> io::Result<Machine> {
        // Allocate zeroed NvmmMachine on heap/Box
        let mut raw_box = Box::new(unsafe { std::mem::zeroed::<sys::NvmmMachine>() });
        
        unsafe {
            debug!("Calling nvmm_machine_create...");
            let ret = sys::nvmm_machine_create(&mut *raw_box);
             debug!("nvmm_machine_create returned: {}", ret);
            if ret != 0 {
                return Err(Error::last_os_error());
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
        unsafe { sys::nvmm_machine_destroy(&mut *self.raw); }
    }
}

impl Machine {
    pub fn create_vcpu(&mut self, id: u32) -> io::Result<Vcpu<'_>> {
        let mut vcpu_box = Box::new(unsafe { std::mem::zeroed::<sys::NvmmVcpu>() });
        
        unsafe {
            debug!("Calling nvmm_vcpu_create...");
            if sys::nvmm_vcpu_create(&mut *self.raw, id, &mut *vcpu_box) != 0 {
                return Err(Error::last_os_error());
            }
        }
        Ok(Vcpu { _id: id, machine: self, raw: vcpu_box })
    }

    /// Maps memory regions defined in `GuestMemoryMmap` into the VM.
    pub fn map_guest_memory(&mut self, guest_memory: &GuestMemoryMmap) -> io::Result<()> {
        for region in guest_memory.iter() {
            let base = region.start_addr().raw_value();
            let size = region.len() as usize;

            // Get pointer to host memory
            let host_ptr = region.get_host_address(MemoryRegionAddress(0))
                .map_err(|e| Error::other(format!("{:?}", e)))?;

            unsafe {
                // Register HVA
                debug!("Calling nvmm_hva_map...");
                if sys::nvmm_hva_map(&mut *self.raw, host_ptr as usize, size) != 0 {
                    return Err(Error::last_os_error());
                }
                // Map to GPA
                debug!("Calling nvmm_gpa_map...");
                if sys::nvmm_gpa_map(&mut *self.raw, host_ptr as usize, base, size, 7) != 0 {
                    return Err(Error::last_os_error());
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
    Io { port: u16, is_in: bool, data: Vec<u8>, npc: u64 },
    Memory { gpa: u64, is_write: bool, inst_len: u8 },
    RdMsr { msr: u32, npc: u64 },
    WrMsr { msr: u32, val: u64, npc: u64 },
    Shutdown,
    Unknown(u64),
}

/// Action to take after handling a VmExit.
#[derive(Debug, Clone)]
pub enum VmAction {
    Continue,
    AdvanceRip(u64),
    WriteRegAndContinue { reg: usize, val: u64, advance_rip: u64 },
    Shutdown,
}

impl<'a> Vcpu<'a> {
    /// Retrieve CPU State.
    pub fn get_state(&mut self, flags: u64) -> io::Result<sys::NvmmX64State> {
        unsafe {
            if sys::nvmm_vcpu_getstate(&mut *self.machine.raw, &mut *self.raw, flags) != 0 {
                return Err(Error::last_os_error());
            }
            let comm_ptr = self.raw.state;
            if comm_ptr.is_null() {
                return Err(Error::other("Comm state is null"));
            }
            Ok(*comm_ptr)
        }
    }

    /// Configure VCPU (e.g. CPUID).
    pub fn configure_cpuid(&mut self, leaf: u32, eax: u32, ebx: u32, ecx: u32, edx: u32) -> io::Result<()> {
         let mut conf = sys::NvmmVcpuConfCpuid {
            mask: 1, // mask=1 (set), exit=0
            leaf,
            u: sys::NvmmVcpuConfCpuidUnion {
                mask: sys::NvmmVcpuConfCpuidMask {
                    set: sys::NvmmCpuidSet { eax, ebx, ecx, edx },
                    del: sys::NvmmCpuidSet { eax: 0, ebx: 0, ecx: 0, edx: 0 },
                }
            }
        };

        unsafe {
             if sys::nvmm_vcpu_configure(
                &mut *self.machine.raw, 
                &mut *self.raw, 
                sys::NVMM_VCPU_CONF_CPUID, 
                &mut conf as *mut _ as *mut std::ffi::c_void
            ) != 0 {
                  return Err(Error::last_os_error());
             }
        }
        Ok(())
    }

    /// Set CPU State.
    pub fn set_state(&mut self, state: &sys::NvmmX64State, flags: u64) -> io::Result<()> {
        unsafe {
            let comm_ptr = self.raw.state;
            if comm_ptr.is_null() {
                return Err(Error::other("Comm state is null"));
            }
            *comm_ptr = *state;
            
            if sys::nvmm_vcpu_setstate(&mut *self.machine.raw, &mut *self.raw, flags) != 0 {
                return Err(Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Inject an interrupt into the VCPU.
    pub fn inject_interrupt(&mut self, vector: u8) -> io::Result<()> {
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
    pub fn run(&mut self) -> io::Result<VmExit> {
         unsafe {
            let ret = sys::nvmm_vcpu_run(&mut *self.machine.raw, &mut *self.raw);
            if ret != 0 {
                return Err(Error::last_os_error());
            }
            
            let exit_ptr = self.raw.exit;
            if exit_ptr.is_null() {
                 return Err(Error::other("Exit struct is null"));
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
                        npc: io_exit.npc
                    }
                },
                sys::NVMM_EXIT_MEMORY => VmExit::Memory { 
                    gpa: exit.u.mem.gpa, 
                    is_write: (exit.u.mem.prot & 2) != 0,
                    inst_len: exit.u.mem.inst_len
                },
                sys::NVMM_EXIT_RDMSR => {
                    let msr_exit = exit.u.rdmsr;
                    VmExit::RdMsr { msr: msr_exit.msr, npc: msr_exit.npc }
                },
                sys::NVMM_EXIT_WRMSR => {
                    let msr_exit = exit.u.wrmsr;
                    VmExit::WrMsr { msr: msr_exit.msr, val: msr_exit.val, npc: msr_exit.npc }
                },
                sys::NVMM_EXIT_SHUTDOWN => VmExit::Shutdown,
                0xffffffffffffffff => {
                    let hw = exit.u.inv.hwcode;
                    debug!("NVMM_EXIT_INVALID: hwcode={:#x}", hw);
                     VmExit::Unknown(0xffffffffffffffff)
                },
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
    pub fn inject_interrupt(&mut self, vector: u8) -> io::Result<()> {
        unsafe {
            let event_ptr = (*self.vcpu).event;
             if event_ptr.is_null() {
                 return Err(Error::other("Event struct is null"));
            }
            
            let event = sys::NvmmX64Event {
                type_: sys::NVMM_VCPU_EVENT_INTR,
                vector,
                u: sys::NvmmX64EventUnion {
                    pad: [0; 16],
                },
            };
            
            *event_ptr = event;
            
            if sys::nvmm_vcpu_inject(self.machine, self.vcpu) != 0 {
                return Err(Error::last_os_error());
            }
        }
        Ok(())
    }
}


impl<'a> Vcpu<'a> {
    pub fn get_rip(&mut self) -> io::Result<u64> {
        let _state = sys::NvmmX64State::default();
        self.get_state(regs::STATE_GPRS).map(|s| s.gprs[regs::GPR_RIP])
    }

    pub fn runner(&mut self) -> VcpuRunner<'a, '_> {
        VcpuRunner::new(self)
    }

    pub fn advance_rip(&mut self, len: u64) -> io::Result<()> {
        let mut state = self.get_state(regs::STATE_GPRS)?;
        state.gprs[regs::GPR_RIP] += len;
        self.set_state(&state, regs::STATE_GPRS)
    }
}

pub type IoHandler<'b> = dyn FnMut(u16, bool, &[u8]) -> BoxFuture<'b, io::Result<VmAction>> + 'b;
pub type MemoryHandler<'b> = dyn FnMut(u64, bool) -> BoxFuture<'b, io::Result<VmAction>> + 'b;
pub type ShutdownHandler<'b> = dyn FnMut() -> BoxFuture<'b, io::Result<VmAction>> + 'b;
pub type UnknownHandler<'b> = dyn FnMut(u64) -> BoxFuture<'b, io::Result<VmAction>> + 'b;

pub struct VcpuRunner<'a, 'b> {
    vcpu: &'b mut Vcpu<'a>,
    io_handler: Box<IoHandler<'b>>,
    memory_handler: Box<MemoryHandler<'b>>,
    shutdown_handler: Box<ShutdownHandler<'b>>,
    unknown_handler: Box<UnknownHandler<'b>>,
}

impl<'a, 'b> VcpuRunner<'a, 'b> {
    pub fn new(vcpu: &'b mut Vcpu<'a>) -> Self {
        use log::{info, error};
        Self {
            vcpu,
            io_handler: Box::new(|port, is_in, _| Box::pin(async move {
                info!("Unhandled IO Exit: port={}, is_in={}", port, is_in);
                Ok(VmAction::Continue)
            })),
            memory_handler: Box::new(|gpa, is_write| Box::pin(async move {
                error!("Unhandled Memory Exit: gpa={:#x}, is_write={}", gpa, is_write);
                Ok(VmAction::Shutdown)
            })),
            shutdown_handler: Box::new(|| Box::pin(async move {
                info!("VM Shutdown");
                Ok(VmAction::Shutdown)
            })),
            unknown_handler: Box::new(|reason| Box::pin(async move {
                error!("Unknown VM Exit Reason: {:#x}", reason);
                Ok(VmAction::Shutdown)
            })),
        }
    }

    pub fn on_io<F>(mut self, handler: F) -> Self
    where F: FnMut(u16, bool, &[u8]) -> BoxFuture<'b, io::Result<VmAction>> + 'b {
        self.io_handler = Box::new(handler);
        self
    }

    pub fn on_memory<F>(mut self, handler: F) -> Self
    where F: FnMut(u64, bool) -> BoxFuture<'b, io::Result<VmAction>> + 'b {
        self.memory_handler = Box::new(handler);
        self
    }

    pub fn on_shutdown<F>(mut self, handler: F) -> Self
    where F: FnMut() -> BoxFuture<'b, io::Result<VmAction>> + 'b {
        self.shutdown_handler = Box::new(handler);
        self
    }

    pub fn on_unknown<F>(mut self, handler: F) -> Self
    where F: FnMut(u64) -> BoxFuture<'b, io::Result<VmAction>> + 'b {
        self.unknown_handler = Box::new(handler);
        self
    }

    pub async fn run(mut self) -> io::Result<()> {
        use log::error;
        loop {
            let exit = self.vcpu.run()?;
            let action = match exit {
                VmExit::Io { port, is_in, ref data, .. } => (self.io_handler)(port, is_in, data).await?,
                VmExit::Memory { gpa, is_write, .. } => (self.memory_handler)(gpa, is_write).await?,
                VmExit::Shutdown => {
                    let rip = self.vcpu.get_rip().unwrap_or(0);
                    error!("VM Shutdown detected at RIP={:#x}", rip);
                    (self.shutdown_handler)().await?
                },
                VmExit::RdMsr { .. } => (self.unknown_handler)(sys::NVMM_EXIT_RDMSR).await?,
                VmExit::WrMsr { .. } => (self.unknown_handler)(sys::NVMM_EXIT_WRMSR).await?,
                VmExit::Unknown(reason) => {
                    let rip = self.vcpu.get_rip().unwrap_or(0);
                    error!("Unknown Exit {:#x} at RIP={:#x}", reason, rip);
                    (self.unknown_handler)(reason).await?
                },
            };

            match action {
                VmAction::Continue => {},
                VmAction::Shutdown => break,
                VmAction::AdvanceRip(len) => self.vcpu.advance_rip(len)?,
                VmAction::WriteRegAndContinue { reg, val, advance_rip } => {
                    let mut state = self.vcpu.get_state(regs::STATE_GPRS)?;
                    state.gprs[reg] = val;
                    state.gprs[regs::GPR_RIP] += advance_rip;
                    self.vcpu.set_state(&state, regs::STATE_GPRS)?;
                }
            }
        }
        Ok(())
    }
}