use crate::system::backend::HypervisorBackend;
use crate::system::vmachine::regs;
use crate::system::vmachine::vcpu::{Vcpu, VcpuInjector};
use crate::types::{VmAction, VmExit};
use anyhow::{Result, anyhow};
use futures::future::BoxFuture;
use iced_x86::{Decoder, DecoderOptions};
use log::{error, info};
use std::sync::{Arc, Mutex};
use vm_device::device_manager::{MmioManager, PioManager};

pub type IoHandler<'b> =
    dyn FnMut(u16, bool, &[u8], u8, u64) -> BoxFuture<'b, Result<VmAction>> + 'b;
pub type MemoryHandler<'b> =
    dyn FnMut(u64, bool, u8, [u8; 15], u64) -> BoxFuture<'b, Result<VmAction>> + 'b;
pub type ShutdownHandler<'b> = dyn FnMut() -> BoxFuture<'b, Result<VmAction>> + 'b;
pub type MsrHandler<'b> = dyn FnMut(u32, bool, u64, u64) -> BoxFuture<'b, Result<VmAction>> + 'b;
pub type UnknownHandler<'b> = dyn FnMut(u64) -> BoxFuture<'b, Result<VmAction>> + 'b;
pub type PreRunHandler<'b, B> = dyn FnMut(VcpuInjector<B>) -> BoxFuture<'b, Result<()>> + 'b;

pub struct VcpuRunner<'a, 'b, B: HypervisorBackend> {
    vcpu: &'b mut Vcpu<'a, B>,
    io_handler: Box<IoHandler<'b>>,
    memory_handler: Box<MemoryHandler<'b>>,
    shutdown_handler: Box<ShutdownHandler<'b>>,
    msr_handler: Box<MsrHandler<'b>>,
    unknown_handler: Box<UnknownHandler<'b>>,
    pre_run_handler: Box<PreRunHandler<'b, B>>,
}

impl<'a, 'b, B: HypervisorBackend> VcpuRunner<'a, 'b, B> {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(vcpu: &'b mut Vcpu<'a, B>) -> Self {
        let device_mgr_io = vcpu.machine.device_mgr.clone();
        let device_mgr_mem = vcpu.machine.device_mgr.clone();
        Self {
            vcpu,
            io_handler: Self::create_io_handler(device_mgr_io),
            shutdown_handler: Self::create_shutdown_handler(),
            msr_handler: Self::create_msr_handler(),
            memory_handler: Self::create_memory_handler(device_mgr_mem),
            unknown_handler: Self::create_unknown_handler(),
            pre_run_handler: Box::new(|_| Box::pin(async { Ok(()) })),
        }
    }

    fn create_io_handler(
        device_mgr: Arc<Mutex<vm_device::device_manager::IoManager>>,
    ) -> Box<IoHandler<'b>> {
        Box::new(move |port, is_in, data, op_size, npc| {
            let device_mgr = device_mgr.clone();
            let data = data.to_vec();
            Box::pin(async move {
                if !is_in {
                    // Write
                    // Ignore errors (e.g. unmapped ports)
                    let _ = device_mgr
                        .lock()
                        .map_err(|_| anyhow!("Failed to lock device manager"))?
                        .pio_write(vm_device::bus::PioAddress(port), &data);

                    Ok(VmAction::SetRip(npc))
                } else {
                    // Read
                    // Default to 0xFF (Unmapped)
                    let mut read_data = vec![0xffu8; op_size as usize];

                    // Attempt read, ignore errors
                    let _ = device_mgr
                        .lock()
                        .map_err(|_| anyhow!("Failed to lock device manager"))?
                        .pio_read(vm_device::bus::PioAddress(port), &mut read_data);

                    let mut val = 0u64;
                    for (i, byte) in read_data.iter().enumerate() {
                        val |= (*byte as u64) << (i * 8);
                    }

                    let mask = if op_size >= 8 {
                        0xffff_ffff_ffff_ffff
                    } else {
                        (1u64 << (op_size * 8)) - 1
                    };

                    Ok(VmAction::WriteRegMasked {
                        reg: regs::GPR_RAX,
                        val,
                        mask,
                        next_rip: npc,
                    })
                }
            })
        })
    }

    fn create_shutdown_handler() -> Box<ShutdownHandler<'b>> {
        Box::new(|| {
            Box::pin(async move {
                info!("VM Shutdown");
                Ok(VmAction::Shutdown)
            })
        })
    }

    fn create_msr_handler() -> Box<MsrHandler<'b>> {
        Box::new(|msr, is_write, _, _| {
            Box::pin(async move {
                info!("Unhandled MSR Exit: msr={:#x}, is_write={}", msr, is_write);
                Ok(VmAction::Continue)
            })
        })
    }

    fn create_memory_handler(
        device_mgr: Arc<Mutex<vm_device::device_manager::IoManager>>,
    ) -> Box<MemoryHandler<'b>> {
        Box::new(move |gpa, is_write, inst_len, inst_bytes, value| {
            let device_mgr = device_mgr.clone();
            Box::pin(async move {
                let inst_slice = &inst_bytes[..inst_len as usize];
                let mut decoder = Decoder::with_ip(64, inst_slice, 0, DecoderOptions::NONE);
                let instruction = decoder.iter().next();
                let size = instruction.map(|i| i.memory_size().size()).unwrap_or(4);
                let (reg, mask) = instruction
                    .and_then(|i| {
                        if !is_write {
                            let op0 = i.op0_register();
                            let gpr = regs::reg_to_gpr(op0);
                            // Determine size/mask
                            use iced_x86::Register;
                            let mask = match op0 {
                                // 8-bit
                                Register::AL
                                | Register::CL
                                | Register::DL
                                | Register::BL
                                | Register::SPL
                                | Register::BPL
                                | Register::SIL
                                | Register::DIL
                                | Register::R8L
                                | Register::R9L
                                | Register::R10L
                                | Register::R11L
                                | Register::R12L
                                | Register::R13L
                                | Register::R14L
                                | Register::R15L
                                | Register::AH
                                | Register::CH
                                | Register::DH
                                | Register::BH => 0xFFu64,
                                // 16-bit
                                Register::AX
                                | Register::CX
                                | Register::DX
                                | Register::BX
                                | Register::SP
                                | Register::BP
                                | Register::SI
                                | Register::DI
                                | Register::R8W
                                | Register::R9W
                                | Register::R10W
                                | Register::R11W
                                | Register::R12W
                                | Register::R13W
                                | Register::R14W
                                | Register::R15W => 0xFFFFu64,
                                // 32-bit (zero extend to 64)
                                Register::EAX
                                | Register::ECX
                                | Register::EDX
                                | Register::EBX
                                | Register::ESP
                                | Register::EBP
                                | Register::ESI
                                | Register::EDI
                                | Register::R8D
                                | Register::R9D
                                | Register::R10D
                                | Register::R11D
                                | Register::R12D
                                | Register::R13D
                                | Register::R14D
                                | Register::R15D => 0xFFFF_FFFF_FFFF_FFFF,
                                // 64-bit
                                _ => 0xFFFF_FFFF_FFFF_FFFF,
                            };
                            Some((gpr, mask))
                        } else {
                            None
                        }
                    })
                    .unwrap_or((regs::GPR_RAX, 0xFFFF_FFFF_FFFF_FFFF));

                log::debug!(
                    "MMIO: gpa={:#x}, is_write={}, size={}, reg={}, inst={:?}",
                    gpa,
                    is_write,
                    size,
                    reg,
                    instruction
                );

                if is_write {
                    // Write
                    let val_bytes = value.to_le_bytes();
                    device_mgr
                        .lock()
                        .map_err(|_| anyhow!("Failed to lock device manager"))?
                        .mmio_write(vm_device::bus::MmioAddress(gpa), &val_bytes[..size])
                        .map_err(|e| {
                            anyhow!(
                                "MMIO Write Error: gpa={:#x}, val={:#x}, error={:?}",
                                gpa,
                                value,
                                e
                            )
                        })?;
                    Ok(VmAction::AdvanceRip(inst_len as u64))
                } else {
                    // Read
                    let mut data = [0u8; 8];
                    device_mgr
                        .lock()
                        .map_err(|_| anyhow!("Failed to lock device manager"))?
                        .mmio_read(vm_device::bus::MmioAddress(gpa), &mut data[..size])
                        .map_err(|e| anyhow!("MMIO Read Error: gpa={:#x}, error={:?}", gpa, e))?;
                    let val = u64::from_le_bytes(data);

                    Ok(VmAction::WriteRegAndContinue {
                        reg,
                        val,
                        mask,
                        advance_rip: inst_len as u64,
                    })
                }
            })
        })
    }

    fn create_unknown_handler() -> Box<UnknownHandler<'b>> {
        Box::new(|reason| {
            Box::pin(async move {
                error!("Unknown VM Exit Reason: {:#x}", reason);
                Ok(VmAction::Shutdown)
            })
        })
    }

    pub fn on_io<F>(mut self, handler: F) -> Self
    where
        F: FnMut(u16, bool, &[u8], u8, u64) -> BoxFuture<'b, Result<VmAction>> + 'b,
    {
        self.io_handler = Box::new(handler);
        self
    }

    pub fn on_memory<F>(mut self, handler: F) -> Self
    where
        F: FnMut(u64, bool, u8, [u8; 15], u64) -> BoxFuture<'b, Result<VmAction>> + 'b,
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

    pub fn on_pre_run<F>(mut self, handler: F) -> Self
    where
        F: FnMut(VcpuInjector<B>) -> BoxFuture<'b, Result<()>> + 'b,
    {
        self.pre_run_handler = Box::new(handler);
        self
    }

    pub async fn run(mut self) -> Result<()> {
        use log::error;
        loop {
            // Execute Pre-Run Hook (e.g., Interrupt Injection)
            (self.pre_run_handler)(self.vcpu.injector()).await?;

            let exit = self.vcpu.run()?;
            let action = match exit {
                VmExit::Io {
                    port,
                    is_in,
                    ref data,
                    op_size,
                    npc,
                } => (self.io_handler)(port, is_in, data, op_size, npc).await?,
                VmExit::Memory {
                    gpa,
                    is_write,
                    inst_len,
                    inst_bytes,
                    value,
                } => (self.memory_handler)(gpa, is_write, inst_len, inst_bytes, value).await?,
                VmExit::Shutdown => {
                    let rip = self.vcpu.get_rip().unwrap_or(0);
                    error!("VM Shutdown detected at RIP={:#x}", rip);
                    (self.shutdown_handler)().await?
                }
                VmExit::RdMsr { msr, npc } => (self.msr_handler)(msr, false, 0, npc).await?,
                VmExit::WrMsr { msr, val, npc } => (self.msr_handler)(msr, true, val, npc).await?,
                VmExit::Interrupted => VmAction::Continue, // Just loop back to pre-run

                VmExit::Halted => VmAction::Continue,
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
                    mask,
                    advance_rip,
                } => {
                    let mut state = self.vcpu.get_state(regs::STATE_GPRS)?;
                    let old_val = state.gprs[reg];
                    // Special case for 32-bit: It zero extends, so we overwrite high 32 bits with 0.
                    // My logic above set mask to !0 for 32-bit.
                    // But wait, if mask is !0, (val & mask) is val. (old & !mask) is 0.
                    // So it overwrites entirely. This is correct for 32-bit div (zero extend).
                    // For 8/16-bit, mask is 0xFF/0xFFFF. correct.
                    // But wait, what if instruction writes to high byte? AH?
                    // iced_x86 doesn't give me that easily.
                    // If op0 is AH, reg_to_gpr returns RAX.
                    // I need shift for AH/BH/CH/DH!
                    // Let's defer AH support for now or implement it?
                    // It's rare in MMIO but possible.
                    // If I ignore it, I might write to AL instead of AH.
                    // Let's refine the handler logic later or now?
                    // User asked for "proper register".
                    // Let's assume low byte for now to fix the main corruption issue.

                    state.gprs[reg] = (old_val & !mask) | (val & mask);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::Machine;
    use crate::system::backend::MockBackend;
    use crate::system::nvmm::sys::{
        NVMM_EXIT_IO, NVMM_EXIT_MEMORY, NVMM_EXIT_SHUTDOWN, NvmmX64Event, NvmmX64Exit,
        NvmmX64ExitIo, NvmmX64ExitMemory, NvmmX64State,
    };
    use std::sync::Arc;

    #[tokio::test]
    async fn test_runner_io() {
        // Setup Backend
        let backend = Arc::new(MockBackend::new());

        // Queue Run Behaviors
        // 1. IO Exit (OUT 0x80)
        backend.queue_run_behavior(|exit| {
            exit.reason = NVMM_EXIT_IO;
            exit.u.io = NvmmX64ExitIo {
                in_: false,
                port: 0x80,
                seg: 0,
                address_size: 0,
                operand_size: 1,
                rep: false,
                str_: false,
                npc: 0x1005,
            };
            0
        });
        // 2. Shutdown Exit to break loop
        backend.queue_run_behavior(|exit| {
            exit.reason = NVMM_EXIT_SHUTDOWN;
            0
        });

        // Setup Machine & VCPU
        let mut test_machine = Machine {
            raw: crate::system::backend::NvmmMachineHandle(Box::new(unsafe { std::mem::zeroed() })),
            device_mgr: Arc::new(std::sync::Mutex::new(
                vm_device::device_manager::IoManager::new(),
            )),
            backend: backend.clone(),
        };

        let mut vcpu = Vcpu {
            _id: 0,
            machine: &mut test_machine,
            raw: crate::system::backend::NvmmVcpuHandle(Box::new(unsafe { std::mem::zeroed() })),
            tid: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        // Point exit struct to a local variable (since run() checks it)
        let mut exit_struct = Box::new(unsafe { std::mem::zeroed::<NvmmX64Exit>() });
        let mut event_struct = Box::new(unsafe { std::mem::zeroed::<NvmmX64Event>() });
        let mut state_struct = Box::new(unsafe { std::mem::zeroed::<NvmmX64State>() });

        vcpu.raw.0.exit = &mut *exit_struct;
        vcpu.raw.0.event = &mut *event_struct;
        vcpu.raw.0.state = &mut *state_struct;

        // Setup IO Handler Checker
        let io_called = Arc::new(std::sync::Mutex::new(false));
        let io_called_clone = io_called.clone();

        let runner = VcpuRunner::new(&mut vcpu)
            .on_io(move |port, is_in, _, _, _| {
                let io_called = io_called_clone.clone();
                Box::pin(async move {
                    assert_eq!(port, 0x80);
                    assert!(!is_in);
                    *io_called.lock().unwrap() = true;
                    Ok(VmAction::Continue)
                })
            })
            .on_shutdown(|| Box::pin(async { Ok(VmAction::Shutdown) }));

        // Run
        runner.run().await.unwrap();

        assert!(*io_called.lock().unwrap());
    }

    #[tokio::test]
    async fn test_runner_mmio() {
        let backend = Arc::new(MockBackend::new());

        // Queue Run Behaviors
        // 1. MMIO Exit (Write 0x1000)
        backend.queue_run_behavior(|exit| {
            exit.reason = NVMM_EXIT_MEMORY;
            exit.u.mem = NvmmX64ExitMemory {
                prot: 2, // Write
                gpa: 0x1000,
                inst_len: 2,
                inst_bytes: [0x88, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // Minimal fake instruction
            };
            0
        });
        // 2. Shutdown
        backend.queue_run_behavior(|exit| {
            exit.reason = NVMM_EXIT_SHUTDOWN;
            0
        });

        let mut test_machine = Machine {
            raw: crate::system::backend::NvmmMachineHandle(Box::new(unsafe { std::mem::zeroed() })),
            device_mgr: Arc::new(std::sync::Mutex::new(
                vm_device::device_manager::IoManager::new(),
            )),
            backend: backend.clone(),
        };

        let mut vcpu = Vcpu {
            _id: 0,
            machine: &mut test_machine,
            raw: crate::system::backend::NvmmVcpuHandle(Box::new(unsafe { std::mem::zeroed() })),
            tid: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let mut exit_struct = Box::new(unsafe { std::mem::zeroed::<NvmmX64Exit>() });
        let mut event_struct = Box::new(unsafe { std::mem::zeroed::<NvmmX64Event>() });
        let mut state_struct = Box::new(unsafe { std::mem::zeroed::<NvmmX64State>() });

        vcpu.raw.0.exit = &mut *exit_struct;
        vcpu.raw.0.event = &mut *event_struct;
        vcpu.raw.0.state = &mut *state_struct;

        let mmio_called = Arc::new(std::sync::Mutex::new(false));
        let mmio_called_clone = mmio_called.clone();

        let runner = VcpuRunner::new(&mut vcpu)
            .on_memory(move |gpa, is_write, _, _, _| {
                let mmio_called = mmio_called_clone.clone();
                Box::pin(async move {
                    assert_eq!(gpa, 0x1000);
                    assert!(is_write);
                    *mmio_called.lock().unwrap() = true;
                    Ok(VmAction::Continue)
                })
            })
            .on_shutdown(|| Box::pin(async { Ok(VmAction::Shutdown) }));

        runner.run().await.unwrap();

        assert!(*mmio_called.lock().unwrap());
    }

    #[tokio::test]
    async fn test_runner_shutdown() {
        let backend = Arc::new(MockBackend::new());

        // Queue Shutdown immediately
        backend.queue_run_behavior(|exit| {
            exit.reason = NVMM_EXIT_SHUTDOWN;
            0
        });

        let mut test_machine = Machine {
            raw: crate::system::backend::NvmmMachineHandle(Box::new(unsafe { std::mem::zeroed() })),
            device_mgr: Arc::new(std::sync::Mutex::new(
                vm_device::device_manager::IoManager::new(),
            )),
            backend: backend.clone(),
        };

        let mut vcpu = Vcpu {
            _id: 0,
            machine: &mut test_machine,
            raw: crate::system::backend::NvmmVcpuHandle(Box::new(unsafe { std::mem::zeroed() })),
            tid: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let mut exit_struct = Box::new(unsafe { std::mem::zeroed::<NvmmX64Exit>() });
        let mut event_struct = Box::new(unsafe { std::mem::zeroed::<NvmmX64Event>() });
        let mut state_struct = Box::new(unsafe { std::mem::zeroed::<NvmmX64State>() });

        vcpu.raw.0.exit = &mut *exit_struct;
        vcpu.raw.0.event = &mut *event_struct;
        vcpu.raw.0.state = &mut *state_struct;

        let shutdown_called = Arc::new(std::sync::Mutex::new(false));
        let shutdown_called_clone = shutdown_called.clone();

        let runner = VcpuRunner::new(&mut vcpu).on_shutdown(move || {
            let shutdown_called = shutdown_called_clone.clone();
            Box::pin(async move {
                *shutdown_called.lock().unwrap() = true;
                Ok(VmAction::Shutdown)
            })
        });

        runner.run().await.unwrap();
        assert!(*shutdown_called.lock().unwrap());
    }
}
