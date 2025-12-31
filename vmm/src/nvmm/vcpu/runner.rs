use crate::nvmm::vcpu::regs;

use crate::Vcpu;
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

pub struct VcpuRunner<'a, 'b> {
    vcpu: &'b mut Vcpu<'a>,
    io_handler: Box<IoHandler<'b>>,
    memory_handler: Box<MemoryHandler<'b>>,
    shutdown_handler: Box<ShutdownHandler<'b>>,
    msr_handler: Box<MsrHandler<'b>>,
    unknown_handler: Box<UnknownHandler<'b>>,
}

impl<'a, 'b> VcpuRunner<'a, 'b> {
    #[allow(clippy::new_ret_no_self)]
    #[allow(clippy::new_ret_no_self)]
    pub fn new(vcpu: &'b mut Vcpu<'a>) -> Self {
        let device_mgr_io = vcpu.machine.device_mgr.clone();
        let device_mgr_mem = vcpu.machine.device_mgr.clone();
        Self {
            vcpu,
            io_handler: Self::create_io_handler(device_mgr_io),
            shutdown_handler: Self::create_shutdown_handler(),
            msr_handler: Self::create_msr_handler(),
            memory_handler: Self::create_memory_handler(device_mgr_mem),
            unknown_handler: Self::create_unknown_handler(),
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
                    device_mgr
                        .lock()
                        .map_err(|_| anyhow!("Failed to lock device manager"))?
                        .pio_write(vm_device::bus::PioAddress(port), &data)
                        .map_err(|e| {
                            anyhow!(
                                "PIO Write Error: port={:#x}, data={:?}, error={:?}",
                                port,
                                data,
                                e
                            )
                        })?;
                    Ok(VmAction::SetRip(npc))
                } else {
                    // Read
                    let mut read_data = vec![0u8; op_size as usize];
                    device_mgr
                        .lock()
                        .map_err(|_| anyhow!("Failed to lock device manager"))?
                        .pio_read(vm_device::bus::PioAddress(port), &mut read_data)
                        .map_err(|e| {
                            anyhow!(
                                "PIO Read Error: port={:#x}, size={}, error={:?}",
                                port,
                                op_size,
                                e
                            )
                        })?;

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
                let reg = instruction
                    .and_then(|i| {
                        if !is_write {
                            // For reads, we need to know where the data goes.
                            // mov register, [memory] -> op0 is register, op1 is memory
                            let op0 = i.op0_register();
                            Some(regs::reg_to_gpr(op0))
                        } else {
                            None
                        }
                    })
                    .unwrap_or(regs::GPR_RAX);

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

    pub async fn run(mut self) -> Result<()> {
        use log::error;
        loop {
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
                VmExit::Interrupted => return Ok(()),
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
