use anyhow::{Context, anyhow};
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::path::PathBuf;

use linux_loader::{
    bootparam::boot_params,
    configurator::{BootConfigurator, BootParams, linux::LinuxBootConfigurator},
    loader::{KernelLoader, bzimage::BzImage, elf::Elf},
};
use log::{debug, error, info};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::devices::i8042::I8042Wrapper;
use crate::devices::lapic::{self, Lapic};
use crate::devices::pic::Pic;
use crate::devices::pit::Pit;
use crate::devices::rtc::RtcWrapper;
use crate::devices::serial::SerialConsole;

use crate::devices::virtio_blk::BlockDevice;
use crate::devices::virtio_console::ConsoleDevice;
use crate::nvmm::sys;
use crate::nvmm::vcpu::regs;
use crate::{Machine, Vcpu, VmAction};

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use vm_device::MutDevicePio;
use vm_device::bus::{MmioAddress, MmioRange, PioAddress, PioRange};
use vm_device::device_manager::MmioManager; // Trait for register_mmio
use vm_device::device_manager::PioManager; // Trait for register_pio

// iced-x86 for robust decoding
use iced_x86::{Decoder, DecoderOptions};

// CPU / Boot Constants
const HIMEM_START: u64 = 0x100000;
const BOOT_CMD_START: u64 = 0x20000;
const BOOT_STACK_POINTER: u64 = 0x8ff0;
const ZERO_PAGE_START: u64 = 0x7000;
const BOOT_GDT_OFFSET: u64 = 0x1000;
const TSS_START: u64 = 0x600;
const _PAGE_TABLE_START: u64 = 0xa000;

pub struct Linux64Guest {
    pub kernel_path: PathBuf,
    pub cmdline: String,
    pub memory_size_mib: u64,
    pub disk_path: Option<PathBuf>,
}

// Helper to translate GVA to GPA
fn translate_gva<M: GuestMemory>(mem: &M, cr3: u64, gva: u64) -> Option<u64> {
    let pml4_idx = (gva >> 39) & 0x1ff;
    let pdpt_idx = (gva >> 30) & 0x1ff;
    let pd_idx = (gva >> 21) & 0x1ff;
    let pt_idx = (gva >> 12) & 0x1ff;
    let offset = gva & 0xfff;

    let pml4_base = cr3 & !0xfff;
    let pml4_entry: u64 = mem.read_obj(GuestAddress(pml4_base + pml4_idx * 8)).ok()?;
    if pml4_entry & 1 == 0 {
        return None;
    }

    let pdpt_base = pml4_entry & 0x000f_ffff_ffff_f000;
    let pdpt_entry: u64 = mem.read_obj(GuestAddress(pdpt_base + pdpt_idx * 8)).ok()?;
    if pdpt_entry & 1 == 0 {
        return None;
    }

    if pdpt_entry & 0x80 != 0 {
        let phys = (pdpt_entry & 0x000f_ffff_c000_0000) + (gva & 0x3fff_ffff);
        return Some(phys);
    }

    let pd_base = pdpt_entry & 0x000f_ffff_ffff_f000;
    let pd_entry: u64 = mem.read_obj(GuestAddress(pd_base + pd_idx * 8)).ok()?;
    if pd_entry & 1 == 0 {
        return None;
    }

    if pd_entry & 0x80 != 0 {
        let phys = (pd_entry & 0x000f_ffff_ffe0_0000) + (gva & 0x1f_ffff);
        return Some(phys);
    }

    let pt_base = pd_entry & 0x000f_ffff_ffff_f000;
    let pt_entry: u64 = mem.read_obj(GuestAddress(pt_base + pt_idx * 8)).ok()?;
    if pt_entry & 1 == 0 {
        return None;
    }

    let phys = (pt_entry & 0x000f_ffff_ffff_f000) + offset;
    Some(phys)
}

impl Linux64Guest {
    pub fn new(
        kernel_path: PathBuf,
        cmdline: String,
        memory_size_mib: u64,
        disk_path: Option<PathBuf>,
    ) -> Self {
        Self {
            kernel_path,
            cmdline,
            memory_size_mib,
            disk_path,
        }
    }

    pub fn load<'a>(
        &self,
        machine: &'a mut Machine,
    ) -> anyhow::Result<(GuestMemoryMmap, Vcpu<'a>)> {
        // 1. Setup Memory
        let guest_mem = self.setup_memory(machine)?;

        // 2. Load Kernel
        let (entry_point, _is_long_mode) = self.load_kernel(&guest_mem)?;

        // 3. Configure Boot Params
        self.configure_boot_params(&guest_mem)?;

        // 4. Setup VCPU
        let vcpu = self.setup_vcpu_state(machine, &guest_mem, entry_point)?;

        Ok((guest_mem, vcpu))
    }

    fn setup_memory(&self, machine: &mut Machine) -> anyhow::Result<GuestMemoryMmap> {
        let mem_size = self.memory_size_mib * 1024 * 1024;
        let guest_mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), mem_size as usize)])
            .map_err(|e| io::Error::other(format!("{:?}", e)))?;
        machine.map_guest_memory(&guest_mem)?;
        Ok(guest_mem)
    }

    fn load_kernel(&self, guest_mem: &GuestMemoryMmap) -> anyhow::Result<(u64, bool)> {
        info!("Loading kernel from {:?}", self.kernel_path);
        let mut kernel_file = File::open(&self.kernel_path)?;

        // Try ELF
        if let Ok(res) = Elf::load(
            guest_mem,
            None,
            &mut kernel_file,
            Some(GuestAddress(HIMEM_START)),
        ) {
            info!(
                "Detected ELF Kernel. Entry: 0x{:x}",
                res.kernel_load.raw_value()
            );
            Ok((res.kernel_load.raw_value(), true))
        } else {
            kernel_file.seek(SeekFrom::Start(0))?;
            let res = BzImage::load(
                guest_mem,
                None,
                &mut kernel_file,
                Some(GuestAddress(HIMEM_START)),
            )?;
            info!(
                "Detected BzImage Kernel. Entry: 0x{:x}",
                res.kernel_load.raw_value()
            );
            Ok((res.kernel_load.raw_value(), false))
        }
    }

    fn configure_boot_params(&self, guest_mem: &GuestMemoryMmap) -> anyhow::Result<()> {
        let mem_size = self.memory_size_mib * 1024 * 1024;
        let mut params = boot_params::default();

        params.hdr.type_of_loader = 0xFF;
        params.hdr.boot_flag = 0xAA55;
        params.hdr.header = 0x5372_6448;
        let mut cmdline = self.cmdline.clone();
        if self.disk_path.is_some() {
            cmdline.push_str(" virtio_mmio.device=512@0xd0002000:5 root=/dev/vda rw");
        }
        params.hdr.cmd_line_ptr = BOOT_CMD_START as u32;
        params.hdr.cmdline_size = cmdline.len() as u32 + 1;
        params.hdr.kernel_alignment = 0x01000000; // 16MB Alignment

        add_e820_entry(&mut params, 0, 0x9fc00, 1);
        add_e820_entry(&mut params, HIMEM_START, mem_size - HIMEM_START, 1);

        LinuxBootConfigurator::write_bootparams(
            &BootParams::new(&params, GuestAddress(ZERO_PAGE_START)),
            guest_mem,
        )
        .map_err(|e| io::Error::other(format!("Failed to write boot params: {:?}", e)))?;

        let mut cmdline_bytes = cmdline.as_bytes().to_vec();
        cmdline_bytes.push(0); // Null terminator
        guest_mem.write_slice(&cmdline_bytes, GuestAddress(BOOT_CMD_START))?;
        Ok(())
    }

    fn setup_vcpu_state<'a>(
        &self,
        machine: &'a mut Machine,
        guest_mem: &GuestMemoryMmap,
        entry_point: u64,
    ) -> anyhow::Result<Vcpu<'a>> {
        let mut vcpu = machine.create_vcpu(0)?;

        // Create TSS (Required for NVMM)
        guest_mem.write_slice(&[0u8; 104], GuestAddress(TSS_START))?;

        // Registers
        let mut state = sys::NvmmX64State::default();

        state.gprs[regs::GPR_RIP] = entry_point;
        state.gprs[regs::GPR_RSP] = BOOT_STACK_POINTER;
        state.gprs[regs::GPR_RSI] = ZERO_PAGE_START;
        state.gprs[regs::GPR_RFLAGS] = 0x2;

        // Segments (64-bit Long Mode)
        let code_seg = sys::NvmmX64StateSeg {
            selector: 0x8,
            base: 0,
            limit: 0xffffffff,
            attrib: 0x0a9b,
        };

        let data_seg = sys::NvmmX64StateSeg {
            selector: 0x10,
            base: 0,
            limit: 0xffffffff,
            attrib: 0x0c93,
        };

        let tss_seg = sys::NvmmX64StateSeg {
            selector: 0x18,
            base: TSS_START,
            limit: 103,
            attrib: 0x008b,
        };

        state.segs[regs::SEG_CS] = code_seg;
        state.segs[regs::SEG_DS] = data_seg;
        state.segs[regs::SEG_ES] = data_seg;
        state.segs[regs::SEG_SS] = data_seg;
        state.segs[regs::SEG_FS] = data_seg;
        state.segs[regs::SEG_GS] = data_seg;
        state.segs[regs::SEG_TR] = tss_seg;

        // GDT Table (Long Mode)
        let mut gdt_table = [0u64; 5];
        gdt_table[0] = 0;
        // Code 64-bit: Flags 0xA (L=1). Access 0x9B.
        gdt_table[1] = make_gdt_entry(0, 0x000fffff, 0x9B, 0xA);
        // Data: Flags 0xC (Big). Access 0x93.
        gdt_table[2] = make_gdt_entry(0, 0x000fffff, 0x93, 0xC);

        gdt_table[3] = make_gdt_entry(TSS_START, 103, 0x8B, 0x0);
        gdt_table[4] = TSS_START >> 32;

        guest_mem.write_slice(
            unsafe { std::slice::from_raw_parts(gdt_table.as_ptr() as *const u8, 40) },
            GuestAddress(BOOT_GDT_OFFSET),
        )?;

        state.segs[regs::SEG_GDT] = sys::NvmmX64StateSeg {
            base: BOOT_GDT_OFFSET,
            limit: 0xffff,
            ..Default::default()
        };

        // Setup Page Tables
        use_long_mode_pagetables(guest_mem)?;

        // CR0 PE | PG | ET. (Matches KVM approx, no NE, no CD/NW yet)
        let cr0 = regs::CR0_PE | regs::CR0_PG | regs::CR0_ET;
        let cr4 = regs::CR4_PAE; // PAE only, no SSE yet (Matches KVM 0x20)
        let efer = regs::EFER_LME | regs::EFER_LMA;

        state.crs[regs::CR0] = cr0;
        state.crs[regs::CR4] = cr4;
        state.crs[regs::CR3] = 0xa000;
        state.msrs[regs::MSR_EFER] = efer;

        state.fpu.fx_cw = 0x037F;
        state.fpu.fx_mxcsr = 0x1F80;

        // Flags for set_state
        let flags = regs::STATE_GPRS
            | regs::STATE_SEGS
            | regs::STATE_CRS
            | regs::STATE_MSRS
            | regs::STATE_FPU
            | regs::STATE_INTR;

        vcpu.set_state(&state, flags)?;

        Ok(vcpu)
    }

    pub async fn run<'a>(
        &self,
        vcpu: &mut Vcpu<'a>,
        guest_mem: &GuestMemoryMmap,
    ) -> anyhow::Result<()> {
        info!("Starting VCPU...");

        // Disable XSAVE (26), OSXSAVE (27), AVX (28), F16C (29) in ECX of Leaf 1
        vcpu.configure_cpuid(
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            (1 << 26) | (1 << 27) | (1 << 28) | (1 << 29),
            0,
        )?;

        // Initialize Devices (Thread-Safe)
        let pit = Arc::new(Mutex::new(Pit::new()));
        let serial = Arc::new(Mutex::new(SerialConsole::new()));
        let rtc = Arc::new(Mutex::new(RtcWrapper::new()));
        let lapic = Arc::new(Mutex::new(Lapic::new()));

        // Initialize PICs
        let master_pic = Arc::new(Mutex::new(Pic::new(true)));
        let slave_pic = Arc::new(Mutex::new(Pic::new(false)));

        let debug_port = Arc::new(Mutex::new(DebugPort));
        let i8042 = Arc::new(Mutex::new(I8042Wrapper::new()));

        {
            let mut device_mgr = vcpu
                .machine
                .device_mgr
                .lock()
                .map_err(|_| anyhow!("Failed to lock device manager"))?;

            // Capture a clone for the handler

            // Register PIO Devices
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x40), 4)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    pit.clone(),
                )
                .context("PIT")?;
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x61), 1)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    pit.clone(),
                )
                .context("Speaker")?;
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x3F8), 8)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    serial.clone(),
                )
                .context("Serial")?;
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x70), 2)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    rtc.clone(),
                )
                .context("RTC")?;
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x80), 0x10)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    debug_port,
                )
                .context("DebugPort")?;
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x60), 1)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    i8042.clone(),
                )
                .context("I8042 Data")?;
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x64), 1)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    i8042.clone(),
                )
                .context("I8042 Cmd")?;
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x20), 2)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    master_pic.clone(),
                )
                .context("Master PIC")?;
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0xA0), 2)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    slave_pic.clone(),
                )
                .context("Slave PIC")?;

            let pci_stub = Arc::new(Mutex::new(PciStub));
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0xCF8), 8)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    pci_stub,
                )
                .context("PCI Stub")?;

            // Register MMIO Devices
            // LAPIC: 0xFEE00000 - 0xFEE00FFF
            device_mgr
                .register_mmio(
                    MmioRange::new(MmioAddress(0xFEE00000), 0x1000)
                        .map_err(|e| anyhow!("Invalid MMIO Range: {:?}", e))?,
                    lapic.clone(),
                )
                .context("Failed to register LAPIC")?;

            // Initialize VirtIO Console
            let virtio_console = Arc::new(Mutex::new(ConsoleDevice::new()?));
            virtio_console
                .lock()
                .expect("Poisoned lock")
                .set_memory(guest_mem.clone());
            device_mgr
                .register_mmio(
                    MmioRange::new(MmioAddress(0xd0000000), 0x200)
                        .map_err(|e| anyhow!("Invalid MMIO Range: {:?}", e))?,
                    virtio_console.clone(),
                )
                .context("Failed to register VirtIO Console")?;

            // Initialize VirtIO Block
            if let Some(disk_path) = &self.disk_path {
                info!("Initializing VirtIO Block with {:?}", disk_path);
                let disk_file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(disk_path)
                    .context("Failed to open disk image")?;
                let virtio_blk = Arc::new(Mutex::new(BlockDevice::new(disk_file)?));
                {
                    let mut blk = virtio_blk.lock().expect("Poisoned lock");
                    blk.set_memory(guest_mem.clone());
                    blk.set_injector(vcpu.injector(), 37); // IRQ 5 -> Vector 37 (0x25)
                }
                device_mgr
                    .register_mmio(
                        MmioRange::new(MmioAddress(0xd0002000), 0x200)
                            .map_err(|e| anyhow!("Invalid MMIO Range: {:?}", e))?,
                        virtio_blk.clone(),
                    )
                    .context("Failed to register VirtIO Block")?;
            }
        }

        // Spawn Timer Thread
        {
            let pit = pit.clone();
            let master_pic = master_pic.clone();
            let mut injector = vcpu.injector();

            thread::spawn(move || {
                loop {
                    thread::sleep(Duration::from_millis(1));
                    let mut p = pit.lock().expect("Poisoned lock");
                    if p.update_irq() > 0 {
                        let mut m = master_pic.lock().expect("Poisoned lock");
                        m.set_irq(0, true);
                        if let Some(vector) = m.ack_interrupt() {
                            let _ = injector.inject_interrupt(vector);
                        }
                    }
                }
            });
        }

        let serial_in = serial.clone();
        thread::spawn(move || {
            let mut buffer = [0; 1];
            loop {
                match io::stdin().read(&mut buffer) {
                    Ok(0) => break,
                    Ok(_) => {
                        serial_in
                            .lock()
                            .expect("Poisoned lock")
                            .queue_input(&buffer);
                        // Local echo
                        let _ = io::stdout().write(&buffer);
                        let _ = io::stdout().flush();
                    }
                    Err(_) => break,
                }
            }
        });

        // Prepare handlers
        let apic_base = Arc::new(Mutex::new(lapic::APIC_BASE | 0x800)); // Base + Enable bit
        let apic_base_msr = apic_base.clone();

        let guest_mem_handler = guest_mem.clone();
        let injector_handler = vcpu.injector();
        let injector_msr = vcpu.injector();
        // device_mgr is locked inside machine, need to access via clone on demand or before
        let device_mgr_mem = vcpu.machine.device_mgr.clone();

        vcpu.runner()
            // Robust Memory Handler (LAPIC Fix)
            .on_memory(move |gpa, is_write, inst_len, inst_bytes, value| {
                let device_mgr = device_mgr_mem.clone();
                let guest_mem = guest_mem_handler.clone();
                let injector = injector_handler;

                Box::pin(async move {
                    let (final_len, reg, size) = if inst_len > 0 {
                        let inst_slice = &inst_bytes[..inst_len as usize];
                        let mut decoder = Decoder::with_ip(64, inst_slice, 0, DecoderOptions::NONE);
                        let instruction = decoder.iter().next();
                        let size = instruction.map(|i| i.memory_size().size()).unwrap_or(4);
                        let reg = instruction.and_then(|i| {
                            if !is_write { Some(regs::reg_to_gpr(i.op0_register())) } else { None }
                        }).unwrap_or(regs::GPR_RAX);
                        (inst_len as u64, reg, size)
                    } else {
                        // Manual fetch fallback
                        if let Ok(state) = injector.get_state(sys::NVMM_X64_STATE_ALL) {
                            let rip = state.gprs[regs::GPR_RIP];
                            let cr3 = state.crs[2];
                            let mut code_bytes = [0u8; 15];
                            let mut fetched = false;
                            // Simple fetch loop
                            for (i, byte) in code_bytes.iter_mut().enumerate() {
                                let gva = rip + i as u64;
                                if let Some(gpa_fe) = translate_gva(&guest_mem, cr3, gva) {
                                    if let Ok(b) = guest_mem.read_obj::<u8>(GuestAddress(gpa_fe)) {
                                        *byte = b;
                                        fetched = true;
                                    } else { break; }
                                } else { break; }
                            }

                            if fetched {
                                let mut decoder = Decoder::with_ip(64, &code_bytes, rip, DecoderOptions::NONE);
                                if let Some(instruction) = decoder.iter().next() {
                                    let size = instruction.memory_size().size();
                                    let len = instruction.len() as u64;
                                    let reg = if !is_write { regs::reg_to_gpr(instruction.op0_register()) } else { regs::GPR_RAX };

                                    if len > 0 {
                                        debug!("Manually decoded MMIO instr at {:#x}: len={}, reg={}, size={}", rip, len, reg, size);
                                        (len, reg, size)
                                    } else { (0, regs::GPR_RAX, 4) }
                                } else { (0, regs::GPR_RAX, 4) }
                            } else { (0, regs::GPR_RAX, 4) }
                        } else { (0, regs::GPR_RAX, 4) }
                    };

                    if final_len == 0 && inst_len == 0 {
                        return Err(anyhow!("Failed to decode instruction"));
                    }

                    if is_write {
                        let val_bytes = value.to_le_bytes();
                        device_mgr.lock().expect("Poisoned lock")
                            .mmio_write(MmioAddress(gpa), &val_bytes[..size])
                            .map_err(|e| anyhow!("MMIO Write Error at {:#x}: {:?}", gpa, e))?;
                        Ok(VmAction::AdvanceRip(final_len))
                    } else {
                        let mut data = [0u8; 8];
                        device_mgr.lock().expect("Poisoned lock")
                            .mmio_read(MmioAddress(gpa), &mut data[..size])
                            .map_err(|e| anyhow!("MMIO Read Error at {:#x}: {:?}", gpa, e))?;

                        let val = u64::from_le_bytes(data);
                        Ok(VmAction::WriteRegAndContinue {
                            reg,
                            val,
                            advance_rip: final_len,
                        })
                    }
                })
            })
            // Robust MSR Handler (Advance on Unknown)
            .on_msr(move |msr, is_write, val, npc| {
                let apic_base = apic_base_msr.clone();
                let injector = injector_msr;
                Box::pin(async move {
                    if msr == 0x1B {
                        if is_write { *apic_base.lock().expect("Poisoned lock") = val; }
                        return Ok(VmAction::SetRip(npc));
                    }
                    debug!("Handling MSR Exit: msr={:#x}", msr);
                    if !is_write {
                        // Return 0
                        let mut state = injector.get_state(sys::NVMM_X64_STATE_GPRS)
                            .map_err(|e| anyhow!("Failed to get state: {}", e))?;
                        state.gprs[regs::GPR_RAX] = 0;
                        state.gprs[regs::GPR_RDX] = 0;
                        injector.set_state(&state, sys::NVMM_X64_STATE_GPRS)
                            .map_err(|e| anyhow!("Failed to set state: {}", e))?;
                        Ok(VmAction::SetRip(npc))
                    } else {
                        Ok(VmAction::SetRip(npc))
                    }
                })
            })
            .on_unknown(|reason| {
                Box::pin(async move {
                    error!("Unknown VM Exit Reason: {:#x}", reason);
                    Ok(VmAction::Shutdown)
                })
            })
            .run()
            .await
    }
}

fn make_gdt_entry(base: u64, limit: u64, access: u8, flags: u8) -> u64 {
    let flags = flags as u64;
    let access = access as u64;

    ((base & 0xff00_0000u64) << 32)
        | ((base & 0x00ff_ffffu64) << 16)
        | (limit & 0x0000_ffffu64)
        | ((limit & 0x000f_0000u64) << 32)
        | (flags << 52)
        | (access << 40)
}

fn add_e820_entry(params: &mut boot_params, addr: u64, size: u64, mem_type: u32) {
    if params.e820_entries >= params.e820_table.len() as u8 {
        return;
    }
    let i = params.e820_entries as usize;
    params.e820_table[i].addr = addr;
    params.e820_table[i].size = size;
    params.e820_table[i].type_ = mem_type;
    params.e820_entries += 1;
}

fn use_long_mode_pagetables(mem: &GuestMemoryMmap) -> anyhow::Result<()> {
    let pml4_addr = GuestAddress(0xa000);
    let pdpte_addr = GuestAddress(0xb000);
    let pde_addr = GuestAddress(0xc000);

    mem.write_slice(&[0u8; 4096], pml4_addr).ok();
    mem.write_slice(&[0u8; 4096], pdpte_addr).ok();
    mem.write_slice(&[0u8; 4096], pde_addr).ok();

    // Low Mapping (0-512GB) -> PDPTE (0xb000)
    // PML4[0] -> PDPTE | 0x3 (P|RW)
    mem.write_obj(pdpte_addr.raw_value() | 0x3, pml4_addr)
        .map_err(|e| anyhow!("Failed to write PML4: {:?}", e))?;

    // Low Mapping (0-1GB) -> PDE (0xc000)
    // PDPTE[0] -> PDE | 0x3
    mem.write_obj(pde_addr.raw_value() | 0x3, pdpte_addr)
        .map_err(|e| anyhow!("Failed to write PDPTE: {:?}", e))?;

    // High Memory / Kernel Space Mapping (-2GB)
    // Virtual 0xffffffff80000000 -> Physical 0
    // PML4[511] -> PDPTE | 0x3 (Reuse 0xb000)
    mem.write_obj(
        pdpte_addr.raw_value() | 0x3,
        pml4_addr
            .checked_add(511 * 8)
            .ok_or(anyhow!("PML4 Address Overflow"))?,
    )
    .map_err(|e| anyhow!("Failed to write PML4 high: {:?}", e))?;

    // PDPTE[510] -> PDE | 0x3 (Reuse 0xc000)
    mem.write_obj(
        pde_addr.raw_value() | 0x3,
        pdpte_addr
            .checked_add(510 * 8)
            .ok_or(anyhow!("PDPTE Address Overflow"))?,
    )
    .map_err(|e| anyhow!("Failed to write PDPTE high: {:?}", e))?;

    // PDE[0..512] -> 2MB Pages | 0x83 (P|RW|PS) -> 0b10000011
    for i in 0..512 {
        let entry = i << 21 | 0x83;
        mem.write_obj(
            entry,
            pde_addr
                .checked_add(i * 8)
                .ok_or(anyhow!("PDE Address Overflow"))?,
        )
        .map_err(|e| anyhow!("Failed to write PDE: {:?}", e))?;
    }

    Ok(())
}

struct PciStub;
impl MutDevicePio for PciStub {
    fn pio_read(&mut self, _base: PioAddress, _offset: u16, data: &mut [u8]) {
        if data.len() == 1 {
            data[0] = 0xff;
        }
    }
    fn pio_write(&mut self, _base: PioAddress, _offset: u16, _data: &[u8]) {}
}

struct DebugPort;
impl MutDevicePio for DebugPort {
    fn pio_read(&mut self, _base: PioAddress, _offset: u16, data: &mut [u8]) {
        if data.len() == 1 {
            data[0] = 0;
        }
    }
    fn pio_write(&mut self, _base: PioAddress, _offset: u16, _data: &[u8]) {}
}
