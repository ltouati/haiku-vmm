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
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

use crate::i8042::I8042Wrapper;
use crate::lapic::Lapic;
use crate::pic::Pic;
use crate::pit::Pit;
use crate::rtc::RtcWrapper;
use crate::serial::SerialConsole;

use crate::virtio::{ConsoleDevice, MmioTransport};
use crate::{Machine, Vcpu, lapic, regs, sys};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use vm_device::MutDevicePio;
use vm_device::bus::{MmioAddress, MmioRange, PioAddress, PioRange};
use vm_device::device_manager::MmioManager; // Trait for register_mmio
use vm_device::device_manager::PioManager; // Trait for register_pio

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
}

impl Linux64Guest {
    pub fn new(kernel_path: PathBuf, cmdline: String, memory_size_mib: u64) -> Self {
        Self {
            kernel_path,
            cmdline,
            memory_size_mib,
        }
    }

    pub fn load<'a>(
        &self,
        machine: &'a mut Machine,
    ) -> anyhow::Result<(GuestMemoryMmap, Vcpu<'a>)> {
        // 1. Setup Memory
        let mem_size = self.memory_size_mib * 1024 * 1024;
        let guest_mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), mem_size as usize)])
            .map_err(|e| io::Error::other(format!("{:?}", e)))?;
        machine.map_guest_memory(&guest_mem)?;

        // 2. Load Kernel
        info!("Loading kernel from {:?}", self.kernel_path);
        let mut kernel_file = File::open(&self.kernel_path)?;

        // Try ELF
        let (entry_point, _is_long_mode) = if let Ok(res) = Elf::load(
            &guest_mem,
            None,
            &mut kernel_file,
            Some(GuestAddress(HIMEM_START)),
        ) {
            info!(
                "Detected ELF Kernel. Entry: 0x{:x}",
                res.kernel_load.raw_value()
            );
            (res.kernel_load.raw_value(), true)
        } else {
            kernel_file.seek(SeekFrom::Start(0))?;
            let res = BzImage::load(
                &guest_mem,
                None,
                &mut kernel_file,
                Some(GuestAddress(HIMEM_START)),
            )?;
            info!(
                "Detected BzImage Kernel. Entry: 0x{:x}",
                res.kernel_load.raw_value()
            );
            (res.kernel_load.raw_value(), false)
        };

        // 3. Configure Boot Params
        let mut params = boot_params::default();

        params.hdr.type_of_loader = 0xFF;
        params.hdr.boot_flag = 0xAA55;
        params.hdr.header = 0x5372_6448;
        params.hdr.cmd_line_ptr = BOOT_CMD_START as u32;
        params.hdr.cmdline_size = self.cmdline.len() as u32 + 1;
        params.hdr.kernel_alignment = 0x01000000; // 16MB Alignment

        add_e820_entry(&mut params, 0, 0x9fc00, 1);
        add_e820_entry(&mut params, HIMEM_START, mem_size - HIMEM_START, 1);

        LinuxBootConfigurator::write_bootparams(
            &BootParams::new(&params, GuestAddress(ZERO_PAGE_START)),
            &guest_mem,
        )
        .map_err(|e| io::Error::other(format!("Failed to write boot params: {:?}", e)))?;

        let mut cmdline_bytes = self.cmdline.as_bytes().to_vec();
        cmdline_bytes.push(0);
        guest_mem.write_slice(&cmdline_bytes, GuestAddress(BOOT_CMD_START))?;

        // 4. Setup VCPU
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
        // CS: Long Mode (G=1, L=1).
        // Attrib: 0xA09B (G=1, D=0, L=1, P=1).
        let code_seg = sys::NvmmX64StateSeg {
            selector: 0x8,
            base: 0,
            limit: 0xffffffff,
            attrib: 0x0a9b, // Haiku NVMM: Type(0-3),S(4),DPL(5-6),P(7),AVL(8),L(9),DEF(10),G(11). 0xA = G=1,L=1
        };

        let data_seg = sys::NvmmX64StateSeg {
            selector: 0x10,
            base: 0,
            limit: 0xffffffff,
            attrib: 0x0c93, // G=1, DEF=1 (Big). 0xC = 1100.
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
        use_long_mode_pagetables(&guest_mem)?;

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

        Ok((guest_mem, vcpu))
    }

    pub async fn run<'a>(
        &self,
        vcpu: &mut Vcpu<'a>,
        guest_mem: &GuestMemoryMmap,
    ) -> anyhow::Result<()> {
        info!("Starting VCPU...");

        // Initialize Devices (Thread-Safe)

        // Disable XSAVE (26), OSXSAVE (27), AVX (28), F16C (29) in ECX of Leaf 1
        // This prevents the kernel from seeing XSAVE support and hitting
        // the "size 576 != kernel_size 0" panic in paranoid_xstate_size_valid.
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
        let lapic = Arc::new(Mutex::new(Lapic::new())); // Make lapic thread-safe

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

            // Register Devices
            // PIT: 0x40-0x43
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x40), 4)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    pit.clone(),
                )
                .context("Failed to register PIT")?;
            // Speaker/Control: 0x61
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x61), 1)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    pit.clone(),
                )
                .context("Failed to register PIT Speaker")?;
            // Serial: 0x3F8-0x3FF
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x3F8), 8)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    serial.clone(),
                )
                .context("Failed to register Serial")?;
            // RTC/CMOS: 0x70-0x71
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x70), 2)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    rtc.clone(),
                )
                .context("Failed to register RTC")?;
            // Debug Port / DMA Page Registers: 0x80-0x8F
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x80), 0x10)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    debug_port,
                )
                .context("Failed to register Debug Port")?;
            // I8042 Data: 0x60
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x60), 1)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    i8042.clone(),
                )
                .context("Failed to register I8042 Data")?;
            // I8042 Command/Status: 0x64
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x64), 1)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    i8042.clone(),
                )
                .context("Failed to register I8042 Cmd")?;
            // Master PIC: 0x20-0x21
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x20), 2)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    master_pic.clone(),
                )
                .context("Failed to register Master PIC")?;
            // Slave PIC: 0xA0-0xA1
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0xA0), 2)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    slave_pic.clone(),
                )
                .context("Failed to register Slave PIC")?; // Using slave_pic
        }
        let pci_stub = Arc::new(Mutex::new(PciStub));
        // PCI Stub: 0xCF8-0xCFF
        vcpu.machine
            .device_mgr
            .lock()
            .map_err(|_| anyhow!("Failed to lock device manager"))?
            .register_pio(
                PioRange::new(PioAddress(0xCF8), 8)
                    .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                pci_stub,
            )
            .context("Failed to register PCI Stub")?;

        // Register LAPIC (Fixed Base for now)
        // 0xFEE00000 - 0xFEE00FFF
        vcpu.machine
            .device_mgr
            .lock()
            .map_err(|_| anyhow!("Failed to lock device manager"))?
            .register_mmio(
                MmioRange::new(MmioAddress(0xFEE00000), 0x1000)
                    .map_err(|e| anyhow!("Invalid MMIO Range: {:?}", e))?,
                lapic.clone(),
            )
            .context("Failed to register LAPIC")?;

        // Initialize VirtIO
        let virtio_console = Arc::new(Mutex::new(MmioTransport::new(Box::new(
            ConsoleDevice::new(),
        ))));
        virtio_console
            .lock()
            .map_err(|_| anyhow!("Failed to lock virtio console"))?
            .set_memory(guest_mem.clone());
        // VirtIO Console: 0xd0000000 - 0xd00001ff
        vcpu.machine
            .device_mgr
            .lock()
            .map_err(|_| anyhow!("Failed to lock device manager"))?
            .register_mmio(
                MmioRange::new(MmioAddress(0xd0000000), 0x200)
                    .map_err(|e| anyhow!("Invalid MMIO Range: {:?}", e))?,
                virtio_console.clone(),
            )
            .context("Failed to register VirtIO Console")?;

        // Lock dropped automatically

        // Spawn Timer Thread
        {
            let pit = pit.clone();
            let master_pic = master_pic.clone();
            let mut injector = vcpu.injector();

            thread::spawn(move || {
                loop {
                    // Check approximately every 1ms
                    thread::sleep(Duration::from_millis(1));

                    let mut p = pit.lock().unwrap();
                    if p.update_irq() > 0 {
                        let mut m = master_pic.lock().unwrap();
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
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        serial_in.lock().unwrap().queue_input(&buffer);
                        // Simple local echo for now since we are not in raw mode
                        let _ = io::stdout().write(&buffer);
                        let _ = io::stdout().flush();
                    }
                    Err(_) => break, // Error
                }
            }
        });

        let apic_base = Arc::new(Mutex::new(lapic::APIC_BASE | 0x800)); // Base + Enable bit
        let apic_base_msr = apic_base.clone();

        vcpu.runner()
            // Removed on_io and on_memory, using defaults from lib.rs
            .on_msr(move |msr, is_write, val, npc| {
                let apic_base = apic_base_msr.clone();
                Box::pin(async move {
                    if msr == 0x1B {
                        // APIC_BASE
                        if is_write {
                            *apic_base.lock().unwrap() = val;
                        }
                        // Write: Just advance RIP. WRMSR provides NPC, so SetRip(npc).
                        Ok(crate::VmAction::SetRip(npc))
                    } else if msr == 0x10a {
                        // ARCH_CAPABILITIES
                        if !is_write {
                            // Read: Return 0 via RAX. Ignore RDX.
                            Ok(crate::VmAction::WriteRegMasked {
                                reg: regs::GPR_RAX,
                                val: 0,
                                mask: 0xFFFFFFFF,
                                next_rip: npc,
                            })
                        } else {
                            Ok(crate::VmAction::SetRip(npc))
                        }
                    } else {
                        debug!("Unhandled MSR {:#x}", msr);
                        Ok(crate::VmAction::SetRip(npc)) // Just skip it
                    }
                })
            })
            .on_unknown(|reason| {
                Box::pin(async move {
                    error!("Unknown VM Exit Reason: {:#x}", reason);
                    Ok(crate::VmAction::Shutdown)
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
