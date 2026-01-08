use crate::devices::virtio::virtio_blk::BlockDevice;
use crate::devices::virtio::virtio_console::ConsoleDevice;
use crate::devices::virtio::virtio_mmio_device::MmioVirtioDevice;
use crate::devices::virtio::virtio_rng::RngDevice;
use anyhow::{Context, anyhow};
use signal_hook::consts::SIGUSR1;
use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::path::PathBuf;

use byte_unit::Byte;
use linux_loader::{
    bootparam::boot_params,
    configurator::{BootConfigurator, BootParams, linux::LinuxBootConfigurator},
    loader::{KernelLoader, bzimage::BzImage, elf::Elf},
};
use log::{debug, error, info};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::devices::cmos::Cmos;
use crate::devices::i8042::I8042Wrapper;
use crate::devices::lapic::{self, Lapic};
use crate::devices::pic::Pic;
use crate::devices::pit::Pit;
use crate::devices::serial::SerialConsole;

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use vm_device::MutDevicePio;
use vm_device::bus::{MmioAddress, MmioRange, PioAddress, PioRange};
use vm_device::device_manager::MmioManager; // Trait for register_mmio
use vm_device::device_manager::PioManager; // Trait for register_pio

// iced-x86 for robust decoding
use crate::system::Machine;
use crate::system::backend::HypervisorBackend;
use crate::system::nvmm::sys;
use crate::system::nvmm::sys::NvmmX64State;
use crate::system::vmachine::regs;
use crate::system::vmachine::vcpu::Vcpu;
use crate::types::VmAction;
use iced_x86::{Decoder, DecoderOptions};

// CPU / Boot Constants
const HIMEM_START: u64 = 0x100000;
const BOOT_CMD_START: u64 = 0x20000;
const BOOT_STACK_POINTER: u64 = 0x8ff0;
const ZERO_PAGE_START: u64 = 0x7000;
const BOOT_GDT_OFFSET: u64 = 0x1000;
const TSS_START: u64 = 0x600;
const _PAGE_TABLE_START: u64 = 0xa000;
const INITRD_START: u64 = 0x4000000; // 64MB

// VirtIO Block Defaults
const VIRTIO_BLK_ADDR: u64 = 0xd0000000;
const VIRTIO_BLK_SIZE: u64 = 0x1000;
const VIRTIO_BLK_IRQ: u32 = 5;

// VirtIO RNG Defaults
const VIRTIO_RNG_ADDR: u64 = 0xd0001000; // 4K after Block
const VIRTIO_RNG_IRQ: u32 = 11; // Swapped with Console

// VirtIO Console Defaults
const VIRTIO_CONSOLE_ADDR: u64 = 0xd0002000; // 4K after RNG
const VIRTIO_CONSOLE_IRQ: u32 = 10; // Swapped with RNG

#[derive(Clone)]
struct VirtioMmioConfig {
    base: u64,
    size: u64,
    irq: u32,
}

pub struct Linux64Guest {
    pub kernel_path: PathBuf,
    pub cmdline: String,
    pub memory_size_mib: u64,
    pub disk_path: Option<PathBuf>,
    pub initrd_path: Option<PathBuf>,
    mmio_devices: Vec<VirtioMmioConfig>,
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
        initrd_path: Option<PathBuf>,
    ) -> Self {
        let mut mmio_devices = Vec::new();

        if disk_path.is_some() {
            mmio_devices.push(VirtioMmioConfig {
                base: VIRTIO_BLK_ADDR,
                size: VIRTIO_BLK_SIZE,
                irq: VIRTIO_BLK_IRQ,
            });
        }

        // Always Add RNG
        mmio_devices.push(VirtioMmioConfig {
            base: VIRTIO_RNG_ADDR,
            size: 0x1000, // 4K
            irq: VIRTIO_RNG_IRQ,
        });

        // Always Add Console
        mmio_devices.push(VirtioMmioConfig {
            base: VIRTIO_CONSOLE_ADDR,
            size: 0x1000,
            irq: VIRTIO_CONSOLE_IRQ,
        });
        Self {
            kernel_path,
            cmdline,
            memory_size_mib,
            disk_path,
            initrd_path,
            mmio_devices,
        }
    }

    pub fn register_signal_handler() {
        // Register a no-op handler for SIGUSR1 to prevent process termination
        // when kicking the VCPU.
        let _ = unsafe { signal_hook::low_level::register(SIGUSR1, || {}) };
    }

    pub fn load<'a, B: HypervisorBackend>(
        &self,
        machine: &'a mut Machine<B>,
    ) -> anyhow::Result<(GuestMemoryMmap, Vcpu<'a, B>)> {
        // 1. Setup Memory
        let guest_mem = self.setup_memory(machine)?;

        // Register Signal Handler for VCPU Kick
        Self::register_signal_handler();

        // 2. Load Kernel
        let (entry_point, _is_long_mode) = self.load_kernel(&guest_mem)?;

        // 2a. Load Initrd
        let initrd_info = self.load_initrd(&guest_mem)?;

        // 3. Configure Boot Params
        self.configure_boot_params(&guest_mem, initrd_info)?;

        // 4. Setup VCPU
        let vcpu = self.setup_vcpu_state(machine, &guest_mem, entry_point)?;

        Ok((guest_mem, vcpu))
    }

    fn setup_memory<B: HypervisorBackend>(
        &self,
        machine: &mut Machine<B>,
    ) -> anyhow::Result<GuestMemoryMmap> {
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

    fn load_initrd(&self, guest_mem: &GuestMemoryMmap) -> anyhow::Result<Option<(u64, u64)>> {
        if let Some(path) = &self.initrd_path {
            info!("Loading initrd from {:?}", path);
            let mut f = File::open(path)?;
            let size = f.metadata()?.len();

            let addr = GuestAddress(INITRD_START);
            guest_mem.read_volatile_from(addr, &mut f, size as usize)?;
            Ok(Some((INITRD_START, size)))
        } else {
            Ok(None)
        }
    }

    fn configure_boot_params(
        &self,
        guest_mem: &GuestMemoryMmap,
        initrd: Option<(u64, u64)>,
    ) -> anyhow::Result<()> {
        let mem_size = self.memory_size_mib * 1024 * 1024;
        let mut params = boot_params::default();

        params.hdr.type_of_loader = 0xFF;
        params.hdr.boot_flag = 0xAA55;
        params.hdr.header = 0x5372_6448;
        let mut cmdline = self.cmdline.clone();

        // 1. Dynamic VirtIO MMIO Arguments
        for dev in &self.mmio_devices {
            let byte = Byte::from_bytes(dev.size as u128);
            let adj_byte = byte.get_appropriate_unit(true); // true for Binary (1024 base)
            let s = adj_byte.format(0); // 0 decimal places
            // "4 KiB" -> "4K", "1 MiB" -> "1M"
            let size_str = s.replace("iB", "").replace("B", "").replace(" ", "");

            let arg = format!(
                " virtio_mmio.device={}@0x{:x}:{}",
                size_str, dev.base, dev.irq
            );
            cmdline.push_str(&arg);
        }

        // 2. Other Required Flags
        if self.disk_path.is_some() {
            let required_flags = ["root=/dev/vda", "rw", "console=ttyS0"];
            for flag in required_flags {
                if !cmdline.contains(flag) {
                    if !cmdline.is_empty() && !cmdline.ends_with(' ') {
                        cmdline.push(' ');
                    }
                    cmdline.push_str(flag);
                }
            }
        }
        params.hdr.cmd_line_ptr = BOOT_CMD_START as u32;
        params.hdr.cmdline_size = cmdline.len() as u32 + 1;
        params.hdr.cmdline_size = cmdline.len() as u32 + 1;
        params.hdr.kernel_alignment = 0x01000000; // 16MB Alignment

        if let Some((addr, size)) = initrd {
            params.hdr.ramdisk_image = addr as u32;
            params.hdr.ramdisk_size = size as u32;
        }

        add_e820_entry(&mut params, 0, 0x9fc00, 1);
        add_e820_entry(&mut params, HIMEM_START, mem_size - HIMEM_START, 1);

        // Write MP Table at 0x9FC00 (Top of base memory)
        crate::os::mptable::write_mp_table(guest_mem, 0x9FC00, 1)
            .map_err(|e| io::Error::other(format!("Failed to write MP Table: {:?}", e)))?;

        LinuxBootConfigurator::write_bootparams(
            &BootParams::new(&params, GuestAddress(ZERO_PAGE_START)),
            guest_mem,
        )
        .map_err(|e| io::Error::other(format!("Failed to write boot params: {:?}", e)))?;
        info!("Final cmdline: {}", cmdline);
        let mut cmdline_bytes = cmdline.as_bytes().to_vec();
        cmdline_bytes.push(0); // Null terminator
        guest_mem.write_slice(&cmdline_bytes, GuestAddress(BOOT_CMD_START))?;
        Ok(())
    }

    fn setup_vcpu_state<'a, B: HypervisorBackend>(
        &self,
        machine: &'a mut Machine<B>,
        guest_mem: &GuestMemoryMmap,
        entry_point: u64,
    ) -> anyhow::Result<Vcpu<'a, B>> {
        let mut vcpu = machine.create_vcpu(0)?;

        // Create TSS (Required for NVMM)
        guest_mem.write_slice(&[0u8; 104], GuestAddress(TSS_START))?;

        // Registers
        let mut state = NvmmX64State::default();

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
        state.segs[regs::SEG_FS] = sys::NvmmX64StateSeg::default();
        state.segs[regs::SEG_GS] = sys::NvmmX64StateSeg::default();
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

    pub fn run<'a, B: HypervisorBackend + 'static>(
        &self,
        vcpu: &mut Vcpu<'a, B>,
        guest_mem: &GuestMemoryMmap,
    ) -> anyhow::Result<()> {
        info!("Starting VCPU...");

        // CPUID Leaf 0x0: Vendor Information
        // EAX: Maximum Input Value for Basic CPUID Information (set to 0x16 for our 0x15/0x16 leaves)
        // EBX: "Genu"
        // ECX: "ntel"
        // EDX: "ineI"
        // Force "GenuineIntel" to ensure kernel uses Intel TSC calibration paths (CPUID 0x15)
        let leaf0_eax = 0x16;
        let leaf0_ebx = 0x756e6547; // "Genu"
        let leaf0_edx = 0x49656e69; // "ineI"
        let leaf0_ecx = 0x6c65746e; // "ntel"

        vcpu.configure_cpuid(
            0, leaf0_eax, leaf0_ebx, leaf0_ecx, leaf0_edx, !leaf0_eax, !leaf0_ebx, !leaf0_ecx,
            !leaf0_edx,
        )?;

        // CPUID Leaf 0x1: Version and Features
        // We restore the "Haswell" fake values but with correct MASKS.
        // Set:  Value we want.
        // Del:  !Value (Anything we don't set to 1, we force to 0).
        let leaf1_eax = 0x000306C3;
        let leaf1_ebx = 0x00000800; // Brand 0, CLFLUSH 8, APIC 0
        // ECX: Disable x2APIC (Bit 21) to force MMIO usage (0xFEE00000).
        // Old: 0x80202001 -> New: 0x80002001
        let leaf1_ecx = 0x80002001;
        let leaf1_edx = 0x078BFBFD;

        vcpu.configure_cpuid(
            1, leaf1_eax, leaf1_ebx, leaf1_ecx, leaf1_edx, !leaf1_eax, !leaf1_ebx, !leaf1_ecx,
            !leaf1_edx,
        )?;

        // CPUID Leaf 0x6: Thermal/Power Management
        // We REMOVE this because enabling ARAT (Bit 2) implies TSC Deadline support
        // which NVMM does not implement (MSR 0x6E0 is not handled).
        // This likely caused the hang after TSC calibration.
        // We force EAX=0 to disable ARAT.
        vcpu.configure_cpuid(
            6, 0, 0, 0, 0, !0, !0, !0, !0, // Force clear all
        )?;

        // Disable FSGSBASE (Leaf 7, Subleaf 0, EBX Bit 0)
        vcpu.configure_cpuid(
            7, 0, 0, 0, 0, 0, 1, // Del EBX bit 0
            0, 0,
        )?;

        // Advertise KVM Signature
        // Leaf 0x40000000
        let kvm_sig_ebx = 0x4b4d_564b;
        let kvm_sig_ecx = 0x564b_4d56;
        let kvm_sig_edx = 0x0000_004d;

        vcpu.configure_cpuid(
            0x4000_0000,
            0x4000_0001,
            kvm_sig_ebx,
            kvm_sig_ecx,
            kvm_sig_edx,
            !0x4000_0001, // Del EAX
            !kvm_sig_ebx, // Del EBX
            !kvm_sig_ecx, // Del ECX
            !kvm_sig_edx, // Del EDX
        )?;

        // Disable KVM Features (Leaf 0x40000001)
        // Force all to 0. Set=0, Del=!0 (0xFFFFFFFF)
        vcpu.configure_cpuid(0x4000_0001, 0, 0, 0, 0, !0, !0, !0, !0)?;

        // CPUID Leaf 0x15: Time Stamp Counter and Core Crystal Clock Information
        // Force values: EAX=1, EBX=1, ECX=3000000000
        let tsc_eax = 1;
        let tsc_ebx = 1;
        let tsc_ecx = 3_000_000_000;

        vcpu.configure_cpuid(
            0x15, tsc_eax, tsc_ebx, tsc_ecx, 0, !tsc_eax, !tsc_ebx, !tsc_ecx, !0,
        )?;

        // CPUID Leaf 0x16: Processor Frequency Information
        // Force values: EAX=3000, EBX=3000, ECX=100
        let freq_eax = 3000;
        let freq_ebx = 3000;
        let freq_ecx = 100;

        vcpu.configure_cpuid(
            0x16, freq_eax, freq_ebx, freq_ecx, 0, !freq_eax, !freq_ebx, !freq_ecx, !0,
        )?;

        // Initialize PICs (Moved up for Serial Dependency)
        // Initialize PIC (Unified)
        let pic = Arc::new(Mutex::new(Pic::new()));

        // Initialize Devices (Thread-Safe)
        let pit = Arc::new(Mutex::new(Pit::new()));
        let serial = Arc::new(Mutex::new(SerialConsole::new(Some(pic.clone()))));

        // CMOS/RTC with real time and memory size info
        let mem_below_4g = 512 * 1024 * 1024; // 512 MB
        let mem_above_4g = 0;
        let cmos = Arc::new(Mutex::new(Cmos::new(mem_below_4g, mem_above_4g)));
        let lapic = Arc::new(Mutex::new(Lapic::new()));

        let debug_port = Arc::new(Mutex::new(DebugPort));
        let reset_evt = Arc::new(AtomicBool::new(false));
        let i8042 = Arc::new(Mutex::new(I8042Wrapper::new(reset_evt.clone())));

        // Initialize VirtIO Console (Early for Scope)
        let virtio_console = Arc::new(Mutex::new(MmioVirtioDevice(ConsoleDevice::<B>::new()?)));

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
                    cmos.clone(),
                )
                .context("CMOS")?;
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
                    pic.clone(),
                )
                .context("Master PIC")?;
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0xA0), 2)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    pic.clone(),
                )
                .context("Slave PIC")?;

            // Register ELCR Ports
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x4D0), 1)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    pic.clone(),
                )
                .context("ELCR1")?;
            device_mgr
                .register_pio(
                    PioRange::new(PioAddress(0x4D1), 1)
                        .map_err(|e| anyhow!("Invalid PIO Range: {:?}", e))?,
                    pic.clone(),
                )
                .context("ELCR2")?;

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

            // Initialize VirtIO Block
            if let Some(disk_path) = &self.disk_path {
                info!("Initializing VirtIO Block with {:?}", disk_path);
                let disk_file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(disk_path)
                    .context("Failed to open disk image")?;
                let virtio_blk = Arc::new(Mutex::new(MmioVirtioDevice(BlockDevice::<B>::new(
                    disk_file,
                )?)));
                {
                    let mut blk = virtio_blk.lock().expect("Poisoned lock");
                    blk.set_memory(guest_mem.clone());
                    blk.set_injector(vcpu.injector(), pic.clone(), VIRTIO_BLK_IRQ as u8); // IRQ 5 (Conflict Free)
                }
                device_mgr
                    .register_mmio(
                        MmioRange::new(MmioAddress(VIRTIO_BLK_ADDR), VIRTIO_BLK_SIZE)
                            .map_err(|e| anyhow!("Invalid MMIO Range: {:?}", e))?,
                        virtio_blk.clone(),
                    )
                    .context("Failed to register VirtIO Block")?;
            }

            // Initialize VirtIO RNG
            {
                info!("Initializing VirtIO RNG");
                let virtio_rng = Arc::new(Mutex::new(MmioVirtioDevice(RngDevice::<B>::new()?)));
                {
                    let mut rng = virtio_rng.lock().expect("Poisoned lock");
                    rng.set_memory(guest_mem.clone());
                    rng.set_injector(vcpu.injector(), pic.clone(), VIRTIO_RNG_IRQ as u8);
                }
                device_mgr
                    .register_mmio(
                        MmioRange::new(MmioAddress(VIRTIO_RNG_ADDR), 0x1000)
                            .map_err(|e| anyhow!("Invalid MMIO Range: {:?}", e))?,
                        virtio_rng.clone(),
                    )
                    .context("Failed to register VirtIO RNG")?;
            }

            // Initialize VirtIO Console
            {
                info!("Initializing VirtIO Console");
                let mut console = virtio_console.lock().expect("Poisoned lock");
                console.set_memory(guest_mem.clone());
                console.set_injector(vcpu.injector(), pic.clone(), VIRTIO_CONSOLE_IRQ as u8);
            }
            device_mgr
                .register_mmio(
                    MmioRange::new(MmioAddress(VIRTIO_CONSOLE_ADDR), 0x1000)
                        .map_err(|e| anyhow!("Invalid MMIO Range: {:?}", e))?,
                    virtio_console.clone(),
                )
                .context("Failed to register VirtIO Console")?;
        }

        // Spawn Timer Thread
        {
            let pit = pit.clone();
            let pic = pic.clone();

            let injector = vcpu.injector();

            thread::spawn(move || {
                loop {
                    thread::sleep(Duration::from_millis(1));

                    // PIT (Legacy) - Always update source state
                    let mut p = pit.lock().expect("Poisoned lock");
                    if p.update_irq() > 0 {
                        let mut m = pic.lock().expect("Poisoned lock");

                        m.set_irq(0, true);
                        m.set_irq(0, false);
                    }

                    // Injection
                    let _ = injector.stop();
                }
            });
        }

        let serial_in = serial.clone();
        let console_in = virtio_console.clone();
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

                        console_in
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
        let device_mgr_io = vcpu.machine.device_mgr.clone();
        let reset_evt_clone = reset_evt.clone();

        vcpu.runner()
            .on_io(move |port, is_in, data, op_size, npc| {
                let device_mgr = device_mgr_io.clone();
                let data = data.to_vec();
                let reset_evt = reset_evt_clone.clone();

                // Check Reset First? No, usually after IO or during.
                // But here the IO *causes* the reset.

                if !is_in {
                    // Write
                    // Ignore errors (e.g. unmapped ports)
                    let _ = device_mgr
                        .lock()
                        .map_err(|_| anyhow!("Failed to lock device manager"))?
                        .pio_write(vm_device::bus::PioAddress(port), &data);
                    // CHECK RESET SIGNAL
                    if reset_evt.load(Ordering::SeqCst) {
                        info!("Reset Signal Detected!");
                        return Ok(VmAction::Shutdown);
                    }

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
            // Robust Memory Handler (LAPIC Fix)
            .on_memory(move |gpa, is_write, inst_len, inst_bytes, value| {
                let device_mgr = device_mgr_mem.clone();
                let guest_mem = guest_mem_handler.clone();
                let injector = injector_handler.clone();

                let (final_len, reg, size, fallback_val) = if inst_len > 0 {
                        let inst_slice = &inst_bytes[..inst_len as usize];
                        let mut decoder = Decoder::with_ip(64, inst_slice, 0, DecoderOptions::NONE);
                        let instruction = decoder.iter().next();
                        if let Some(i) = instruction {
                             log::debug!("MMIO Instr: {:?} {} (len={})", i.code(), i, i.len());
                        }
                        let size = instruction.map(|i| i.memory_size().size()).unwrap_or(4);
                        let reg = instruction.and_then(|i| {
                            if !is_write { Some(regs::reg_to_gpr(i.op0_register())) } else { None }
                        }).unwrap_or(regs::GPR_RAX);
                        (inst_len as u64, reg, size, None)
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
                                    let (reg, val) = if !is_write {
                                        (regs::reg_to_gpr(instruction.op0_register()), None)
                                    } else {
                                        // For Write: Op0 is destination (Memory), Op1 is Source (Register or Immediate)
                                        // But wait, for MOV [mem], reg -> Op0=Mem, Op1=Reg.
                                        // We need the Register from Op1.
                                        let op1 = instruction.op1_register();
                                        if op1 != iced_x86::Register::None {
                                            let r = regs::reg_to_gpr(op1);
                                            (r, Some(state.gprs[r]))
                                        } else {
                                            // Handle Immediate?
                                            if instruction.op1_kind() == iced_x86::OpKind::Immediate8 {
                                                 (regs::GPR_RAX, Some(instruction.immediate8() as u64))
                                            } else if instruction.op1_kind() == iced_x86::OpKind::Immediate32 {
                                                 (regs::GPR_RAX, Some(instruction.immediate32() as u64))
                                            } else {
                                                 (regs::GPR_RAX, None) // Unknown
                                            }
                                        }
                                    };

                                    if len > 0 {
                                        debug!("Manually decoded MMIO instr at {:#x}: len={}, reg={}, size={}, val={:?}", rip, len, reg, size, val);
                                        (len, reg, size, val)
                                    } else { (0, regs::GPR_RAX, 4, None) }
                                } else { (0, regs::GPR_RAX, 4, None) }
                            } else { (0, regs::GPR_RAX, 4, None) }
                        } else { (0, regs::GPR_RAX, 4, None) }
                    };

                    if final_len == 0 && inst_len == 0 {
                        return Err(anyhow!("Failed to decode instruction"));
                    }

                    if is_write {
                        let val_to_write = fallback_val.unwrap_or(value);
                        let val_bytes = val_to_write.to_le_bytes();
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
                        let mask = match size {
                            1 => 0xFF,
                            2 => 0xFFFF,
                            4 => 0xFFFF_FFFF_FFFF_FFFF, // Zero extend
                            8 => 0xFFFF_FFFF_FFFF_FFFF,
                            _ => 0xFFFF_FFFF_FFFF_FFFF,
                        };
                        Ok(VmAction::WriteRegAndContinue {
                            reg,
                            val,
                            mask,
                            advance_rip: final_len,
                        })
                    }
            })
            // Robust MSR Handler (Advance on Unknown)
            .on_msr(move |msr, is_write, val, npc| {
                let apic_base = apic_base_msr.clone();
                let injector = injector_msr.clone();
                if msr == 0x1B {
                        if is_write { *apic_base.lock().expect("Poisoned lock") = val; }
                        return Ok(VmAction::SetRip(npc));
                    }

                    // KVM Clock MSRs
                    if msr == 0x11 || msr == 0x12 || msr == 0x4b564d00 || msr == 0x4b564d01 {
                        debug!("KVM Clock MSR Access: msr={:#x}, is_write={}, val={:#x}", msr, is_write, val);
                        // For now, return 0 on read and ignore write.
                        // Real implementation would track GPA and update wallclock/system time.
                        if !is_write {
                            let mut state = injector.get_state(sys::NVMM_X64_STATE_GPRS)
                                .map_err(|e| anyhow!("Failed to get state: {}", e))?;
                            state.gprs[regs::GPR_RAX] = 0;
                            state.gprs[regs::GPR_RDX] = 0;
                            injector.set_state(&state, sys::NVMM_X64_STATE_GPRS)
                                .map_err(|e| anyhow!("Failed to set state: {}", e))?;
                        }
                        return Ok(VmAction::SetRip(npc));
                    }

                    // IA32_ARCH_CAPABILITIES
                    if msr == 0x10a {
                         if !is_write {
                            let mut state = injector.get_state(sys::NVMM_X64_STATE_GPRS)
                                .map_err(|e| anyhow!("Failed to get state: {}", e))?;
                            state.gprs[regs::GPR_RAX] = 0; // No special capabilities
                            state.gprs[regs::GPR_RDX] = 0;
                            injector.set_state(&state, sys::NVMM_X64_STATE_GPRS)
                                .map_err(|e| anyhow!("Failed to set state: {}", e))?;
                         }
                         return Ok(VmAction::SetRip(npc));
                    }

                    // FS_BASE (0xC0000100)
                    if msr == 0xC0000100 {
                        let mut state = injector.get_state(sys::NVMM_X64_STATE_SEGS)
                            .map_err(|e| anyhow!("Failed to get SEGS: {}", e))?;
                        if is_write {
                            info!("Setting FS_BASE to {:#x}", val);
                            state.segs[sys::NVMM_X64_SEG_FS].base = val;
                            injector.set_state(&state, sys::NVMM_X64_STATE_SEGS)
                                .map_err(|e| anyhow!("Failed to set FS_BASE: {}", e))?;
                        } else {
                            // TODO: Read
                        }
                         return Ok(VmAction::SetRip(npc));
                    }
                    // GS_BASE (0xC0000101)
                    if msr == 0xC0000101 {
                        let mut state = injector.get_state(sys::NVMM_X64_STATE_SEGS)
                            .map_err(|e| anyhow!("Failed to get SEGS: {}", e))?;
                        if is_write {
                            state.segs[sys::NVMM_X64_SEG_GS].base = val;
                            injector.set_state(&state, sys::NVMM_X64_STATE_SEGS)
                                .map_err(|e| anyhow!("Failed to set GS_BASE: {}", e))?;
                        }
                         return Ok(VmAction::SetRip(npc));
                    }

                    // KERNEL_GS_BASE (0xC0000102) -> MSR Index 5
                    if msr == 0xC0000102 {
                        let mut state = injector.get_state(sys::NVMM_X64_STATE_MSRS)
                            .map_err(|e| anyhow!("Failed to get MSRS: {}", e))?;
                        if is_write {
                            state.msrs[5] = val;
                            injector.set_state(&state, sys::NVMM_X64_STATE_MSRS)
                                .map_err(|e| anyhow!("Failed to set KERNEL_GS_BASE: {}", e))?;
                        }
                         return Ok(VmAction::SetRip(npc));
                    }

                     // STAR (0xC0000081) -> MSR Index 1
                    if msr == 0xC0000081 {
                         let mut state = injector.get_state(sys::NVMM_X64_STATE_MSRS)
                            .map_err(|e| anyhow!("Failed to get MSRS: {}", e))?;
                        if is_write {
                            state.msrs[1] = val;
                            injector.set_state(&state, sys::NVMM_X64_STATE_MSRS)
                                .map_err(|e| anyhow!("Failed to set STAR: {}", e))?;
                        }
                         return Ok(VmAction::SetRip(npc));
                    }

                    // LSTAR (0xC0000082) -> MSR Index 2
                    if msr == 0xC0000082 {
                         let mut state = injector.get_state(sys::NVMM_X64_STATE_MSRS)
                            .map_err(|e| anyhow!("Failed to get MSRS: {}", e))?;
                        if is_write {
                            debug!("Setting LSTAR to {:#x}", val);
                            state.msrs[2] = val;
                            injector.set_state(&state, sys::NVMM_X64_STATE_MSRS)
                                .map_err(|e| anyhow!("Failed to set LSTAR: {}", e))?;
                        }
                         return Ok(VmAction::SetRip(npc));
                    }

                     // SFMASK (0xC0000084) -> MSR Index 4
                    if msr == 0xC0000084 {
                         let mut state = injector.get_state(sys::NVMM_X64_STATE_MSRS)
                            .map_err(|e| anyhow!("Failed to get MSRS: {}", e))?;
                        if is_write {
                            state.msrs[4] = val;
                            injector.set_state(&state, sys::NVMM_X64_STATE_MSRS)
                                .map_err(|e| anyhow!("Failed to set SFMASK: {}", e))?;
                        }
                         return Ok(VmAction::SetRip(npc));
                    }
                    debug!("Handling MSR Exit: msr={:#x}, is_write={}, val={:#x}", msr, is_write, val);
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
            .on_pre_run(move |mut injector| {
                let lapic = lapic.clone();
                let pic = pic.clone();
                    // Optimized Injection: Only check state if pending interrupts exist
                    let timer_peek = lapic.lock().expect("Poisoned").peek_timer();
                    let pic_pending = pic.lock().expect("Poisoned").peek_external_interrupt();

                    #[allow(clippy::collapsible_if)]
                    if timer_peek.is_some() || pic_pending.is_some() {
                        if let Ok(true) = injector.interrupts_enabled() {
                            // Priority: PIC (I/O) > Timer to ensure responsiveness.
                            // We must NOT inject two interrupts in one cycle as the second overwrites the first.
                            // 1. Check PIC
                            if pic_pending.is_some() {
                                if let Some(vector) = pic.lock().expect("Poisoned").get_external_interrupt() {
                                    let _ = injector.inject_interrupt(vector);
                                }
                            } else {
                                // 2. Check Timer (Only if PIC didn't inject)
                                #[allow(clippy::collapsible_if)]
                                if timer_peek.is_some() {
                                    if let Some(vector) = lapic.lock().expect("Poisoned").check_timer() {
                                        let _ = injector.inject_interrupt(vector);
                                    }
                                }
                            }
                        }
                    }
                    Ok(())
            })
            .on_unknown(|reason| {
                error!("Unknown VM Exit Reason: {:#x}", reason);
                Ok(VmAction::Shutdown)
            })
            .run()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_gdt_entry() {
        let entry = make_gdt_entry(0, 0xfffff, 0x9b, 0xa);
        // Base 0, Limit 0xfffff, Access 0x9b, Flags 0xa
        // Expected: ((0 & 0xff000000) << 32) (0) | ((0 & 0x00ffffff) << 16) (0) | (0xfffff & 0xffff) (0xffff) | ((0xfffff & 0xf0000) << 32) (0xf0000_00000000)
        // Access 0x9b << 40, Flags 0xa << 52
        assert_eq!(entry, 0x00af9b000000ffff);
    }

    #[test]
    fn test_add_e820_entry() {
        use linux_loader::bootparam::boot_params;
        let mut params = boot_params::default();
        add_e820_entry(&mut params, 0x1000, 0x2000, 1);
        assert_eq!(params.e820_entries, 1);
        let addr = params.e820_table[0].addr;
        let size = params.e820_table[0].size;
        let type_ = params.e820_table[0].type_;
        assert_eq!(addr, 0x1000);
        assert_eq!(size, 0x2000);
        assert_eq!(type_, 1);
    }

    #[test]
    fn test_pci_stub() {
        let mut pci = PciStub;
        let mut data = [0u8; 1];
        pci.pio_read(PioAddress(0), 0, &mut data);
        assert_eq!(data[0], 0xff);
    }

    #[test]
    fn test_debug_port() {
        let mut debug_port = DebugPort;
        let mut data = [0u8; 1];
        debug_port.pio_read(PioAddress(0), 0, &mut data);
        assert_eq!(data[0], 0x00);
    }

    #[test]
    fn test_translate_gva() {
        let mem: GuestMemoryMmap<()> =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 1024 * 1024)]).unwrap();

        // Setup Page Tables for identity mapping 0->0
        // CR3 = 0x1000
        let cr3 = 0x1000;
        let pml4_addr = 0x1000;
        let pdpt_addr = 0x2000;
        let pd_addr = 0x3000;
        let pt_addr = 0x4000;

        // PML4 Entry 0 points to PDPT
        let pml4e = pdpt_addr | 0x3; // P, RW
        mem.write_obj(pml4e, GuestAddress(pml4_addr)).unwrap();

        // PDPT Entry 0 points to PD
        let pdpte = pd_addr | 0x3;
        mem.write_obj(pdpte, GuestAddress(pdpt_addr)).unwrap();

        // PD Entry 0 points to PT
        let pde = pt_addr | 0x3;
        mem.write_obj(pde, GuestAddress(pd_addr)).unwrap();

        // PT Entry 0 points to Page 0
        let pte = 0x3;
        mem.write_obj(pte, GuestAddress(pt_addr)).unwrap();

        // Test Translation
        // GVA 0 -> Phys 0
        let res = translate_gva(&mem, cr3, 0);
        assert_eq!(res, Some(0));

        // Test Offset
        let res = translate_gva(&mem, cr3, 0x123);
        assert_eq!(res, Some(0x123));

        // Test Unmapped
        // PML4 Entry 1 is empty (0)
        let res = translate_gva(&mem, cr3, 1 << 39); // Index 1 in PML4
        assert_eq!(res, None);
    }
}
