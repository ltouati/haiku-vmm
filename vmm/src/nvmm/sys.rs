//! Low-level FFI bindings to libnvmm
#![allow(non_camel_case_types)]

use libc::{c_int, c_void, size_t, uintptr_t};

pub type NvmmMachid = u32;
pub type NvmmCpuid = u32;
pub type GpAddr = u64;
pub type GvAddr = u64;

// -----------------------------------------------------------------------------
// Structs from nvmm.h
// -----------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NvmmAssistCallbacks {
    pub io: Option<extern "C" fn(*mut NvmmIo)>,
    pub mem: Option<extern "C" fn(*mut NvmmMem)>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NvmmMachine {
    pub machid: NvmmMachid,
    pub pages: *mut *mut NvmmCommPage,
    pub areas: *mut c_void,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NvmmVcpu {
    pub cpuid: NvmmCpuid,
    pub cbs: NvmmAssistCallbacks,
    pub state: *mut NvmmX64State,
    pub event: *mut NvmmX64Event,
    pub exit: *mut NvmmX64Exit,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NvmmIo {
    pub mach: *mut NvmmMachine,
    pub vcpu: *mut NvmmVcpu,
    pub port: u16,
    pub in_: bool, // C bool is usually 1 byte
    pub size: size_t,
    pub data: *mut u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NvmmMem {
    pub mach: *mut NvmmMachine,
    pub vcpu: *mut NvmmVcpu,
    pub gpa: GpAddr,
    pub write: bool,
    pub size: size_t,
    pub data: *mut u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NvmmCommPage {
    pub state_wanted: u64,
    pub state_cached: u64,
    pub state_commit: u64,
    pub state: NvmmX64State,
    pub event_commit: bool,
    pub event: NvmmX64Event,
}

// -----------------------------------------------------------------------------
// Structs from x86/nvmm_x86.h
// -----------------------------------------------------------------------------

// Segments
pub const NVMM_X64_SEG_ES: usize = 0;
pub const NVMM_X64_SEG_CS: usize = 1;
pub const NVMM_X64_SEG_SS: usize = 2;
pub const NVMM_X64_SEG_DS: usize = 3;
pub const NVMM_X64_SEG_FS: usize = 4;
pub const NVMM_X64_SEG_GS: usize = 5;
pub const NVMM_X64_SEG_GDT: usize = 6;
pub const NVMM_X64_SEG_IDT: usize = 7;
pub const NVMM_X64_SEG_LDT: usize = 8;
pub const NVMM_X64_SEG_TR: usize = 9;
pub const NVMM_X64_NSEG: usize = 10;
pub const NVMM_X64_NGPR: usize = 18;
pub const NVMM_X64_NCR: usize = 6;
pub const NVMM_X64_NDR: usize = 6;
pub const NVMM_X64_NMSR: usize = 11;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmmX64StateSeg {
    pub selector: u16,
    pub attrib: u16,
    pub limit: u32,
    pub base: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NvmmX64StateIntr {
    pub int_shadow: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NvmmX64StateFpu {
    pub fx_cw: u16,
    pub fx_sw: u16,
    pub fx_tw: u8,
    pub fx_zero: u8,
    pub fx_opcode: u16,
    pub fx_ip: u64,
    pub fx_dp: u64,
    pub fx_mxcsr: u32,
    pub fx_mxcsr_mask: u32,
    pub fx_87_ac: [u8; 16 * 8],
    pub fx_xmm: [u8; 16 * 16],
    pub fx_rsvd: [u8; 96],
}
// Manually implement Debug for Fpu to avoid array churn
impl std::fmt::Debug for NvmmX64StateFpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NvmmX64StateFpu {{ ... }}")
    }
}
impl Default for NvmmX64StateFpu {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NvmmX64State {
    pub segs: [NvmmX64StateSeg; NVMM_X64_NSEG],
    pub gprs: [u64; NVMM_X64_NGPR],
    pub crs: [u64; NVMM_X64_NCR],
    pub drs: [u64; NVMM_X64_NDR],
    pub msrs: [u64; NVMM_X64_NMSR],
    pub intr: u64,
    pub fpu: NvmmX64StateFpu,
}

impl Default for NvmmX64State {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

// Exit Structs

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NvmmX64ExitMemory {
    pub prot: c_int,
    pub gpa: GpAddr,
    pub inst_len: u8,
    pub inst_bytes: [u8; 15],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NvmmX64ExitIo {
    pub in_: bool,
    pub port: u16,
    pub seg: i8,
    pub address_size: u8,
    pub operand_size: u8,
    pub rep: bool,
    pub str_: bool,
    pub npc: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NvmmX64ExitRdMsr {
    pub msr: u32,
    pub _pad: u32,
    pub npc: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NvmmX64ExitWrMsr {
    pub msr: u32,
    pub _pad: u32,
    pub val: u64,
    pub npc: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union NvmmX64ExitUnion {
    pub mem: NvmmX64ExitMemory,
    pub io: NvmmX64ExitIo,
    pub rdmsr: NvmmX64ExitRdMsr,
    pub wrmsr: NvmmX64ExitWrMsr,
    pub inv: NvmmX64ExitInvalid,
    pub pad: [u8; 256],
}
impl std::fmt::Debug for NvmmX64ExitUnion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NvmmX64ExitUnion {{ ... }}")
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NvmmX64ExitInvalid {
    pub hwcode: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NvmmX64Exit {
    pub reason: u64,
    pub u: NvmmX64ExitUnion,
    pub exitstate: u64,
}

// Event Structs

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NvmmX64Event {
    pub type_: u32,
    pub vector: u8,
    pub u: NvmmX64EventUnion,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union NvmmX64EventUnion {
    pub excp: NvmmX64EventExcp,
    pub pad: [u8; 16],
}
impl std::fmt::Debug for NvmmX64EventUnion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NvmmX64EventUnion")
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct NvmmX64EventExcp {
    pub error: u64,
}

// CPUID Configuration Structs
#[repr(C)]
#[derive(Copy, Clone)]
pub struct NvmmVcpuConfCpuid {
    pub mask: u32, // bit 0: mask, bit 1: exit, bits 2-31: rsvd
    pub leaf: u32,
    pub u: NvmmVcpuConfCpuidUnion,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union NvmmVcpuConfCpuidUnion {
    pub mask: NvmmVcpuConfCpuidMask,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NvmmVcpuConfCpuidMask {
    pub set: NvmmCpuidSet,
    pub del: NvmmCpuidSet,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NvmmCpuidSet {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub const NVMM_VCPU_CONF_CPUID: u64 = 200;

// --- Constants ---
pub const NVMM_VCPU_EVENT_EXCP: u32 = 0;
pub const NVMM_VCPU_EVENT_INTR: u32 = 1;

pub const NVMM_EXIT_NONE: u64 = 0x00;
pub const NVMM_EXIT_MEMORY: u64 = 0x01;
pub const NVMM_EXIT_IO: u64 = 0x02;
pub const NVMM_EXIT_SHUTDOWN: u64 = 0x1000;
pub const NVMM_EXIT_RDMSR: u64 = 0x2000;
pub const NVMM_EXIT_WRMSR: u64 = 0x2001;
pub const NVMM_EXIT_HALTED: u64 = 0x1003;

// State flags
pub const NVMM_X64_STATE_SEGS: u64 = 0x01;
pub const NVMM_X64_STATE_GPRS: u64 = 0x02;
pub const NVMM_X64_STATE_CRS: u64 = 0x04;
pub const NVMM_X64_STATE_DRS: u64 = 0x08;
pub const NVMM_X64_STATE_MSRS: u64 = 0x10;
pub const NVMM_X64_STATE_INTR: u64 = 0x20;
pub const NVMM_X64_STATE_FPU: u64 = 0x40;
pub const NVMM_X64_STATE_ALL: u64 = NVMM_X64_STATE_SEGS
    | NVMM_X64_STATE_GPRS
    | NVMM_X64_STATE_CRS
    | NVMM_X64_STATE_DRS
    | NVMM_X64_STATE_MSRS
    | NVMM_X64_STATE_INTR
    | NVMM_X64_STATE_FPU;

#[link(name = "nvmm")]
unsafe extern "C" {
    pub fn nvmm_init() -> c_int;
    pub fn nvmm_machine_create(mach: *mut NvmmMachine) -> c_int;
    pub fn nvmm_machine_destroy(mach: *mut NvmmMachine) -> c_int;

    pub fn nvmm_vcpu_create(mach: *mut NvmmMachine, cpuid: NvmmCpuid, vcpu: *mut NvmmVcpu)
    -> c_int;
    pub fn nvmm_vcpu_destroy(mach: *mut NvmmMachine, vcpu: *mut NvmmVcpu) -> c_int;
    pub fn nvmm_vcpu_configure(
        mach: *mut NvmmMachine,
        vcpu: *mut NvmmVcpu,
        key: u64,
        value: *mut c_void,
    ) -> c_int;
    pub fn nvmm_vcpu_run(mach: *mut NvmmMachine, vcpu: *mut NvmmVcpu) -> c_int;

    pub fn nvmm_hva_map(mach: *mut NvmmMachine, hva: uintptr_t, size: size_t) -> c_int;
    pub fn nvmm_gpa_map(
        mach: *mut NvmmMachine,
        hva: uintptr_t,
        gpa: GpAddr,
        size: size_t,
        flags: c_int,
    ) -> c_int;

    pub fn nvmm_vcpu_getstate(mach: *mut NvmmMachine, vcpu: *mut NvmmVcpu, flags: u64) -> c_int;
    pub fn nvmm_vcpu_setstate(mach: *mut NvmmMachine, vcpu: *mut NvmmVcpu, flags: u64) -> c_int;
    pub fn nvmm_vcpu_inject(mach: *mut NvmmMachine, vcpu: *mut NvmmVcpu) -> c_int;
    pub fn nvmm_vcpu_dump(mach: *mut NvmmMachine, vcpu: *mut NvmmVcpu);
}
