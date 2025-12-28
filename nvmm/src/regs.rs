//! Register constants and Segment Attribute bitflags
use bitflags::bitflags;

// State Masks
pub const STATE_SEGS: u64 = 0x01;
pub const STATE_GPRS: u64 = 0x02;
pub const STATE_CRS: u64  = 0x04;
pub const STATE_DRS: u64  = 0x08;
pub const STATE_MSRS: u64 = 0x10;
pub const STATE_INTR: u64 = 0x20;
pub const STATE_FPU:  u64 = 0x40;
pub const STATE_ALL: u64  = 0x7F;

// GPR Indices
pub const GPR_RAX: usize = 0;
pub const GPR_RCX: usize = 1;
pub const GPR_RDX: usize = 2;
pub const GPR_RBX: usize = 3;
pub const GPR_RSP: usize = 4;
pub const GPR_RBP: usize = 5;
pub const GPR_RSI: usize = 6;
pub const GPR_RDI: usize = 7;
pub const GPR_RIP: usize = 16;
pub const GPR_RFLAGS: usize = 17;

// Segment Indices (NVMM ABI)
pub const SEG_ES: usize = 0;
pub const SEG_CS: usize = 1;
pub const SEG_SS: usize = 2;
pub const SEG_DS: usize = 3;
pub const SEG_FS: usize = 4;
pub const SEG_GS: usize = 5;
pub const SEG_GDT: usize = 6;
pub const SEG_IDT: usize = 7;
pub const SEG_LDT: usize = 8;
pub const SEG_TR:  usize = 9;

// CR Indices (NVMM ABI)
pub const CR0: usize = 0;
pub const CR2: usize = 1;
pub const CR3: usize = 2;
pub const CR4: usize = 3;
pub const CR8: usize = 4;
pub const XCR0: usize = 5;

// MSR Indices (NetBSD/Haiku NVMM convention)
pub const MSR_EFER: usize = 0;
pub const MSR_STAR: usize = 1;
pub const MSR_LSTAR: usize = 2;
pub const MSR_CSTAR: usize = 3;
pub const MSR_SFMASK: usize = 4;
pub const MSR_KERNEL_GS_BASE: usize = 5;

// CR0 Bits
pub const CR0_PE: u64 = 1 << 0;
pub const CR0_MP: u64 = 1 << 1;
pub const CR0_EM: u64 = 1 << 2;
pub const CR0_TS: u64 = 1 << 3;
pub const CR0_ET: u64 = 1 << 4;
pub const CR0_NE: u64 = 1 << 5;
pub const CR0_WP: u64 = 1 << 16;
pub const CR0_AM: u64 = 1 << 18;
pub const CR0_NW: u64 = 1 << 29;
pub const CR0_CD: u64 = 1 << 30;
pub const CR0_PG: u64 = 1 << 31;

// CR4 Bits
pub const CR4_PAE: u64 = 1 << 5;

// EFER Bits
pub const EFER_LME: u64 = 1 << 8;
pub const EFER_LMA: u64 = 1 << 10;
pub const EFER_NXE: u64 = 1 << 11;

bitflags! {
    /// x86 Segment Attributes for GDT/LDT entries
    pub struct SegmentAttributes: u16 {
        const ACCESSED      = 1 << 0;
        const RW            = 1 << 1;
        const DC            = 1 << 2;
        const EXECUTABLE    = 1 << 3;
        const DESC_TYPE     = 1 << 4;
        const DPL0          = 0;
        const DPL3          = (1 << 5) | (1 << 6);
        const PRESENT       = 1 << 7;
        const LONG_MODE     = 1 << 13;
        const DB            = 1 << 14;
        const GRANULARITY   = 1 << 15;
    }
}

impl SegmentAttributes {
    pub const REAL_MODE_CODE: Self = Self::from_bits_truncate(Self::PRESENT.bits() | Self::DESC_TYPE.bits() | Self::EXECUTABLE.bits() | Self::RW.bits());
    pub const REAL_MODE_DATA: Self = Self::from_bits_truncate(Self::PRESENT.bits() | Self::DESC_TYPE.bits() | Self::RW.bits());
}