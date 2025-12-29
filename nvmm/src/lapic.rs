use crate::memory_bus::MemoryDevice;
use log::debug;

pub const APIC_BASE: u64 = 0xFEE00000;
pub const APIC_SIZE: u64 = 0x1000; // 4KB

// APIC Register Offsets
const _APIC_ID: u32 = 0x020;
const APIC_VER: u32 = 0x030;
const _APIC_TPR: u32 = 0x080;
const APIC_EOI: u32 = 0x0B0;
const _APIC_LDR: u32 = 0x0D0;
const _APIC_DFR: u32 = 0x0E0;
const APIC_SVR: u32 = 0x0F0;
const _APIC_ESR: u32 = 0x280;
const APIC_ICR_LOW: u32 = 0x300;
const _APIC_ICR_HIGH: u32 = 0x310;
const APIC_LVT_TIMER: u32 = 0x320;
const APIC_LVT_LINT0: u32 = 0x350;
const APIC_LVT_LINT1: u32 = 0x360;
const APIC_LVT_ERROR: u32 = 0x370;
const _APIC_TMR_INIT_CNT: u32 = 0x380;
const _APIC_TMR_CUR_CNT: u32 = 0x390;
const APIC_TMR_DIV: u32 = 0x3E0;

pub struct Lapic {
    regs: [u32; 1024], // 4KB space, accessed as 32-bit registers
}

impl Default for Lapic {
    fn default() -> Self {
        Self::new()
    }
}

impl Lapic {
    pub fn new() -> Self {
        let mut lapic = Lapic { regs: [0; 1024] };
        lapic.reset();
        lapic
    }

    pub fn reset(&mut self) {
        // Set default values (simplified)
        self.write_reg(APIC_VER, 0x50014); // Version 0x14, Max LVT 5
        self.write_reg(APIC_SVR, 0xFF); // Spurious Vector Reg (enabled)
        self.write_reg(APIC_LVT_LINT0, 0x10000); // Masked
        self.write_reg(APIC_LVT_LINT1, 0x10000); // Masked
        self.write_reg(APIC_LVT_ERROR, 0x10000); // Masked
        self.write_reg(APIC_LVT_TIMER, 0x10000); // Masked
        self.write_reg(APIC_TMR_DIV, 0xB); // Divide by 1
    }

    fn read_reg(&self, offset: u32) -> u32 {
        let index = (offset / 4) as usize;
        if index < self.regs.len() {
            self.regs[index]
        } else {
            0
        }
    }

    fn write_reg(&mut self, offset: u32, val: u32) {
        let index = (offset / 4) as usize;
        if index < self.regs.len() {
            self.regs[index] = val;
        }
    }

    pub fn read(&self, offset: u64) -> u32 {
        let offset = offset as u32;
        let val = self.read_reg(offset);
        debug!("LAPIC Read: Offset={:#x} Val={:#x}", offset, val);
        val
    }

    pub fn write(&mut self, offset: u64, val: u32) {
        let offset = offset as u32;
        debug!("LAPIC Write: Offset={:#x} Val={:#x}", offset, val);

        match offset {
            APIC_EOI => {
                // End of Interrupt - Acknowledge irq (simplification: do nothing for now)
                self.write_reg(APIC_EOI, 0);
            }
            APIC_ICR_LOW => {
                // When writing to ICR_LOW, we clear the Delivery Status bit (bit 12)
                // because we handle the IPI synchronously/immediately for now.
                self.write_reg(APIC_ICR_LOW, val & !(1 << 12));
                // Handle IPI sending here if needed
            }
            _ => {
                self.write_reg(offset, val);
            }
        }
    }
}

impl MemoryDevice for Lapic {
    fn read(&mut self, _base: u64, offset: u64) -> u64 {
        self.read_reg(offset as u32) as u64
    }

    fn write(&mut self, _base: u64, offset: u64, val: u64) {
        self.write_reg(offset as u32, val as u32);
    }
}
