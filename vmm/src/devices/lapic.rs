use log::debug;
use std::time::Instant;

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
const APIC_TMR_INIT_CNT: u32 = 0x380;
const APIC_TMR_CUR_CNT: u32 = 0x390;
const APIC_TMR_DIV: u32 = 0x3E0;

pub struct Lapic {
    regs: [u32; 1024], // 4KB space, accessed as 32-bit registers
    // Timer State
    initial_count: u32,
    divide_conf: u32,
    start_time: Option<Instant>,
    timer_mode: u8, // 0=OneShot, 1=Periodic
    lvt_timer_vector: u8,
    lvt_timer_masked: bool,
}

impl Default for Lapic {
    fn default() -> Self {
        Self::new()
    }
}

impl Lapic {
    pub fn new() -> Self {
        let mut lapic = Lapic {
            regs: [0; 1024],
            initial_count: 0,
            divide_conf: 0,
            start_time: None,
            timer_mode: 0,
            lvt_timer_vector: 0,
            lvt_timer_masked: true,
        };
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

        self.initial_count = 0;
        self.divide_conf = 0xB;
        self.start_time = None;
        self.lvt_timer_masked = true;
    }

    fn read_reg(&self, offset: u32) -> u32 {
        let index = (offset / 4) as usize;
        match offset {
            APIC_TMR_CUR_CNT => self.get_current_count(),
            _ => {
                if index < self.regs.len() {
                    self.regs[index]
                } else {
                    0
                }
            }
        }
    }

    fn write_reg(&mut self, offset: u32, val: u32) {
        let index = (offset / 4) as usize;
        if index < self.regs.len() {
            self.regs[index] = val;
        }
    }

    fn get_divide_value(&self) -> u32 {
        let val = self.divide_conf & 0xB; // Bits 0,1,3. Bit 2 is always 0.
        match val {
            0x0 => 2,
            0x1 => 4,
            0x2 => 8,
            0x3 => 16,
            0x8 => 32,
            0x9 => 64,
            0xA => 128,
            0xB => 1,
            _ => 1,
        }
    }

    fn get_current_count(&self) -> u32 {
        if let Some(start) = self.start_time {
            let elapsed_ns = start.elapsed().as_nanos() as u64;
            // 100MHz Frequency (10ns period)
            let freq_hz = 100_000_000;
            let divide = self.get_divide_value() as u64;

            let ticks = (elapsed_ns * freq_hz / 1_000_000_000) / divide;

            if ticks >= self.initial_count as u64 {
                if self.timer_mode == 1 {
                    // Periodic
                    let rem = ticks % (self.initial_count as u64);
                    return self.initial_count - (rem as u32);
                }
                return 0;
            } else {
                return self.initial_count - (ticks as u32);
            }
        }
        0
    }

    // Check if interrupt pending
    pub fn check_timer(&mut self) -> Option<u8> {
        if self.lvt_timer_masked || self.initial_count == 0 {
            return None;
        }

        if let Some(start) = self.start_time {
            // 100Hz Check Frequency? (10ms)
            // We return interrupt if enough time passed to warrant a tick.
            // This is simplified. KVM usually uses a dedicated thread or hrtimer.
            // We rely on the VMM loop calling this frequently.

            if start.elapsed().as_millis() > 10 && self.timer_mode == 1 {
                self.start_time = Some(Instant::now()); // Restart cycle
                return Some(self.lvt_timer_vector);
            }
        }
        None
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
                self.write_reg(APIC_ICR_LOW, val & !(1 << 12));
            }
            APIC_TMR_DIV => {
                self.divide_conf = val;
                self.write_reg(APIC_TMR_DIV, val);
            }
            APIC_LVT_TIMER => {
                self.lvt_timer_masked = (val & 0x10000) != 0;
                self.timer_mode = ((val >> 17) & 1) as u8; // Bit 17: 0=OneShot, 1=Periodic
                self.lvt_timer_vector = (val & 0xFF) as u8;
                self.write_reg(APIC_LVT_TIMER, val);
            }
            APIC_TMR_INIT_CNT => {
                self.initial_count = val;
                self.write_reg(APIC_TMR_INIT_CNT, val);
                // Writing initial count starts the timer
                if val > 0 {
                    self.start_time = Some(Instant::now());
                } else {
                    self.start_time = None;
                }
            }
            _ => {
                self.write_reg(offset, val);
            }
        }
    }
}

use vm_device::MutDeviceMmio;
use vm_device::bus::MmioAddress;

impl MutDeviceMmio for Lapic {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        if data.len() == 4 {
            let val = self.read(offset);
            data.copy_from_slice(&val.to_le_bytes());
        }
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        if data.len() == 4 {
            let mut val_bytes = [0u8; 4];
            val_bytes.copy_from_slice(data);
            let val = u32::from_le_bytes(val_bytes);
            self.write(offset, val);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lapic_reset() {
        let lapic = Lapic::new();
        assert_eq!(lapic.read(APIC_VER as u64), 0x50014);
        assert_eq!(lapic.read(APIC_SVR as u64), 0xFF);
        assert_eq!(lapic.read(APIC_LVT_TIMER as u64), 0x10000);
    }

    #[test]
    fn test_lapic_read_write() {
        let mut lapic = Lapic::new();
        let offset = 0x380; // TMR_INIT_CNT
        lapic.write(offset, 0x12345678);
        assert_eq!(lapic.read(offset), 0x12345678);
    }

    #[test]
    fn test_lapic_special_write() {
        let mut lapic = Lapic::new();

        // Test ICR_LOW: bit 12 (Delivery Status) should be cleared
        lapic.write(APIC_ICR_LOW as u64, 0x1000); // Set bit 12
        assert_eq!(lapic.read(APIC_ICR_LOW as u64) & (1 << 12), 0);

        // Test EOI: should clear register in simplified impl
        lapic.write_reg(APIC_EOI, 0x1);
        lapic.write(APIC_EOI as u64, 0x1234);
        assert_eq!(lapic.read(APIC_EOI as u64), 0);
    }

    #[test]
    fn test_lapic_mmio() {
        let mut lapic = Lapic::new();
        let offset = 0x300; // ICR_LOW

        let mut data = [0u8; 4];
        lapic.mmio_read(MmioAddress(0), offset as u64, &mut data);
        assert_eq!(u32::from_le_bytes(data), 0);

        lapic.mmio_write(MmioAddress(0), offset as u64, &0xdeadbeefu32.to_le_bytes());
        // Bit 12 should be cleared
        assert_eq!(lapic.read(offset as u64), 0xdeadbeef & !(1 << 12));
    }
    #[test]
    fn test_lapic_timer_config() {
        let mut lapic = Lapic::new();
        // Set Periodic, Vector 0xEF, Unmasked
        lapic.write(APIC_LVT_TIMER as u64, 0x200EF);
        assert_eq!(lapic.timer_mode, 1);
        assert_eq!(lapic.lvt_timer_vector, 0xEF);
        assert!(!lapic.lvt_timer_masked);

        // Start Timer
        lapic.write(APIC_TMR_INIT_CNT as u64, 1000);
        assert!(lapic.start_time.is_some());
    }
}
