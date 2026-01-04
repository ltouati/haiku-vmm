use std::time::{Duration, Instant};
use vm_device::MutDeviceMmio;
use vm_device::bus::MmioAddress;

// LAPIC Register Offsets
pub const APIC_ID: u64 = 0x20;
pub const APIC_VER: u64 = 0x30;
pub const APIC_TPR: u64 = 0x80;
pub const APIC_EOI: u64 = 0xB0;
pub const APIC_LDR: u64 = 0xD0;
pub const APIC_DFR: u64 = 0xE0;
pub const APIC_SPIV: u64 = 0xF0;
pub const APIC_ICR_LOW: u64 = 0x300;
pub const APIC_ICR_HIGH: u64 = 0x310;
pub const APIC_LVT_TIMER: u64 = 0x320;
pub const APIC_LVT_LINT0: u64 = 0x350;
pub const APIC_LVT_LINT1: u64 = 0x360;
pub const APIC_LVT_ERROR: u64 = 0x370;
pub const APIC_TMICT: u64 = 0x380; // Initial Count
pub const APIC_TMCCT: u64 = 0x390; // Current Count
pub const APIC_TDCR: u64 = 0x3E0; // Divide Configuration

// Base Address (Default)
pub const APIC_BASE: u64 = 0xFEE00000;

// Timer Modes (Bits 17:18 in LVT Timer)
pub const APIC_LVT_TIMER_ONESHOT: u32 = 0 << 17;
pub const APIC_LVT_TIMER_PERIODIC: u32 = 1 << 17;
pub const APIC_LVT_TIMER_TSCDEADLINE: u32 = 2 << 17;

const LAPIC_FREQ_HZ: u64 = 1_000_000_000; // 1 GHz base for simplicity / calculation

pub struct Lapic {
    regs: [u32; 1024], // 4KB space, 4-byte registers
    timer_last_update: Instant,
    timer_target_expires: Option<Instant>,
    timer_period: Option<Duration>,
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
            timer_last_update: Instant::now(),
            timer_target_expires: None,
            timer_period: None,
        };
        lapic.reset();
        lapic
    }

    pub fn reset(&mut self) {
        // default values
        self.regs[(APIC_VER / 4) as usize] = 0x50014; // Version 0x14, Max LVT 5
        self.regs[(APIC_SPIV / 4) as usize] = 0xFF; // Spurious Interrupt Vector (enabled)
        // Mask LVTs
        self.regs[(APIC_LVT_TIMER / 4) as usize] = 0x10000;
        self.regs[(APIC_LVT_LINT0 / 4) as usize] = 0x10000;
        self.regs[(APIC_LVT_LINT1 / 4) as usize] = 0x10000;
        self.regs[(APIC_LVT_ERROR / 4) as usize] = 0x10000;
        self.regs[(APIC_TMICT / 4) as usize] = 0;
        self.regs[(APIC_TMCCT / 4) as usize] = 0;
        self.regs[(APIC_TDCR / 4) as usize] = 0xB; // Divide by 1 (or whatever default)
    }

    fn read_reg(&self, offset: u64) -> u32 {
        let idx = (offset / 4) as usize;
        if idx >= self.regs.len() {
            return 0;
        }
        // Special handling for Current Count (TMCCT)
        if offset == APIC_TMCCT {
            return self.get_current_count();
        }
        self.regs[idx]
    }

    fn write_reg(&mut self, offset: u64, val: u32) {
        let idx = (offset / 4) as usize;
        if idx >= self.regs.len() {
            return;
        }

        // log::debug!("LAPIC Write: Offset {:#x}, Val {:#x}", offset, val);

        match offset {
            APIC_TMICT => {
                // log::info!("LAPIC Timer Initial Count Set: {}", val);
                self.regs[idx] = val;
                self.update_timer(val);
            }
            APIC_LVT_TIMER => {
                // log::info!("LAPIC LVT Timer Set: {:#x}", val);
                self.regs[idx] = val;
            }
            APIC_SPIV => {
                // log::info!("LAPIC SPIV Set: {:#x}", val);
                self.regs[idx] = val;
            }
            _ => {
                self.regs[idx] = val;
            }
        }
    }

    fn get_current_count(&self) -> u32 {
        if let Some(expires) = self.timer_target_expires {
            let now = Instant::now();
            if now >= expires {
                return 0;
            } else {
                let remaining = expires - now;
                let ticks = (remaining.as_nanos() as u64 * LAPIC_FREQ_HZ) / 1_000_000_000;
                return ticks as u32;
            }
        }
        0
    }

    fn update_timer(&mut self, initial_count: u32) {
        if initial_count == 0 {
            self.timer_target_expires = None;
            self.timer_period = None;
            return;
        }
        // Period = (Initial * Divide) / Frequency
        // Assuming divide = 1 for simplicity
        let nanos = (initial_count as u64 * 1_000_000_000) / LAPIC_FREQ_HZ;
        let period = Duration::from_nanos(nanos);

        // log::info!("LAPIC Timer Armed: Period = {:?}", period);

        self.timer_period = Some(period);
        self.timer_target_expires = Some(Instant::now() + period);
        self.timer_last_update = Instant::now();
    }

    pub fn peek_timer(&self) -> Option<Instant> {
        self.timer_target_expires
    }

    pub fn check_timer(&mut self) -> Option<u8> {
        if let Some(expires) = self.timer_target_expires
            && Instant::now() >= expires
        {
            // Timer Expired!
            let lvt_timer = self.regs[(APIC_LVT_TIMER / 4) as usize];
            if (lvt_timer & 0x10000) != 0 {
                return None; // Masked
            }

            let vector = (lvt_timer & 0xFF) as u8;
            // log::debug!("LAPIC Timer Expired! Vector: {}", vector);

            let mode = lvt_timer & (3 << 17);
            if mode == APIC_LVT_TIMER_PERIODIC {
                if let Some(period) = self.timer_period {
                    self.timer_target_expires = Some(Instant::now() + period);
                }
            } else {
                self.timer_target_expires = None;
            }

            return Some(vector);
        }

        None
    }
}

impl MutDeviceMmio for Lapic {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        let val = self.read_reg(offset);
        // Only support 4-byte reads for now
        if data.len() == 4 {
            data.copy_from_slice(&val.to_le_bytes());
        }
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        if data.len() == 4 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(data);
            let val = u32::from_le_bytes(bytes);
            self.write_reg(offset, val);
        }
    }
}
