//! CMOS/RTC Device (I/O Ports 0x70/0x71)
//!
//! Based on crosvm's implementation. Provides:
//! - Real-time clock registers (seconds, minutes, hours, day, month, year)
//! - Status registers A, B, C, D
//! - Extended memory size registers
//! - All values in BCD format
#![allow(dead_code)]
use chrono::{Datelike, Timelike, Utc};
use log::debug;
use vm_device::MutDevicePio;
use vm_device::bus::PioAddress;

const INDEX_MASK: u8 = 0x7f;
const DATA_LEN: usize = 128;

// RTC Time Registers
const RTC_REG_SEC: u8 = 0x00;
const RTC_REG_ALARM_SEC: u8 = 0x01;
const RTC_REG_MIN: u8 = 0x02;
const RTC_REG_ALARM_MIN: u8 = 0x03;
const RTC_REG_HOUR: u8 = 0x04;
const RTC_REG_ALARM_HOUR: u8 = 0x05;
const RTC_REG_WEEK_DAY: u8 = 0x06;
const RTC_REG_DAY: u8 = 0x07;
const RTC_REG_MONTH: u8 = 0x08;
const RTC_REG_YEAR: u8 = 0x09;

// Status Registers
const RTC_REG_A: u8 = 0x0a;
const RTC_REG_B: u8 = 0x0b;
const RTC_REG_C: u8 = 0x0c;
const RTC_REG_D: u8 = 0x0d;

// Extended registers
const RTC_REG_CENTURY: u8 = 0x32;

// Status Register A flags
const RTC_REG_A_UIP: u8 = 0x80; // Update in progress (always 0 for us)

// Status Register B flags
const RTC_REG_B_24_HOUR_MODE: u8 = 0x02;
const RTC_REG_B_DATA_MODE: u8 = 0x04; // 0 = BCD, 1 = Binary

// Status Register D flags
const RTC_REG_D_VRT: u8 = 0x80; // RAM and time valid

/// CMOS/RTC device commonly seen on x86 I/O port 0x70/0x71.
pub struct Cmos {
    index: u8,
    data: [u8; DATA_LEN],
}

impl Cmos {
    /// Creates a new CMOS device.
    /// `mem_below_4g` is the size of memory in bytes below the 32-bit gap.
    /// `mem_above_4g` is the size of memory in bytes above the 32-bit gap.
    #[must_use]
    pub fn new(mem_below_4g: u64, mem_above_4g: u64) -> Self {
        let mut data = [0u8; DATA_LEN];

        // Status Register A: Normal operation, divider set
        data[RTC_REG_A as usize] = 0x26;

        // Status Register B: 24-hour mode, BCD format
        data[RTC_REG_B as usize] = RTC_REG_B_24_HOUR_MODE;

        // Status Register C: No interrupts pending
        data[RTC_REG_C as usize] = 0x00;

        // Status Register D: RAM and time valid
        data[RTC_REG_D as usize] = RTC_REG_D_VRT;

        // Base memory size (0x15-0x16): 640 KB in KB
        data[0x15] = 0x80; // 640 & 0xFF
        data[0x16] = 0x02; // 640 >> 8

        // Extended memory from 1 MB to 16 MB in KB (0x17-0x18)
        let ext_mem_kb = std::cmp::min(0xFFFF, mem_below_4g.saturating_sub(1024 * 1024) / 1024);
        data[0x17] = ext_mem_kb as u8;
        data[0x18] = (ext_mem_kb >> 8) as u8;

        // Extended memory from 16 MB to 4 GB in units of 64 KB (0x34-0x35)
        let ext_mem_64k = std::cmp::min(
            0xFFFF,
            mem_below_4g.saturating_sub(16 * 1024 * 1024) / (64 * 1024),
        );
        data[0x34] = ext_mem_64k as u8;
        data[0x35] = (ext_mem_64k >> 8) as u8;

        // High memory (>4GB) in units of 64 KB (0x5b-0x5d)
        let high_mem_64k = std::cmp::min(0x00FF_FFFF, mem_above_4g / (64 * 1024));
        data[0x5b] = high_mem_64k as u8;
        data[0x5c] = (high_mem_64k >> 8) as u8;
        data[0x5d] = (high_mem_64k >> 16) as u8;

        Cmos { index: 0, data }
    }

    /// Convert a value to BCD format
    fn to_bcd(v: u8) -> u8 {
        assert!(v < 100);
        ((v / 10) << 4) | (v % 10)
    }

    /// Read the current time register
    fn read_time_register(&self, reg: u8) -> u8 {
        let now = Utc::now();

        let seconds = now.second() as u8; // 0..=59
        let minutes = now.minute() as u8; // 0..=59
        let hours = now.hour() as u8; // 0..=23 (24-hour mode)
        let week_day = now.weekday().number_from_sunday() as u8; // 1 (Sun) ..= 7 (Sat)
        let day = now.day() as u8; // 1..=31
        let month = now.month() as u8; // 1..=12
        let year = now.year();

        let is_bcd = (self.data[RTC_REG_B as usize] & RTC_REG_B_DATA_MODE) == 0;

        let value = match reg {
            RTC_REG_SEC => seconds,
            RTC_REG_MIN => minutes,
            RTC_REG_HOUR => hours,
            RTC_REG_WEEK_DAY => week_day,
            RTC_REG_DAY => day,
            RTC_REG_MONTH => month,
            RTC_REG_YEAR => (year % 100) as u8,
            RTC_REG_CENTURY => (year / 100) as u8,
            _ => return self.data[reg as usize],
        };

        if is_bcd { Self::to_bcd(value) } else { value }
    }
}

impl Default for Cmos {
    fn default() -> Self {
        // Default: 512 MB below 4G, 0 above
        Self::new(512 * 1024 * 1024, 0)
    }
}

impl MutDevicePio for Cmos {
    fn pio_read(&mut self, _base: PioAddress, offset: u16, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }

        data[0] = match offset {
            0 => {
                // Index port (0x70) - usually write-only, return last written index
                self.index
            }
            1 => {
                // Data port (0x71)
                match self.index {
                    // Time registers - read from real time
                    RTC_REG_SEC | RTC_REG_MIN | RTC_REG_HOUR | RTC_REG_WEEK_DAY | RTC_REG_DAY
                    | RTC_REG_MONTH | RTC_REG_YEAR | RTC_REG_CENTURY => {
                        self.read_time_register(self.index)
                    }

                    // Status Register A - no update in progress
                    RTC_REG_A => self.data[RTC_REG_A as usize] & !RTC_REG_A_UIP,

                    // Status Register C - reading clears interrupt flags
                    RTC_REG_C => {
                        let val = self.data[RTC_REG_C as usize];
                        self.data[RTC_REG_C as usize] = 0;
                        val
                    }

                    // Status Register D - always valid
                    RTC_REG_D => RTC_REG_D_VRT,

                    // All other registers - return stored data
                    _ => self.data[(self.index & INDEX_MASK) as usize],
                }
            }
            _ => {
                debug!("CMOS: bad read offset {offset}");
                0
            }
        };
    }

    fn pio_write(&mut self, _base: PioAddress, offset: u16, data: &[u8]) {
        if data.len() != 1 {
            return;
        }

        match offset {
            0 => {
                // Index port (0x70)
                self.index = data[0] & INDEX_MASK;
            }
            1 => {
                // Data port (0x71)
                let value = data[0];

                match self.index {
                    // Status Register B - enforce 24-hour mode
                    RTC_REG_B => {
                        self.data[RTC_REG_B as usize] = value | RTC_REG_B_24_HOUR_MODE;
                    }

                    // Status Register C/D are read-only
                    RTC_REG_C | RTC_REG_D => {}

                    // All other registers - store data
                    _ => {
                        self.data[(self.index & INDEX_MASK) as usize] = value;
                    }
                }
            }
            _ => {
                debug!("CMOS: bad write offset {offset}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmos_index() {
        let mut cmos = Cmos::new(512 * 1024 * 1024, 0);

        // Write index 0x00 (seconds)
        cmos.pio_write(PioAddress(0x70), 0, &[0x00]);
        assert_eq!(cmos.index, 0x00);

        // Write index with NMI bit set (0x80) - should be masked
        cmos.pio_write(PioAddress(0x70), 0, &[0x82]);
        assert_eq!(cmos.index, 0x02);
    }

    #[test]
    fn test_cmos_status_registers() {
        let mut cmos = Cmos::new(512 * 1024 * 1024, 0);
        let mut data = [0u8];

        // Read Status Register D - should have VRT bit set
        cmos.pio_write(PioAddress(0x70), 0, &[RTC_REG_D]);
        cmos.pio_read(PioAddress(0x70), 1, &mut data);
        assert_eq!(data[0] & RTC_REG_D_VRT, RTC_REG_D_VRT);

        // Read Status Register B - should have 24-hour mode
        cmos.pio_write(PioAddress(0x70), 0, &[RTC_REG_B]);
        cmos.pio_read(PioAddress(0x70), 1, &mut data);
        assert_eq!(data[0] & RTC_REG_B_24_HOUR_MODE, RTC_REG_B_24_HOUR_MODE);
    }

    #[test]
    fn test_cmos_time_read() {
        let mut cmos = Cmos::new(512 * 1024 * 1024, 0);
        let mut data = [0u8];

        // Read seconds - should be a valid BCD value (0x00-0x59)
        cmos.pio_write(PioAddress(0x70), 0, &[RTC_REG_SEC]);
        cmos.pio_read(PioAddress(0x70), 1, &mut data);
        // BCD values have max nibble values of 5 for tens, 9 for units
        assert!(data[0] <= 0x59);

        // Read month - should be 0x01-0x12 in BCD
        cmos.pio_write(PioAddress(0x70), 0, &[RTC_REG_MONTH]);
        cmos.pio_read(PioAddress(0x70), 1, &mut data);
        assert!(data[0] >= 0x01 && data[0] <= 0x12);
    }

    #[test]
    fn test_cmos_memory_size() {
        // Test with 512 MB below 4G, 1 GB above 4G
        let cmos = Cmos::new(512 * 1024 * 1024, 1024 * 1024 * 1024);

        // Extended memory 16MB-4GB in 64KB units at 0x34-0x35
        // (512 MB - 16 MB) / 64 KB = 7936 = 0x1F00
        let ext_mem = (cmos.data[0x34] as u16) | ((cmos.data[0x35] as u16) << 8);
        assert_eq!(ext_mem, 0x1F00);

        // High memory in 64KB units at 0x5b-0x5d
        // 1 GB / 64 KB = 16384 = 0x4000
        let high_mem = (cmos.data[0x5b] as u32)
            | ((cmos.data[0x5c] as u32) << 8)
            | ((cmos.data[0x5d] as u32) << 16);
        assert_eq!(high_mem, 0x4000);
    }
}
