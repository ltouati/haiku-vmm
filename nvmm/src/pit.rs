use crate::io_bus::IoDevice;
use std::time::Instant;

const FREQUENCY: u64 = 1193182; // 1.193182 MHz
const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

#[derive(Clone, Copy, PartialEq, Debug)]
enum RwState {
    Lsb = 1,
    Msb = 2,
    Word0 = 3, // LSB first
    Word1 = 4, // MSB next
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Channel {
    count: u32, // 32-bit to store strict value, but 8254 is 16-bit
    latched_count: u16,
    count_latched: u8, // 0 = none, or RwState value
    status_latched: bool,
    status: u8,

    read_state: RwState,
    write_state: RwState,
    write_latch: u8,

    rw_mode: u8, // 1=LSB, 2=MSB, 3=Word
    mode: u8,    // 0-5
    bcd: u8,     // 0=Binary, 1=BCD
    gate: bool,

    count_load_time: Instant,
    prev_tick_count: u64,
}

impl Channel {
    fn new() -> Self {
        Self {
            count: 0, // Default 0x10000 effectively
            latched_count: 0,
            count_latched: 0,
            status_latched: false,
            status: 0,
            read_state: RwState::Word0, // Default? QEMU doesn't explicitly init, assumes 0
            write_state: RwState::Word0,
            write_latch: 0,
            rw_mode: 3, // Default to Word
            mode: 3,    // Default to Mode 3
            bcd: 0,
            gate: true, // Ch 0/1 usually always enabled, Ch 2 controlled by port 0x61
            count_load_time: Instant::now(),
            prev_tick_count: 0,
        }
    }

    fn get_count(&self) -> u16 {
        let elapsed_ns = self.count_load_time.elapsed().as_nanos() as u64;
        let d = (elapsed_ns * FREQUENCY) / NANOSECONDS_PER_SECOND;

        let count = self.count as u64;
        let counter_val = match self.mode {
            0 | 1 | 4 | 5 => {
                // Mode 0: Interrupt on Terminal Count
                // Counter = (count - d) & 0xffff
                count.wrapping_sub(d) & 0xffff
            }
            3 => {
                // Mode 3: Square Wave Generator
                // QEMU: counter = s->count - ((2 * d) % s->count)
                // Avoid divide by zero
                if count != 0 {
                    count.wrapping_sub((2 * d) % count)
                } else {
                    0
                }
            }
            _ => {
                // Mode 2: Rate Generator
                // QEMU: counter = s->count - (d % s->count)
                if count != 0 {
                    count.wrapping_sub(d % count)
                } else {
                    0
                }
            }
        };
        counter_val as u16
    }

    pub fn get_out(&self) -> bool {
        let elapsed_ns = self.count_load_time.elapsed().as_nanos() as u64;
        let d = (elapsed_ns * FREQUENCY) / NANOSECONDS_PER_SECOND;
        let count = self.count as u64;

        match self.mode {
            0 | 1 => d >= count,
            2 => {
                if count != 0 {
                    (d % count) == 0 && d != 0
                } else {
                    false
                }
            }
            3 => {
                if count != 0 {
                    (d % count) < ((count + 1) >> 1)
                } else {
                    false
                }
            }
            4 | 5 => d == count,
            _ => false,
        }
    }

    pub fn update_irq(&mut self) -> u64 {
        let elapsed_ns = self.count_load_time.elapsed().as_nanos() as u64;
        let d = (elapsed_ns * FREQUENCY) / NANOSECONDS_PER_SECOND;
        let count = self.count as u64;
        if count == 0 {
            return 0;
        }

        let total_irqs = match self.mode {
            0 | 1 => {
                if d >= count {
                    1
                } else {
                    0
                }
            }
            2 | 3 => {
                if d > 0 {
                    d / count
                } else {
                    0
                }
            }
            _ => 0,
        };

        if total_irqs > self.prev_tick_count {
            let diff = total_irqs - self.prev_tick_count;
            self.prev_tick_count = total_irqs;
            diff
        } else {
            0
        }
    }

    fn load_count(&mut self, val: u16) {
        let val32 = if val == 0 { 0x10000 } else { val as u32 };
        self.count = val32;
        self.count_load_time = Instant::now();
        self.prev_tick_count = 0;
    }

    fn latch_count(&mut self) {
        if self.count_latched == 0 {
            self.latched_count = self.get_count();
            // In QEMU: s->count_latched = s->rw_mode
            // Map rw_mode (1,2,3) to RwState (1,2,3 - Word0)
            self.count_latched = match self.rw_mode {
                1 => 1, // Lsb
                2 => 2, // Msb
                3 => 3, // Word0
                _ => 3,
            };
        }
    }
}

pub struct Pit {
    channel0: Channel,
    channel1: Channel,
    channel2: Channel,
    port61: u8,
}

impl Default for Pit {
    fn default() -> Self {
        Self::new()
    }
}

impl Pit {
    pub fn new() -> Self {
        let mut p = Pit {
            channel0: Channel::new(),
            channel1: Channel::new(),
            channel2: Channel::new(),
            port61: 0,
        };
        // Explicitly set Gate 2 to false initially? Or match port 61 default?
        // Default port61 is usually 0, so gate is disabled.
        p.channel2.gate = false;
        p
    }

    pub fn get_irq(&self) -> bool {
        self.channel0.get_out()
    }

    pub fn update_irq(&mut self) -> u64 {
        self.channel0.update_irq()
    }

    pub fn read(&mut self, port: u16) -> u8 {
        if port == 0x61 {
            let mut val = self.port61;
            // Clear dynamic bits
            val &= !0x30;

            // Bit 5: Timer 2 Output
            if self.channel2.get_out() {
                val |= 0x20;
            }

            // Bit 4: Refresh Detect Toggle
            // Toggle every read to simulate refresh cycles
            self.port61 ^= 0x10;
            if (self.port61 & 0x10) != 0 {
                val |= 0x10;
            }

            return val;
        }

        // Map 0x40-0x42 to channel
        let channel_idx = (port & 3) as usize;
        let s = match channel_idx {
            0 => &mut self.channel0,
            1 => &mut self.channel1,
            2 => &mut self.channel2,
            _ => return 0,
        };

        if s.status_latched {
            s.status_latched = false;
            return s.status;
        }

        if s.count_latched != 0 {
            // Read latched value
            match s.count_latched {
                1 => {
                    // RwState::Lsb
                    s.count_latched = 0;
                    return (s.latched_count & 0xff) as u8;
                }
                2 => {
                    // RwState::Msb
                    s.count_latched = 0;
                    return (s.latched_count >> 8) as u8;
                }
                3 => {
                    // RwState::Word0
                    s.count_latched = 4; // Move to Word1 (RW_STATE_WORD1)
                    return (s.latched_count & 0xff) as u8;
                }
                4 => {
                    // RwState::Word1
                    s.count_latched = 0; // Done
                    return (s.latched_count >> 8) as u8;
                }
                _ => return 0,
            }
        }

        // Read Live Value
        let count = s.get_count();
        match s.read_state {
            RwState::Lsb => (count & 0xff) as u8,
            RwState::Msb => (count >> 8) as u8,
            RwState::Word0 => {
                s.read_state = RwState::Word1;
                (count & 0xff) as u8
            }
            RwState::Word1 => {
                s.read_state = RwState::Word0;
                (count >> 8) as u8
            }
        }
    }

    pub fn write(&mut self, port: u16, val: u8) {
        if port == 0x61 {
            // Speaker control
            self.port61 = val;
            // Gate 2 is Bit 0
            let valid_gate = (val & 1) != 0;
            if self.channel2.gate != valid_gate {
                // Gate changed
                self.channel2.gate = valid_gate;
                if valid_gate {
                    // Restart counting on rising edge
                    self.channel2.count_load_time = Instant::now();
                }
            }
            return;
        }

        let addr = port & 3;
        if addr == 3 {
            // Mode Control Register
            let channel_idx = (val >> 6) & 3;

            if channel_idx == 3 {
                // Read-Back Command
                for i in 0..3 {
                    let s = match i {
                        0 => &mut self.channel0,
                        1 => &mut self.channel1,
                        2 => &mut self.channel2,
                        _ => unreachable!(),
                    };

                    // Check if this channel is selected in the command (Bits 1, 2, 3 corresponding to ch 0, 1, 2?)
                    // QEMU: if (val & (2 << channel)) { ... }
                    // Note: QEMU loop: channel = 0..3. (2 << 0) = 2 (bit 1). (2 << 1) = 4 (bit 2). Yes.
                    if (val & (2 << i)) != 0 {
                        // Bit 5 = !Latch Count
                        if (val & 0x20) == 0 {
                            s.latch_count();
                        }
                        // Bit 4 = !Latch Status
                        if (val & 0x10) == 0 && !s.status_latched {
                            // Status Byte format:
                            // 7: OUT pin state
                            // 6: Null Count (not impl)
                            // 5-4: RW Mode
                            // 3-1: Mode
                            // 0: BCD
                            let out = if s.get_out() { 1 } else { 0 };
                            s.status = (out << 7) | (s.rw_mode << 4) | (s.mode << 1) | s.bcd;
                            s.status_latched = true;
                        }
                    }
                }
            } else {
                // Regular Mode Command
                let s = match channel_idx {
                    0 => &mut self.channel0,
                    1 => &mut self.channel1,
                    2 => &mut self.channel2,
                    _ => return, // Should not happen
                };

                let access = (val >> 4) & 3;
                if access == 0 {
                    // Latch Count Command for specific channel
                    s.latch_count();
                } else {
                    // Set Mode
                    s.rw_mode = access;
                    // Set read/write state based on access mode
                    s.read_state = match access {
                        1 => RwState::Lsb,
                        2 => RwState::Msb,
                        3 => RwState::Word0,
                        _ => RwState::Word0,
                    };
                    s.write_state = s.read_state;

                    s.mode = (val >> 1) & 7;
                    s.bcd = val & 1;
                }
            }
        } else {
            // Write to channel data port
            let s = match addr {
                0 => &mut self.channel0,
                1 => &mut self.channel1,
                2 => &mut self.channel2,
                _ => return,
            };

            match s.write_state {
                RwState::Lsb => {
                    s.load_count(val as u16);
                }
                RwState::Msb => {
                    s.load_count((val as u16) << 8);
                }
                RwState::Word0 => {
                    s.write_latch = val;
                    s.write_state = RwState::Word1;
                }
                RwState::Word1 => {
                    s.load_count((s.write_latch as u16) | ((val as u16) << 8));
                    s.write_state = RwState::Word0;
                }
            }
        }
    }
}

impl IoDevice for Pit {
    fn read(&mut self, base: u16, _offset: u16) -> u8 {
        let port = base + _offset;
        self.read(port)
    }

    fn write(&mut self, base: u16, _offset: u16, val: u8) {
        let port = base + _offset;
        self.write(port, val);
    }
}
