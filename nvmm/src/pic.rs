// Basic 8259A PIC Implementation

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Ready,
    _Icw1,
    Icw2,
    Icw3,
    Icw4,
}

#[derive(Clone, Debug)]
pub struct Pic {
    // Registers
    irr: u8, // Interrupt Request Register
    isr: u8, // In-Service Register
    imr: u8, // Interrupt Mask Register

    // Configuration
    vector_offset: u8,
    _is_master: bool,

    // Init State Machine
    state: State,
    init_target: bool, // Are we initializing?

    // Read Select
    read_isr: bool,
    // Reference to other PIC? No, typically handled by bus logic
    // We just expose input lines and output
}

impl Pic {
    pub fn new(is_master: bool) -> Self {
        Self {
            irr: 0,
            isr: 0,
            imr: 0, // All allowed initially? Or masked? Usually 0.
            vector_offset: if is_master { 0x8 } else { 0x70 }, // Defaults
            _is_master: is_master,
            state: State::Ready,
            init_target: false,
            read_isr: false,
        }
    }

    pub fn set_irq(&mut self, irq: u8, level: bool) {
        if irq > 7 {
            return;
        }
        let mask = 1 << irq;
        if level {
            self.irr |= mask;
        } else {
            self.irr &= !mask;
        }
    }

    pub fn get_interrupt(&self) -> Option<u8> {
        // Find highest priority request in IRR that is NOT masked by IMR and NOT currently in ISR
        // Simple priority: 0 is highest

        // Masked requests
        let masked_irr = self.irr & !self.imr;

        if masked_irr == 0 {
            return None;
        }

        // Find LSB
        for i in 0..8 {
            if (masked_irr & (1 << i)) != 0 {
                // Check if higher priority is in service?
                // For simplicity, we assume fully nested mode:
                // Any IRQ can interrupt distinct lower priority, but here we just check if *any* is serving?
                // Actually 8259A prevents *same or lower* priority from interrupting.
                // We simplify: If ISR is 0, we can interrupt.
                // If ISR is NOT 0, we can only interrupt if priority > current isr?
                // Let's implement full priority later.
                // For Linux boot, simplest behavior: return first found.
                return Some(self.vector_offset + i);
            }
        }
        None
    }

    pub fn ack_interrupt(&mut self) -> Option<u8> {
        // Same as get, but moves to ISR
        let masked_irr = self.irr & !self.imr;
        if masked_irr == 0 {
            return None;
        }

        for i in 0..8 {
            let mask = 1 << i;
            if (masked_irr & mask) != 0 {
                // Found it.
                // Note: Usually IRR cleared if edge triggered, kept if level.
                // We assume Edge for now for simplicity or handle logic outside.
                // If PIT is edge, we should clear IRR bit here?
                // Or caller clears?
                // 8259 spec: IRR bit is reset when interrupt is acknowledged (INTA sequence).
                self.irr &= !mask;
                self.isr |= mask;
                return Some(self.vector_offset + i);
            }
        }
        None
    }

    pub fn io_write(&mut self, addr: u8, val: u8) {
        // Addr 0 = Command (0x20/0xA0), Addr 1 = Data (0x21/0xA1)
        if addr == 0 {
            // Command Port
            if (val & 0x10) != 0 {
                // ICW1 (Init)
                self.imr = 0; // Clear mask? Or preserve? Usually clear.
                self.isr = 0;
                self.irr = 0;
                self.vector_offset = 0; // Will be set in ICW2
                self.state = State::Icw2;
                self.init_target = true; // Waiting for subsequent bytes

            // ICW1 parsing:
            // Bit 0: ICW4 needed?
            // Bit 1: Single?
            // Bit 3: Level/Edge?
            } else if (val & 0x08) != 0 {
                // OCW3
                if (val & 0x02) != 0 {
                    // Read Register Command
                    self.read_isr = (val & 0x01) != 0; // 0=IRR, 1=ISR
                }
            } else {
                // OCW2
                let op = val & 0xE0;
                if op == 0x20 {
                    // Non-Specific EOI
                    // Clear highest priority bit in ISR
                    if self.isr != 0 {
                        // Find LSB (Highest prio)
                        for i in 0..8 {
                            if (self.isr & (1 << i)) != 0 {
                                self.isr &= !(1 << i);
                                break;
                            }
                        }
                    }
                } else if op == 0x60 {
                    // Specific EOI
                    let irq = val & 0x07;
                    self.isr &= !(1 << irq);
                }
            }
        } else {
            // Data Port
            match self.state {
                State::Icw2 => {
                    self.vector_offset = val & 0xF8; // Bits 3-7 used
                    // Move to ICW3 or ICW4
                    // We assume we are in Cascade mode?
                    // Simplified: Go to ICW3 if master?
                    // Let's assume standard sequence ICW1 -> 2 -> 3 -> 4
                    self.state = State::Icw3;
                }
                State::Icw3 => {
                    // Master: Bit mask of slaves. Slave: ID.
                    self.state = State::Icw4;
                }
                State::Icw4 => {
                    // Mode. 8086 etc.
                    self.state = State::Ready;
                }
                State::Ready => {
                    // OCW1: Read/Write IMR
                    self.imr = val;
                }
                _ => {} // Should not happen
            }
        }
    }

    pub fn io_read(&mut self, addr: u8) -> u8 {
        if addr == 0 {
            // Read IRR or ISR
            if self.read_isr { self.isr } else { self.irr }
        } else {
            // Read IMR
            self.imr
        }
    }
}

use vm_device::MutDevicePio;
use vm_device::bus::PioAddress;

impl MutDevicePio for Pic {
    fn pio_read(&mut self, _base: PioAddress, offset: u16, _data: &mut [u8]) {
        if _data.len() == 1 {
            _data[0] = self.io_read(offset as u8);
        }
    }

    fn pio_write(&mut self, _base: PioAddress, offset: u16, data: &[u8]) {
        if data.len() == 1 {
            self.io_write(offset as u8, data[0]);
        }
    }
}
