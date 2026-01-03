#![allow(dead_code)]
// Ported from Crosvm (BSD License)
// Simplified for this VMM
use log::debug;
// use std::fmt;
// use std::sync::{Arc, Mutex};
use vm_device::bus::PioAddress;

const PIC_MASTER_CMD: u16 = 0x20;
const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_CMD: u16 = 0xA0;
const PIC_SLAVE_DATA: u16 = 0xA1;
const PIC_ELCR1: u16 = 0x4D0;
const PIC_ELCR2: u16 = 0x4D1;

// Initialization Control Word 1
const ICW1_ICW4: u8 = 0x01; // ICW4 needed
const ICW1_SINGLE: u8 = 0x02; // Single (cascade) mode
const ICW1_INTERVAL4: u8 = 0x04; // Call address interval 4 (8 otherwise)
const ICW1_LEVEL: u8 = 0x08; // Level triggered (edge) mode
const ICW1_INIT: u8 = 0x10; // Initialization - required!

// Initialization Control Word 4
const ICW4_8086: u8 = 0x01; // 8086/88 (MCS-80/85) mode
const ICW4_AUTO: u8 = 0x02; // Auto (normal) EOI
const ICW4_BUF_SLAVE: u8 = 0x08; // Buffered mode/slave
const ICW4_BUF_MASTER: u8 = 0x0C; // Buffered mode/master
const ICW4_SFNM: u8 = 0x10; // Special fully nested (not)

// Operation Control Word 2
const OCW2_ROTATE_AUTO: u8 = 0x80; // Rotate on non-specific EOI
const OCW2_SL: u8 = 0x40; // Specific level
const OCW2_EOI: u8 = 0x20; // End of Interrupt
const OCW2_ROTATE_SL: u8 = 0xC0; // Rotate on specific EOI

// Operation Control Word 3
const OCW3_RIS: u8 = 0x01; // Read Interrupt status
const OCW3_RR: u8 = 0x02; // Read Register
const OCW3_POLL: u8 = 0x04; // Poll command
const OCW3_SEL: u8 = 0x08; // Select register
const OCW3_SMM: u8 = 0x20; // Special Mask Mode
const OCW3_ESMM: u8 = 0x40; // Enable Special Mask Mode

#[derive(Clone, Copy, Debug, PartialEq)]
enum PicInitState {
    Icw1,
    Icw2,
    Icw3,
    Icw4,
}

#[derive(Clone, Debug)]
struct PicState {
    last_irr: u8,
    irr: u8,
    imr: u8,
    isr: u8,
    priority_add: u8,
    irq_base: u8,
    read_reg_select: bool, // false = IRR, true = ISR
    poll: bool,
    special_mask: bool,
    init_state: PicInitState,
    auto_eoi: bool,
    rotate_on_auto_eoi: bool,
    init_icw4: bool, // icw4 was requested in icw1
    use_4_byte_icw: bool,
    elcr: u8, // Edge/Level Control Register
    elcr_mask: u8,
}

impl PicState {
    fn new() -> Self {
        PicState {
            last_irr: 0,
            irr: 0,
            imr: 0,
            isr: 0,
            priority_add: 0,
            irq_base: 0,
            read_reg_select: false,
            poll: false,
            special_mask: false,
            init_state: PicInitState::Icw1,
            auto_eoi: false,
            rotate_on_auto_eoi: false,
            init_icw4: false,
            use_4_byte_icw: false,
            elcr: 0,
            elcr_mask: 0,
        }
    }

    /// Get the highest priority IRQ currently pending and not in service (or Special Mask)
    fn get_priority(&self, mask: u8) -> Option<u8> {
        if self.irr == 0 {
            return None;
        }

        // Apply Mask (IMR)
        // If Special Mask Mode is enabled, IMR does not inhibit interrupts?
        // Actually, Special Mask Mode allows enabling interrupts from a level LOWER than current ISR.
        // For standard "get interrupt", we mask.
        let active_irr = self.irr & !mask;
        if active_irr == 0 {
            return None;
        }

        // Priority rotation
        // Lowest priority is `priority_add`.
        // We search from priority_add + 1 wrapping to 7.
        for i in 0..8 {
            let irq = (self.priority_add.wrapping_add(i).wrapping_add(1)) & 7;
            if (active_irr & (1 << irq)) != 0 {
                return Some(irq);
            }
        }
        None
    }

    fn get_highest_isr(&self) -> Option<u8> {
        // Highest priority *Active* ISR bit?
        // Standard EOI clears Highest Priority *Active* ISR bit.
        // Start from priority_add + 1.
        for i in 0..8 {
            let irq = (self.priority_add.wrapping_add(i).wrapping_add(1)) & 7;
            if (self.isr & (1 << irq)) != 0 {
                return Some(irq);
            }
        }
        None
    }
}

/// Represents the Master and Slave PICs
#[derive(Clone)]
pub struct Pic {
    pics: [PicState; 2],
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PicSelect {
    Primary = 0,
    Secondary = 1,
}

impl Default for Pic {
    fn default() -> Self {
        Self::new()
    }
}

impl Pic {
    pub fn new() -> Self {
        let mut primary = PicState::new();
        primary.irq_base = 0x20; // Default Master Vector Base
        // Master ELCR Mask: IRQ 0, 1, 2, 8, 13 must be Edge (0).
        primary.elcr_mask = !((1 << 0) | (1 << 1) | (1 << 2));
        // Strict Default: All Edge used to be the norm.
        // But for VirtIO (IRQ 5), we need Level Triggered behavior to avoid lost interrupts.
        // Strict Default: All Edge used to be the norm.
        // Reverting to Edge to avoid Storm if ACK missing/slow.
        // With Edge, we need Pulse (0->1->0).
        // Our ACK handler provides the 1->0 transition.
        // So this should work and be safer than Level.
        primary.elcr = 0;

        let mut secondary = PicState::new();
        secondary.irq_base = 0x28; // Default Slave Vector Base

        // Slave ELCR Mask: IRQ 8 (0), 13 (5) must be Edge.
        // Ports 8-15 map to Bits 0-7 of Slave ELCR.
        // IRQ 8 -> Bit 0. IRQ 13 -> Bit 5.
        secondary.elcr_mask = !((1 << 0) | (1 << 5));

        Pic {
            pics: [primary, secondary],
        }
    }

    pub fn set_irq(&mut self, irq: u8, level: bool) {
        let (pic_idx, local_irq) = if irq < 8 { (0, irq) } else { (1, irq - 8) };

        let pic = &mut self.pics[pic_idx];
        let mask = 1 << local_irq;
        let last_level = (pic.last_irr & mask) != 0;

        // Edge detection logic
        // If elcr bit is 1 => Level Triggered. 0 => Edge Triggered.
        let is_level = (pic.elcr & mask) != 0;

        // Update input state used for edge detection
        if level {
            pic.last_irr |= mask;
        } else {
            pic.last_irr &= !mask;
        }

        if is_level {
            // Level triggered: IRR reflects input level
            if level {
                pic.irr |= mask;
            } else {
                pic.irr &= !mask;
            }
        } else {
            // Edge triggered: Catch rising edge
            if level && !last_level {
                pic.irr |= mask;
            }
        }

        // Cascade If Master IRQ 2 (Conn to Slave) needed?
        // In this model, we invoke get_external_interrupt to resolve cascade.
        // But if Slave attempts to raise IRQ, does it assert Master IRQ 2 line?
        // Yes. We must simulate this connection!
        if pic_idx == 1 {
            // Check if Secondary has ANY pending interrupt?
            // Or only if we JUST set one?
            // Real hardware: INT line of Slave connects to IR2 of Master.
            // If Slave sends INT, Master sees IR2.
            // We can simplify:
            // Always check secondary output when modifying it.
            // But checking priority logic here is complex.
            // Let's rely on `get_external_interrupt` to pull from Slave.
            // Wait, if Master doesn't know Slave is active, it won't check?
            // We should assert Master IRQ 2 if Slave has pending request?
            // Actually, `get_external_interrupt` checks Master.
            // If Master sees IRQ 2, it asks Slave.
            // So we MUST set Master IRQ 2 if Slave is active.

            // Re-evaluate Slave Output
            let slave_req = self.pics[1].get_priority(self.pics[1].imr);
            // If Slave has ANY request, Assert Master IRQ 2
            let slave_int = slave_req.is_some();
            self.set_irq_internal(0, 2, slave_int);
        }
    }

    // Internal helper to set IRQ without recursion loop
    fn set_irq_internal(&mut self, pic_idx: usize, irq: u8, level: bool) {
        let pic = &mut self.pics[pic_idx];
        let mask = 1 << irq;
        let last_level = (pic.last_irr & mask) != 0;
        let is_level = (pic.elcr & mask) != 0;

        if level {
            pic.last_irr |= mask;
        } else {
            pic.last_irr &= !mask;
        }

        if is_level {
            if level {
                pic.irr |= mask;
            } else {
                pic.irr &= !mask;
            }
        } else if level && !last_level {
            // Edge Rising
            pic.irr |= mask;
        }
    }

    /// Primary interface for VCPU to get Interrupt Vector
    pub fn get_external_interrupt(&mut self) -> Option<u8> {
        // 1. Get Highest Priority from Master
        // Split modify to avoid double borrow
        let (master_slice, slave_slice) = self.pics.split_at_mut(1);
        let master = &mut master_slice[0];
        let slave = &mut slave_slice[0];

        let irq = master.get_priority(master.imr)?;

        // 2. Check overlap with ISR (unless Special Mask Mode)
        if !master.special_mask && (master.isr & (1 << irq)) != 0 {
            // Priority blocked by ISR.
            // We revert the check to avoid Timer Hangs (guest missing EOI/dropped inject).
            // return None;
        }

        // 3. Ack the Interrupt (Set ISR, Clear IRR)
        master.isr |= 1 << irq; // Set In-Service
        if (master.elcr & (1 << irq)) == 0 {
            // Edge triggered: Clear IRR
            master.irr &= !(1 << irq);
        }

        // 4. Resolve Vector
        // Is it the Cascade IRQ (IRQ 2)?
        if irq == 2 {
            // Slave Interrupt
            if let Some(slave_irq) = slave.get_priority(slave.imr) {
                // Ack Slave
                slave.isr |= 1 << slave_irq;
                if (slave.elcr & (1 << slave_irq)) == 0 {
                    slave.irr &= !(1 << slave_irq);
                }
                Some(slave.irq_base.wrapping_add(slave_irq))
            } else {
                // Spurious Slave?
                Some(master.irq_base.wrapping_add(irq))
            }
        } else {
            Some(master.irq_base.wrapping_add(irq))
        }
    }

    // PIO Read/Write Wrappers
    pub fn pio_read(&mut self, port: u16, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }
        let val = match port {
            PIC_MASTER_CMD => self.pic_read_command(PicSelect::Primary),
            PIC_MASTER_DATA => self.pic_read_data(PicSelect::Primary),
            PIC_SLAVE_CMD => self.pic_read_command(PicSelect::Secondary),
            PIC_SLAVE_DATA => self.pic_read_data(PicSelect::Secondary),
            PIC_ELCR1 => self.elcr_read(PicSelect::Primary),
            PIC_ELCR2 => self.elcr_read(PicSelect::Secondary),
            _ => 0xFF,
        };
        data[0] = val;
    }

    pub fn pio_write(&mut self, port: u16, data: &[u8]) {
        if data.len() != 1 {
            return;
        }
        let val = data[0];
        match port {
            PIC_MASTER_CMD => self.pic_write_command(PicSelect::Primary, val),
            PIC_MASTER_DATA => self.pic_write_data(PicSelect::Primary, val),
            PIC_SLAVE_CMD => self.pic_write_command(PicSelect::Secondary, val),
            PIC_SLAVE_DATA => self.pic_write_data(PicSelect::Secondary, val),
            PIC_ELCR1 => self.elcr_write(PicSelect::Primary, val),
            PIC_ELCR2 => self.elcr_write(PicSelect::Secondary, val),
            _ => {}
        }
    }

    fn pic_read_command(&self, select: PicSelect) -> u8 {
        let pic = &self.pics[select as usize];
        if pic.read_reg_select {
            pic.isr
        } else {
            pic.irr
        }
    }

    fn pic_read_data(&self, select: PicSelect) -> u8 {
        let pic = &self.pics[select as usize];
        pic.imr
    }

    fn elcr_read(&self, select: PicSelect) -> u8 {
        let pic = &self.pics[select as usize];
        pic.elcr
    }

    fn elcr_write(&mut self, select: PicSelect, val: u8) {
        let pic = &mut self.pics[select as usize];
        debug!("PIC {:?} ELCR Write: {:#x}", select, val);
        pic.elcr = val & pic.elcr_mask;
    }

    fn pic_write_command(&mut self, select: PicSelect, val: u8) {
        let pic = &mut self.pics[select as usize];
        if (val & 0x10) != 0 {
            // ICW1
            pic.init_state = PicInitState::Icw2;
            pic.imr = 0;
            pic.isr = 0;
            pic.irr = 0; // Clear IRR on init? Usually preserved?
            pic.priority_add = 7; // Reset priority
            pic.read_reg_select = false; // Reset read select
            pic.init_icw4 = (val & 0x01) != 0;
            // Trace
            debug!("PIC {:?} Init ICW1: {:#x}", select, val);
        } else if (val & 0x08) != 0 {
            // OCW3
            if (val & OCW3_POLL) != 0 {
                pic.poll = true;
                // TODO: Handle poll command immediately?
            }
            if (val & OCW3_RR) != 0 {
                pic.read_reg_select = (val & OCW3_RIS) != 0;
            }
            if (val & OCW3_ESMM) != 0 {
                pic.special_mask = (val & OCW3_SMM) != 0;
            }
        } else {
            // OCW2
            // Priority rotation and EOI
            let priority = val & 0x7;
            match val & 0xE0 {
                0x20 => {
                    // Non-specific EOI
                    // Clear highest priority ISR bit
                    if let Some(irq) = pic.get_highest_isr() {
                        pic.isr &= !(1 << irq);
                    }
                }
                0x60 => {
                    // Specific EOI
                    pic.isr &= !(1 << priority);
                }
                0xA0 => {
                    // Rotate on Non-Specific EOI
                    if let Some(irq) = pic.get_highest_isr() {
                        pic.isr &= !(1 << irq);
                        pic.priority_add = irq;
                    }
                }
                _ => {}
            }
        }
    }

    fn pic_write_data(&mut self, select: PicSelect, val: u8) {
        let pic = &mut self.pics[select as usize];
        match pic.init_state {
            PicInitState::Icw1 => {
                // Not init state: OCW1 (IMR Write)
                pic.imr = val;
                debug!("PIC {:?} IMR update: {:#x}", select, val);
            }
            PicInitState::Icw2 => {
                pic.irq_base = val & 0xF8;
                pic.init_state = PicInitState::Icw3;
                debug!("PIC {:?} Base update: {:#x}", select, pic.irq_base);
            }
            PicInitState::Icw3 => {
                // Cascade info - ignored for simplified model
                if pic.init_icw4 {
                    pic.init_state = PicInitState::Icw4;
                } else {
                    pic.init_state = PicInitState::Icw1;
                }
            }
            PicInitState::Icw4 => {
                pic.auto_eoi = (val & ICW4_AUTO) != 0;
                pic.init_state = PicInitState::Icw1;
            }
        }
    }
}

// Implement MutDevicePio for Bus (Optional or unused if manually routed)
use vm_device::MutDevicePio;
impl MutDevicePio for Pic {
    fn pio_read(&mut self, base: PioAddress, offset: u16, data: &mut [u8]) {
        // Mapping:
        // 0x20 -> Cmd, 0x21 -> Data
        // 0xA0 -> Cmd, 0xA1 -> Data
        // 0x4D0 -> ELCR1, 0x4D1 -> ELCR2
        // We assume caller routes correctly.
        // But `base` + `offset` allows flexible routing.
        let port = (base.0 as u64) + (offset as u64);

        self.pio_read(port as u16, data);
    }

    fn pio_write(&mut self, base: PioAddress, offset: u16, data: &[u8]) {
        let port = (base.0 as u64) + (offset as u64);

        self.pio_write(port as u16, data);
    }
}
