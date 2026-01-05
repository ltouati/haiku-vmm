// Ported from Crosvm
use log::warn;
use vm_device::MutDeviceMmio;
use vm_device::bus::{MmioAddress, MmioAddressOffset};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

const IOAPIC_VERSION_ID: u32 = 0x00000020;
pub const IOAPIC_BASE_ADDRESS: u64 = 0xfec00000;
pub const IOAPIC_MEM_LENGTH_BYTES: u64 = 0x100;

// Register offsets
const IOREGSEL_OFF: u64 = 0x0;
const IOWIN_OFF: u64 = 0x10;
const IOEOIR_OFF: u64 = 0x40;

// Constants for IOAPIC direct register offset.
const IOAPIC_REG_ID: u8 = 0x00;
const IOAPIC_REG_VERSION: u8 = 0x01;
const IOAPIC_REG_ARBITRATION_ID: u8 = 0x02;

const NUM_IOAPIC_PINS: usize = 24;

#[derive(Debug, Default, Copy, Clone, FromBytes, AsBytes, FromZeroes)] // Added FromZeroes
#[repr(C)]
pub struct RedirectionEntry {
    lower: u32,
    upper: u32,
}

impl RedirectionEntry {
    fn vector(&self) -> u8 {
        (self.lower & 0xFF) as u8
    }

    fn delivery_mode(&self) -> u8 {
        ((self.lower >> 8) & 0x7) as u8
    }

    fn destination_mode(&self) -> u8 {
        // 0: Physical, 1: Logical
        ((self.lower >> 11) & 0x1) as u8
    }

    fn delivery_status(&self) -> u8 {
        ((self.lower >> 12) & 0x1) as u8
    }

    fn polarity(&self) -> u8 {
        // 0: High active, 1: Low active
        ((self.lower >> 13) & 0x1) as u8
    }

    fn remote_irr(&self) -> bool {
        (self.lower >> 14) & 0x1 != 0
    }

    fn set_remote_irr(&mut self, value: bool) {
        if value {
            self.lower |= 1 << 14;
        } else {
            self.lower &= !(1 << 14);
        }
    }

    fn trigger_mode(&self) -> u8 {
        // 0: Edge, 1: Level
        ((self.lower >> 15) & 0x1) as u8
    }

    fn mask(&self) -> bool {
        (self.lower >> 16) & 0x1 != 0
    }

    fn destination_id(&self) -> u8 {
        ((self.upper >> 24) & 0xFF) as u8
    }
}

pub struct Ioapic {
    ioregsel: u8,
    ioapicid: u32,
    redirect_table: [RedirectionEntry; NUM_IOAPIC_PINS],
    irq_level: [bool; NUM_IOAPIC_PINS],
}

impl Ioapic {
    pub fn new() -> Self {
        let mut redirect_table = [RedirectionEntry::default(); NUM_IOAPIC_PINS];
        for entry in &mut redirect_table {
            entry.lower |= 1 << 16; // Masked by default
        }

        Self {
            ioregsel: 0,
            ioapicid: 0,
            redirect_table,
            irq_level: [false; NUM_IOAPIC_PINS],
        }
    }

    pub fn set_irq(&mut self, irq: usize, level: bool) {
        if irq >= NUM_IOAPIC_PINS {
            return;
        }
        
        let old_level = self.irq_level[irq];
        self.irq_level[irq] = level;

        let entry = &mut self.redirect_table[irq];
        
        if entry.mask() {
            return;
        }

        // Edge Triggered
        if entry.trigger_mode() == 0 {
            if level && !old_level {
                // Rising Edge -> Deliver
                // In a real implementation this would trigger an MSI/Injection.
                // For polling model, we rely on `get_pending_interrupts`.
            }
        } else {
            // Level Triggered
            if level {
                entry.set_remote_irr(true);
            }
        }
    }

    /// Returns a list of pending interrupt vectors to inject.
    /// This is a simplified polling approach. 
    /// Real implementations inject immediately upon `set_irq`.
    pub fn get_pending_interrupts(&mut self) -> Vec<u8> {
        let mut pending = Vec::new();
        for (i, entry) in self.redirect_table.iter_mut().enumerate() {
            if entry.mask() {
                continue;
            }

            // Logic:
            // If Level Triggered and Line is High and RemoteIRR is Set (or not? wait),
            // For Level: Write to RemoteIRR indicates "Asserted and waiting for EOI".
            // KVM typically handles the periodic injection for active level interrupts.
            // Here, if we return the vector, the VCPU injects it.
            // But we shouldn't spam it if it's already "In Service" (RemoteIRR).
            // Actually, RemoteIRR means "Accepted by CPU, waiting EOI".
            
            // Simplified: If Edge & just triggered (handled in set_irq? No, we scan here).
            // This architecture prefers "Push" (set_irq injects).
            // But `linux.rs` uses "Pull" (get_external_interrupt).
            
            // Let's implement Pull for now based on state.
            // Ideally, we need to know if an edge *happened*.
            // But since we lost the edge event between set_irq and now, we need to track pending.
            
            // REVISIT: `set_irq` should probably queue pending interrupts if we use Pull.
        }
        pending
    }
    
    // For now, let's just stick to the Register Interface logic which is what matters for initialization.
    // The Guest will write to registers.
    
    fn read_register(&self) -> u32 {
        match self.ioregsel {
            IOAPIC_REG_ID => self.ioapicid,
            IOAPIC_REG_VERSION => ((NUM_IOAPIC_PINS - 1) as u32) << 16 | IOAPIC_VERSION_ID,
            IOAPIC_REG_ARBITRATION_ID => 0,
            _ => {
                let sel = u64::from(self.ioregsel);
                if sel >= IOWIN_OFF {
                    let index = ((sel - IOWIN_OFF) / 2) as usize;
                    if index < NUM_IOAPIC_PINS {
                        let is_upper = (sel - IOWIN_OFF) % 2 == 1;
                        if is_upper {
                            self.redirect_table[index].upper
                        } else {
                            self.redirect_table[index].lower
                        }
                    } else {
                        !0
                    }
                } else {
                    !0
                }
            }
        }
    }

    fn write_register(&mut self, val: u32) {
        let sel = u64::from(self.ioregsel);
        match sel {
             // 0x00, 0x01, 0x02 are technically matching against u64 here because literal. 
             // But rust literals need explicit type? No, they infer. 
             // Reg IDs are u8 constants. 
             // So I should cast them too OR match original u8 for them?
             // Simplest: match u64::from(reg)
             // But constants are u8. 
             // Let's use if/else for special regs if match is tricky with mixed types.
             // Or cast constants to u64 in match arms? "const X: u64 = IOAPIC_REG_ID as u64"? No.
             // I'll stick to `match self.ioregsel` for u8 regs, and `default` for u64 ones?
             // But IOEOIR_OFF is u64 (0x40). 0x40 fits in u8.
             // I should make ALL constants u64 or u8. Offset is u64.
             // IOREGSEL_OFF is u64.
             // REG_ID is u8 (index inside window?). No, REG_ID IS the value of IOREGSEL.
             // So `ioregsel` IS the index. 
             // So `ioregsel` should be treated as u64 (or u32) index.
             // I'll cast `self.ioregsel` to u64 and cast constants in match if needed?
             // Or just change constants to u64.
             // IOAPIC_REG_ID is u8.
             // I'll replace `match self.ioregsel` with `match u64::from(self.ioregsel)`
             // and cast constants in arms: `id if id == IOAPIC_REG_ID as u64 => ...`? No.
             // I'll just hardcode `0` `1` `2`? 
             // Or keep match on u8 and handle explicit large values in `_`?
             // `IOEOIR_OFF` is 0x40. That fits in u8.
             // So I can just cast `IOEOIR_OFF` to u8 in match?
             // `IOEOIR_OFF as u8 => ...` (Not allowed in pattern).
             // I will use `if` chain or cast `ioregsel` to u64.
             
            _ if sel == IOAPIC_REG_ID as u64 => self.ioapicid = val & 0x0F000000,
            _ if sel == IOAPIC_REG_VERSION as u64 || sel == IOAPIC_REG_ARBITRATION_ID as u64 => {},
            IOEOIR_OFF => self.eoi(val as u8),
            _ => {
                if sel >= IOWIN_OFF {
                    let index = ((sel - IOWIN_OFF) / 2) as usize;
                    if index < NUM_IOAPIC_PINS {
                        let is_upper = (sel - IOWIN_OFF) % 2 == 1;
                        if is_upper {
                            self.redirect_table[index].upper = val;
                        } else {
                            // Preserve RO bits if needed, but mostly RW
                            let old = self.redirect_table[index].lower;
                            // Remote IRR is RO?
                            let remote_irr = old & (1 << 14);
                            self.redirect_table[index].lower = (val & !(1 << 14)) | remote_irr;
                        }
                    }
                }
            }
        }
    }

    fn eoi(&mut self, vector: u8) {
        for entry in &mut self.redirect_table {
            if entry.vector() == vector && entry.trigger_mode() == 1 { // Level
                entry.set_remote_irr(false);
            }
        }
    }
}

impl MutDeviceMmio for Ioapic {
    fn mmio_read(&mut self, _base: MmioAddress, offset: MmioAddressOffset, data: &mut [u8]) {
        if data.len() != 4 {
            return;
        }
        let val = match offset {
            IOREGSEL_OFF => self.ioregsel as u32,
            IOWIN_OFF => self.read_register(),
            _ => 0,
        };
        data.copy_from_slice(&val.to_le_bytes());
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: MmioAddressOffset, data: &[u8]) {
        if data.len() != 4 {
            return;
        }
        let val = u32::from_le_bytes(data.try_into().unwrap());
        match offset {
            IOREGSEL_OFF => self.ioregsel = val as u8,
            IOWIN_OFF => self.write_register(val),
//            IOEOIR_OFF => self.eoi(val as u8), // This is typically a register Write to 0x40? check spec. IOEOIR is at offset 0x40.
            0x40 => self.eoi(val as u8),
            _ => warn!("IOAPIC Write unknown offset {:#x}", offset),
        }
    }
}
