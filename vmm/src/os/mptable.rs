#![allow(dead_code)]
use std::mem;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

// MP Floating Pointer Structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes)]
struct MpFloatingPointer {
    signature: [u8; 4], // "_MP_"
    phys_addr: u32,     // Address of MP Config Table
    length: u8,         // Length in 16-byte paragraphs
    spec_rev: u8,       // 0x04 for 1.4
    checksum: u8,
    feature1: u8, // MP System Config Type (0 for config table)
    feature2: u8, // IMCR?
    reserved: [u8; 3],
}
unsafe impl ByteValued for MpFloatingPointer {}

// MP Configuration Table Header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes)]
struct MpConfigTable {
    signature: [u8; 4], // "PCMP"
    length: u16,        // Base table length
    spec_rev: u8,       // 0x04
    checksum: u8,
    oem_id: [u8; 8],
    product_id: [u8; 12],
    oem_table_ptr: u32,
    oem_table_size: u16,
    entry_count: u16,
    lapic_addr: u32, // 0xFEE00000
    extended_table_len: u16,
    extended_table_checksum: u8,
    reserved: u8,
}
unsafe impl ByteValued for MpConfigTable {}

// Processor Entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes)]
struct MpProcessorEntry {
    type_: u8, // 0
    lapic_id: u8,
    lapic_ver: u8,
    cpu_flags: u8,      // Bit 0: Enabled, Bit 1: BSP
    cpu_signature: u32, // Stepping, Model, Family
    feature_flags: u32,
    reserved: [u8; 8],
}
unsafe impl ByteValued for MpProcessorEntry {}

// Bus Entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes)]
struct MpBusEntry {
    type_: u8, // 1
    bus_id: u8,
    bus_type: [u8; 6], // "ISA   "
}
unsafe impl ByteValued for MpBusEntry {}

// // IO APIC Entry
// #[repr(C, packed)]
// #[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes)]
// struct MpIoApicEntry {
//     type_: u8,      // 2
//     ioapic_id: u8,
//     ioapic_ver: u8,
//     ioapic_flags: u8, // Bit 0: Enabled
//     ioapic_addr: u32,
// }
// unsafe impl ByteValued for MpIoApicEntry {}
//
// // Interrupt Assignment Entry
// #[repr(C, packed)]
// #[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes)]
// struct MpIrqEntry {
//     type_: u8,      // 3 (IO INT) or 4 (Local INT)
//     irq_type: u8,   // 0: INT, 1: NMI, 2: SMI, 3: ExtINT
//     po_el: u16,     // Polarity/Trigger
//     source_bus_id: u8,
//     source_bus_irq: u8,
//     dest_ioapic_id: u8,
//     dest_ioapic_intin: u8,
// }
// unsafe impl ByteValued for MpIrqEntry {}

fn compute_checksum<T: AsBytes>(data: &T, field_checksum: u8) -> u8 {
    let mut sum: u8 = 0;
    for b in data.as_bytes() {
        sum = sum.wrapping_add(*b);
    }
    // Subtract valid checksum field itself if included?
    // Usually checksum is calculated such that sum of all bytes + checksum = 0.
    // So target = 0 - (sum of other bytes).
    // Here we just sum all bytes.
    // To make it valid: final_checksum = 0 - sum_without_checksum_field.
    // But struct has checksum field.
    // We assume field is 0 during sum.
    sum = sum.wrapping_sub(field_checksum);
    (0u8).wrapping_sub(sum)
}

fn compute_checksum_slice(data: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for b in data {
        sum = sum.wrapping_add(*b);
    }
    (0u8).wrapping_sub(sum)
}

pub fn write_mp_table(mem: &GuestMemoryMmap, base_addr: u64, cpus: u8) -> anyhow::Result<()> {
    let mpfps_addr = GuestAddress(base_addr);
    let config_addr_offset = 16; // FPS is 16 bytes
    let config_addr = GuestAddress(base_addr + config_addr_offset as u64);

    // 1. Prepare Config Table Header
    let mut config = MpConfigTable {
        signature: *b"PCMP",
        length: 0, // Fill later
        spec_rev: 4,
        checksum: 0,
        oem_id: *b"HAIKU   ",
        product_id: *b"VMM         ",
        oem_table_ptr: 0,
        oem_table_size: 0,
        entry_count: 0,
        lapic_addr: 0xFEE00000,
        extended_table_len: 0,
        extended_table_checksum: 0,
        reserved: 0,
    };

    let mut entries_data = Vec::new();

    // 2. Add Processor Entries
    for i in 0..cpus {
        let entry = MpProcessorEntry {
            type_: 0,
            lapic_id: i,
            lapic_ver: 0x14,
            cpu_flags: if i == 0 { 3 } else { 1 }, // Enabled | BSP (if 0)
            cpu_signature: 0x306C3,                // Haswell
            feature_flags: 0xbfebfbff,             // From CPUID 1
            reserved: [0; 8],
        };
        entries_data.extend_from_slice(entry.as_bytes());
        config.entry_count += 1;
    }

    // 3. Add Bus Entry (ISA)
    let bus_entry = MpBusEntry {
        type_: 1,
        bus_id: 0,
        bus_type: *b"ISA   ",
    };
    entries_data.extend_from_slice(bus_entry.as_bytes());
    config.entry_count += 1;

    // 4. Finalize Config Table
    config.length = (mem::size_of::<MpConfigTable>() + entries_data.len()) as u16;

    // Checksum Config Table
    let mut sum: u8 = 0;
    sum = sum.wrapping_add(compute_checksum(&config, 0));
    sum = sum.wrapping_add(compute_checksum_slice(&entries_data));
    config.checksum = (0u8).wrapping_sub(sum); // Wait, logic above was 0-sum.
    // Correct way: Sum of all bytes mod 256 = 0.
    // sum_header (with 0 checksum) + sum_entries + X = 0
    // X = -(sum_header + sum_entries)
    // My compute_checksum returns -sum.
    // So config.checksum = -( (sum header without checksum) + sum_entries )

    // Let's redo checksum calculation simply
    let header_bytes = config.as_bytes();
    let mut csum: u8 = 0;
    for (i, b) in header_bytes.iter().enumerate() {
        if i != 7 {
            // Skip checksum field at offset 7
            csum = csum.wrapping_add(*b);
        }
    }
    for b in &entries_data {
        csum = csum.wrapping_add(*b);
    }
    config.checksum = (0u8).wrapping_sub(csum);

    // 5. Write Config Table
    mem.write_obj(config, config_addr)?;
    mem.write_slice(
        &entries_data,
        config_addr.unchecked_add(mem::size_of::<MpConfigTable>() as u64),
    )?;

    // 6. Prepare and Write MPFPS
    let mut mpfps = MpFloatingPointer {
        signature: *b"_MP_",
        phys_addr: config_addr.0 as u32,
        length: 1, // 16 bytes = 1 paragraph
        spec_rev: 4,
        checksum: 0,
        feature1: 0,
        feature2: 0,
        reserved: [0; 3],
    };

    // Checksum MPFPS
    let fps_bytes = mpfps.as_bytes();
    let mut fps_sum: u8 = 0;
    for (i, b) in fps_bytes.iter().enumerate() {
        if i != 10 {
            // Skip checksum field at offset 10
            fps_sum = fps_sum.wrapping_add(*b);
        }
    }
    mpfps.checksum = (0u8).wrapping_sub(fps_sum);

    mem.write_obj(mpfps, mpfps_addr)?;

    Ok(())
}
