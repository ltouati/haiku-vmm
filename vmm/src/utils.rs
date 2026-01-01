use vm_memory::{Bytes, GuestAddress, GuestMemory};

/// Helper to translate GVA to GPA
pub fn translate_gva<M: GuestMemory>(mem: &M, cr3: u64, gva: u64) -> Option<u64> {
    let pml4_idx = (gva >> 39) & 0x1ff;
    let pdpt_idx = (gva >> 30) & 0x1ff;
    let pd_idx = (gva >> 21) & 0x1ff;
    let pt_idx = (gva >> 12) & 0x1ff;
    let offset = gva & 0xfff;

    let pml4_base = cr3 & !0xfff;
    let pml4_entry: u64 = mem.read_obj(GuestAddress(pml4_base + pml4_idx * 8)).ok()?;
    if pml4_entry & 1 == 0 {
        return None;
    }

    let pdpt_base = pml4_entry & 0x000f_ffff_ffff_f000;
    let pdpt_entry: u64 = mem.read_obj(GuestAddress(pdpt_base + pdpt_idx * 8)).ok()?;
    if pdpt_entry & 1 == 0 {
        return None;
    }

    if pdpt_entry & 0x80 != 0 {
        let phys = (pdpt_entry & 0x000f_ffff_c000_0000) + (gva & 0x3fff_ffff);
        return Some(phys);
    }

    let pd_base = pdpt_entry & 0x000f_ffff_ffff_f000;
    let pd_entry: u64 = mem.read_obj(GuestAddress(pd_base + pd_idx * 8)).ok()?;
    if pd_entry & 1 == 0 {
        return None;
    }

    if pd_entry & 0x80 != 0 {
        let phys = (pd_entry & 0x000f_ffff_ffe0_0000) + (gva & 0x1f_ffff);
        return Some(phys);
    }

    let pt_base = pd_entry & 0x000f_ffff_ffff_f000;
    let pt_entry: u64 = mem.read_obj(GuestAddress(pt_base + pt_idx * 8)).ok()?;
    if pt_entry & 1 == 0 {
        return None;
    }

    let phys = (pt_entry & 0x000f_ffff_ffff_f000) + offset;
    Some(phys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    #[test]
    fn test_translate_gva() {
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let cr3 = 0xa000;

        // PML4[0] -> 0xb000
        mem.write_obj(0xb000u64 | 1, GuestAddress(0xa000)).unwrap();
        // PDPTE[0] -> 0xc000
        mem.write_obj(0xc000u64 | 1, GuestAddress(0xb000)).unwrap();
        // PDE[0] -> 0xd000
        mem.write_obj(0xd000u64 | 1, GuestAddress(0xc000)).unwrap();
        // PTE[0] -> 0x5000
        mem.write_obj(0x5000u64 | 1, GuestAddress(0xd000)).unwrap();

        // GVA 0 should be GPA 0x5000
        assert_eq!(translate_gva(&mem, cr3, 0), Some(0x5000));

        // Test non-present entry
        mem.write_obj(0x5000u64, GuestAddress(0xd000)).unwrap();
        assert_eq!(translate_gva(&mem, cr3, 0), None);

        // Test huge page (2MB) in PDE
        mem.write_obj(0xc000u64 | 1, GuestAddress(0xb000)).unwrap();
        mem.write_obj(0xe00000u64 | 0x81, GuestAddress(0xc000))
            .unwrap(); // 0x81 = Present | Huge
        // GVA 0 -> GPA 0xe00000
        assert_eq!(translate_gva(&mem, cr3, 0), Some(0xe00000));
        // GVA 0x1000 -> GPA 0xe01000
        assert_eq!(translate_gva(&mem, cr3, 0x1000), Some(0xe01000));

        // Test huge page (1GB) in PDPTE
        mem.write_obj(0x40000000u64 | 0x81, GuestAddress(0xb000))
            .unwrap();
        assert_eq!(translate_gva(&mem, cr3, 0), Some(0x40000000));
        assert_eq!(translate_gva(&mem, cr3, 0x1234), Some(0x40001234));
    }
}
