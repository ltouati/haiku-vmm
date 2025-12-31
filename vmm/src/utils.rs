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
