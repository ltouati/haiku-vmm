#[derive(Debug)]
pub enum VmExit {
    Io {
        port: u16,
        is_in: bool,
        data: Vec<u8>,
        op_size: u8,
        npc: u64,
    },
    Memory {
        gpa: u64,
        is_write: bool,
        inst_len: u8,
        inst_bytes: [u8; 15],
        value: u64,
    },
    RdMsr {
        msr: u32,
        npc: u64,
    },
    WrMsr {
        msr: u32,
        val: u64,
        npc: u64,
    },
    Interrupted,
    Halted,
    Shutdown,
    Unknown(u64),
}

#[derive(Debug, Clone)]
pub enum VmAction {
    Continue,
    AdvanceRip(u64),
    WriteRegAndContinue {
        reg: usize,
        val: u64,
        advance_rip: u64,
    },
    SetRip(u64),
    WriteRegMasked {
        reg: usize,
        val: u64,
        mask: u64,
        next_rip: u64,
    },
    Shutdown,
}
