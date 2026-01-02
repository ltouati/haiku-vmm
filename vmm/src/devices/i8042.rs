use log::{debug, error, warn};
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use vm_device::MutDevicePio;
use vm_device::bus::PioAddress;

/// Offset of the status port (port 0x64)
const OFS_STATUS: u64 = 4;
/// Offset of the data port (port 0x60)
const OFS_DATA: u64 = 0;

/// i8042 commands
const CMD_READ_CTR: u8 = 0x20; // Read control register
const CMD_WRITE_CTR: u8 = 0x60; // Write control register
const CMD_READ_OUTP: u8 = 0xD0; // Read output port
const CMD_WRITE_OUTP: u8 = 0xD1; // Write output port
const CMD_RESET_CPU: u8 = 0xFE; // Reset CPU

/// i8042 status register bits
const SB_OUT_DATA_AVAIL: u8 = 0x0001; // Data available at port 0x60
const SB_I8042_CMD_DATA: u8 = 0x0008; // i8042 expecting command parameter at port 0x60
const SB_KBD_ENABLED: u8 = 0x0010; // 1 = kbd enabled, 0 = kbd locked

/// i8042 control register bits
const CB_KBD_INT: u8 = 0x0001; // kbd interrupt enabled
const CB_POST_OK: u8 = 0x0004; // POST ok (should always be 1)

pub struct I8042Wrapper {
    status: u8,
    control: u8,
    outp: u8,
    cmd: u8,
    buf: VecDeque<u8>,
    reset_evt: Arc<AtomicBool>,
}

impl I8042Wrapper {
    pub fn new(reset_evt: Arc<AtomicBool>) -> Self {
        I8042Wrapper {
            control: CB_POST_OK | CB_KBD_INT,
            cmd: 0,
            outp: 0,
            status: SB_KBD_ENABLED,
            buf: VecDeque::new(),
            reset_evt,
        }
    }

    fn push_byte(&mut self, byte: u8) {
        self.status |= SB_OUT_DATA_AVAIL;
        self.buf.push_back(byte);
    }

    fn pop_byte(&mut self) -> Option<u8> {
        let res = self.buf.pop_front();
        if self.buf.is_empty() {
            self.status &= !SB_OUT_DATA_AVAIL;
        }
        res
    }

    fn flush_buf(&mut self) {
        self.buf.clear();
        self.status &= !SB_OUT_DATA_AVAIL;
    }
}

impl MutDevicePio for I8042Wrapper {
    fn pio_read(&mut self, base: PioAddress, _offset: u16, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }

        // Map base address to internal offset logic
        // Port 0x60 -> Data (Offset 0)
        // Port 0x64 -> Status (Offset 4)
        let offset = if base.0 == 0x64 { OFS_STATUS } else { OFS_DATA };

        match offset {
            OFS_STATUS => {
                data[0] = self.status;
                debug!("I8042 Read Status: {:#x}", self.status);
            }
            OFS_DATA => {
                data[0] = self.pop_byte().unwrap_or(0);
                debug!("I8042 Read Data: {:#x}", data[0]);
            }
            _ => {
                warn!("I8042: Invalid read at offset {}", offset);
                data[0] = 0;
            }
        }
    }

    fn pio_write(&mut self, base: PioAddress, _offset: u16, data: &[u8]) {
        if data.len() != 1 {
            return;
        }

        let val = data[0];
        let offset = if base.0 == 0x64 { OFS_STATUS } else { OFS_DATA };

        match offset {
            OFS_STATUS => {
                debug!("I8042 Write Command: {:#x}", val);
                match val {
                    CMD_RESET_CPU => {
                        error!("I8042: CPU Reset requested");
                        self.reset_evt.store(true, Ordering::SeqCst);
                    }
                    CMD_READ_CTR => {
                        self.flush_buf();
                        let ctrl = self.control;
                        self.push_byte(ctrl);
                        debug!("I8042: CMD_READ_CTR -> {:#x}", ctrl);
                    }
                    CMD_WRITE_CTR => {
                        self.flush_buf();
                        self.status |= SB_I8042_CMD_DATA;
                        self.cmd = val;
                        debug!("I8042: CMD_WRITE_CTR (Expect Data)");
                    }
                    CMD_READ_OUTP => {
                        self.flush_buf();
                        let outp = self.outp;
                        self.push_byte(outp);
                        debug!("I8042: CMD_READ_OUTP -> {:#x}", outp);
                    }
                    CMD_WRITE_OUTP => {
                        self.status |= SB_I8042_CMD_DATA;
                        self.cmd = val;
                        debug!("I8042: CMD_WRITE_OUTP (Expect Data)");
                    }
                    _ => {
                        debug!("I8042: Unknown/Ignored Command {:#x}", val);
                    }
                }
            }
            OFS_DATA => {
                debug!("I8042 Write Data: {:#x}", val);
                if (self.status & SB_I8042_CMD_DATA) != 0 {
                    match self.cmd {
                        CMD_WRITE_CTR => {
                            self.control = val;
                            debug!("I8042: Control set to {:#x}", val);
                        }
                        CMD_WRITE_OUTP => {
                            self.outp = val;
                            debug!("I8042: Output set to {:#x}", val);
                        }
                        _ => {}
                    }
                    self.status &= !SB_I8042_CMD_DATA;
                } else {
                    // Send force ack for keyboard data
                    self.flush_buf();
                    self.push_byte(0xFA);
                    debug!("I8042: Keyboard Data {:#x}, sending ACK", val);
                }
            }
            _ => warn!("I8042: Invalid write at offset {}", offset),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_i8042_reset_cmd() {
        let reset_evt = Arc::new(AtomicBool::new(false));
        let mut i8042 = I8042Wrapper::new(reset_evt.clone());
        // Send Reset Command (0xFE) to Status port
        let data = [0xFE];
        i8042.pio_write(PioAddress(0x64), 0, &data);

        assert!(reset_evt.load(Ordering::SeqCst));
    }

    #[test]
    fn test_i8042_read_ctr() {
        let reset_evt = Arc::new(AtomicBool::new(false));
        let mut i8042 = I8042Wrapper::new(reset_evt);
        // Default Control: CB_POST_OK (0x04) | CB_KBD_INT (0x01) = 0x05

        // Write CMD_READ_CTR (0x20) to Status port (0x64)
        let data = [CMD_READ_CTR];
        i8042.pio_write(PioAddress(0x64), 0, &data);

        // Read result from Data port (0x60)
        let mut res = [0];
        i8042.pio_read(PioAddress(0x60), 0, &mut res);

        assert_eq!(res[0], 0x05);
    }

    #[test]
    fn test_i8042_write_ctr() {
        let reset_evt = Arc::new(AtomicBool::new(false));
        let mut i8042 = I8042Wrapper::new(reset_evt);

        // 1. Send CMD_WRITE_CTR (0x60) to Status port (0x64)
        let data = [CMD_WRITE_CTR];
        i8042.pio_write(PioAddress(0x64), 0, &data);

        // 2. Write new Value (e.g. 0xAA) to Data port (0x60)
        let val = [0xAA];
        i8042.pio_write(PioAddress(0x60), 0, &val);

        // Verify by reading it back
        let data = [CMD_READ_CTR];
        i8042.pio_write(PioAddress(0x64), 0, &data);

        let mut res = [0];
        i8042.pio_read(PioAddress(0x60), 0, &mut res);

        assert_eq!(res[0], 0xAA);
    }
}
