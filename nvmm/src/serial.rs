use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub struct SerialConsole {
    /// Input buffer for characters received from stdin
    buffer: Arc<Mutex<VecDeque<u8>>>,
    /// Interrupt enable register (IER) state - specific bit tracking can be added if needed
    interrupt_enable: Arc<AtomicBool>,
}

impl Default for SerialConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialConsole {
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(VecDeque::new())),
            interrupt_enable: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Read from a serial port register
    /// offset: 0-7, corresponding to 0x3F8 + offset
    pub fn read(&self, offset: u16) -> u8 {
        match offset {
            0 => {
                // RBR: Receiver Buffer Register (Read Only)
                // If DLAB=0.
                // We simplify and assume DLAB=0 for read.
                if let Ok(mut buf) = self.buffer.lock() {
                    buf.pop_front().unwrap_or(0)
                } else {
                    0
                }
            }
            1 => {
                // IER: Interrupt Enable Register
                if self.interrupt_enable.load(Ordering::Relaxed) {
                    1
                } else {
                    0
                }
            }
            2 => {
                // IIR: Interrupt Identification Register
                // 0xC1 = FIFO enabled, no interrupt pending
                0xC1
            }
            3 => {
                // LCR: Line Control Register
                0x3 // 8 bits, no parity, 1 stop bit
            }
            4 => {
                // MCR: Modem Control Register
                0
            }
            5 => {
                // LSR: Line Status Register
                let mut lsr = 0x60; // THRE | TEMT (Transmitter Empty)
                if let Ok(buf) = self.buffer.lock()
                    && !buf.is_empty()
                {
                    lsr |= 0x1; // DR (Data Ready)
                }
                lsr
            }
            6 => {
                // MSR: Modem Status Register
                0
            }
            7 => {
                // SCR: Scratch Register
                0
            }
            _ => 0,
        }
    }

    /// Write to a serial port register
    pub fn write(&self, offset: u16, val: u8) {
        match offset {
            0 => {
                // THR: Transmitter Holding Register (Write Only)
                // Output to stdout
                let _ = io::stdout().write(&[val]);
                let _ = io::stdout().flush();
            }
            1 => {
                // IER
                self.interrupt_enable
                    .store((val & 0x1) != 0, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Add data to the input buffer (called from stdin thread)
    pub fn queue_input(&self, data: &[u8]) {
        if let Ok(mut buf) = self.buffer.lock() {
            for &b in data {
                buf.push_back(b);
            }
        }
    }
}

use vm_device::MutDevicePio;
use vm_device::bus::PioAddress;

impl MutDevicePio for SerialConsole {
    fn pio_read(&mut self, _base: PioAddress, offset: u16, data: &mut [u8]) {
        if data.len() == 1 {
            data[0] = SerialConsole::read(self, offset);
        }
    }

    fn pio_write(&mut self, _base: PioAddress, offset: u16, data: &[u8]) {
        if data.len() == 1 {
            SerialConsole::write(self, offset, data[0]);
        }
    }
}
