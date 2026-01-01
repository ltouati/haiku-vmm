use crate::devices::pic::Pic;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use vm_device::MutDevicePio;
use vm_device::bus::{PioAddress, PioAddressOffset};
use vm_superio::serial::NoEvents;
use vm_superio::{Serial, Trigger};

/// No-op Trigger for Polled Mode
struct NoOpTrigger;

impl Trigger for NoOpTrigger {
    type E = io::Error;
    fn trigger(&self) -> Result<(), Self::E> {
        Ok(())
    }
}

/// Serial Console Wrapper using vm-superio.
pub struct SerialConsole {
    device: Serial<NoOpTrigger, NoEvents, Box<dyn Write + Send>>,
}

impl SerialConsole {
    /// Create a new SerialConsole instance.
    /// Polled mode (No Interrupts).
    pub fn new(_pic: Option<Arc<Mutex<Pic>>>) -> Self {
        // Output to stdout
        let out = Box::new(io::stdout());

        Self {
            device: Serial::new(NoOpTrigger, out),
        }
    }

    pub fn queue_input(&mut self, data: &[u8]) {
        if let Err(e) = self.device.enqueue_raw_bytes(data) {
            log::error!("Failed to enqueue serial input: {:?}", e);
        }
    }
}

impl MutDevicePio for SerialConsole {
    fn pio_read(&mut self, _base: PioAddress, offset: PioAddressOffset, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }
        data[0] = self.device.read(offset as u8);
    }

    fn pio_write(&mut self, _base: PioAddress, offset: PioAddressOffset, data: &[u8]) {
        if data.len() != 1 {
            return;
        }
        if let Err(e) = self.device.write(offset as u8, data[0]) {
            log::error!("Serial write error: {:?}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_serial_creation() {
        // SerialConsole ignores Pic in Polled mode
        let mut serial = SerialConsole::new(None);

        // Basic read test (LSR)
        let mut data = [0u8; 1];
        serial.pio_read(PioAddress(0), 5, &mut data);
        // vm-superio default LSR is usually 0x60 (THRE|TEMT)
        assert_eq!(data[0] & 0x60, 0x60);
    }
}
