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

/// Trigger that signals a PIC IRQ.
struct PicTrigger {
    pic: Arc<Mutex<Pic>>,
    irq: u8,
}

impl Trigger for PicTrigger {
    type E = io::Error;
    fn trigger(&self) -> Result<(), Self::E> {
        let mut p = self
            .pic
            .lock()
            .map_err(|_| io::Error::other("Poisoned lock"))?;
        p.set_irq(self.irq, true);
        p.set_irq(self.irq, false);
        Ok(())
    }
}

/// Trigger that wraps either a `NoOp` or a PIC IRQ.
struct SerialTrigger {
    inner: TriggerType,
}

enum TriggerType {
    NoOp(NoOpTrigger),
    Pic(PicTrigger),
}

impl Trigger for SerialTrigger {
    type E = io::Error;
    fn trigger(&self) -> Result<(), Self::E> {
        match &self.inner {
            TriggerType::NoOp(t) => t.trigger(),
            TriggerType::Pic(t) => t.trigger(),
        }
    }
}

/// Serial Console Wrapper using vm-superio.
pub struct SerialConsole {
    device: Serial<SerialTrigger, NoEvents, Box<dyn Write + Send>>,
}

impl SerialConsole {
    /// Create a new `SerialConsole` instance.
    #[must_use]
    pub fn new(pic: Option<Arc<Mutex<Pic>>>) -> Self {
        // Output to stdout
        let out = Box::new(io::stdout());

        let trigger = if let Some(p) = pic {
            SerialTrigger {
                inner: TriggerType::Pic(PicTrigger { pic: p, irq: 4 }), // COM1 is usually IRQ 4
            }
        } else {
            SerialTrigger {
                inner: TriggerType::NoOp(NoOpTrigger),
            }
        };

        Self {
            device: Serial::new(trigger, out),
        }
    }

    pub fn queue_input(&mut self, data: &[u8]) {
        if let Err(e) = self.device.enqueue_raw_bytes(data) {
            log::error!("Failed to enqueue serial input: {e:?}");
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
            log::error!("Serial write error: {e:?}");
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
