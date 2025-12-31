use log::info;
use vm_device::MutDevicePio;
use vm_device::bus::PioAddress;
use vm_superio::I8042Device;
use vm_superio::Trigger;

/// A simple Trigger that logs the event.
/// For I8042, this usually signals a Reset.
pub struct LogTrigger {
    name: String,
}

impl LogTrigger {
    pub fn new(name: &str) -> Self {
        LogTrigger {
            name: name.to_string(),
        }
    }
}

impl Trigger for LogTrigger {
    type E = ();

    fn trigger(&self) -> Result<(), Self::E> {
        info!("Trigger fired: {}", self.name);
        Ok(())
    }
}

pub struct I8042Wrapper {
    device: I8042Device<LogTrigger>,
}

impl I8042Wrapper {
    pub fn new() -> Self {
        let trigger = LogTrigger::new("I8042 Reset");
        I8042Wrapper {
            device: I8042Device::new(trigger),
        }
    }
}

impl Default for I8042Wrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl MutDevicePio for I8042Wrapper {
    fn pio_read(&mut self, base: PioAddress, _offset: u16, data: &mut [u8]) {
        if data.len() == 1 {
            // I8042Device expects offset 0 for Data (0x60) and 4 for Cmd (0x64) usually?
            // Wait, vm-superio I8042Device typically handles offsets relative to its base?
            // But we register it at two discontiguous ranges: 0x60 and 0x64.
            // My IoManager dispatch sends offset relative to Base.
            // If registered at 0x60 len 1 -> offset 0.
            // If registered at 0x64 len 1 -> offset 0.
            // But I8042Device might expect 0 and 4?
            // Docs for vm-superio 0.5.0:
            // "The I8042 device... It handles reads and writes at offsets 0 (DATA) and 4 (COMMAND/STATUS)."
            // So if I map 0x60->0 and 0x64->4, I need to adjust offset.

            // If base is 0x60, offset 0 -> device offset 0.
            // If base is 0x64, offset 0 -> device offset 4.

            let internal_offset = if base.0 == 0x60 { 0 } else { 4 };
            data[0] = self.device.read(internal_offset);
        }
    }

    fn pio_write(&mut self, base: PioAddress, _offset: u16, data: &[u8]) {
        if data.len() == 1 {
            let internal_offset = if base.0 == 0x60 { 0 } else { 4 };
            let _ = self.device.write(internal_offset, data[0]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_i8042_offsets() {
        let mut i8042 = I8042Wrapper::new();

        // Data port 0x60 should map to offset 0 in the device
        // We can't easily check the internal device state without pub fields,
        // but we can verify the wrapper calls don't crash and follow the logic.
        let mut data = [0];
        i8042.pio_read(PioAddress(0x60), 0, &mut data);
        // Default I8042 status usually has some bits set (like 0x1c)

        i8042.pio_read(PioAddress(0x64), 0, &mut data);
        // Bit 1 of status is Input Buffer Full, should be 0 initially.
        assert_eq!(data[0] & 0x02, 0);
    }
}
