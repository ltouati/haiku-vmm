use log::debug;
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
        debug!("Trigger fired: {}", self.name);
        Ok(())
    }
}

pub struct I8042Wrapper {
    device: I8042Device<LogTrigger>,
}

impl I8042Wrapper {
    pub fn new() -> Self {
        debug!("Initializing I8042 device");
        let trigger = LogTrigger::new("I8042 Reset");
        let mut device = I8042Device::new(trigger);
        // Bit 2 of Controller Command Byte (CTR) / Status is "System Flag".
        // Setting it to 1 indicates POST completion, which many kernels expect.
        // vm-superio I8042Device: offset 0 is Data, offset 4 is Command/Status.
        debug!("I8042: Sending Write-CTR command (0x60) to command port (0x64)");
        let _ = device.write(4, 0x60); // Command: Write CTR
        debug!("I8042: Writing 0x05 to data port (0x60) to enable and set SysFlag");
        let _ = device.write(0, 0x05); // Value: Bit 2 (Sys flag) = 1, Bit 0 (En) = 1
        I8042Wrapper { device }
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
            let internal_offset = if base.0 == 0x60 { 0 } else { 4 };
            let val = self.device.read(internal_offset);
            debug!("DEBUG: I8042 Read Port {:#x} -> {:#x}", base.0, val);
            data[0] = val;
        }
    }

    fn pio_write(&mut self, base: PioAddress, _offset: u16, data: &[u8]) {
        if data.len() == 1 {
            let internal_offset = if base.0 == 0x60 { 0 } else { 4 };
            debug!("DEBUG: I8042 Write Port {:#x} <- {:#x}", base.0, data[0]);
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
