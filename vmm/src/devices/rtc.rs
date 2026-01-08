use vm_device::MutDevicePio;
use vm_device::bus::PioAddress;

/// Simple CMOS/RTC Stub
pub struct RtcWrapper {
    index: u8,
}

impl RtcWrapper {
    #[must_use]
    pub fn new() -> Self {
        RtcWrapper { index: 0 }
    }
}

impl Default for RtcWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl MutDevicePio for RtcWrapper {
    fn pio_read(&mut self, _base: PioAddress, _offset: u16, data: &mut [u8]) {
        if data.len() == 1 {
            // Minimal stub: always return 0
            // Offset 0 (0x70) is Index port (write-only usually, but...)
            // Offset 1 (0x71) is Data port
            data[0] = 0;
        }
    }

    fn pio_write(&mut self, _base: PioAddress, _offset: u16, data: &[u8]) {
        if data.len() == 1 && _offset == 0 {
            self.index = data[0] & 0x7F; // Mask NMI bit
        }
        // Ignore writes to data port 0x71
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtc_minimal() {
        let mut rtc = RtcWrapper::new();
        // Write index 0x01
        rtc.pio_write(PioAddress(0x70), 0, &[0x01]);
        assert_eq!(rtc.index, 0x01);

        // Write index 0x82 (NMI masked)
        rtc.pio_write(PioAddress(0x70), 0, &[0x82]);
        assert_eq!(rtc.index, 0x02);

        // Data read should always be 0 in current stub
        let mut data = [0xff];
        rtc.pio_read(PioAddress(0x71), 0, &mut data);
        assert_eq!(data[0], 0);
    }
}
