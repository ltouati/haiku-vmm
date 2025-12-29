use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};

/// Trait for devices that can be attached to the IO Bus.
pub trait IoDevice: Send + Sync {
    fn read(&mut self, base: u16, offset: u16) -> u8;
    fn write(&mut self, base: u16, offset: u16, val: u8);
}

type IoTupple = (RangeInclusive<u16>, Arc<Mutex<dyn IoDevice>>);

/// A simple IO Bus that routes port accesses to registered devices.
#[derive(Default, Clone)]
pub struct IoBus {
    devices: Vec<IoTupple>,
}

impl IoBus {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    pub fn register(&mut self, range: RangeInclusive<u16>, device: Arc<Mutex<dyn IoDevice>>) {
        self.devices.push((range, device));
    }

    pub fn read(&self, port: u16) -> u8 {
        for (range, device) in &self.devices {
            if range.contains(&port) {
                let offset = port - range.start();
                if let Ok(mut dev) = device.lock() {
                    return dev.read(*range.start(), offset);
                }
            }
        }
        0xff
    }

    pub fn write(&self, port: u16, val: u8) {
        for (range, device) in &self.devices {
            if range.contains(&port) {
                let offset = port - range.start();
                if let Ok(mut dev) = device.lock() {
                    dev.write(*range.start(), offset, val);
                }
                return;
            }
        }
    }
}
