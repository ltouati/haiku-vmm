use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};

/// Trait for devices that can be attached to the Memory Bus.
pub trait MemoryDevice: Send + Sync {
    fn read(&mut self, base: u64, offset: u64) -> u64;
    fn write(&mut self, base: u64, offset: u64, val: u64);
}

type MemoryTupple = (RangeInclusive<u64>, Arc<Mutex<dyn MemoryDevice>>);

/// A simple Memory Bus that routes memory accesses to registered devices.
#[derive(Default, Clone)]
pub struct MemoryBus {
    devices: Vec<MemoryTupple>,
}

impl MemoryBus {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    pub fn register(&mut self, range: RangeInclusive<u64>, device: Arc<Mutex<dyn MemoryDevice>>) {
        self.devices.push((range, device));
    }

    pub fn read(&self, addr: u64) -> u64 {
        for (range, device) in &self.devices {
            if range.contains(&addr) {
                let offset = addr - range.start();
                if let Ok(mut dev) = device.lock() {
                    return dev.read(*range.start(), offset);
                }
            }
        }
        0 // Default to 0 for unhandled read? Or maybe 0xFF? 0 is safer for memory.
    }

    pub fn write(&self, addr: u64, val: u64) {
        for (range, device) in &self.devices {
            if range.contains(&addr) {
                let offset = addr - range.start();
                if let Ok(mut dev) = device.lock() {
                    dev.write(*range.start(), offset, val);
                }
                return;
            }
        }
    }
}
