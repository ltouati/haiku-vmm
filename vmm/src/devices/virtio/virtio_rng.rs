use std::borrow::{Borrow, BorrowMut};
use std::sync::{Arc, Mutex};

use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_device::{VirtioConfig, VirtioDeviceActions, VirtioDeviceType, VirtioMmioDevice};
use virtio_queue::{Queue, QueueOwnedT, QueueT};

use vm_memory::{Address, Bytes, GuestMemoryMmap};

use crate::devices::pic::Pic;
use crate::devices::virtio::{DeviceType, default_signal_interrupt};
use crate::system::backend::HypervisorBackend;
use crate::system::vmachine::vcpu::VcpuInjector;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

// Chosen to match the Linux guest driver RNG buffer refill size.
const CHUNK_SIZE: usize = 64;

/// VirtIO RNG Device
pub struct RngDevice<B: HypervisorBackend> {
    config: VirtioConfig<Queue>,
    rng_source: StdRng,
    guest_mem: Option<GuestMemoryMmap>,
    injector: Option<VcpuInjector<B>>,
    pic: Option<Arc<Mutex<Pic>>>,
    irq_line: u8,
}

impl<B: HypervisorBackend> RngDevice<B> {
    pub fn new() -> anyhow::Result<Self> {
        let mut queues = Vec::new();
        queues
            .push(Queue::new(256).map_err(|e| anyhow::anyhow!("Failed to create queue: {:?}", e))?);

        let config_space = Vec::new();
        let mut device_features = 0u64;
        device_features |= 1 << VIRTIO_F_VERSION_1;

        let rng_source = StdRng::from_os_rng();

        Ok(Self {
            config: VirtioConfig::new(device_features, queues, config_space),
            rng_source,
            guest_mem: None,
            injector: None,
            pic: None,
            irq_line: 0,
        })
    }

    pub fn set_memory(&mut self, mem: GuestMemoryMmap) {
        self.guest_mem = Some(mem);
    }

    pub fn set_injector(&mut self, injector: VcpuInjector<B>, pic: Arc<Mutex<Pic>>, line: u8) {
        self.injector = Some(injector);
        self.pic = Some(pic);
        self.irq_line = line;
    }

    fn process_queue(&mut self) -> anyhow::Result<bool> {
        let mem = match self.guest_mem.as_ref() {
            Some(m) => m,
            None => return Ok(false),
        };

        let queue = match self.config.queues.get_mut(0) {
            Some(q) => q,
            None => return Ok(false),
        };

        let mut needs_interrupt = false;
        let mut buf = [0u8; CHUNK_SIZE];

        while let Some(mut chain) = queue.iter(mem).ok().and_then(|mut i| i.next()) {
            let mut total_written = 0;

            for desc in chain.by_ref() {
                if (desc.flags() & virtio_bindings::virtio_ring::VRING_DESC_F_WRITE as u16) == 0 {
                    continue;
                }

                let mut desc_offset = 0;
                let desc_len = desc.len() as usize;

                while desc_offset < desc_len {
                    let chunk_len = std::cmp::min(desc_len - desc_offset, buf.len());

                    self.rng_source.fill_bytes(&mut buf[..chunk_len]);
                    let n = chunk_len;

                    let addr = desc.addr().checked_add(desc_offset as u64).unwrap();
                    if let Err(e) = mem.write_slice(&buf[..n], addr) {
                        log::error!("Failed to write RNG slice: {:?}", e);
                        break;
                    }
                    total_written += n;
                    desc_offset += n;
                }
            }

            if total_written > 0 {
                if let Err(e) = queue.add_used(mem, chain.head_index(), total_written as u32) {
                    log::error!("Failed to add used RNG: {:?}", e);
                }

                if queue.needs_notification(mem).unwrap_or(true) {
                    needs_interrupt = true;
                }
            }
        }

        Ok(needs_interrupt)
    }
    fn signal_interrupt(&mut self) {
        default_signal_interrupt(&mut self.config, self.pic.as_ref(), self.irq_line)
    }
}

impl<B: HypervisorBackend> VirtioDeviceType for RngDevice<B> {
    fn device_type(&self) -> u32 {
        DeviceType::Rng as u32
    }
}

impl<B: HypervisorBackend> VirtioDeviceActions for RngDevice<B> {
    type E = anyhow::Error;

    fn activate(&mut self) -> anyhow::Result<()> {
        log::debug!("VirtIO RNG Activated");
        Ok(())
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        log::debug!("VirtIO RNG Reset");
        Ok(())
    }
}

impl<B: HypervisorBackend> Borrow<VirtioConfig<Queue>> for RngDevice<B> {
    fn borrow(&self) -> &VirtioConfig<Queue> {
        &self.config
    }
}

impl<B: HypervisorBackend> BorrowMut<VirtioConfig<Queue>> for RngDevice<B> {
    fn borrow_mut(&mut self) -> &mut VirtioConfig<Queue> {
        &mut self.config
    }
}

impl<B: HypervisorBackend> VirtioMmioDevice for RngDevice<B> {
    fn queue_notify(&mut self, _val: u32) {
        println!("VirtIO RNG Notify");
        let ret = self.process_queue();
        println!("VirtIO RNG Notify Result: {:?}", ret);
        match ret {
            Ok(needs_irq) => {
                if needs_irq {
                    log::debug!("RNG: Signaling Interrupt");
                    self.signal_interrupt();
                }
            }
            Err(e) => log::error!("RNG queue processing error: {:?}", e),
        }
    }
}
