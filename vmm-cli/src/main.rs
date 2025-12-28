use clap::Parser;
use log::{info};
use nvmm::{NvmmSystem};
use std::path::PathBuf;
use nvmm::linux::Linux64Guest;

/// Simple VMM to boot Linux
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the Linux kernel (elf or bzImage)
    #[arg(short, long)]
    kernel: PathBuf,

    /// Kernel command line parameters
    #[arg(long, default_value = "console=ttyS0 earlyprintk=serial reboot=k panic=1 pci=off nomodule acpi=off noapic virtio_mmio.device=512@0xd0000000:3 nokaslr")]
    cmdline: String,

    /// RAM size in MiB
    #[arg(long, default_value_t = 512)]
    memory: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    info!("Initialize NVMM...");
    let sys = NvmmSystem::new()?;
    let mut machine = sys.create_machine()?;

    // Use Linux64Guest to setup the machine
    let guest = Linux64Guest::new(args.kernel, args.cmdline, args.memory);
    let (guest_mem, mut vcpu) = guest.load(&mut machine)?;

    // Run the guest
    guest.run(&mut vcpu, &guest_mem)?;

    Ok(())
}