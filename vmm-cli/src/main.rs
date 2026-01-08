use clap::Parser;
use deloxide::Deloxide;
use log::{error, info};
use std::path::PathBuf;
use vmm::os::Linux64Guest;
use vmm::system::VmmSystem;
use vmm::system::nvmm::system::NVMMSystem;

/// Simple VMM to boot Linux
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the Linux kernel (elf or bzImage)
    #[arg(short, long)]
    kernel: PathBuf,

    /// Kernel command line parameters
    #[arg(
        long,
        default_value = "console=ttyS0 earlyprintk=serial reboot=k panic=1 pci=off nomodule acpi=off noapic "
    )]
    cmdline: String,

    /// RAM size in MiB
    #[arg(long, default_value_t = 512)]
    memory: u64,

    /// Path to a raw disk image
    #[arg(short, long)]
    disk: Option<PathBuf>,

    /// Path to initrd
    #[arg(long)]
    initrd: Option<PathBuf>,
}

// Helper re-implemented or imported?
// Since `translate_gva` is now internal to `linux.rs` and local `main.rs` needs it for SIGHUP dump,
// we must re-implement it briefly here or make it public in `linux.rs`.
// For simplicity and decoupling, I'll keep the small helper here for the SIGHUP dumper.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Deloxide::new()
        .callback(|info| {
            println!("Deadlock detected! Cycle: {:?}", info.thread_cycle);
        })
        .start()
        .expect("Failed to initialize detector");

    env_logger::init();
    let args = Args::parse();

    info!("Initialize NVMM...");
    let sys = NVMMSystem::new()?;
    let mut machine = sys.create_machine()?;

    // Use Linux64Guest to setup the machine
    let guest = Linux64Guest::new(
        args.kernel,
        args.cmdline,
        args.memory,
        args.disk,
        args.initrd,
    );
    let (guest_mem, mut vcpu) = guest.load(&mut machine)?;

    // Create injector for the signal thread
    let injector = vcpu.injector();
    let guest_mem_thread = guest_mem.clone();

    // Spawn SIGHUP Handler
    std::thread::spawn(move || {
        let mut signals = signal_hook::iterator::Signals::new([signal_hook::consts::SIGHUP])
            .expect("Failed to create signals iterator");

        for _ in signals.forever() {
            println!("\nReceived SIGHUP, dumping VCPU state & Stack Trace...");
            // Use ./vmlinux for addr2line as hardcoded previously, or could derive from args if suitable
            if let Err(e) = injector.dump_debug_state(
                &guest_mem_thread,
                Some(std::path::Path::new("../../kernels/vmlinux")),
            ) {
                eprintln!("Failed to dump debug state: {}", e);
            }
        }
    });

    println!("SIGHUP handler registered. PID: {}", std::process::id());

    // START THE GUEST
    println!("VMM-CLI: Calling guest.run()...");
    if let Err(e) = guest.run(&mut vcpu, &guest_mem).await {
        error!("Guest exited with error: {}", e);
    }

    Ok(())
}
