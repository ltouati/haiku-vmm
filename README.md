# Haiku VMM

A lightweight, modular Virtual Machine Monitor (VMM) for Haiku, leveraging the NetBSD NVMM hypervisor.

## Overview

This project provides a modular architecture for running virtual machines. It is currently focused on supporting Linux 64-bit guests using the NVMM backend.

## Project Structure

The codebase is organized into two main components:

- **`vmm`**: The core library handling hypervisor abstraction, memory management, and device emulation.
- **`vmm-cli`**: A command-line tool for launching and managing virtual machines.

### `vmm` Crate Internals

- `src/nvmm/`: Hypervisor-specific backend (FFI bindings, Machine management, VCPU implementation).
- `src/os/`: Guest OS loader and configuration logic (e.g., `linux.rs`).
- `src/devices/`: Emulated hardware components (VirtIO Console/Block, PIT, PIC, LAPIC, RTC, Serial).
- `src/lib.rs`: Ergonomic root API for high-level VM management.

## Features

- **Hypervisor**: NetBSD NVMM on haiku.
- **Guest Support**: Linux 64-bit (bzImage or ELF).
- **Storage**: VirtIO Block device support with raw disk images.
- **Console**: VirtIO Console and legacy Serial (UART) support.
- **Interrupts**: Implementation of LAPIC, dual 8259 PICs, and 8254 PIT.
- **Debugging**: Built-in VCPU state dumper and stack walker (via SIGHUP).

## Getting Started

### Prerequisites

- A system with the NVMM hypervisor available (Haiku with NVMM support).
- Rust toolchain (stable).

### Building

```bash
# Build the entire workspace
cargo build --release
```

### Running a VM

Use the `vmm-cli` to start a guest. You will need a Linux kernel (`vmlinux` or `bzImage`) and optionally a disk image.

```bash
./target/release/vmm-cli --kernel path/to/vmlinux --memory 512 --disk path/to/disk.img
```

#### CLI Options

- `--kernel`: Path to the Linux kernel image.
- `--memory`: RAM size in MiB (default: 512).
- `--disk`: (Optional) Path to a raw disk image.
- `--cmdline`: (Optional) Custom kernel command line.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details (if available).
