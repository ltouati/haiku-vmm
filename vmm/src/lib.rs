pub mod devices;
pub mod nvmm;
pub mod os;
pub mod types;
pub mod utils;

// Re-export specific structs to maintain cleaner API.
pub use nvmm::Machine;
pub use nvmm::NvmmSystem;
pub use nvmm::vcpu::{
    IoHandler, MemoryHandler, MsrHandler, ShutdownHandler, UnknownHandler, Vcpu, VcpuInjector,
    VcpuRunner,
};
pub use os::linux::Linux64Guest;
pub use types::{VmAction, VmExit};
pub use utils::translate_gva;
