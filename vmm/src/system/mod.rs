pub mod backend;
pub mod machine;
pub mod nvmm;
pub mod vmachine;
use backend::HypervisorBackend;
pub use machine::Machine;

pub trait VmmSystem: Send + Sync {
    type Backend: HypervisorBackend;
    fn create_machine(&self) -> anyhow::Result<Machine<Self::Backend>>;
}
