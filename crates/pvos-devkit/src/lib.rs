//! Test a PVOS app against the real PVOS.
//!
//! [`Instance::start`] runs the dev kit's real `pvfsd` and `pvosd` in a temp
//! directory, with a forest made for the test and a companion that holds
//! throwaway keys. Nothing is mocked and nothing is relaxed: this is the daemon a
//! real install runs, and it checks every signature and grant the same way.
//!
//! ```no_run
//! use pvos_devkit::{App, Instance};
//!
//! let pvos = Instance::start().unwrap();
//! pvos.install(&App::new("target/debug/notes", "manifest.json")).unwrap();
//! pvos.start_app("com.example.notes").unwrap();
//! let mut desktop = pvos.desktop().unwrap();
//! desktop.open_surface("com.example.notes", "main");
//! let view = desktop.next_view("com.example.notes", "main");
//! ```
//!
//! The kit is a separate download; see [`Kit::find`] for how it is found. With no
//! kit, a test fails and says how to get one. It does not skip.

mod companion;
mod desktop;
mod forest;
mod instance;
mod kit;
pub mod view;

pub use desktop::Desktop;
pub use forest::{Region, TestForest};
pub use instance::{App, Instance, Member, RealCompanion};
pub use kit::Kit;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

/// Wait up to 15 seconds for `f` to say yes; panic naming `what` if it never does.
pub fn wait_for<F: FnMut() -> bool>(what: &str, f: F) {
    wait_for_within(what, std::time::Duration::from_secs(15), f)
}

/// [`wait_for`] with your own limit.
pub fn wait_for_within<F: FnMut() -> bool>(what: &str, limit: std::time::Duration, mut f: F) {
    let start = std::time::Instant::now();
    while !f() {
        assert!(start.elapsed() < limit, "timed out after {limit:?} waiting for {what}");
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
