#[cfg(unix)]
pub mod linux;
#[cfg(unix)]
pub mod macos;
#[cfg(windows)]
pub mod windows;

use anyhow::Result;
#[cfg(unix)]
use linux::LinuxSandbox;
#[cfg(unix)]
use macos::MacosSandbox;
use std::path::Path;
use std::process::Command;
#[cfg(windows)]
use windows::WindowsSandbox;

pub(crate) enum Sandbox {
    #[cfg(unix)]
    Linux(LinuxSandbox),
    #[cfg(unix)]
    Darwin(MacosSandbox),
    #[cfg(windows)]
    Windows(WindowsSandbox),
}

impl Sandbox {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            #[cfg(unix)]
            Self::Linux(_) => "bubblewrap",
            #[cfg(unix)]
            Self::Darwin(_) => "seatbelt",
            #[cfg(windows)]
            Self::Windows(_) => "psec",
        }
    }

    pub(crate) fn command(
        &self,
        program: &str,
        workspace: &Path,
        extra_reads: &[&Path],
        writes: &[&Path],
    ) -> Result<Command> {
        match self {
            #[cfg(unix)]
            Self::Linux(sandbox) => sandbox.command(program, workspace, extra_reads, writes),
            #[cfg(unix)]
            Self::Darwin(sandbox) => sandbox.command(program, workspace, extra_reads, writes),
            #[cfg(windows)]
            Self::Windows(sandbox) => sandbox.command(program, workspace, extra_reads, writes),
        }
    }
}
