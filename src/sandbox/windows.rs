//! Windows sandbox: each action runs inside a Process Security Environment
//! (PSEC), which limits the files it can see and blocks the network.
//!
//! `command` returns a Command that re-runs Corgi as a small helper. Its
//! arguments, environment, cwd and stdio reach the real program unchanged.
//! Only the encoded PSEC policy travels separately, through a single-use file:
//! it can list every source file and exceed the 32K command-line limit.
//!
//! Reads are limited to the store, toolchain and declared inputs; writes to
//! the action's scratch and output directories. `.git`, `target` and
//! `Cargo.lock` are denied even before they exist.

mod jobserver;
mod wire;

pub use self::jobserver::configure_jobserver;

use crate::store::Store;
use anyhow::{bail, ensure, Context, Result};
use std::ffi::{c_void, CStr, OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use windows::core::{w, HRESULT, PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, GetExitCodeProcess, InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOEXW,
};
use wire::Policy;

const SENTINEL: &str = "__corgi_psec";
const PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT: usize = 35 | 0x0002_0000;

/// Fail before building when this Windows lacks the required PSEC support.
pub fn check_windows_sandbox() -> Result<()> {
    Api::load().map(drop)
}

pub struct WindowsSandbox {
    read_roots: Vec<PathBuf>,
    policy_directory: PathBuf,
    jobserver_capability: String,
}

pub fn setup_windows_sandbox(
    store: &Store,
    rustc: &Path,
    sysroot: &Path,
    cargo_home: &Path,
    runtime_paths: Vec<PathBuf>,
    jobserver_capability: String,
) -> Result<WindowsSandbox> {
    let mut read_roots = vec![
        store.root.clone(),
        rustc.to_owned(),
        sysroot.to_owned(),
        cargo_home.to_owned(),
    ];
    read_roots.extend(runtime_paths);
    Ok(WindowsSandbox {
        read_roots,
        policy_directory: store.root.join("tmp"),
        jobserver_capability,
    })
}

impl WindowsSandbox {
    pub fn command(
        &self,
        program: &str,
        workspace: &Path,
        extra_reads: &[&Path],
        writes: &[&Path],
    ) -> Result<Command> {
        let policy = self.policy(workspace, extra_reads, writes)?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = self.policy_directory.join(format!(
            "psec-{}-{}.bin",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, policy.encode(&self.jobserver_capability))
            .with_context(|| format!("writing sandbox policy {}", path.display()))?;
        let mut command = Command::new(std::env::current_exe()?);
        command.arg(SENTINEL).arg(path).arg(program);
        Ok(command)
    }

    fn policy(&self, workspace: &Path, extra_reads: &[&Path], writes: &[&Path]) -> Result<Policy> {
        let mut deny = Vec::new();
        let source_roots = extra_reads.iter().copied().filter(|path| path.is_dir());
        for root in std::iter::once(workspace).chain(source_roots) {
            let root = policy_path(root)?;
            deny.extend([".git", "target", "Cargo.lock"].map(|name| format!(r"{root}\{name}")));
        }
        let reads = self.read_roots.iter().map(PathBuf::as_path);
        Ok(Policy {
            read_only: reads
                .chain(extra_reads.iter().copied())
                .map(policy_path)
                .collect::<Result<_>>()?,
            read_write: writes
                .iter()
                .copied()
                .map(policy_path)
                .collect::<Result<_>>()?,
            deny,
        })
    }
}

/// PSEC matches resolved `C:\...` or `\server\share\...` spellings.
fn policy_path(path: &Path) -> Result<String> {
    let path = dunce::canonicalize(path)
        .with_context(|| format!("resolving sandbox path {}", path.display()))?;
    path.into_os_string()
        .into_string()
        .map_err(|path| anyhow::anyhow!("sandbox paths must be Unicode: {}", path.display()))
}

/// Put this process in a job that Windows kills, with everything this process
/// starts, when the process exits for any reason. Jobs nest, so the build and
/// each sandbox helper both do this. Without it, killing a build releases its
/// locks while its actions keep writing to the folders those locks protect.
pub fn kill_descendants_on_exit() -> Result<()> {
    // SAFETY: `limits` outlives the call that reads it. The job handle is
    // deliberately never closed: closing it would kill this process.
    unsafe {
        let job = CreateJobObjectW(None, PCWSTR::null())?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of_val(&limits) as u32,
        )?;
        AssignProcessToJobObject(job, GetCurrentProcess()).context("joining a kill-on-exit job")?;
    }
    Ok(())
}

/// `argv` includes the executable at index zero.
pub fn is_helper_invocation(argv: &[OsString]) -> bool {
    argv.get(1).is_some_and(|arg| arg == SENTINEL)
}

/// Run the action inside PSEC and return its exit code. The caller must exit
/// immediately afterwards: process exit releases this helper's handles and
/// closes its kill-on-close job, which ends any descendants left behind.
pub fn run_helper(argv: &[OsString]) -> Result<u32> {
    let [_, _, policy_path, program, args @ ..] = argv else {
        bail!("usage: corgi {SENTINEL} POLICY PROGRAM [ARGS...]");
    };
    let policy = std::fs::read(policy_path);
    std::fs::remove_file(policy_path).ok();
    let policy = policy.context("reading sandbox policy")?;
    let api = Api::load()?;
    let mut command_line = command_line(program, args)?;
    let environment_block = environment_block()?;

    // SAFETY: every pointer refers to a local that outlives the call using it,
    // and the PSEC function pointers have the ABI declared by their types.
    unsafe {
        let mut environment = HANDLE::default();
        (api.create)(
            policy.as_ptr().cast(),
            policy.len() as u32,
            0,
            &mut environment,
        )
        .ok()
        .context("CreateProcessSecurityEnvironment")?;

        // Join before creating the child so the child inherits the job.
        kill_descendants_on_exit()?;

        let mut size = 0;
        // The sizing call reports failure by design.
        let _ = InitializeProcThreadAttributeList(None, 1, None, &mut size);
        let mut storage = vec![0u64; size.div_ceil(8)];
        let attributes = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        InitializeProcThreadAttributeList(Some(attributes), 1, None, &mut size)?;
        UpdateProcThreadAttribute(
            attributes,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT,
            Some((&raw const environment).cast()),
            size_of::<HANDLE>(),
            None,
            None,
        )?;

        // The child inherits this helper's cwd and stdio. PSEC does not pass
        // an inherited environment through, so hand it over explicitly.
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE).unwrap_or_default();
        startup.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE).unwrap_or_default();
        startup.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE).unwrap_or_default();
        startup.lpAttributeList = attributes;
        let mut process = PROCESS_INFORMATION::default();
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            true,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            Some(environment_block.as_ptr().cast()),
            PCWSTR::null(),
            &startup.StartupInfo,
            &mut process,
        )
        .with_context(|| format!("starting {} in the sandbox", program.display()))?;
        WaitForSingleObject(process.hProcess, INFINITE);
        let mut code = 0;
        GetExitCodeProcess(process.hProcess, &mut code)?;
        (api.close)(environment);
        Ok(code)
    }
}

type Export = unsafe extern "system" fn() -> isize;
type Create = unsafe extern "system" fn(*const c_void, u32, u32, *mut HANDLE) -> HRESULT;
type Close = unsafe extern "system" fn(HANDLE);
type Version = unsafe extern "system" fn(u32, *mut u8, *mut u32) -> HRESULT;
type Query = unsafe extern "system" fn(*mut u64) -> HRESULT;

struct Api {
    create: Create,
    close: Close,
}

impl Api {
    /// Require PSEC 1.1 with native file denies and network ingress filtering.
    /// Missing support is an error, never a reason to run without isolation.
    fn load() -> Result<Self> {
        // SAFETY: the DLL comes only from System32, and each export is cast
        // to the signature documented by the PSEC preview API.
        unsafe {
            let module = LoadLibraryExW(w!("processmodel.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32)
                .context("Windows builds need PSEC, but processmodel.dll is unavailable")?;
            let export = |name: &CStr| {
                GetProcAddress(module, PCSTR(name.as_ptr().cast()))
                    .with_context(|| format!("this Windows has no PSEC {}", name.to_string_lossy()))
            };
            let version = std::mem::transmute::<Export, Version>(export(
                c"IsProcessSecurityEnvironmentVersionSupported",
            )?);
            let query = std::mem::transmute::<Export, Query>(export(
                c"QueryProcessSecurityEnvironmentSupport",
            )?);
            let (mut available, mut minor, mut flags) = (0, 0, 0);
            version(1, &mut available, &mut minor).ok()?;
            query(&mut flags).ok()?;
            ensure!(available != 0 && minor >= 1, "PSEC version 1.1 is required");
            ensure!(flags & 1 != 0, "PSEC native filesystem deny is required");
            ensure!(flags & 8 != 0, "PSEC network ingress filtering is required");
            Ok(Self {
                create: std::mem::transmute::<Export, Create>(export(
                    c"CreateProcessSecurityEnvironment",
                )?),
                close: std::mem::transmute::<Export, Close>(export(
                    c"CloseProcessSecurityEnvironment",
                )?),
            })
        }
    }
}

/// A NUL-terminated command line that the child's C runtime splits back into
/// exactly `program` and `args`.
fn command_line(program: &OsStr, args: &[OsString]) -> Result<Vec<u16>> {
    // argv[0] follows a different rule: backslashes are literal and a quote
    // ends it, so quote it without escaping and reject embedded quotes.
    let program: Vec<u16> = program.encode_wide().collect();
    ensure!(
        !program.contains(&0) && !program.contains(&(b'"' as u16)),
        "invalid executable name"
    );
    let mut out = vec![b'"' as u16];
    out.extend(program);
    out.push(b'"' as u16);
    for arg in args {
        out.push(b' ' as u16);
        out.extend(quote(arg)?);
    }
    out.push(0);
    ensure!(out.len() <= 32_767, "command line too long");
    Ok(out)
}

/// This process's environment as a sorted, double-NUL-terminated block.
fn environment_block() -> Result<Vec<u16>> {
    let mut variables: Vec<_> = std::env::vars_os().collect();
    variables.sort_by_key(|(name, _)| name.to_string_lossy().to_uppercase());
    let mut out = Vec::new();
    for (name, value) in variables {
        out.extend(name.encode_wide());
        out.push(b'=' as u16);
        out.extend(value.encode_wide());
        out.push(0);
    }
    ensure!(!out.is_empty(), "empty sandbox environment");
    out.push(0);
    Ok(out)
}

fn quote(arg: &OsStr) -> Result<Vec<u16>> {
    let mut out = vec![b'"' as u16];
    let mut slashes = 0;
    for c in arg.encode_wide() {
        ensure!(c != 0, "NUL in command argument");
        if c == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        // Backslashes are literal unless they precede a quote.
        let quote = c == b'"' as u16;
        out.extend(std::iter::repeat_n(
            b'\\' as u16,
            slashes * if quote { 2 } else { 1 },
        ));
        slashes = 0;
        if quote {
            out.push(b'\\' as u16);
        }
        out.push(c);
    }
    out.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    out.push(b'"' as u16);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStringExt;

    #[test]
    fn quoting_preserves_empty_spaces_quotes_unicode_and_slashes() {
        for (arg, expected) in [
            ("", "\"\""),
            ("a b", "\"a b\""),
            ("ü", "\"ü\""),
            ("a\"b", "\"a\\\"b\""),
            ("C:\\dir\\", "\"C:\\dir\\\\\""),
            ("\\\"", "\"\\\\\\\"\""),
        ] {
            assert_eq!(
                String::from_utf16(&quote(OsStr::new(arg)).unwrap()).unwrap(),
                expected
            );
        }
        let arg = OsString::from_wide(&[0xd800]);
        assert_eq!(quote(&arg).unwrap(), [34, 0xd800, 34]);
        assert!(quote(OsStr::new("a\0b")).is_err());
    }

    #[test]
    fn command_line_checks_executable_and_length() {
        assert!(command_line(OsStr::new("bad\"exe"), &[]).is_err());
        assert!(command_line(OsStr::new("bad\0exe"), &[]).is_err());
        assert!(command_line(OsStr::new("x"), &["a".repeat(32_767).into()]).is_err());
        assert_eq!(
            String::from_utf16(
                &command_line(OsStr::new(r"C:\program dir\tool.exe"), &["".into()]).unwrap()
            )
            .unwrap(),
            "\"C:\\program dir\\tool.exe\" \"\"\0"
        );
    }
}
