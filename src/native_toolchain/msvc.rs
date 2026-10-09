//! Installed MSVC and Windows SDK, discovered without the caller's environment.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::NativeToolchain;
use crate::store::Store;

/// Beside the link driver: the path of the real link.exe it starts.
const REAL_LINKER: &str = "real-linker.txt";

/// Discovery sees only these variables: never the caller's PATH/INCLUDE/LIB,
/// developer-shell selections, or CL/_CL_ flags.
struct DiscoveryEnvironment;

impl find_msvc_tools::EnvGetter for DiscoveryEnvironment {
    fn get_env(&self, name: &'static str) -> Option<find_msvc_tools::Env> {
        matches!(name, "ProgramFiles" | "ProgramFiles(x86)")
            .then(|| std::env::var_os(name))
            .flatten()
            .map(find_msvc_tools::Env::Owned)
    }
}

pub(super) fn discover(host: &str, store: &Store) -> Result<NativeToolchain> {
    let arch = match host.split('-').next() {
        Some("x86_64") => "x64",
        Some("aarch64") => "arm64",
        _ => bail!("unsupported Windows host {host}"),
    };
    let find = |name| {
        let tool = find_msvc_tools::find_tool_with_env(arch, name, &DiscoveryEnvironment)
            .with_context(|| {
                format!("no {arch} MSVC {name}; install the Visual Studio C++ build tools and Windows SDK")
            })?;
        let path = dunce::canonicalize(tool.path())?;
        anyhow::Ok((tool, path))
    };
    let (cl, compiler) = find("cl.exe")?;
    let (_, linker) = find("link.exe")?;
    let (_, librarian) = find("lib.exe")?;

    // cl's discovery environment is exactly PATH, INCLUDE and LIB.
    let mut environment = BTreeMap::new();
    let mut read_paths = vec![compiler
        .parent()
        .context("cl.exe has no parent")?
        .to_owned()];
    for (name, value) in cl.env() {
        let directories = std::env::split_paths(value)
            .filter(|path| !path.as_os_str().is_empty())
            .map(dunce::canonicalize)
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("resolving discovered {}", name.display()))?;
        read_paths.extend(directories.iter().cloned());
        environment.insert(text(name)?, text(&std::env::join_paths(directories)?)?);
    }
    for (name, path) in [("CC", &compiler), ("CXX", &compiler), ("AR", &librarian)] {
        environment.insert(name.to_owned(), text(path.as_os_str())?);
    }
    // bindgen loads libclang while build scripts run. Visual Studio's optional
    // "C++ Clang tools" component installs one beside MSVC:
    // ...\VC\Tools\MSVC\<version>\bin\Host<arch>\<arch>\cl.exe
    // ...\VC\Tools\Llvm\<arch>\bin\libclang.dll, headers in lib\clang.
    let llvm_arch = if arch == "arm64" { "ARM64" } else { arch };
    if let Some(llvm) = compiler
        .ancestors()
        .nth(6)
        .map(|tools| tools.join("Llvm").join(llvm_arch))
    {
        let bin = llvm.join("bin");
        let libclang = bin.join("libclang.dll");
        let headers = llvm.join("lib").join("clang");
        if libclang.is_file() && headers.is_dir() {
            read_paths.extend([libclang, headers]);
            environment.insert("LIBCLANG_PATH".into(), text(bin.as_os_str())?);
        }
    }
    for name in ["SystemRoot", "LOCALAPPDATA"] {
        let value = std::env::var_os(name).with_context(|| format!("{name} is required"))?;
        environment.insert(name.to_owned(), text(&value)?);
    }
    // Windows' default system PATH, like /usr/bin:/bin on macOS. The sandbox
    // already lets every action run these; like macOS's, they are not hashed.
    let system_root = Path::new(&environment["SystemRoot"]).to_owned();
    let path = std::env::split_paths(environment.get("PATH").map_or("", String::as_str))
        .filter(|path| !path.as_os_str().is_empty())
        .chain([
            system_root.join("System32"),
            system_root.clone(),
            system_root.join(r"System32\Wbem"),
            system_root.join(r"System32\WindowsPowerShell\v1.0"),
        ])
        .collect::<Vec<_>>();
    environment.insert("PATH".into(), text(&std::env::join_paths(path)?)?);

    let inputs = super::inputs::resolve(store, &read_paths)?;
    let identity = crate::store::sha256_hex(&serde_json::to_vec(&(
        "windows-msvc/1",
        &inputs.identity,
        &environment,
    ))?);
    // ...\MSVC\<version>\bin\Host<arch>\<arch>\cl.exe
    let version = compiler.iter().rev().nth(4).map(Path::new);
    Ok(NativeToolchain {
        compiler_version: format!("MSVC {}", version.unwrap_or(&compiler).display()),
        environment: environment.into_iter().collect(),
        runtime_paths: inputs.paths,
        compiler,
        linker: link_driver(store, &linker)?,
        identity,
    })
}

/// link.exe writes its working directory into every PDB, and no switch turns
/// that off. rustc runs this copy of Corgi as its linker instead; it starts
/// the real link.exe from the driver's own store directory, never a checkout.
fn link_driver(store: &Store, linker: &Path) -> Result<PathBuf> {
    let corgi = std::env::current_exe()?;
    let identity = crate::store::sha256_hex(&serde_json::to_vec(&(
        crate::store::sha256_file(&corgi)?,
        linker,
    ))?);
    let directory = store
        .root
        .join("tools")
        .join(format!("msvc-link-{}", &identity[..16]));
    let driver = directory.join("link.exe");
    if !driver.is_file() {
        let staging = store.tmp_path("msvc-link");
        fs::create_dir_all(&staging)?;
        fs::write(staging.join(REAL_LINKER), text(linker.as_os_str())?)?;
        fs::copy(&corgi, staging.join("link.exe"))?;
        match fs::rename(&staging, &directory) {
            Ok(()) => {}
            Err(_) if driver.is_file() => fs::remove_dir_all(&staging)?,
            Err(error) => return Err(error).context("publishing the MSVC link driver"),
        }
    }
    crate::build::touch_tool_marker(&directory);
    Ok(driver)
}

/// Whether this process is the link driver that rustc started.
pub fn is_link_invocation() -> bool {
    std::env::current_exe().is_ok_and(|exe| {
        exe.file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("link.exe"))
            && exe.with_file_name(REAL_LINKER).is_file()
    })
}

/// Run the real link.exe with rustc's arguments from the driver's directory,
/// returning its exit code.
pub fn run_link_invocation(argv: &[OsString]) -> Result<i32> {
    let exe = std::env::current_exe()?;
    let directory = exe.parent().context("link driver has no directory")?;
    let linker = fs::read_to_string(directory.join(REAL_LINKER))?;
    let status = Command::new(linker.trim())
        .args(argv.iter().skip(1))
        .current_dir(directory)
        .status()
        .context("starting link.exe")?;
    Ok(status.code().unwrap_or(1))
}

fn text(value: &std::ffi::OsStr) -> Result<String> {
    value
        .to_str()
        .map(str::to_owned)
        .context("Windows build environments require Unicode paths")
}
