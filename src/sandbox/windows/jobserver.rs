//! Lets sandboxed actions share Corgi's jobserver.
//!
//! On Windows the jobserver is a named semaphore. A sandboxed process may open
//! an object only if its permissions name the sandbox, all app containers, or
//! a capability the sandbox holds. Corgi grants this one semaphore to a
//! capability named after it, and the helper gives each sandbox that capability.

use anyhow::{Context, Result};
use std::ptr::null_mut;
use windows::core::{Owned, HSTRING, PWSTR};
use windows::Win32::Foundation::HLOCAL;
use windows::Win32::Security::Authorization::{
    GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    SE_KERNEL_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::{
    DeriveCapabilitySidsFromName, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSECURITY_DESCRIPTOR,
    PSID,
};
use windows::Win32::System::Threading::{
    OpenSemaphoreW, SEMAPHORE_MODIFY_STATE, SYNCHRONIZATION_READ_CONTROL,
    SYNCHRONIZATION_SYNCHRONIZE, SYNCHRONIZATION_WRITE_DAC,
};

/// Call once on Corgi's own jobserver, before any action starts. Returns the
/// capability each sandbox needs to use it.
pub fn configure_jobserver(client: &::jobserver::Client) -> Result<String> {
    let mut probe = std::process::Command::new("unused");
    client.configure(&mut probe);
    let name = probe
        .get_envs()
        .find(|(key, _)| *key == "CARGO_MAKEFLAGS")
        .and_then(|(_, flags)| semaphore(flags?))
        .context("the jobserver did not configure a semaphore")?;
    // SAFETY: every out-pointer refers to a local. `Owned` frees each handle
    // and LocalAlloc'd result (SIDs, their arrays, descriptor, ACL) on return.
    unsafe {
        let semaphore = Owned::new(
            OpenSemaphoreW(
                SYNCHRONIZATION_READ_CONTROL | SYNCHRONIZATION_WRITE_DAC,
                false,
                &HSTRING::from(&name),
            )
            .context("opening the jobserver semaphore")?,
        );
        let (mut groups, mut group_count) = (null_mut::<PSID>(), 0);
        let (mut sids, mut sid_count) = (null_mut::<PSID>(), 0);
        DeriveCapabilitySidsFromName(
            &HSTRING::from(capability(&name)),
            &mut groups,
            &mut group_count,
            &mut sids,
            &mut sid_count,
        )?;
        let group_sids = (0..group_count as usize).map(|i| (*groups.add(i)).0);
        let capability_sids = (0..sid_count as usize).map(|i| (*sids.add(i)).0);
        let _allocations: Vec<_> = group_sids
            .chain(capability_sids)
            .chain([groups.cast(), sids.cast()])
            .map(|allocation| Owned::new(HLOCAL(allocation)))
            .collect();
        let mut acl = null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        GetSecurityInfo(
            *semaphore,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut acl),
            None,
            Some(&mut descriptor),
        )
        .ok()?;
        let _descriptor = Owned::new(HLOCAL(descriptor.0));
        let grant = EXPLICIT_ACCESS_W {
            // Exactly what jobserver::Client::from_env() requests.
            grfAccessPermissions: (SYNCHRONIZATION_SYNCHRONIZE | SEMAPHORE_MODIFY_STATE).0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: PWSTR((*sids).0.cast()),
                ..Default::default()
            },
        };
        let mut granted = null_mut();
        SetEntriesInAclW(Some(&[grant]), Some(acl), &mut granted).ok()?;
        let _granted = Owned::new(HLOCAL(granted.cast()));
        SetSecurityInfo(
            *semaphore,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(granted),
            None,
        )
        .ok()
        .context("granting sandboxes the jobserver semaphore")?;
    }
    Ok(capability(&name))
}

fn semaphore(flags: &std::ffi::OsStr) -> Option<String> {
    let (_, rest) = flags.to_str()?.rsplit_once("--jobserver-auth=")?;
    Some(rest.split(' ').next()?.to_owned()).filter(|name| !name.is_empty())
}

fn capability(semaphore: &str) -> String {
    format!("corgi.jobserver.{semaphore}")
}
