//! Win32 DACL enforcement for the locally generated MITM CA (Windows only).
//!
//! The CA directory and private key are protected by an explicit DACL with
//! exactly one non-inheritable ACE: `GENERIC_ALL` for the current user's SID,
//! with inherited ACEs removed. Every Win32 handle and LocalAlloc allocation is
//! released through an RAII guard, including on early-return paths.

use anyhow::{anyhow, Result};
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_CALL_NOT_IMPLEMENTED,
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_SUCCESS, FALSE, GENERIC_ALL, HANDLE,
    HLOCAL,
};
use windows_sys::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetLengthSid, GetTokenInformation,
    IsValidSid, TokenUser, ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, INHERITED_ACE, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
};
#[cfg(test)]
use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// A `TOKEN_USER` structure is tiny; cap the sizing call to avoid trusting an
/// implausible length returned by the OS.
const MAX_TOKEN_USER_BYTES: u32 = 64 * 1024;

/// Result of inspecting a DACL. `Weak` is a known-bad ACL and must be a hard
/// error; `Unavailable` means the Win32 query itself failed, which is only a
/// warning when the per-user location check has passed.
#[derive(Debug)]
pub enum DaclStatus {
    Secure,
    Weak(String),
    Unavailable(String),
}

/// Owns a real kernel handle. The pseudo-handle returned by
/// `GetCurrentProcess()` is deliberately never wrapped in this guard.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Owns memory returned by `SetEntriesInAclW` / `GetNamedSecurityInfoW`, which
/// must be released with `LocalFree` (not `free`).
struct OwnedLocalAlloc(HLOCAL);

impl Drop for OwnedLocalAlloc {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn status_text(status: u32) -> String {
    match status {
        ERROR_SUCCESS => "ERROR_SUCCESS".to_string(),
        ERROR_ACCESS_DENIED => "ERROR_ACCESS_DENIED".to_string(),
        ERROR_CALL_NOT_IMPLEMENTED => "ERROR_CALL_NOT_IMPLEMENTED".to_string(),
        ERROR_INSUFFICIENT_BUFFER => "ERROR_INSUFFICIENT_BUFFER".to_string(),
        ERROR_INVALID_PARAMETER => "ERROR_INVALID_PARAMETER".to_string(),
        other => format!("Win32 status {other}"),
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Return the current process token user's SID bytes (a self-relative SID).
pub fn current_user_sid() -> Result<Vec<u8>> {
    unsafe {
        // Pseudo-handle: valid for the life of the process, must NOT be closed.
        let process = GetCurrentProcess();
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == FALSE {
            return Err(anyhow!("OpenProcessToken failed: {}", GetLastError()));
        }
        let _token = OwnedHandle(token);

        let mut needed = 0u32;
        let sizing = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if sizing != FALSE || GetLastError() != ERROR_INSUFFICIENT_BUFFER {
            return Err(anyhow!(
                "GetTokenInformation(TokenUser) sizing call failed: {}",
                GetLastError()
            ));
        }
        if needed == 0 || needed > MAX_TOKEN_USER_BYTES {
            return Err(anyhow!("implausible TokenUser size: {needed}"));
        }

        // TOKEN_USER contains pointers, so the buffer must be pointer-aligned.
        // A Vec<usize> guarantees that; Vec<u8> would not.
        let words = (needed as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0usize; words];
        if GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        ) == FALSE
        {
            return Err(anyhow!(
                "GetTokenInformation(TokenUser) failed: {}",
                GetLastError()
            ));
        }
        if needed as usize > buffer.len() * size_of::<usize>() {
            return Err(anyhow!("GetTokenInformation returned an oversized buffer"));
        }

        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let sid = user.User.Sid;
        if sid.is_null() || IsValidSid(sid) == FALSE {
            return Err(anyhow!("token user SID is missing or invalid"));
        }
        let length = GetLengthSid(sid) as usize;
        if length == 0 || length > needed as usize {
            return Err(anyhow!("invalid token user SID length: {length}"));
        }
        Ok(std::slice::from_raw_parts(sid as *const u8, length).to_vec())
    }
}

/// Replace the DACL on `path` with exactly one `GENERIC_ALL` allow ACE for
/// `sid`. `PROTECTED_DACL_SECURITY_INFORMATION` removes inherited ACEs and
/// blocks future auto-inheritance. This never widens an existing DACL.
pub fn set_current_user_only_dacl(path: &Path, sid: &[u8]) -> Result<()> {
    if sid.is_empty() {
        return Err(anyhow!("empty SID"));
    }
    let wide = wide_path(path);
    unsafe {
        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, sid.as_ptr() as PSID);

        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: trustee,
        };

        let mut acl: *mut ACL = std::ptr::null_mut();
        let status = SetEntriesInAclW(1, &entry, std::ptr::null::<ACL>(), &mut acl);
        if status != ERROR_SUCCESS {
            return Err(anyhow!("SetEntriesInAclW failed: {}", status_text(status)));
        }
        if acl.is_null() {
            return Err(anyhow!("SetEntriesInAclW returned a null ACL"));
        }
        let _acl = OwnedLocalAlloc(acl as HLOCAL);

        let status = SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(), // owner
            std::ptr::null_mut(), // group
            acl as *const ACL,
            std::ptr::null(), // SACL (unchanged)
        );
        if status != ERROR_SUCCESS {
            return Err(anyhow!(
                "SetNamedSecurityInfoW failed: {}",
                status_text(status)
            ));
        }
        Ok(())
    }
}

/// Inspect the DACL of `path`. Win32 query failures are reported as
/// `Unavailable`; an ACL that is demonstrably broad is reported as `Weak`.
pub fn verify_current_user_only_dacl(path: &Path, sid: &[u8]) -> Result<DaclStatus> {
    if sid.is_empty() {
        return Err(anyhow!("empty SID"));
    }
    let wide = wide_path(path);
    unsafe {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        );
        if status != ERROR_SUCCESS {
            return Ok(DaclStatus::Unavailable(format!(
                "GetNamedSecurityInfoW failed: {}",
                status_text(status)
            )));
        }
        // The DACL points inside this security descriptor: free only the SD.
        let _sd = OwnedLocalAlloc(sd as HLOCAL);

        if dacl.is_null() {
            // A NULL DACL grants everyone full control.
            return Ok(DaclStatus::Weak("NULL DACL".to_string()));
        }

        let mut info = ACL_SIZE_INFORMATION::default();
        if GetAclInformation(
            dacl as *const ACL,
            &mut info as *mut ACL_SIZE_INFORMATION as *mut c_void,
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == FALSE
        {
            return Ok(DaclStatus::Unavailable(format!(
                "GetAclInformation failed: {}",
                GetLastError()
            )));
        }
        if info.AceCount != 1 {
            return Ok(DaclStatus::Weak(format!(
                "DACL has {} ACEs, expected exactly one current-user ACE",
                info.AceCount
            )));
        }

        let mut ace: *mut c_void = std::ptr::null_mut();
        if GetAce(dacl as *const ACL, 0, &mut ace) == FALSE {
            return Ok(DaclStatus::Unavailable(format!(
                "GetAce failed: {}",
                GetLastError()
            )));
        }
        if ace.is_null() {
            return Ok(DaclStatus::Unavailable(
                "GetAce returned a null ACE".to_string(),
            ));
        }
        let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
        if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
            return Ok(DaclStatus::Weak(format!(
                "DACL ACE type {} is not an allow ACE",
                ace.Header.AceType
            )));
        }
        if (ace.Header.AceFlags as u32) & INHERITED_ACE != 0 {
            return Ok(DaclStatus::Weak("DACL ACE is inherited".to_string()));
        }
        // Windows normalizes GENERIC_ALL on a file object to FILE_ALL_ACCESS
        // (0x001F01FF) when the ACE is stored. Accept either representation,
        // but still require the full access set.
        const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
        let full_access =
            ace.Mask == GENERIC_ALL || (ace.Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS;
        if !full_access {
            return Ok(DaclStatus::Weak(format!(
                "DACL ACE mask {:#x} is not full access",
                ace.Mask
            )));
        }
        // `SidStart` is at the start of the SID stored inside the ACE.
        let ace_sid = std::ptr::addr_of!(ace.SidStart) as PSID;
        if IsValidSid(ace_sid) == FALSE {
            return Ok(DaclStatus::Weak("DACL ACE SID is invalid".to_string()));
        }
        if EqualSid(ace_sid, sid.as_ptr() as PSID) == FALSE {
            return Ok(DaclStatus::Weak(
                "DACL ACE SID is not the current user".to_string(),
            ));
        }
        Ok(DaclStatus::Secure)
    }
}

#[cfg(test)]
fn set_everyone_dacl_for_test(path: &Path, inheritance: u32) -> Result<()> {
    // S-1-1-0: revision 1, one subauthority, authority 1, subauthority 0.
    let everyone: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    let wide = wide_path(path);
    unsafe {
        let mut trustee = TRUSTEE_W::default();
        BuildTrusteeWithSidW(&mut trustee, everyone.as_ptr() as PSID);
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee,
        };
        let mut acl: *mut ACL = std::ptr::null_mut();
        let status = SetEntriesInAclW(1, &entry, std::ptr::null::<ACL>(), &mut acl);
        if status != ERROR_SUCCESS {
            return Err(anyhow!("SetEntriesInAclW failed: {}", status_text(status)));
        }
        if acl.is_null() {
            return Err(anyhow!("SetEntriesInAclW returned a null ACL"));
        }
        let _acl = OwnedLocalAlloc(acl as HLOCAL);
        let status = SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl as *const ACL,
            std::ptr::null(),
        );
        if status != ERROR_SUCCESS {
            return Err(anyhow!(
                "SetNamedSecurityInfoW failed: {}",
                status_text(status)
            ));
        }
        Ok(())
    }
}

/// Test helper: replace the DACL with a broad `Everyone (S-1-1-0)` full-control
/// ACE using the same call path as production, so the widening is deterministic.
#[cfg(test)]
pub fn set_everyone_full_dacl_for_test(path: &Path) -> Result<()> {
    set_everyone_dacl_for_test(path, NO_INHERITANCE)
}

/// Test helper: put an inheritable broad ACE on a parent directory so a test
/// can confirm the CA DACL does not retain inherited ACEs.
#[cfg(test)]
pub fn set_inheritable_everyone_dacl_for_test(path: &Path) -> Result<()> {
    set_everyone_dacl_for_test(path, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
}
