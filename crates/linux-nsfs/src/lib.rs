#![deny(unsafe_op_in_unsafe_fn)]
//! Minimal safe wrappers for the Linux nsfs identity ioctls KernAid uses.
//!
//! Keeping the syscall boundaries in this leaf crate lets every process that
//! handles vault or provider state continue to forbid unsafe Rust.

#[cfg(target_os = "linux")]
use std::{
    io,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
};

/// Kernel namespace type returned by `NS_GET_NSTYPE`.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespaceType(i32);

#[cfg(target_os = "linux")]
impl NamespaceType {
    /// Mount namespace (`CLONE_NEWNS`).
    pub const MOUNT: Self = Self(libc::CLONE_NEWNS);
    /// Network namespace (`CLONE_NEWNET`).
    pub const NETWORK: Self = Self(libc::CLONE_NEWNET);
    /// User namespace (`CLONE_NEWUSER`).
    pub const USER: Self = Self(libc::CLONE_NEWUSER);
}

/// Return the kernel-authenticated namespace type for an nsfs descriptor.
#[cfg(target_os = "linux")]
pub fn namespace_type(descriptor: impl AsFd) -> io::Result<NamespaceType> {
    // SAFETY: NS_GET_NSTYPE takes no pointer argument and neither reads nor
    // writes userspace memory. `AsFd` keeps the descriptor live for the call.
    let result = unsafe {
        libc::ioctl(
            descriptor.as_fd().as_raw_fd(),
            libc::NS_GET_NSTYPE as libc::c_ulong,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else if matches!(
        result,
        libc::CLONE_NEWCGROUP
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWTIME
            | libc::CLONE_NEWUSER
            | libc::CLONE_NEWUTS
    ) {
        Ok(NamespaceType(result))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown namespace type",
        ))
    }
}

/// Return the owning user namespace for a non-user nsfs descriptor.
///
/// The returned descriptor is always close-on-exec before it becomes visible
/// to callers. This API never accepts a path or namespace identifier.
#[cfg(target_os = "linux")]
pub fn owner_user_namespace(descriptor: impl AsFd) -> io::Result<OwnedFd> {
    // SAFETY: NS_GET_USERNS takes no pointer argument and returns either a new
    // owned file descriptor or -1. `AsFd` keeps the input live for the call.
    let raw = unsafe {
        libc::ioctl(
            descriptor.as_fd().as_raw_fd(),
            libc::NS_GET_USERNS as libc::c_ulong,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful NS_GET_USERNS result is a fresh descriptor whose
    // ownership is transferred exactly once into this OwnedFd.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let flags = rustix::io::fcntl_getfd(&owned)?;
    rustix::io::fcntl_setfd(&owned, flags | rustix::io::FdFlags::CLOEXEC)?;
    Ok(owned)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{fs::File, os::unix::fs::MetadataExt};

    #[test]
    fn namespace_types_are_kernel_authenticated() {
        let mount = File::open("/proc/self/ns/mnt").expect("mount namespace");
        let user = File::open("/proc/self/ns/user").expect("user namespace");
        let network = File::open("/proc/self/ns/net").expect("network namespace");
        assert_eq!(
            namespace_type(&mount).expect("mount namespace type"),
            NamespaceType::MOUNT
        );
        assert_eq!(
            namespace_type(&user).expect("user namespace type"),
            NamespaceType::USER
        );
        assert_eq!(
            namespace_type(&network).expect("network namespace type"),
            NamespaceType::NETWORK
        );
    }

    #[test]
    fn mount_owner_is_current_user_namespace_and_cloexec() {
        let mount = File::open("/proc/self/ns/mnt").expect("mount namespace");
        let owner = owner_user_namespace(&mount).expect("owner user namespace");
        let current = File::open("/proc/self/ns/user").expect("current user namespace");
        let owner_stat = File::from(owner.try_clone().expect("clone owner namespace"))
            .metadata()
            .expect("owner metadata");
        let current_stat = current.metadata().expect("current metadata");
        assert_eq!(
            (owner_stat.dev(), owner_stat.ino()),
            (current_stat.dev(), current_stat.ino())
        );
        let flags = rustix::io::fcntl_getfd(&owner).expect("owner descriptor flags");
        assert_eq!(flags, rustix::io::FdFlags::CLOEXEC);
    }

    #[test]
    fn owner_lookup_rejects_user_namespace_input() {
        let user = File::open("/proc/self/ns/user").expect("user namespace");
        assert!(owner_user_namespace(&user).is_err());
    }

    #[test]
    fn regular_file_is_rejected_by_both_nsfs_calls() {
        let regular = File::open("/dev/null").expect("regular descriptor");
        assert!(namespace_type(&regular).is_err());
        assert!(owner_user_namespace(&regular).is_err());
    }
}
