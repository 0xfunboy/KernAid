#![deny(unsafe_op_in_unsafe_fn)]
//! Safe, descriptor-only access to Linux block-device identity ioctls.
//!
//! This crate never resolves a pathname or discovers a device. Callers retain
//! ownership of an already-open descriptor and keep it live through `AsFd`.

#[cfg(target_os = "linux")]
use std::{
    io::{self, Write},
    os::fd::{AsFd, AsRawFd, BorrowedFd},
};

#[cfg(target_os = "linux")]
const KERNEL_SECTOR_BYTES: u64 = 512;

/// Kernel-reported properties of one open Linux block-device descriptor.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockDeviceProbe {
    /// Kernel disk sequence returned by `BLKGETDISKSEQ`.
    pub disk_sequence: u64,
    /// Current device size in bytes returned by `BLKGETSIZE64`.
    pub size_bytes: u64,
    /// Logical sector size in bytes returned by `BLKSSZGET`.
    pub logical_sector_bytes: u32,
}

/// Write the fixed broker wire format: three newline-terminated decimal rows.
#[cfg(target_os = "linux")]
pub fn write_probe(output: &mut impl Write, probe: BlockDeviceProbe) -> io::Result<()> {
    writeln!(output, "{}", probe.disk_sequence)?;
    writeln!(output, "{}", probe.size_bytes)?;
    writeln!(output, "{}", probe.logical_sector_bytes)
}

/// Probe one already-open Linux block device without performing path lookup.
///
/// The kernel rejects descriptors which do not implement all three block
/// ioctls. The descriptor is borrowed for the complete probe and is never
/// duplicated, reopened, or closed by this function.
#[cfg(target_os = "linux")]
pub fn probe(descriptor: impl AsFd) -> io::Result<BlockDeviceProbe> {
    let descriptor = descriptor.as_fd();
    validate_descriptor(descriptor)?;
    let disk_sequence = ioctl_get_u64(descriptor, linux_raw_sys::ioctl::BLKGETDISKSEQ)?;
    let size_bytes = ioctl_get_u64(descriptor, linux_raw_sys::ioctl::BLKGETSIZE64)?;
    let logical_sector_bytes = ioctl_get_u32(descriptor, linux_raw_sys::ioctl::BLKSSZGET)?;
    validate_properties(disk_sequence, size_bytes, logical_sector_bytes)
}

#[cfg(target_os = "linux")]
fn validate_descriptor(descriptor: BorrowedFd<'_>) -> io::Result<()> {
    let metadata = rustix::fs::fstat(descriptor)?;
    if !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_block_device() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "descriptor is not a block device",
        ));
    }
    let flags = rustix::fs::fcntl_getfl(descriptor)?;
    if flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
        || !flags.contains(rustix::fs::OFlags::NONBLOCK)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "block descriptor must be read-only and nonblocking",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_properties(
    disk_sequence: u64,
    size_bytes: u64,
    logical_sector_bytes: u32,
) -> io::Result<BlockDeviceProbe> {
    let logical_sector_bytes_u64 = u64::from(logical_sector_bytes);
    if disk_sequence == 0
        || size_bytes == 0
        || !size_bytes.is_multiple_of(KERNEL_SECTOR_BYTES)
        || !(512..=65_536).contains(&logical_sector_bytes)
        || !logical_sector_bytes.is_power_of_two()
        || !size_bytes.is_multiple_of(logical_sector_bytes_u64)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid block-device ioctl properties",
        ));
    }
    Ok(BlockDeviceProbe {
        disk_sequence,
        size_bytes,
        logical_sector_bytes,
    })
}

#[cfg(target_os = "linux")]
fn ioctl_get_u64(descriptor: BorrowedFd<'_>, request: u32) -> io::Result<u64> {
    let mut value = 0_u64;
    // SAFETY: every caller supplies a Linux getter ioctl whose UAPI result is
    // exactly `u64`. `value` is initialized, writable, correctly aligned, and
    // lives through the call; `BorrowedFd` keeps the descriptor valid.
    let result = unsafe {
        libc::ioctl(
            descriptor.as_raw_fd(),
            request as libc::Ioctl,
            &raw mut value,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

#[cfg(target_os = "linux")]
fn ioctl_get_u32(descriptor: BorrowedFd<'_>, request: u32) -> io::Result<u32> {
    let mut value = 0_u32;
    // SAFETY: every caller supplies a Linux getter ioctl whose UAPI result is
    // exactly `u32`. `value` is initialized, writable, correctly aligned, and
    // lives through the call; `BorrowedFd` keeps the descriptor valid.
    let result = unsafe {
        libc::ioctl(
            descriptor.as_raw_fd(),
            request as libc::Ioctl,
            &raw mut value,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{BlockDeviceProbe, probe, validate_properties, write_probe};
    use std::{
        fs::{self, File, OpenOptions},
        io,
        os::unix::fs::OpenOptionsExt,
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TempRegularFile(PathBuf);

    impl Drop for TempRegularFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn open_readonly_nonblocking(path: &std::path::Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
    }

    fn regular_temp_file() -> io::Result<(TempRegularFile, File)> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "kernaid-linux-blockfd-{}-{nonce}.tmp",
            process::id()
        ));
        let created = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        drop(created);
        let descriptor = open_readonly_nonblocking(&path)?;
        Ok((TempRegularFile(path), descriptor))
    }

    #[test]
    fn dev_null_is_rejected() -> io::Result<()> {
        let descriptor = open_readonly_nonblocking(std::path::Path::new("/dev/null"))?;
        match probe(&descriptor) {
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => Ok(()),
            Err(error) => Err(io::Error::other(format!(
                "unexpected rejection for /dev/null: {error}"
            ))),
            Ok(_) => Err(io::Error::other(
                "a non-block descriptor unexpectedly accepted block ioctls",
            )),
        }
    }

    #[test]
    fn regular_temp_file_is_rejected() -> io::Result<()> {
        let (_cleanup, descriptor) = regular_temp_file()?;
        match probe(&descriptor) {
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => Ok(()),
            Err(error) => Err(io::Error::other(format!(
                "unexpected rejection for regular file: {error}"
            ))),
            Ok(_) => Err(io::Error::other(
                "a regular descriptor unexpectedly accepted block ioctls",
            )),
        }
    }

    #[test]
    fn property_validation_is_closed() -> io::Result<()> {
        for (disk_sequence, size_bytes, logical_sector_bytes) in [
            (0, 4096, 512),
            (1, 0, 512),
            (1, 4097, 512),
            (1, 4096, 256),
            (1, 4096, 65_537),
            (1, 4096, 768),
            (1, 4608, 4096),
        ] {
            if validate_properties(disk_sequence, size_bytes, logical_sector_bytes).is_ok() {
                return Err(io::Error::other(
                    "invalid block-device properties were accepted",
                ));
            }
        }
        let expected = BlockDeviceProbe {
            disk_sequence: 7,
            size_bytes: 4096,
            logical_sector_bytes: 512,
        };
        if validate_properties(7, 4096, 512)? != expected {
            return Err(io::Error::other(
                "valid block-device properties changed during validation",
            ));
        }
        Ok(())
    }

    #[test]
    fn probe_wire_format_is_exact() -> io::Result<()> {
        let mut output = Vec::new();
        write_probe(
            &mut output,
            BlockDeviceProbe {
                disk_sequence: 77,
                size_bytes: 32_000_000_000,
                logical_sector_bytes: 512,
            },
        )?;
        if output.as_slice() != b"77\n32000000000\n512\n" {
            return Err(io::Error::other("block probe wire format changed"));
        }
        Ok(())
    }
}
