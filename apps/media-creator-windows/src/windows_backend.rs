use kernaid_media_creator_core::{
    AuthorizedImage, ConfirmedSelection, CreationReport, DiskBackend, DiskCandidate,
    Error as CoreError, MediaHandle, MediaProgress, QUALIFICATION_NAME,
    RELEASE_BUNDLE_MANIFEST_NAME, RETAIL_METADATA_NAME, RETAIL_NAME, authorize_release_bundle,
    create_media_with_progress, decode_release_bundle_trust_anchor,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::{
        IO::DeviceIoControl,
        Ioctl::{FSCTL_DISMOUNT_VOLUME, FSCTL_LOCK_VOLUME},
    },
};
use wmi::WMIConnection;

const TRUSTED_CATALOG: &[u8] =
    include_bytes!("../../../tools/make-device/trusted-rescue-images.v2.json");
const RELEASE_BUNDLE_TRUST_ANCHOR: &str = env!("KERNAID_MEDIA_BUNDLE_TRUST_ANCHOR");
const MAX_BUNDLE_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;

#[derive(Debug)]
pub(crate) enum AppError {
    Message(String),
    Io(io::Error),
    Core(CoreError),
    Wmi(wmi::WMIError),
    Json(serde_json::Error),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Core(error) => write!(formatter, "{error}"),
            Self::Wmi(error) => {
                let _ = error;
                formatter.write_str("Windows disk inventory could not be read")
            }
            Self::Json(error) => {
                let _ = error;
                formatter.write_str("the creation report could not be encoded")
            }
        }
    }
}

impl std::error::Error for AppError {}

impl From<io::Error> for AppError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<CoreError> for AppError {
    fn from(value: CoreError) -> Self {
        Self::Core(value)
    }
}

impl From<wmi::WMIError> for AppError {
    fn from(value: wmi::WMIError) -> Self {
        Self::Wmi(value)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Clone)]
pub(crate) struct LoadedRelease {
    pub(crate) manifest_path: PathBuf,
    pub(crate) image_path: PathBuf,
    pub(crate) authorized: AuthorizedImage,
}

#[derive(Clone)]
pub(crate) struct CreatedMedia {
    pub(crate) report_path: Option<PathBuf>,
    pub(crate) report_warning: Option<String>,
}

pub(crate) fn load_release_bundle(path: &Path) -> Result<LoadedRelease, AppError> {
    require_name(path, RELEASE_BUNDLE_MANIFEST_NAME)?;
    let manifest = read_bounded(path, MAX_BUNDLE_MANIFEST_BYTES, "release bundle manifest")?;
    let parent = path.parent().ok_or_else(|| {
        AppError::Message("the release bundle must be inside a normal folder".to_owned())
    })?;
    let catalog_path = parent.join(kernaid_media_creator_core::CATALOG_NAME);
    let qualification_path = parent.join(QUALIFICATION_NAME);
    let metadata_path = parent.join(RETAIL_METADATA_NAME);
    let image_path = parent.join(RETAIL_NAME);
    let catalog = read_bounded(&catalog_path, MAX_METADATA_BYTES, "catalog entry")?;
    let qualification = read_bounded(
        &qualification_path,
        MAX_METADATA_BYTES,
        "qualification manifest",
    )?;
    let metadata = read_bounded(&metadata_path, MAX_METADATA_BYTES, "retail metadata")?;
    let trust_anchor = decode_release_bundle_trust_anchor(RELEASE_BUNDLE_TRUST_ANCHOR)?;
    let authorized = authorize_release_bundle(
        TRUSTED_CATALOG,
        &manifest,
        &trust_anchor,
        &catalog,
        &qualification,
        &metadata,
    )?;
    let image_metadata = fs::symlink_metadata(&image_path).map_err(|_| {
        AppError::Message("the signed bundle is missing its retail image".to_owned())
    })?;
    if !image_metadata.file_type().is_file()
        || image_metadata.len() != authorized.compressed_bytes()
    {
        return Err(AppError::Message(
            "the retail image is not the exact regular file declared by the signed bundle"
                .to_owned(),
        ));
    }
    Ok(LoadedRelease {
        manifest_path: path.to_path_buf(),
        image_path,
        authorized,
    })
}

pub(crate) fn create_release_media(
    mut backend: WindowsDiskBackend,
    confirmed: ConfirmedSelection,
    release: LoadedRelease,
    progress: impl FnMut(MediaProgress),
) -> Result<CreatedMedia, AppError> {
    let image_metadata = fs::symlink_metadata(&release.image_path)?;
    if !image_metadata.file_type().is_file()
        || image_metadata.len() != release.authorized.compressed_bytes()
    {
        return Err(AppError::Message(
            "the signed retail image changed before verification".to_owned(),
        ));
    }
    let mut image = OpenOptions::new().read(true).open(&release.image_path)?;
    let report = create_media_with_progress(
        &mut backend,
        confirmed,
        RETAIL_NAME,
        &mut image,
        &release.authorized,
        progress,
    )?;
    let report_parent = release
        .manifest_path
        .parent()
        .ok_or_else(|| AppError::Message("the release bundle folder is unavailable".to_owned()))?;
    match save_report(report_parent, &report) {
        Ok(report_path) => Ok(CreatedMedia {
            report_path: Some(report_path),
            report_warning: None,
        }),
        Err(error) => Ok(CreatedMedia {
            report_path: None,
            report_warning: Some(format!(
                "The USB is ready, but the optional creation report could not be saved: {error}"
            )),
        }),
    }
}

fn require_name(path: &Path, expected: &str) -> Result<(), AppError> {
    if path.file_name().and_then(|name| name.to_str()) != Some(expected) {
        return Err(AppError::Message(format!(
            "required filename is exactly {expected}"
        )));
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, AppError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| AppError::Message(format!("the signed bundle is missing {label}")))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(AppError::Message(format!(
            "{label} is not a bounded regular file"
        )));
    }
    Ok(fs::read(path)?)
}

fn create_report_file(parent: &Path) -> Result<(PathBuf, File), AppError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Message("the system clock is invalid".to_owned()))?
        .as_secs();
    for suffix in 0_u8..100 {
        let name = if suffix == 0 {
            format!("KernAid-Media-Creation-report-{timestamp}.json")
        } else {
            format!("KernAid-Media-Creation-report-{timestamp}-{suffix}.json")
        };
        let path = parent.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(AppError::Io(error)),
        }
    }
    Err(AppError::Message(
        "a new creation report filename could not be reserved".to_owned(),
    ))
}

fn save_report(parent: &Path, report: &CreationReport) -> Result<PathBuf, AppError> {
    let (path, mut file) = create_report_file(parent)?;
    if let Err(error) = write_report(&mut file, report) {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    Ok(path)
}

fn write_report(file: &mut File, report: &CreationReport) -> Result<(), AppError> {
    serde_json::to_writer_pretty(&mut *file, report)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[derive(Clone, Debug)]
struct SnapshotDisk {
    number: u32,
    candidate: DiskCandidate,
}

pub(crate) struct WindowsDiskBackend {
    snapshot: BTreeMap<String, SnapshotDisk>,
}

impl WindowsDiskBackend {
    pub(crate) fn new() -> Self {
        Self {
            snapshot: BTreeMap::new(),
        }
    }

    fn query_disks() -> Result<Vec<SnapshotDisk>, AppError> {
        let storage = WMIConnection::with_namespace_path("ROOT\\Microsoft\\Windows\\Storage")?;
        let disks: Vec<MsftDisk> = storage.raw_query(
            "SELECT Number,FriendlyName,SerialNumber,Size,BusType,IsBoot,IsSystem,IsReadOnly,IsOffline FROM MSFT_Disk",
        )?;
        let cim = WMIConnection::new()?;
        let legacy: Vec<Win32Disk> = cim
            .raw_query("SELECT Index,InterfaceType,MediaType,Capabilities FROM Win32_DiskDrive")?;
        let by_index: BTreeMap<u32, Win32Disk> =
            legacy.into_iter().map(|disk| (disk.index, disk)).collect();
        let mut result = Vec::new();
        for disk in disks {
            let model = disk.friendly_name.unwrap_or_default().trim().to_owned();
            let serial = disk.serial_number.unwrap_or_default().trim().to_owned();
            let legacy = by_index.get(&disk.number);
            let removable = legacy.is_some_and(|item| {
                item.media_type
                    .as_deref()
                    .is_some_and(|value| value.eq_ignore_ascii_case("Removable Media"))
                    || item
                        .capabilities
                        .as_ref()
                        .is_some_and(|values| values.contains(&7))
            });
            let interface_usb = legacy
                .and_then(|item| item.interface_type.as_deref())
                .is_some_and(|value| value.eq_ignore_ascii_case("USB"));
            let id_material = format!("{}\0{}\0{}\0{}", disk.number, model, serial, disk.size);
            let digest = format!("{:x}", Sha256::digest(id_material.as_bytes()));
            let opaque_id = format!("KAUSB-{}", &digest[..16]);
            result.push(SnapshotDisk {
                number: disk.number,
                candidate: DiskCandidate {
                    opaque_id,
                    model: model.clone(),
                    serial: serial.clone(),
                    capacity_bytes: disk.size,
                    usb: disk.bus_type == 7 && interface_usb,
                    removable,
                    whole_disk: true,
                    read_only: disk.is_read_only,
                    contains_system: disk.is_system,
                    contains_boot: disk.is_boot,
                    ambiguous: disk.is_offline || model.is_empty() || serial.is_empty(),
                },
            });
        }
        Ok(result)
    }

    fn volume_paths(number: u32) -> Result<Vec<String>, AppError> {
        let storage = WMIConnection::with_namespace_path("ROOT\\Microsoft\\Windows\\Storage")?;
        let query = format!("SELECT AccessPaths FROM MSFT_Partition WHERE DiskNumber = {number}");
        let partitions: Vec<MsftPartition> = storage.raw_query(query)?;
        let mut paths = BTreeSet::new();
        for partition in partitions {
            let access_paths = partition.access_paths.unwrap_or_default();
            let recognized: BTreeSet<String> = access_paths
                .iter()
                .filter_map(|path| normalize_volume_path(path))
                .collect();
            let guid_paths: Vec<&String> = recognized
                .iter()
                .filter(|path| path.starts_with(r"\\?\Volume{"))
                .collect();
            let selected = if guid_paths.len() == 1 {
                guid_paths.first().copied()
            } else if guid_paths.is_empty() && recognized.len() == 1 {
                recognized.iter().next()
            } else {
                None
            };
            if !access_paths.is_empty() && selected.is_none() {
                return Err(AppError::Message(
                    "a mounted USB partition has no unique safely lockable Windows volume path"
                        .to_owned(),
                ));
            }
            if let Some(path) = selected {
                paths.insert(path.clone());
            }
        }
        Ok(paths.into_iter().collect())
    }
}

impl DiskBackend for WindowsDiskBackend {
    type Handle = WindowsDisk;

    fn enumerate(&mut self) -> Result<Vec<DiskCandidate>, CoreError> {
        let disks =
            Self::query_disks().map_err(|error| CoreError::InvalidInputOwned(error.to_string()))?;
        self.snapshot.clear();
        for disk in &disks {
            self.snapshot
                .insert(disk.candidate.opaque_id.clone(), disk.clone());
        }
        Ok(disks.into_iter().map(|disk| disk.candidate).collect())
    }

    fn open_revalidated(&mut self, selected: &DiskCandidate) -> Result<Self::Handle, CoreError> {
        let old = self
            .snapshot
            .get(&selected.opaque_id)
            .filter(|snapshot| snapshot.candidate == *selected)
            .cloned()
            .ok_or(CoreError::InvalidInput(
                "disk selection was not produced by this enumeration",
            ))?;
        let fresh_inventory =
            Self::query_disks().map_err(|error| CoreError::InvalidInputOwned(error.to_string()))?;
        let identity_count = fresh_inventory
            .iter()
            .filter(|disk| {
                disk.candidate.opaque_id == old.candidate.opaque_id
                    || disk.candidate.serial == old.candidate.serial
            })
            .count();
        let fresh = fresh_inventory
            .into_iter()
            .filter(|disk| disk.number == old.number && disk.candidate == old.candidate)
            .collect::<Vec<_>>();
        if fresh.len() != 1 || identity_count != 1 {
            return Err(CoreError::InvalidInput(
                "USB identity or safety properties changed before opening",
            ));
        }
        let volume_paths = Self::volume_paths(old.number)
            .map_err(|error| CoreError::InvalidInputOwned(error.to_string()))?;
        let mut volume_locks = Vec::new();
        for path in volume_paths {
            let volume = OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .open(path)
                .map_err(|_| {
                    CoreError::InvalidInput(
                        "a USB volume could not be opened for an exclusive lock",
                    )
                })?;
            lock_and_dismount(&volume).map_err(|_| {
                CoreError::InvalidInput("a USB volume could not be locked and dismounted")
            })?;
            volume_locks.push(volume);
        }
        let generated_path = format!(r"\\.\PhysicalDrive{}", old.number);
        let disk = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(generated_path)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::PermissionDenied {
                    CoreError::InvalidInput(
                        "Windows did not grant administrator access to this removable USB drive",
                    )
                } else {
                    CoreError::Io(error)
                }
            })?;
        Ok(WindowsDisk {
            disk,
            _volume_locks: volume_locks,
        })
    }
}

pub(crate) struct WindowsDisk {
    disk: File,
    _volume_locks: Vec<File>,
}

impl Read for WindowsDisk {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.disk.read(buffer)
    }
}

impl Write for WindowsDisk {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.disk.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.disk.flush()
    }
}

impl Seek for WindowsDisk {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.disk.seek(position)
    }
}

impl MediaHandle for WindowsDisk {
    fn sync_all(&mut self) -> io::Result<()> {
        self.disk.sync_all()
    }
}

fn lock_and_dismount(volume: &File) -> io::Result<()> {
    control(volume, FSCTL_LOCK_VOLUME)?;
    control(volume, FSCTL_DISMOUNT_VOLUME)
}

fn control(file: &File, code: u32) -> io::Result<()> {
    let mut returned = 0_u32;
    // SAFETY: the borrowed File owns a valid synchronous Windows handle for
    // the duration of the call. Both selected FSCTLs take no input/output
    // buffers; null pointers and zero lengths are their documented contract.
    let result = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as HANDLE,
            code,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn normalize_volume_path(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.starts_with(r"\\?\Volume{") && trimmed.ends_with('\\') {
        return Some(trimmed.trim_end_matches('\\').to_owned());
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() == 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return Some(format!(
            r"\\.\{}:",
            char::from(bytes[0]).to_ascii_uppercase()
        ));
    }
    None
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MsftDisk {
    number: u32,
    friendly_name: Option<String>,
    serial_number: Option<String>,
    size: u64,
    bus_type: u16,
    is_boot: bool,
    is_system: bool,
    is_read_only: bool,
    is_offline: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Win32Disk {
    index: u32,
    interface_type: Option<String>,
    media_type: Option<String>,
    capabilities: Option<Vec<u16>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MsftPartition {
    access_paths: Option<Vec<String>>,
}
