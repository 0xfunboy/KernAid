//! Fixed, read-only Windows Resident P0 collector contract.
//!
//! Collector programs, arguments, and PowerShell scripts in this module are
//! compile-time constants. Observed data is returned only on stdout and is
//! validated by `kernaid-windows-pack` before Desk exposes it.

use crate::diagnostics::EvidenceInput;
#[cfg(test)]
use crate::diagnostics::{WindowsP0Inputs, diagnose_windows_p0};
use serde::Serialize;
#[cfg(test)]
use std::collections::BTreeMap;
use std::time::Duration;

/// Opaque failure at the fixed collector-to-projection boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentContractError;

#[cfg(target_os = "windows")]
pub const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
#[cfg(target_os = "windows")]
pub const DISM: &str = r"C:\Windows\System32\dism.exe";
#[cfg(target_os = "windows")]
pub const REG: &str = r"C:\Windows\System32\reg.exe";
#[cfg(target_os = "windows")]
pub const BCDEDIT: &str = r"C:\Windows\System32\bcdedit.exe";
pub const WINDOWS_ENVIRONMENT: [(&str, &str); 4] = [
    ("SystemRoot", r"C:\Windows"),
    ("WINDIR", r"C:\Windows"),
    (
        "PSModulePath",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules",
    ),
    ("POWERSHELL_TELEMETRY_OPTOUT", "1"),
];

#[cfg(target_os = "windows")]
pub const POWERSHELL_PREFIX_ARGS: [&str; 4] =
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"];
pub const DISM_ARGS: [&str; 4] = ["/Online", "/Cleanup-Image", "/CheckHealth", "/English"];
#[cfg(target_os = "windows")]
pub const FIRMWARE_REG_ARGS: [&str; 4] = [
    "QUERY",
    r"HKLM\SYSTEM\CurrentControlSet\Control",
    "/v",
    "PEFirmwareType",
];
pub const BOOT_MANAGER_ARGS: [&str; 2] = ["/enum", "{bootmgr}"];
pub const OS_LOADER_ARGS: [&str; 2] = ["/enum", "osloader"];
pub const DEFAULT_LOADER_ARGS: [&str; 2] = ["/enum", "{default}"];

pub const POWERSHELL_TIMEOUT: Duration = Duration::from_secs(45);
pub const DISM_TIMEOUT: Duration = Duration::from_secs(90);
pub const BOOT_TIMEOUT: Duration = Duration::from_secs(30);
pub const P0_WALL_CLOCK_BUDGET: Duration = Duration::from_secs(150);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectorKind {
    PowerShell(&'static str),
    Dism,
    SfcNotRunUnqualified,
    Boot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollectorSpec {
    pub collector: &'static str,
    pub kind: CollectorKind,
}

pub const COLLECTORS: [CollectorSpec; 11] = [
    CollectorSpec {
        collector: "windows.event-log.window",
        kind: CollectorKind::PowerShell(EVENT_LOG_SCRIPT),
    },
    CollectorSpec {
        collector: "windows.reliability.records",
        kind: CollectorKind::PowerShell(RELIABILITY_SCRIPT),
    },
    CollectorSpec {
        collector: "windows.component-store.check-health",
        kind: CollectorKind::Dism,
    },
    CollectorSpec {
        collector: "windows.sfc.verify-only",
        kind: CollectorKind::SfcNotRunUnqualified,
    },
    CollectorSpec {
        collector: "windows.update.state",
        kind: CollectorKind::PowerShell(UPDATE_SCRIPT),
    },
    CollectorSpec {
        collector: "windows.services.state",
        kind: CollectorKind::PowerShell(SERVICES_SCRIPT),
    },
    CollectorSpec {
        collector: "windows.network.state",
        kind: CollectorKind::PowerShell(NETWORK_SCRIPT),
    },
    CollectorSpec {
        collector: "windows.drivers.state",
        kind: CollectorKind::PowerShell(DRIVERS_SCRIPT),
    },
    CollectorSpec {
        collector: "windows.bitlocker.state",
        kind: CollectorKind::PowerShell(BITLOCKER_SCRIPT),
    },
    CollectorSpec {
        collector: "windows.boot.state",
        kind: CollectorKind::Boot,
    },
    CollectorSpec {
        collector: "windows.volumes.state",
        kind: CollectorKind::PowerShell(VOLUMES_SCRIPT),
    },
];

const EVENT_LOG_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='Stop'
$VerbosePreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
$utf8=New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding=$utf8
$since=[DateTime]::UtcNow.AddHours(-168)
$events=@()
try {
  $events=@(Get-WinEvent -FilterHashtable @{LogName=@('System','Application');StartTime=$since;Level=@(1,2,3,4)} -MaxEvents 4097 -ErrorAction Stop)
} catch {
  if ($_.FullyQualifiedErrorId -notmatch '^NoMatchingEventsFound') { throw }
}
if ($events.Count -gt 4096) { throw 'bounded event window exceeded' }
$records=@($events | Sort-Object LogName,RecordId | ForEach-Object {
  if ($null -eq $_.TimeCreated -or $null -eq $_.RecordId) { throw 'incomplete event record' }
  $level=switch ([int]$_.Level) { 1 {'Critical'} 2 {'Error'} 3 {'Warning'} 4 {'Information'} default { throw 'unsupported event level' } }
  [ordered]@{
    logName=[string]$_.LogName
    recordId=[uint64]$_.RecordId
    providerName=[string]$_.ProviderName
    eventId=[uint32]$_.Id
    level=$level
    timestampUtc=$_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture)
  }
})
[ordered]@{lookbackHours=168;queryComplete=$true;records=$records} | ConvertTo-Json -Depth 6 -Compress
"#;

const RELIABILITY_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='Stop'
$VerbosePreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
$utf8=New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding=$utf8
$since=[DateTime]::UtcNow.AddHours(-168)
$dmtf=[System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($since.ToLocalTime())
try {
  $items=@(Get-CimInstance -ClassName Win32_ReliabilityRecords -Filter "TimeGenerated >= '$dmtf'" -ErrorAction Stop)
} catch {
  [ordered]@{lookbackHours=168;queryState='unavailable';records=@()} | ConvertTo-Json -Depth 6 -Compress
  exit 0
}
if ($items.Count -gt 4096) { throw 'bounded reliability window exceeded' }
$records=@($items | Sort-Object LogFile,RecordNumber,TimeGenerated | ForEach-Object {
  if ($null -eq $_.TimeGenerated -or $null -eq $_.LogFile -or $null -eq $_.RecordNumber) { throw 'incomplete reliability record' }
  $source=[string]$_.SourceName
  $eventId=[uint32]$_.EventIdentifier
  $recordType=if ($source -eq 'Microsoft-Windows-WHEA-Logger') {'HardwareFailure'} elseif ($eventId -eq 1000 -or $eventId -eq 1002 -or $source -eq 'Application Error' -or $source -eq 'Application Hang') {'ApplicationFailure'} elseif ($eventId -eq 1001 -or $source -eq 'Windows Error Reporting') {'WindowsFailure'} else {'Informational'}
  $product=if ([string]::IsNullOrWhiteSpace([string]$_.ProductName)) {$null} else {[string]$_.ProductName}
  [ordered]@{
    logFile=[string]$_.LogFile
    recordNumber=[uint32]$_.RecordNumber
    sourceName=$source
    productName=$product
    recordType=$recordType
    timestampUtc=$_.TimeGenerated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture)
  }
})
[ordered]@{lookbackHours=168;queryState='complete';records=$records} | ConvertTo-Json -Depth 6 -Compress
"#;

const UPDATE_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='Stop'
$VerbosePreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
$utf8=New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding=$utf8
$since=[DateTime]::UtcNow.AddHours(-168)
$cbs=Test-Path -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
$wu=Test-Path -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
$sessionManager=Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
$renameProperty=$sessionManager.PSObject.Properties['PendingFileRenameOperations']
$rename=($null -ne $renameProperty -and $null -ne $renameProperty.Value -and @($renameProperty.Value).Count -gt 0)
$scanState='unavailable'
$lastScan=$null
$failed=@()
try {
  $session=New-Object -ComObject Microsoft.Update.Session
  $searcher=$session.CreateUpdateSearcher()
  $total=[int]$searcher.GetTotalHistoryCount()
  $take=[Math]::Min($total,4097)
  $history=if ($take -gt 0) {@($searcher.QueryHistory(0,$take))} else {@()}
  if ($take -eq 4097 -and $history[-1].Date.ToUniversalTime() -ge $since) { throw 'bounded update window exceeded' }
  $detect=(Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect' -Name LastSuccessTime -ErrorAction Stop).LastSuccessTime
  $parsed=[DateTime]::MinValue
  if (-not [DateTime]::TryParse([string]$detect,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeLocal,[ref]$parsed)) { throw 'invalid update scan time' }
  $lastScan=$parsed.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture)
  $seen=@{}
  foreach ($entry in @($history | Where-Object {$_.Date.ToUniversalTime() -ge $since -and ($_.ResultCode -eq 4 -or $_.ResultCode -eq 5)} | Sort-Object Date -Descending)) {
    if ($null -eq $entry.UpdateIdentity -or [string]::IsNullOrWhiteSpace([string]$entry.UpdateIdentity.UpdateID)) { throw 'failed update without identity' }
    $id=([Guid]$entry.UpdateIdentity.UpdateID).ToString('D')
    if (-not $seen.ContainsKey($id)) {
      $code=[uint32]([int64]$entry.HResult -band 0xffffffffL)
      $seen[$id]=[ordered]@{updateId=$id;hresult=('0x{0:X8}' -f $code)}
    }
  }
  $failed=@($seen.Keys | Sort-Object | ForEach-Object {$seen[$_]})
  if ($failed.Count -gt 4096) { throw 'bounded failed update set exceeded' }
  $scanState='complete'
} catch {
  $scanState='unavailable'
  $lastScan=$null
  $failed=@()
}
$pending=($cbs -or $wu -or $rename)
[ordered]@{
  historyLookbackHours=168
  scanState=$scanState
  pendingReboot=$pending
  cbsRebootPending=[bool]$cbs
  windowsUpdateRebootPending=[bool]$wu
  pendingFileRenameOperations=[bool]$rename
  lastSuccessfulScanUtc=$lastScan
  failedUpdates=$failed
} | ConvertTo-Json -Depth 7 -Compress
"#;

const SERVICES_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='Stop'
$VerbosePreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
$utf8=New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding=$utf8
$items=@(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
if ($items.Count -eq 0 -or $items.Count -gt 4096) { throw 'invalid service inventory size' }
$services=@($items | Sort-Object Name | ForEach-Object {
  $delayed=$false
  if ($null -ne $_.PSObject.Properties['DelayedAutoStart']) { $delayed=[bool]$_.DelayedAutoStart }
  $start=switch ([string]$_.StartMode) { 'Boot' {'boot'} 'System' {'system'} 'Auto' {if ($delayed) {'automatic-delayed'} else {'automatic'}} 'Manual' {'manual'} 'Disabled' {'disabled'} default { throw 'unsupported service start mode' } }
  $state=switch ([string]$_.State) { 'Running' {'running'} 'Stopped' {'stopped'} 'Start Pending' {'start-pending'} 'Stop Pending' {'stop-pending'} 'Continue Pending' {'continue-pending'} 'Pause Pending' {'pause-pending'} 'Paused' {'paused'} default {'unknown'} }
  [ordered]@{name=[string]$_.Name;startMode=$start;state=$state;win32ExitCode=[uint32]$_.ExitCode}
})
[ordered]@{snapshotComplete=$true;services=$services} | ConvertTo-Json -Depth 6 -Compress
"#;

const NETWORK_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='Stop'
$VerbosePreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
$utf8=New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding=$utf8
$adapterItems=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
$routeItems=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop)
$dnsItems=@(Get-DnsClientServerAddress -ErrorAction Stop)
if ($adapterItems.Count -gt 4096 -or $routeItems.Count -gt 4096 -or $dnsItems.Count -gt 4096) { throw 'bounded network inventory exceeded' }
$adapterMap=@{}
foreach ($item in $adapterItems) {
  $index=[uint32]$item.ifIndex
  $key=[string]$index
  if ($index -eq 0 -or $adapterMap.ContainsKey($key)) { throw 'invalid adapter identity' }
  $state=switch ([string]$item.Status) { 'Up' {'Up'} 'Down' {'Down'} 'Disconnected' {'Down'} 'Disabled' {'Down'} 'Not Present' {'Down'} default {'Unknown'} }
  $adapterMap[$key]=[ordered]@{interfaceIndex=$index;status=$state;hardwareInterface=[bool]$item.HardwareInterface}
}
foreach ($item in (@($routeItems) + @($dnsItems))) {
  $index=[uint32]$item.InterfaceIndex
  $key=[string]$index
  if ($index -eq 0) { throw 'invalid network interface identity' }
  if (-not $adapterMap.ContainsKey($key)) {
    $adapterMap[$key]=[ordered]@{interfaceIndex=$index;status='Unknown';hardwareInterface=$false}
  }
}
if ($adapterMap.Count -gt 4096) { throw 'bounded adapter inventory exceeded' }
$adapters=@($adapterMap.Keys | Sort-Object {[uint32]$_} | ForEach-Object {
  $adapterMap[$_]
})
$routes=@($routeItems | Sort-Object DestinationPrefix,ifIndex,NextHop,RouteMetric | ForEach-Object {
  $destination=[string]$_.DestinationPrefix
  $next=[string]$_.NextHop
  if ([string]::IsNullOrWhiteSpace($next)) { if ($destination.Contains(':')) {$next='::'} else {$next='0.0.0.0'} }
  [ordered]@{destinationPrefix=$destination;interfaceIndex=[uint32]$_.ifIndex;nextHop=$next;routeMetric=[uint32]$_.RouteMetric}
})
$dnsMap=@{}
foreach ($item in $dnsItems) {
  $key=[string][uint32]$item.InterfaceIndex
  if (-not $dnsMap.ContainsKey($key)) { $dnsMap[$key]=New-Object 'System.Collections.Generic.List[string]' }
  foreach ($address in @($item.ServerAddresses)) { if (-not [string]::IsNullOrWhiteSpace([string]$address)) { $dnsMap[$key].Add([string]$address) } }
}
$dns=@($dnsMap.Keys | Sort-Object {[uint32]$_} | ForEach-Object {
  [ordered]@{interfaceIndex=[uint32]$_;addresses=@($dnsMap[$_] | Sort-Object -Unique)}
})
[ordered]@{snapshotComplete=$true;adapters=$adapters;routes=$routes;dnsServers=$dns} | ConvertTo-Json -Depth 7 -Compress
"#;

const DRIVERS_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='Stop'
$VerbosePreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
$utf8=New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding=$utf8
$signed=@(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop)
$entities=@(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop)
if ($signed.Count -eq 0 -or $signed.Count -gt 4096 -or $entities.Count -gt 4096) { throw 'invalid driver inventory size' }
$entityMap=@{}
foreach ($entity in $entities) { if (-not [string]::IsNullOrWhiteSpace([string]$entity.DeviceID)) { $entityMap[[string]$entity.DeviceID]=$entity } }
$drivers=@($signed | Sort-Object DeviceID | ForEach-Object {
  $id=[string]$_.DeviceID
  if ([string]::IsNullOrWhiteSpace($id)) { throw 'driver without device identity' }
  $entity=$entityMap[$id]
  $status=if ($null -eq $entity) {'Unknown'} else {switch ([string]$entity.Status) {'OK' {'Ok'} 'Error' {'Error'} 'Degraded' {'Degraded'} default {'Unknown'}}}
  $problem=if ($null -eq $entity -or $null -eq $entity.ConfigManagerErrorCode) {0} else {[uint16]$entity.ConfigManagerErrorCode}
  $version=if ([string]::IsNullOrWhiteSpace([string]$_.DriverVersion)) {'0'} else {[string]$_.DriverVersion}
  $date=if ($null -eq $_.DriverDate) {'1601-01-01T00:00:00Z'} else {$_.DriverDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture)}
  [ordered]@{deviceId=$id;status=$status;problemCode=$problem;signed=[bool]$_.IsSigned;driverVersion=$version;driverDateUtc=$date}
})
$since=[DateTime]::UtcNow.AddHours(-168)
$changes=@()
$seen=@{}
foreach ($hotfix in @(Get-HotFix -ErrorAction Stop)) {
  if ($null -ne $hotfix.InstalledOn -and $hotfix.InstalledOn.ToUniversalTime() -ge $since -and -not [string]::IsNullOrWhiteSpace([string]$hotfix.HotFixID)) {
    $time=$hotfix.InstalledOn.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture)
    $key=([string]$hotfix.HotFixID).ToLowerInvariant()+'|'+$time
    if (-not $seen.ContainsKey($key)) { $seen[$key]=$true; $changes+=,[ordered]@{kind='update';identifier=[string]$hotfix.HotFixID;installedAtUtc=$time} }
  }
}
if ($changes.Count -gt 4096) { throw 'bounded driver change window exceeded' }
[ordered]@{changeLookbackHours=168;snapshotComplete=$true;drivers=$drivers;recentChanges=@($changes | Sort-Object installedAtUtc,identifier)} | ConvertTo-Json -Depth 7 -Compress
"#;

const BITLOCKER_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='Stop'
$VerbosePreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
$utf8=New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding=$utf8
try {
  $os=(Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Select-Object -First 1)
  $systemDrive=[string]$os.SystemDrive
  $logical=@(Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop)
  $driveTypes=@{}
  foreach ($disk in $logical) { $driveTypes[[string]$disk.DeviceID]=[uint32]$disk.DriveType }
  $items=@(Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop | Where-Object {-not [string]::IsNullOrWhiteSpace([string]$_.DriveLetter)})
  if ($items.Count -gt 4096) { throw 'bounded BitLocker inventory exceeded' }
  $volumes=@($items | Sort-Object DriveLetter | ForEach-Object {
    $conversion=Invoke-CimMethod -InputObject $_ -MethodName GetConversionStatus -Arguments @{PrecisionFactor=[uint32]0} -ErrorAction Stop
    $conversionState=switch ([uint32]$conversion.ConversionStatus) {0 {'fully-decrypted'} 1 {'fully-encrypted'} 2 {'encryption-in-progress'} 3 {'decryption-in-progress'} 4 {'encryption-paused'} 5 {'decryption-paused'} default {'unknown'}}
    $protection=switch ([uint32]$_.ProtectionStatus) {0 {'Off'} 1 {'On'} default {'Unknown'}}
    $lock=switch ([uint32]$_.LockStatus) {0 {'Unlocked'} 1 {'Locked'} default {'Unknown'}}
    $letter=[string]$_.DriveLetter
    $type=if ($letter -ieq $systemDrive) {'OperatingSystem'} elseif ($driveTypes[$letter] -eq 2) {'RemovableData'} else {'FixedData'}
    [ordered]@{mountPoint=$letter;volumeType=$type;protectionStatus=$protection;lockStatus=$lock;conversionStatus=$conversionState;encryptionPercentage=[uint32]$conversion.EncryptionPercentage}
  })
  [ordered]@{queryState='complete';volumes=$volumes} | ConvertTo-Json -Depth 7 -Compress
} catch {
  [ordered]@{queryState='unavailable';volumes=@()} | ConvertTo-Json -Depth 4 -Compress
}
"#;

pub const VOLUMES_SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='Stop'
$VerbosePreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
$utf8=New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding=$utf8
$os=(Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Select-Object -First 1)
$systemDrive=[string]$os.SystemDrive
$items=@(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)
if ($items.Count -eq 0 -or $items.Count -gt 4096) { throw 'invalid volume inventory size' }
$volumes=@($items | Sort-Object DeviceID | ForEach-Object {
  if ($null -eq $_.Size -or $null -eq $_.FreeSpace) { throw 'incomplete volume capacity' }
  $filesystem=if ([string]::IsNullOrWhiteSpace([string]$_.FileSystem)) {'UNKNOWN'} else {[string]$_.FileSystem}
  [ordered]@{driveLetter=[string]$_.DeviceID;fileSystem=$filesystem;capacityBytes=[uint64]$_.Size;freeBytes=[uint64]$_.FreeSpace;systemVolume=([string]$_.DeviceID -ieq $systemDrive)}
})
[ordered]@{snapshotComplete=$true;volumes=$volumes} | ConvertTo-Json -Depth 6 -Compress
"#;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ComponentStoreProjection<'a> {
    check_mode: &'a str,
    state: &'a str,
    exit_code: i32,
    reboot_required: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SfcProjection<'a> {
    mode: &'a str,
    execution_state: &'a str,
    state: &'a str,
    exit_code: i32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BootProjection<'a> {
    query_state: &'a str,
    firmware_type: Option<&'a str>,
    windows_boot_manager_present: Option<bool>,
    os_loader_count: Option<u16>,
    default_loader_present: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StorageIdentityProjection {
    schema_version: u8,
    volumes: Vec<StorageIdentityVolume>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StorageIdentityVolume {
    drive_letter: String,
    file_system: String,
    capacity_bytes: u64,
    system_volume: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeOutput<'a> {
    pub stdout: &'a str,
    pub exit_code: i32,
}

pub fn normalize_dism(
    stdout: &str,
    stderr: &str,
    exit_code: i32,
) -> Result<String, ResidentContractError> {
    let observed = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    let state = if observed.contains("no component store corruption detected") {
        "healthy"
    } else if observed.contains("the component store is repairable") {
        "repairable"
    } else if observed.contains("the component store cannot be repaired") {
        "non-repairable"
    } else {
        "unknown"
    };
    let reboot_required = observed.contains("restart is required")
        || observed.contains("reboot required")
        || exit_code == 3010;
    let encoded = serde_json::to_string(&ComponentStoreProjection {
        check_mode: "check-health-read-only",
        state,
        exit_code,
        reboot_required,
    })
    .map_err(|_| ResidentContractError)?;
    validate_projection("windows.component-store.check-health", &encoded)?;
    Ok(encoded)
}

/// SFC is deliberately not launched by the Resident P0 collector. Its console
/// text is localized and there is no qualified, language-independent result
/// adapter in this milestone. Keeping a typed projection preserves the exact
/// 11-document corpus without claiming that verification ran or succeeded.
pub fn sfc_not_run_projection() -> Result<String, ResidentContractError> {
    let encoded = serde_json::to_string(&SfcProjection {
        mode: "verify-only",
        execution_state: "not-run-unqualified",
        state: "could-not-verify",
        exit_code: -1,
    })
    .map_err(|_| ResidentContractError)?;
    validate_projection("windows.sfc.verify-only", &encoded)?;
    Ok(encoded)
}

fn brace_tokens(value: &str) -> Vec<String> {
    let bytes = value.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        if bytes[cursor] != b'{' {
            cursor += 1;
            continue;
        }
        let Some(relative_end) = bytes[cursor..].iter().position(|byte| *byte == b'}') else {
            break;
        };
        let end = cursor + relative_end;
        if end.saturating_sub(cursor) <= 64 {
            tokens.push(value[cursor..=end].to_ascii_lowercase());
        }
        cursor = end.saturating_add(1);
    }
    tokens
}

fn block_identifiers(value: &str) -> Vec<String> {
    let normalized = value.replace("\r\n", "\n");
    normalized
        .split("\n\n")
        .filter_map(|block| brace_tokens(block).into_iter().next())
        .collect()
}

pub fn normalize_boot(
    firmware: NativeOutput<'_>,
    manager: NativeOutput<'_>,
    loaders: NativeOutput<'_>,
    default_loader: NativeOutput<'_>,
) -> Result<String, ResidentContractError> {
    let command_failed = firmware.exit_code != 0
        || manager.exit_code != 0
        || loaders.exit_code != 0
        || default_loader.exit_code != 0;
    let complete = if command_failed {
        None
    } else {
        let firmware_lower = firmware.stdout.to_ascii_lowercase();
        let firmware_type = if firmware_lower
            .split_whitespace()
            .any(|token| token == "0x2")
        {
            Some("Uefi")
        } else if firmware_lower
            .split_whitespace()
            .any(|token| token == "0x1")
        {
            Some("Bios")
        } else {
            None
        };
        let manager_tokens = brace_tokens(manager.stdout);
        let loader_ids = block_identifiers(loaders.stdout);
        let default_ids = block_identifiers(default_loader.stdout);
        let windows_boot_manager_present = manager_tokens
            .first()
            .is_some_and(|token| token == "{bootmgr}");
        let default_loader_present = default_ids
            .first()
            .filter(|_| default_ids.len() == 1)
            .map(|identifier| loader_ids.contains(identifier));
        firmware_type.zip(default_loader_present).and_then(
            |(firmware_type, default_loader_present)| {
                let loader_count = u16::try_from(loader_ids.len()).ok()?;
                if loader_count > 256 {
                    return None;
                }
                Some((
                    firmware_type,
                    windows_boot_manager_present,
                    loader_count,
                    default_loader_present,
                ))
            },
        )
    };
    let projection =
        if let Some((firmware_type, manager_present, loader_count, default_present)) = complete {
            BootProjection {
                query_state: "complete",
                firmware_type: Some(firmware_type),
                windows_boot_manager_present: Some(manager_present),
                os_loader_count: Some(loader_count),
                default_loader_present: Some(default_present),
            }
        } else {
            BootProjection {
                query_state: "unavailable",
                firmware_type: None,
                windows_boot_manager_present: None,
                os_loader_count: None,
                default_loader_present: None,
            }
        };
    let encoded = serde_json::to_string(&projection).map_err(|_| ResidentContractError)?;
    validate_projection("windows.boot.state", &encoded)?;
    Ok(encoded)
}

/// Derives a stable, non-secret target binding from the schema-valid volume
/// projection. Volatile free-space and deep boot-query state are deliberately
/// excluded so startup, Diagnose and Verify use the same fast identity path.
pub fn derive_storage_identity(volumes_body: &str) -> Result<String, ResidentContractError> {
    use crate::diagnostics::parse_volumes;

    let volumes = parse_volumes(EvidenceInput {
        id: "E-WIN-IDENTITY-VOLUMES",
        body: volumes_body.as_bytes(),
    })
    .map_err(|_| ResidentContractError)?;
    let mut canonical_volumes = volumes
        .volumes
        .into_iter()
        .map(|volume| StorageIdentityVolume {
            drive_letter: volume.drive_letter.to_ascii_uppercase(),
            file_system: volume.file_system.to_ascii_uppercase(),
            capacity_bytes: volume.capacity_bytes,
            system_volume: volume.system_volume,
        })
        .collect::<Vec<_>>();
    canonical_volumes.sort_by(|left, right| left.drive_letter.cmp(&right.drive_letter));
    let encoded = serde_json::to_string(&StorageIdentityProjection {
        schema_version: 2,
        volumes: canonical_volumes,
    })
    .map_err(|_| ResidentContractError)?;
    if encoded.len() > crate::diagnostics::MAX_INPUT_BYTES {
        return Err(ResidentContractError);
    }
    Ok(encoded)
}

fn validation_id(collector: &str) -> Option<&'static str> {
    match collector {
        "windows.event-log.window" => Some("E-WIN-COLLECT-1"),
        "windows.reliability.records" => Some("E-WIN-COLLECT-2"),
        "windows.component-store.check-health" => Some("E-WIN-COLLECT-3"),
        "windows.sfc.verify-only" => Some("E-WIN-COLLECT-4"),
        "windows.update.state" => Some("E-WIN-COLLECT-5"),
        "windows.services.state" => Some("E-WIN-COLLECT-6"),
        "windows.network.state" => Some("E-WIN-COLLECT-7"),
        "windows.drivers.state" => Some("E-WIN-COLLECT-8"),
        "windows.bitlocker.state" => Some("E-WIN-COLLECT-9"),
        "windows.boot.state" => Some("E-WIN-COLLECT-10"),
        "windows.volumes.state" => Some("E-WIN-COLLECT-11"),
        _ => None,
    }
}

pub fn validate_projection(collector: &str, body: &str) -> Result<(), ResidentContractError> {
    use crate::diagnostics::{
        parse_bitlocker, parse_boot, parse_component_store, parse_drivers, parse_event_log,
        parse_network, parse_reliability, parse_services, parse_sfc, parse_update, parse_volumes,
    };

    let input = EvidenceInput {
        id: validation_id(collector).ok_or(ResidentContractError)?,
        body: body.as_bytes(),
    };
    match collector {
        "windows.event-log.window" => parse_event_log(input).map(|_| ()),
        "windows.reliability.records" => parse_reliability(input).map(|_| ()),
        "windows.component-store.check-health" => parse_component_store(input).map(|_| ()),
        "windows.sfc.verify-only" => parse_sfc(input).map(|_| ()),
        "windows.update.state" => parse_update(input).map(|_| ()),
        "windows.services.state" => parse_services(input).map(|_| ()),
        "windows.network.state" => parse_network(input).map(|_| ()),
        "windows.drivers.state" => parse_drivers(input).map(|_| ()),
        "windows.bitlocker.state" => parse_bitlocker(input).map(|_| ()),
        "windows.boot.state" => parse_boot(input).map(|_| ()),
        "windows.volumes.state" => parse_volumes(input).map(|_| ()),
        _ => return Err(ResidentContractError),
    }
    .map_err(|_| ResidentContractError)
}

#[cfg(test)]
pub fn validate_complete_set(documents: &[(&str, &str)]) -> Result<(), ResidentContractError> {
    if documents.len() != COLLECTORS.len() {
        return Err(ResidentContractError);
    }
    let mut by_collector = BTreeMap::new();
    for (collector, body) in documents {
        if validation_id(collector).is_none() || by_collector.insert(*collector, *body).is_some() {
            return Err(ResidentContractError);
        }
    }
    let input = |collector: &str| -> Result<EvidenceInput<'_>, ResidentContractError> {
        Ok(EvidenceInput {
            id: validation_id(collector).ok_or(ResidentContractError)?,
            body: by_collector
                .get(collector)
                .ok_or(ResidentContractError)?
                .as_bytes(),
        })
    };
    diagnose_windows_p0(WindowsP0Inputs {
        event_log_json: input("windows.event-log.window")?,
        reliability_json: input("windows.reliability.records")?,
        component_store_json: input("windows.component-store.check-health")?,
        sfc_json: input("windows.sfc.verify-only")?,
        update_json: input("windows.update.state")?,
        services_json: input("windows.services.state")?,
        network_json: input("windows.network.state")?,
        drivers_json: input("windows.drivers.state")?,
        bitlocker_json: input("windows.bitlocker.state")?,
        boot_json: input("windows.boot.state")?,
        volumes_json: input("windows.volumes.state")?,
    })
    .map(|_| ())
    .map_err(|_| ResidentContractError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn healthy_documents() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "windows.event-log.window",
                include_str!("../fixtures/diagnostics/healthy/event-log.json"),
            ),
            (
                "windows.reliability.records",
                include_str!("../fixtures/diagnostics/healthy/reliability.json"),
            ),
            (
                "windows.component-store.check-health",
                include_str!("../fixtures/diagnostics/healthy/component-store.json"),
            ),
            (
                "windows.sfc.verify-only",
                include_str!("../fixtures/diagnostics/healthy/sfc.json"),
            ),
            (
                "windows.update.state",
                include_str!("../fixtures/diagnostics/healthy/update.json"),
            ),
            (
                "windows.services.state",
                include_str!("../fixtures/diagnostics/healthy/services.json"),
            ),
            (
                "windows.network.state",
                include_str!("../fixtures/diagnostics/healthy/network.json"),
            ),
            (
                "windows.drivers.state",
                include_str!("../fixtures/diagnostics/healthy/drivers.json"),
            ),
            (
                "windows.bitlocker.state",
                include_str!("../fixtures/diagnostics/healthy/bitlocker.json"),
            ),
            (
                "windows.boot.state",
                include_str!("../fixtures/diagnostics/healthy/boot.json"),
            ),
            (
                "windows.volumes.state",
                include_str!("../fixtures/diagnostics/healthy/volumes.json"),
            ),
        ]
    }

    #[test]
    fn collector_surface_is_exactly_the_pack_contract() {
        assert_eq!(
            COLLECTORS.map(|spec| spec.collector),
            [
                "windows.event-log.window",
                "windows.reliability.records",
                "windows.component-store.check-health",
                "windows.sfc.verify-only",
                "windows.update.state",
                "windows.services.state",
                "windows.network.state",
                "windows.drivers.state",
                "windows.bitlocker.state",
                "windows.boot.state",
                "windows.volumes.state",
            ]
        );
        let names = COLLECTORS
            .iter()
            .map(|spec| spec.collector)
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), COLLECTORS.len());
        assert!(
            COLLECTORS
                .iter()
                .all(|spec| validation_id(spec.collector).is_some())
        );
        assert_eq!(
            WINDOWS_ENVIRONMENT.map(|(name, _)| name),
            [
                "SystemRoot",
                "WINDIR",
                "PSModulePath",
                "POWERSHELL_TELEMETRY_OPTOUT"
            ]
        );
        assert_eq!(
            DISM_ARGS,
            ["/Online", "/Cleanup-Image", "/CheckHealth", "/English"]
        );
        assert_eq!(BOOT_MANAGER_ARGS, ["/enum", "{bootmgr}"]);
        assert_eq!(OS_LOADER_ARGS, ["/enum", "osloader"]);
        assert_eq!(DEFAULT_LOADER_ARGS, ["/enum", "{default}"]);
    }

    #[test]
    fn embedded_commands_are_constant_bounded_and_exclude_recovery_material() {
        for spec in COLLECTORS {
            if let CollectorKind::PowerShell(script) = spec.kind {
                assert!(!script.is_empty());
                assert!(script.len() < 24 * 1024);
                assert!(!script.contains('\0'));
                for (prefix, suffix) in [
                    ("GetKey", "Protector"),
                    ("Key", "Protector"),
                    ("Recovery", "Password"),
                    ("Numerical", "Password"),
                    ("Get-Bit", "LockerVolume"),
                ] {
                    let forbidden = format!("{prefix}{suffix}");
                    assert!(
                        !script.contains(&forbidden),
                        "forbidden collector token: {forbidden}"
                    );
                }
            }
        }
    }

    #[test]
    fn complete_fixture_set_passes_cross_source_validation() {
        assert_eq!(validate_complete_set(&healthy_documents()), Ok(()));
        let mut incomplete = healthy_documents();
        incomplete.pop();
        assert_eq!(
            validate_complete_set(&incomplete),
            Err(ResidentContractError)
        );
    }

    #[test]
    fn native_tool_output_is_normalized_before_pack_validation() {
        let dism = normalize_dism(
            "No component store corruption detected.\nThe operation completed successfully.",
            "",
            0,
        )
        .expect("normalize DISM");
        assert!(dism.contains("\"state\":\"healthy\""));
        let sfc = sfc_not_run_projection().expect("project unqualified SFC state");
        assert!(sfc.contains("\"executionState\":\"not-run-unqualified\""));
        assert!(sfc.contains("\"state\":\"could-not-verify\""));
        assert!(!sfc.contains("clean"));
        assert!(!sfc.contains("violations"));
    }

    #[test]
    fn p0_timeout_contract_stays_below_five_minutes_without_sfc() {
        assert!(POWERSHELL_TIMEOUT <= P0_WALL_CLOCK_BUDGET);
        assert!(DISM_TIMEOUT <= P0_WALL_CLOCK_BUDGET);
        assert!(BOOT_TIMEOUT <= P0_WALL_CLOCK_BUDGET);
        assert!(P0_WALL_CLOCK_BUDGET < Duration::from_secs(5 * 60));
        assert!(
            COLLECTORS
                .iter()
                .any(|spec| matches!(spec.kind, CollectorKind::SfcNotRunUnqualified))
        );
    }

    #[test]
    fn boot_normalizer_uses_fixed_native_identifiers_not_localized_labels() {
        let boot = normalize_boot(
            NativeOutput {
                stdout: "PEFirmwareType    REG_DWORD    0x2",
                exit_code: 0,
            },
            NativeOutput {
                stdout: "Windows Boot Manager\r\n--------------------\r\nidentifier {bootmgr}\r\ndefault {current}\r\n",
                exit_code: 0,
            },
            NativeOutput {
                stdout: "Windows Boot Loader\r\n-------------------\r\nidentifier {current}\r\npath \\Windows\\system32\\winload.efi\r\n",
                exit_code: 0,
            },
            NativeOutput {
                stdout: "Windows Boot Loader\r\n-------------------\r\nidentifier {current}\r\n",
                exit_code: 0,
            },
        )
        .expect("normalize boot state");
        assert!(boot.contains("\"firmwareType\":\"Uefi\""));
        assert!(boot.contains("\"defaultLoaderPresent\":true"));
    }

    #[test]
    fn boot_command_errors_and_unparseable_output_become_typed_unavailable() {
        for boot in [
            normalize_boot(
                NativeOutput {
                    stdout: "",
                    exit_code: 1,
                },
                NativeOutput {
                    stdout: "warning on stderr is intentionally irrelevant",
                    exit_code: 0,
                },
                NativeOutput {
                    stdout: "",
                    exit_code: 0,
                },
                NativeOutput {
                    stdout: "",
                    exit_code: 0,
                },
            ),
            normalize_boot(
                NativeOutput {
                    stdout: "localized output without the fixed firmware value",
                    exit_code: 0,
                },
                NativeOutput {
                    stdout: "localized output without {bootmgr}",
                    exit_code: 0,
                },
                NativeOutput {
                    stdout: "",
                    exit_code: 0,
                },
                NativeOutput {
                    stdout: "",
                    exit_code: 0,
                },
            ),
        ] {
            let boot = boot.expect("typed unavailable boot projection");
            assert!(boot.contains("\"queryState\":\"unavailable\""));
            assert!(boot.contains("\"firmwareType\":null"));
        }
    }

    #[test]
    fn storage_identity_excludes_free_space_but_binds_capacity_and_drive() {
        let volumes = include_str!("../fixtures/diagnostics/healthy/volumes.json");
        let baseline = derive_storage_identity(volumes).expect("baseline identity");

        let mut changed_free: serde_json::Value =
            serde_json::from_str(volumes).expect("fixture JSON");
        changed_free["volumes"][0]["freeBytes"] = serde_json::json!(1);
        let changed_free = serde_json::to_string(&changed_free).expect("serialize fixture");
        assert_eq!(
            derive_storage_identity(&changed_free).expect("free-space identity"),
            baseline
        );

        let mut changed_capacity: serde_json::Value =
            serde_json::from_str(volumes).expect("fixture JSON");
        changed_capacity["volumes"][0]["capacityBytes"] = serde_json::json!(511101108225_u64);
        let changed_capacity = serde_json::to_string(&changed_capacity).expect("serialize fixture");
        assert_ne!(
            derive_storage_identity(&changed_capacity).expect("capacity identity"),
            baseline
        );

        let mut changed_drive: serde_json::Value =
            serde_json::from_str(volumes).expect("fixture JSON");
        changed_drive["volumes"][1]["driveLetter"] = serde_json::json!("E:");
        let changed_drive = serde_json::to_string(&changed_drive).expect("serialize fixture");
        assert_ne!(
            derive_storage_identity(&changed_drive).expect("drive identity"),
            baseline
        );
    }
}
