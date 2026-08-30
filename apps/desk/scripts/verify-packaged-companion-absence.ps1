param(
  [Parameter(Mandatory = $true)]
  [string]$BundleRoot,
  [switch]$QualifiedFirstLaunchProbe
)

$ErrorActionPreference = "Stop"
$probeFlag = "--qualified-first-launch-probe"
$probeMarker = "KERNAID_QUALIFIED_FIRST_LAUNCH_PROBE_OK_V1"
$msiInstallers = @(Get-ChildItem -LiteralPath (Join-Path $BundleRoot "msi") -Filter "*.msi" -File)
$nsisInstallers = @(Get-ChildItem -LiteralPath (Join-Path $BundleRoot "nsis") -Filter "*.exe" -File)
if ($msiInstallers.Count -ne 1 -or $nsisInstallers.Count -ne 1) {
  throw "Expected exactly one MSI and one NSIS installer under $BundleRoot"
}

$sevenZip = "C:\Program Files\7-Zip\7z.exe"
if (-not (Test-Path -LiteralPath $sevenZip -PathType Leaf)) {
  throw "7-Zip is required to inspect the Windows NSIS installer"
}

foreach ($installer in @($msiInstallers[0], $nsisInstallers[0])) {
  $extractRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
  New-Item -ItemType Directory -Path $extractRoot | Out-Null
  try {
    if ($installer.Extension -ieq ".msi") {
      $administrativeInstall = Start-Process -FilePath "msiexec.exe" -ArgumentList @(
        "/a", ('"{0}"' -f $installer.FullName), "/qn", ('TARGETDIR="{0}"' -f $extractRoot)
      ) -Wait -PassThru
      if ($administrativeInstall.ExitCode -ne 0) {
        throw "MSI administrative extraction failed for $($installer.FullName) with exit code $($administrativeInstall.ExitCode)"
      }
    }
    else {
      & $sevenZip x -y "-o$extractRoot" $installer.FullName | Out-Null
      if ($LASTEXITCODE -ne 0) {
        throw "7-Zip could not inspect $($installer.FullName)"
      }
    }
    $leak = Get-ChildItem -LiteralPath $extractRoot -Recurse -Force |
      Where-Object { $_.Name -like "*kernaid-provider-key*" } |
      Select-Object -First 1
    if ($null -ne $leak) {
      throw "Credential companion leaked into $($installer.FullName): $($leak.FullName)"
    }
    if ($QualifiedFirstLaunchProbe -and $installer.Extension -ieq ".msi") {
      $mainExecutables = @(Get-ChildItem -LiteralPath $extractRoot -Recurse -Force -File -Filter "kernaid-desk-shell.exe")
      if ($mainExecutables.Count -ne 1 -or ($mainExecutables[0].Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Expected exactly one regular packaged Desk main in the administrative MSI extraction"
      }
      $probeOutput = @(& $mainExecutables[0].FullName $probeFlag)
      if ($LASTEXITCODE -ne 0) {
        throw "Qualified first-launch probe failed for the administratively extracted MSI"
      }
      if ($probeOutput.Count -ne 1 -or $probeOutput[0] -cne $probeMarker) {
        throw "Qualified first-launch marker mismatch for the administratively extracted MSI"
      }
    }
  }
  finally {
    Remove-Item -LiteralPath $extractRoot -Recurse -Force
  }
}

Write-Output "Credential companion is absent from the packaged MSI and NSIS installers in $BundleRoot"
