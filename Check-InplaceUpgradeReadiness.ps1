<# 
.SYNOPSIS
  Validates whether a Windows PC is ready for an in-place upgrade (e.g., to Windows 11).

.DESCRIPTION
  Checks:
    - CPU appears on a supported track (heuristic: Intel Core 8th gen+; AMD Ryzen 2000+; Intel Core Ultra; Snapdragon X; others = unknown)
    - RAM >= 7 GB
    - System drive is SSD
    - Firmware boot mode is UEFI (not Legacy/CSM)
    - TPM present, enabled, ready; spec version includes 2.0

  Outputs: human-readable table + JSON block.
  Exit code: 0 if all pass; 1 if any requirement fails; 2 if only CPU is “unknown”.

.PARAMETER AssumeCpuSupported
  Treat CPU as supported even if the heuristic can’t prove it.

.PARAMETER CpuAllowRegex
  A regex; if the CPU name matches, treat it as supported. Example: "Xeon.*(Silver|Gold) 4"

.EXAMPLE
  .\Check-InplaceUpgradeReadiness.ps1

.EXAMPLE
  .\Check-InplaceUpgradeReadiness.ps1 -CpuAllowRegex "Xeon.*Silver 41"

.NOTES
  CPU support lists from Microsoft are model-specific. This script uses practical heuristics + an override.
  For hard compliance, feed known-good models via -CpuAllowRegex or set -AssumeCpuSupported and keep a separate allowlist.
#>

[CmdletBinding()]
param(
  [switch]$AssumeCpuSupported,
  [string]$CpuAllowRegex
)

function New-Result {
  param(
    [string]$Name,
    [bool]$Pass,
    [string]$Detail
  )
  [pscustomobject]@{ Check = $Name; Pass = $Pass; Detail = $Detail }
}

function Format-State {
  param([object]$Value)

  if ($Value -eq $true) { return 'True' }
  if ($Value -eq $false) { return 'False' }
  return 'Unknown'
}

function Test-Ram {
  $mem = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
  $minBytes = 7GB
  $ok = ($mem -ge $minBytes)
  $detail = "{0:N1} GB installed (min 7 GB)" -f ($mem/1GB)
  return New-Result -Name "RAM >= 7 GB" -Pass:$ok -Detail:$detail
}

$script:SystemDiskResolutionTrace = $null

function Get-SystemDisk {
  $trace = @()
  $driveRoot = $env:SystemDrive

  if (-not $driveRoot) {
    $trace += "SystemDrive environment variable not set"
    $script:SystemDiskResolutionTrace = $trace -join '; '
    return $null
  }

  $driveNormalized = $driveRoot.TrimEnd('\')
  if (-not $driveNormalized.EndsWith(':')) {
    $driveNormalized += ':'
  }

  $driveLetter = $driveNormalized.TrimEnd(':')
  if ([string]::IsNullOrWhiteSpace($driveLetter)) {
    $trace += "Could not derive drive letter from '$driveRoot'"
    $script:SystemDiskResolutionTrace = $trace -join '; '
    return $null
  }
  $driveLetter = $driveLetter.Substring($driveLetter.Length - 1, 1).ToUpper()

  try {
    $part = Get-Partition -DriveLetter $driveLetter -ErrorAction Stop
    $disk = Get-Disk -Number $part.DiskNumber -ErrorAction Stop
    $trace += "Storage module resolved drive '$driveNormalized' to Disk #$($disk.Number)"
    $script:SystemDiskResolutionTrace = $trace -join '; '
    return $disk
  } catch {
    $trace += "Storage module lookup failed: $($_.Exception.Message)"
  }

  try {
    $logical = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$driveNormalized'" -ErrorAction Stop
    $partition = Get-CimAssociatedInstance -InputObject $logical -Association Win32_LogicalDiskToPartition -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $partition) {
      throw "No associated partition found"
    }

    $diskDrive = Get-CimAssociatedInstance -InputObject $partition -Association Win32_DiskDriveToDiskPartition -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $diskDrive) {
      throw "No associated disk drive found"
    }

    $diskNumber = [int]$diskDrive.Index
    try {
      $disk = Get-Disk -Number $diskNumber -ErrorAction Stop
      $trace += "CIM fallback resolved drive '$driveNormalized' to Disk #$diskNumber"
      $script:SystemDiskResolutionTrace = $trace -join '; '
      return $disk
    } catch {
      $trace += "CIM fallback resolved disk #$diskNumber but Get-Disk failed: $($_.Exception.Message)"

      $partitionStyle = 'Unknown'
      if ($partition.Type -like 'GPT*') {
        $partitionStyle = 'GPT'
      } elseif ($partition.Type) {
        $partitionStyle = 'MBR/Unknown'
      }

      $busType = 'Unknown'
      if ($diskDrive.InterfaceType) {
        $busType = $diskDrive.InterfaceType
      }

      $fallbackDisk = [pscustomobject]@{
        Number         = $diskNumber
        BusType        = $busType
        PartitionStyle = $partitionStyle
        Model          = $diskDrive.Model
        Source         = 'CIM Fallback'
      }
      $script:SystemDiskResolutionTrace = $trace -join '; '
      return $fallbackDisk
    }
  } catch {
    $trace += "CIM fallback failed: $($_.Exception.Message)"
  }

  $script:SystemDiskResolutionTrace = $trace -join '; '
  return $null
}

function Test-SSD {
  $disk = Get-SystemDisk
  if (-not $disk) {
    $detail = "Unable to resolve system disk."
    if ($script:SystemDiskResolutionTrace) {
      $detail += " Attempts: $script:SystemDiskResolutionTrace"
    }
    return New-Result "System Drive is SSD" $false $detail
  }

  $isSSD = $false
  $evidence = @()

  # Primary (Storage module)
  try {
    $pd = Get-PhysicalDisk -ErrorAction Stop | Where-Object { $_.DeviceId -eq $disk.Number }
    if ($pd) {
      if ($pd.MediaType -eq 'SSD') { $isSSD = $true; $evidence += "PhysicalDisk.MediaType=SSD" }
      elseif ($pd.SpindleSpeed -eq 0) { $isSSD = $true; $evidence += "SpindleSpeed=0" }
      else { $evidence += "PhysicalDisk.MediaType=$($pd.MediaType); Spindle=$($pd.SpindleSpeed)" }
    } else {
      $evidence += "No PhysicalDisk match by DeviceId=$($disk.Number)"
    }
  } catch {
    $evidence += "Get-PhysicalDisk unavailable: $($_.Exception.Message)"
  }

  # Fallback (WMI)
  if (-not $isSSD) {
    try {
      $wmi = Get-CimInstance -ClassName Win32_DiskDrive | Where-Object { $_.Index -eq $disk.Number }
      if ($wmi) {
        if ($wmi.Model -match 'SSD') { $isSSD = $true; $evidence += "Win32_DiskDrive.Model contains 'SSD' ($($wmi.Model))" }
        else { $evidence += "Win32_DiskDrive.Model=$($wmi.Model)" }
      }
    } catch {
      $evidence += "Win32_DiskDrive lookup failed: $($_.Exception.Message)"
    }
  }

  $source = 'Storage'
  if ($disk.PSObject.Properties['Source']) {
    $source = $disk.Source
  }
  $detail = "Disk #$($disk.Number) | Bus: $($disk.BusType) | GPT: $($disk.PartitionStyle -eq 'GPT') | Source: $source | Evidence: " + ($evidence -join '; ')
  return New-Result -Name "System Drive is SSD" -Pass:$isSSD -Detail:$detail
}

function Resolve-FirmwareMode {
  $signals = @()
  $notes = @()

  try {
    $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'PEFirmwareType' -ErrorAction Stop | Select-Object -ExpandProperty PEFirmwareType
    if ($val -eq 2) {
      $signals += [pscustomobject]@{ Source = 'PEFirmwareType'; Value = 'UEFI'; Text = "PEFirmwareType=2 (UEFI signal)" }
    } elseif ($val -eq 1) {
      $signals += [pscustomobject]@{ Source = 'PEFirmwareType'; Value = 'Legacy'; Text = "PEFirmwareType=1 (Legacy signal)" }
    } else {
      $signals += [pscustomobject]@{ Source = 'PEFirmwareType'; Value = 'Unknown'; Text = "PEFirmwareType=$val (unrecognized value)" }
    }
  } catch {
    $notes += "PEFirmwareType lookup failed: $($_.Exception.Message)"
  }

  try {
    $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
    $status = 'disabled'
    if ($secureBoot) {
      $status = 'enabled'
    }
    $signals += [pscustomobject]@{ Source = 'Confirm-SecureBootUEFI'; Value = 'UEFI'; Text = "Confirm-SecureBootUEFI returned $secureBoot (Secure Boot $status)" }
  } catch {
    $msg = $_.Exception.Message
    if ($msg -match 'not supported on this platform') {
      $signals += [pscustomobject]@{ Source = 'Confirm-SecureBootUEFI'; Value = 'Legacy'; Text = "Confirm-SecureBootUEFI not supported (Legacy signal): $msg" }
    } else {
      $notes += "Confirm-SecureBootUEFI failed: $msg"
    }
  }

  try {
    $msInfo = Get-CimInstance -Namespace 'root\\wmi' -Class MS_SystemInformation -ErrorAction Stop
    if ($msInfo.BIOSMode) {
      $modeText = $msInfo.BIOSMode
      if ($modeText -match 'UEFI') {
        $signals += [pscustomobject]@{ Source = 'MS_SystemInformation'; Value = 'UEFI'; Text = "MS_SystemInformation.BIOSMode=$modeText" }
      } elseif ($modeText -match 'Legacy|CSM|BIOS') {
        $signals += [pscustomobject]@{ Source = 'MS_SystemInformation'; Value = 'Legacy'; Text = "MS_SystemInformation.BIOSMode=$modeText" }
      } else {
        $signals += [pscustomobject]@{ Source = 'MS_SystemInformation'; Value = 'Unknown'; Text = "MS_SystemInformation.BIOSMode=$modeText (unrecognized)" }
      }
    } else {
      $notes += 'MS_SystemInformation.BIOSMode empty or null'
    }
  } catch {
    $notes += "MS_SystemInformation lookup failed: $($_.Exception.Message)"
  }

  try {
    $systeminfoLines = systeminfo.exe 2>&1
    $biosModeValue = $null

    foreach ($line in $systeminfoLines) {
      if ($line -match '^\s*BIOS Mode\s*:\s*(.+)$') {
        $biosModeValue = $Matches[1].Trim()
        break
      }
    }

    if ($biosModeValue) {
      if ($biosModeValue -match 'UEFI') {
        $signals += [pscustomobject]@{ Source = 'System Information'; Value = 'UEFI'; Text = "systeminfo BIOS Mode=$biosModeValue" }
      } elseif ($biosModeValue -match 'Legacy|CSM|BIOS') {
        $signals += [pscustomobject]@{ Source = 'System Information'; Value = 'Legacy'; Text = "systeminfo BIOS Mode=$biosModeValue" }
      } else {
        $signals += [pscustomobject]@{ Source = 'System Information'; Value = 'Unknown'; Text = "systeminfo BIOS Mode=$biosModeValue (unrecognized)" }
      }
    } else {
      $notes += 'systeminfo output did not include a BIOS Mode entry'
    }
  } catch {
    $notes += "systeminfo query failed: $($_.Exception.Message)"
  }

  try {
    $secureBootKey = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop
    $notes += "SecureBoot registry present (UEFI-capable platform). UEFISecureBootEnabled=$($secureBootKey.UEFISecureBootEnabled)"
    $signals += [pscustomobject]@{ Source = 'SecureBootRegistry'; Value = 'UEFI'; Text = 'SecureBoot state registry present (UEFI signal)' }
  } catch {
    $notes += "SecureBoot registry absent or inaccessible: $($_.Exception.Message)"
  }

  $uefiCount = ($signals | Where-Object { $_.Value -eq 'UEFI' }).Count
  $legacyCount = ($signals | Where-Object { $_.Value -eq 'Legacy' }).Count
  $hasConflict = ($uefiCount -gt 0 -and $legacyCount -gt 0)
  $decided = $null

  if ($hasConflict) {
    $notes += 'Conflicting firmware signals detected'
  } elseif ($uefiCount -gt 0 -and $legacyCount -eq 0) {
    $decided = $true
  } elseif ($legacyCount -gt 0 -and $uefiCount -eq 0) {
    $decided = $false
  }

  return [pscustomobject]@{
    IsUefi       = $decided
    Signals      = $signals
    Notes        = $notes
    HasConflict  = $hasConflict
  }
}

function Format-GptStatus {
  param($Disk)

  if (-not $Disk) {
    return 'Unknown (system disk unresolved)'
  }

  if (-not $Disk.PSObject.Properties['PartitionStyle']) {
    return 'Unknown (partition style unavailable)'
  }

  $style = $Disk.PartitionStyle
  if ($style -is [string]) {
    if ($style -eq 'GPT') { return 'True' }
    elseif ($style -eq 'MBR') { return 'False (style: MBR)' }
    elseif ($style -eq 'RAW') { return 'False (style: RAW)' }
    elseif ($style -eq 'MBR/Unknown') { return 'False/Unknown (fallback reported)' }
    else { return "Unknown (style: $style)" }
  }

  try {
    if ($style -eq [Microsoft.Management.Infrastructure.CimFlags]::NullValue) { return 'Unknown (style null)' }
  } catch {
    # Ignore if enum type not available
  }

  try {
    $styleString = [string]$style
    if ($styleString) {
      return "Unknown (style: $styleString)"
    }
  } catch {
    # ignored
  }

  return 'Unknown'
}

function Test-UEFI {
  $mode = Resolve-FirmwareMode
  $disk = Get-SystemDisk

  $signalTexts = @()
  if ($mode.Signals) {
    $signalTexts += ($mode.Signals | ForEach-Object { $_.Text })
  }
  if ($mode.Notes) {
    $signalTexts += $mode.Notes
  }

  if (-not $signalTexts) {
    $signalTexts = @('No firmware signals gathered')
  }

  $gptStatus = Format-GptStatus -Disk $disk
  $detail = "Signals: " + ($signalTexts -join '; ') + ". System disk GPT=$gptStatus."

  $pass = $false
  if ($mode.IsUefi -eq $true) {
    $pass = $true
  } elseif ($mode.IsUefi -eq $false) {
    $pass = $false
  } else {
    $pass = $false
  }

  return New-Result -Name "UEFI Boot Mode (not Legacy/CSM)" -Pass:$pass -Detail:$detail
}

function Resolve-TpmStatus {
  $signals = @()
  $notes = @()

  $present = $null
  $enabled = $null
  $activated = $null
  $ready = $null
  $specCandidates = @()

  try {
    $tpm = Get-Tpm -ErrorAction Stop
    if ($tpm) {
      $signals += "Get-Tpm => Present=$($tpm.TpmPresent); Enabled=$($tpm.TpmEnabled); Activated=$($tpm.TpmActivated); Ready=$($tpm.TpmReady); SpecVersion='$($tpm.SpecVersion)'"

      if ($null -eq $present -and ($tpm.PSObject.Properties['TpmPresent'])) { $present = $tpm.TpmPresent }
      if ($null -eq $enabled -and ($tpm.PSObject.Properties['TpmEnabled'])) { $enabled = $tpm.TpmEnabled }
      if ($null -eq $activated -and ($tpm.PSObject.Properties['TpmActivated'])) { $activated = $tpm.TpmActivated }
      if ($null -eq $ready -and ($tpm.PSObject.Properties['TpmReady'])) { $ready = $tpm.TpmReady }
      if ($tpm.SpecVersion) { $specCandidates += [string]$tpm.SpecVersion }
    } else {
      $notes += 'Get-Tpm returned no data'
    }
  } catch {
    $notes += "Get-Tpm failed: $($_.Exception.Message)"
  }

  try {
    $cimTpm = Get-CimInstance -Namespace 'root\\CIMV2\\Security\\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop | Select-Object -First 1
    if ($cimTpm) {
      $enabledSignal = $null
      if ($cimTpm.PSObject.Properties['IsEnabled'] -and $null -ne $cimTpm.IsEnabled) { $enabledSignal = [bool]$cimTpm.IsEnabled }
      elseif ($cimTpm.PSObject.Properties['IsEnabled_InitialValue'] -and $null -ne $cimTpm.IsEnabled_InitialValue) { $enabledSignal = [bool]$cimTpm.IsEnabled_InitialValue }

      $activatedSignal = $null
      if ($cimTpm.PSObject.Properties['IsActivated'] -and $null -ne $cimTpm.IsActivated) { $activatedSignal = [bool]$cimTpm.IsActivated }
      elseif ($cimTpm.PSObject.Properties['IsActivated_InitialValue'] -and $null -ne $cimTpm.IsActivated_InitialValue) { $activatedSignal = [bool]$cimTpm.IsActivated_InitialValue }

      $signals += "Win32_Tpm => Present=True; Enabled=$(Format-State $enabledSignal); Activated=$(Format-State $activatedSignal); SpecVersion='$($cimTpm.SpecVersion)'"

      if ($null -eq $present) { $present = $true }

      if ($null -eq $enabled -and $null -ne $enabledSignal) { $enabled = $enabledSignal }

      if ($null -eq $activated -and $null -ne $activatedSignal) { $activated = $activatedSignal }

      if ($cimTpm.PSObject.Properties['SpecVersion'] -and $cimTpm.SpecVersion) { $specCandidates += [string]$cimTpm.SpecVersion }
      if ($cimTpm.PSObject.Properties['PhysicalPresenceVersionInfo'] -and $cimTpm.PhysicalPresenceVersionInfo) { $specCandidates += [string]$cimTpm.PhysicalPresenceVersionInfo }

      if ($null -eq $ready) {
        if ($cimTpm.PSObject.Properties['IsOwned'] -and $null -ne $cimTpm.IsOwned -and $cimTpm.IsOwned -eq $true) {
          # Owning the TPM typically implies it has been provisioned/ready; treat as a positive proxy when direct signal unavailable.
          $ready = $true
        }
      }
    } else {
      $notes += 'Win32_Tpm query returned no instances'
    }
  } catch {
    $notes += "Win32_Tpm lookup failed: $($_.Exception.Message)"
  }

  try {
    $reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\TrustedPlatformModule' -ErrorAction Stop
    if ($reg -and $reg.PSObject.Properties['TpmSupport']) {
      $signals += "Registry TrustedPlatformModule => TpmSupport=$($reg.TpmSupport)"
      if ($null -eq $present -and $reg.TpmSupport -ne $null) { $present = ($reg.TpmSupport -ne 0) }
    }
    if ($reg -and $reg.PSObject.Properties['SpecVersion'] -and $reg.SpecVersion) {
      $specValue = $reg.SpecVersion
      if ($specValue -is [byte[]]) {
        try {
          $decoded = [System.Text.Encoding]::Unicode.GetString($specValue).Trim([char]0)
          if ($decoded) { $specCandidates += $decoded }
        } catch {
          $notes += "TrustedPlatformModule SpecVersion registry decode failed: $($_.Exception.Message)"
        }
      } elseif ($specValue -is [System.Array]) {
        foreach ($item in $specValue) {
          if ($item) { $specCandidates += [string]$item }
        }
      } else {
        $specCandidates += [string]$specValue
      }
    }
  } catch {
    $notes += "TrustedPlatformModule registry lookup failed: $($_.Exception.Message)"
  }

  $specTokens = @()
  foreach ($candidate in $specCandidates) {
    if ($candidate) {
      $tokens = ([string]$candidate) -split '[,;\s]+' | Where-Object { $_ }
      foreach ($token in $tokens) {
        $specTokens += $token.Trim()
      }
    }
  }
  if ($specTokens) {
    $specTokens = @($specTokens | Sort-Object -Unique)
  } else {
    $specTokens = @()
  }

  $spec20 = $false
  foreach ($token in $specTokens) {
    if ($token -match '^v?2(\.0+)?$' -or $token -match '(^|[^0-9])2\.0($|[^0-9])') {
      $spec20 = $true
      break
    }
  }

  if (-not $spec20 -and $specCandidates) {
    foreach ($candidate in $specCandidates) {
      if ([string]$candidate -match '(^|[^0-9])2\.0($|[^0-9])') {
        $spec20 = $true
        break
      }
    }
  }

  return [pscustomobject]@{
    Present      = $present
    Enabled      = $enabled
    Activated    = $activated
    Ready        = $ready
    SpecVersions = $specTokens
    Spec20       = $spec20
    Signals      = $signals
    Notes        = $notes
  }
}

function Test-TPM {
  $status = Resolve-TpmStatus

  $pass = ($status.Present -eq $true -and
           $status.Enabled -eq $true -and
           $status.Activated -eq $true -and
           $status.Ready -eq $true -and
           $status.Spec20)

  $specList = @()
  if ($status.SpecVersions) {
    if ($status.SpecVersions -is [System.Collections.IEnumerable] -and -not ($status.SpecVersions -is [string])) {
      foreach ($item in $status.SpecVersions) {
        if ($item) { $specList += [string]$item }
      }
    } else {
      $specList += [string]$status.SpecVersions
    }
  }

  if ($specList) {
    $specList = @($specList | Sort-Object -Unique)
  } else {
    $specList = @()
  }
  $specVersions = 'Unknown'
  if ($specList.Count -gt 0) {
    $specVersions = $specList -join ', '
  }

  $detailParts = @(
    "Present=$(Format-State $status.Present)",
    "Enabled=$(Format-State $status.Enabled)",
    "Activated=$(Format-State $status.Activated)",
    "Ready=$(Format-State $status.Ready)",
    "SpecVersions=$specVersions"
  )

  if ($status.Signals) { $detailParts += "Signals: " + ($status.Signals -join '; ') }
  if ($status.Notes) { $detailParts += "Notes: " + ($status.Notes -join '; ') }

  $detail = $detailParts -join '. '
  return New-Result -Name "TPM 2.0 Present/Enabled/Ready" -Pass:$pass -Detail:$detail
}

function Parse-IntelGen {
  param([string]$cpuName)
  # Match common formats: i5-8500, i7-1065G7, i5-1135G7, i9-12900K
  if ($cpuName -match 'Core\(TM\)\s+i\d{1,2}-([0-9]{4,5})') {
    $digits = [string]$Matches[1]

    if ($digits.Length -ge 5) {
      # Five digits covers 10th gen desktop parts and newer (e.g. 10400, 12900)
      return [int]$digits.Substring(0,2)
    }

    if ($digits.Length -eq 4) {
      # Four digits are ambiguous: 8th/9th gen desktop parts use a single leading digit
      # while 10th+ gen mobile parts start with "10", "11", etc. Distinguish by the
      # leading characters.
      if ($digits.StartsWith('1')) {
        return [int]$digits.Substring(0,2)  # 1005G1 -> 10th gen, 1135G7 -> 11th gen
      }

      return [int]$digits.Substring(0,1)    # 8500 -> 8th gen, 9700 -> 9th gen
    }

    if ($digits.Length -eq 3) {
      return [int]$digits.Substring(0,1)
    }
  }
  return $null
}

function Parse-AmdRyzenSeries {
  param([string]$cpuName)
  # Ryzen 5 2600, Ryzen 7 3700X, Ryzen 5 5600G, Threadripper 2950X, EPYC 7742
  if ($cpuName -match 'Ryzen\s+\d\s+([0-9]{4,5})') { return [int]$Matches[1] }
  if ($cpuName -match 'Threadripper\s+([0-9]{4,5})') { return [int]$Matches[1] }
  if ($cpuName -match 'EPYC\s+([0-9]{3,5})') { return [int]$Matches[1] }
  return $null
}

function Test-CPU {
  $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
  $name = $cpu.Name.Trim()
  $vh = $cpu.VirtualizationFirmwareEnabled
  $vendor = $cpu.Manufacturer

  $supported = $false
  $unknown   = $false
  $evidence  = @()

  if ($CpuAllowRegex -and ($name -match $CpuAllowRegex)) {
    $supported = $true
    $evidence += "Matched CpuAllowRegex '$CpuAllowRegex'"
  }

  if (-not $supported) {
    if ($name -match 'Intel\(R\)\s+Core\(TM\)\s+Ultra') {
      $supported = $true
      $evidence += "Intel Core Ultra detected"
    } elseif ($name -match 'Intel\(R\)\s+Core\(TM\)\s+i[3-9]-') {
      $gen = Parse-IntelGen $name
      if ($gen -ne $null) {
        if ($gen -ge 8) { $supported = $true; $evidence += "Intel Core Gen=$gen (>=8)" }
        else { $supported = $false; $evidence += "Intel Core Gen=$gen (<8)" }
      } else {
        $unknown = $true; $evidence += "Intel Core but gen parse failed"
      }
    } elseif ($name -match 'Intel\(R\)\s+Xeon') {
      # Too many Xeon variants; treat as unknown unless overridden
      $unknown = $true
      $evidence += "Intel Xeon => unknown (use -CpuAllowRegex to allow specific lines)"
    } elseif ($name -match 'AMD') {
      $series = Parse-AmdRyzenSeries $name
      if ($name -match 'Ryzen') {
        if ($series -and $series -ge 2000) { $supported = $true; $evidence += "AMD Ryzen series=$series (>=2000)" }
        elseif ($series) { $supported = $false; $evidence += "AMD Ryzen series=$series (<2000)" }
        else { $unknown = $true; $evidence += "AMD Ryzen series parse failed" }
      } elseif ($name -match 'EPYC|Threadripper') {
        if ($series -and $series -ge 2000) { $supported = $true; $evidence += "HEDT/Server series=$series (>=2000 heuristic)" }
        else { $unknown = $true; $evidence += "HEDT/Server parse ambiguous" }
      } else {
        $unknown = $true; $evidence += "AMD non-Ryzen => unknown"
      }
    } elseif ($name -match 'Qualcomm|Snapdragon') {
      if ($name -match 'Snapdragon\s+X') { $supported = $true; $evidence += "Snapdragon X detected" }
      else { $unknown = $true; $evidence += "ARM CPU ambiguous" }
    } else {
      $unknown = $true
      $evidence += "Unrecognized CPU family"
    }
  }

  if (-not $supported -and ($AssumeCpuSupported.IsPresent)) {
    $supported = $true
    $evidence += "Overridden by -AssumeCpuSupported"
  }

  $detail = "CPU='$name'; Vendor='$vendor'; Evidence: " + ($evidence -join '; ')
  $status = $false
  if ($supported) {
    $status = $true
  }

  $result = New-Result -Name "CPU Supported (heuristic)" -Pass:$status -Detail:$detail
  # Attach a hint about unknown classification
  $result | Add-Member -NotePropertyName Unknown -NotePropertyValue:$unknown
  return $result
}

function Write-Report {
  param([Parameter(Mandatory)][object[]]$Results)

  $allPass = $true
  $cpuUnknown = $false

  foreach ($r in $Results) {
    if (-not $r.Pass) { $allPass = $false }
    if ($r.Check -eq 'CPU Supported (heuristic)' -and $r.PSObject.Properties['Unknown'] -and $r.Unknown) {
      $cpuUnknown = $true
    }
  }

  if ($allPass) {
    $overall = "PASS"
  } else {
    $overall = "FAIL"
  }
  if (-not $allPass -and $cpuUnknown -and ($Results | Where-Object { $_.Check -ne 'CPU Supported (heuristic)' -and -not $_.Pass }).Count -eq 0) {
    # Only CPU is unknown but others passed
    $overall = "WARN (CPU unknown)"
  }

  $hostName = $env:COMPUTERNAME
  $os = (Get-CimInstance Win32_OperatingSystem)
  $sys = (Get-CimInstance Win32_ComputerSystem)
  $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1)

  $summary = [pscustomobject]@{
    ComputerName = $hostName
    OS           = "$($os.Caption) $($os.Version) ($($os.OSArchitecture))"
    Model        = $sys.Model
    Manufacturer = $sys.Manufacturer
    CPU          = $cpu.Name
    Results      = $Results
    Overall      = $overall
    Timestamp    = (Get-Date).ToString('s')
  }

  # Human readable
  Write-Host ""
  Write-Host "=== In-Place Upgrade Readiness ===" -ForegroundColor Cyan
  Write-Host "Computer : $($summary.ComputerName)"
  Write-Host "OS       : $($summary.OS)"
  Write-Host "HW       : $($summary.Manufacturer) $($summary.Model)"
  Write-Host "CPU      : $($summary.CPU)"
  Write-Host ""

  $Results | Select-Object @{n='Check';e={$_.Check}},
                         @{n='Pass'; e={ if ($_.Pass) {'Yes'} else {'No'} }},
                         @{n='Detail';e={$_.Detail}} |
    Format-Table -AutoSize

  Write-Host ""
  Write-Host "Overall  : $overall"
  Write-Host ""

  # JSON block
  $json = $summary | ConvertTo-Json -Depth 5
  Write-Host "JSON:" -ForegroundColor DarkGray
  Write-Output $json

  # Exit codes:
  # 0 = all pass
  # 1 = at least one definitive failure (non-CPU or CPU definitely below bar)
  # 2 = only CPU unknown, everything else passes
  if ($overall -eq 'PASS') { exit 0 }
  elseif ($overall -like 'WARN*') { exit 2 }
  else { exit 1 }
}

# ---- Run checks ----
$results = @()
$results += Test-CPU
$results += Test-Ram
$results += Test-SSD
$results += Test-UEFI
$results += Test-TPM

Write-Report -Results $results
