<# 
.SYNOPSIS
  Validates whether a Windows PC is ready for an in-place upgrade (e.g., to Windows 11).

.DESCRIPTION
  Checks:
    - CPU appears on a supported track (heuristic: Intel Core 8th gen+; AMD Ryzen 2000+; Intel Core Ultra; Snapdragon X; others = unknown)
    - RAM >= 8 GB
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

function Test-Ram {
  $mem = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
  $minBytes = 8GB
  $ok = ($mem -ge $minBytes)
  $detail = "{0:N1} GB installed (min 8 GB)" -f ($mem/1GB)
  return New-Result -Name "RAM >= 8 GB" -Pass:$ok -Detail:$detail
}

function Get-SystemDisk {
  try {
    $driveLetter = $env:SystemDrive.TrimEnd('\')[-1]
    $part = Get-Partition -DriveLetter $driveLetter -ErrorAction Stop
    $disk = Get-Disk -Number $part.DiskNumber -ErrorAction Stop
    return $disk
  } catch {
    return $null
  }
}

function Test-SSD {
  $disk = Get-SystemDisk
  if (-not $disk) {
    return New-Result "System Drive is SSD" $false "Unable to resolve system disk."
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

  $detail = "Disk #$($disk.Number) | Bus: $($disk.BusType) | GPT: $($disk.PartitionStyle -eq 'GPT') | Evidence: " + ($evidence -join '; ')
  return New-Result -Name "System Drive is SSD" -Pass:$isSSD -Detail:$detail
}

function Test-UEFI {
  # Check registry PEFirmwareType: 1=BIOS, 2=UEFI
  try {
    $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'PEFirmwareType' -ErrorAction Stop | Select-Object -ExpandProperty PEFirmwareType
    $uefi = ($val -eq 2)
    $disk = Get-SystemDisk
    $gpt = $false
    if ($disk) { $gpt = ($disk.PartitionStyle -eq 'GPT') }
    $detail = "PEFirmwareType=$val (2=UEFI). System disk GPT=$gpt."
    return New-Result -Name "UEFI Boot Mode (not Legacy/CSM)" -Pass:$uefi -Detail:$detail
  } catch {
    return New-Result -Name "UEFI Boot Mode (not Legacy/CSM)" -Pass:$false -Detail:"Could not read PEFirmwareType: $($_.Exception.Message)"
  }
}

function Test-TPM {
  try {
    $tpm = Get-Tpm
  } catch {
    return New-Result -Name "TPM 2.0 Present/Enabled/Ready" -Pass:$false -Detail:"Get-Tpm not available. TPM module not accessible."
  }

  $present  = $tpm.TpmPresent
  $enabled  = $tpm.TpmEnabled
  $activated= $tpm.TpmActivated
  $ready    = $tpm.TpmReady
  $spec20   = $false

  # SpecVersion is a delimited string like "1.2, 2.0"
  if ($tpm.SpecVersion) {
    $spec20 = ($tpm.SpecVersion -split '[,\s]+' | Where-Object { $_ -eq '2.0' } | ForEach-Object { $true }) -contains $true
  } else {
    # Some environments expose ManufacturerVersion, but Windows 11 requires 2.0; be strict:
    $spec20 = $false
  }

  $ok = ($present -and $enabled -and $activated -and $ready -and $spec20)
  $detail = "Present=$present; Enabled=$enabled; Activated=$activated; Ready=$ready; SpecVersion='$($tpm.SpecVersion)'."
  return New-Result -Name "TPM 2.0 Present/Enabled/Ready" -Pass:$ok -Detail:$detail
}

function Parse-IntelGen {
  param([string]$cpuName)
  # Match common formats: i5-8500, i7-1065G7, i9-12900K
  if ($cpuName -match 'Core\(TM\)\s+i\d{1,2}-([0-9]{4,5})') {
    $num = [int]$Matches[1]
    if ($num -ge 10000) { return [int]([string]$num).Substring(0,2) }  # 1065G7 -> 10th gen, 12900K -> 12th
    else { return [int]([string]$num).Substring(0,1) + 0 }             # 8500 -> 8th gen
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
  $status = if ($supported) { $true } else { $false }

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

  $overall = if ($allPass) { "PASS" } else { "FAIL" }
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
    OS           = "$($os.Caption) $($os.Version) ($([int]$os.OSArchitecture)-bit)"
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
