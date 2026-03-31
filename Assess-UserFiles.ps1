#Requires -Version 5.1
<#
.SYNOPSIS
    Assess-UserFiles.ps1 - Comprehensive Windows PC Health & Inventory Assessment
.DESCRIPTION
    Collects hardware, OS, storage (inc SMART health), network, security,
    performance, software, tasks, services, users, and event log data.
    Outputs a self-contained HTML report that opens in any browser.
.NOTES
    Compatible : Windows 10 / Windows 11
    PowerShell : 5.1+  (also works under pwsh 7.x)
    Run As     : Administrator recommended for full output
    Output     : .\PC-Assessment-<hostname>-<date>.html
#>

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# -------------------------------------------------------------------------------
# DATA COLLECTION
# -------------------------------------------------------------------------------
Write-Host "  Collecting data..." -ForegroundColor Cyan

$ReportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$ReportFile = ".\PC-Assessment-$($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd-HHmm').html"
$isAdmin    = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole]'Administrator')

Write-Host "  [1/18] OS & BIOS..." -ForegroundColor DarkCyan
$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$upDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
$lic  = Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND Name LIKE 'Windows%'" |
        Select-Object -First 1
$licStatus = if ($lic) {
    switch ($lic.LicenseStatus) {
        0{'Unlicensed'} 1{'Licensed'} 2{'OOBGrace'} 3{'OOTGrace'}
        4{'NonGenuineGrace'} 5{'Notification'} default{"Unknown"}
    }
} else { 'N/A' }

Write-Host "  [2/18] Hardware..." -ForegroundColor DarkCyan
$cpu   = Get-CimInstance Win32_Processor | Select-Object -First 1
$ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
$freeGB= [math]::Round($os.FreePhysicalMemory  / 1MB, 1)
$usedGB= [math]::Round($ramGB - $freeGB, 1)
$dimms = Get-CimInstance Win32_PhysicalMemory
$mb    = Get-CimInstance Win32_BaseBoard
$gpus  = Get-CimInstance Win32_VideoController
$monitors = Get-CimInstance WmiMonitorID -Namespace root/wmi
$sound = Get-CimInstance Win32_SoundDevice

Write-Host "  [3/18] Storage & SMART..." -ForegroundColor DarkCyan
$physDisks  = Get-CimInstance Win32_DiskDrive | Sort-Object Index
$logVols    = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in 2,3,4,5 }
$smartDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
$smartDetails = Get-CimInstance -Namespace root/Microsoft/Windows/Storage `
                -ClassName MSFT_StorageReliabilityCounter -ErrorAction SilentlyContinue

Write-Host "  [4/18] Profile folder sizes..." -ForegroundColor DarkCyan
$profileFolders = Get-ChildItem $env:USERPROFILE -Directory -ErrorAction SilentlyContinue |
    ForEach-Object {
        $sz = (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue |
               Measure-Object Length -Sum).Sum
        [PSCustomObject]@{ Folder=$_.Name; Path=$_.FullName; Bytes=[long]($sz) }
    } | Sort-Object Bytes -Descending | Select-Object -First 20

Write-Host "  [5/18] Documents folder..." -ForegroundColor DarkCyan
$docsPath    = [Environment]::GetFolderPath('MyDocuments')
$docsFolders = Get-ChildItem $docsPath -Directory -ErrorAction SilentlyContinue | Sort-Object Name |
    ForEach-Object {
        $sz   = (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue |
                 Measure-Object Length -Sum).Sum
        $subs = Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name |
            ForEach-Object {
                $subSz = (Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue |
                          Measure-Object Length -Sum).Sum
                [PSCustomObject]@{ Name=$_.Name; Bytes=[long]($subSz) }
            }
        [PSCustomObject]@{ Name=$_.Name; Path=$_.FullName; Bytes=[long]($sz); SubFolders=$subs }
    }
$docsFiles = Get-ChildItem $docsPath -File -ErrorAction SilentlyContinue | Sort-Object Name

Write-Host "  [6/18] Network..." -ForegroundColor DarkCyan
$netAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
$tcpConns    = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
               Sort-Object RemoteAddress | Select-Object -First 40
$tcpListen   = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort
$wifiRaw     = netsh wlan show profiles 2>$null

Write-Host "  [7/18] Security..." -ForegroundColor DarkCyan
$mpStatus   = Get-MpComputerStatus -ErrorAction SilentlyContinue
$fwProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
$blVolumes  = if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
    Get-BitLockerVolume -ErrorAction SilentlyContinue } else { $null }
$uacReg     = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
              -ErrorAction SilentlyContinue
$localUsers = Get-LocalUser -ErrorAction SilentlyContinue
$failedLogons = if ($isAdmin) {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 -ErrorAction SilentlyContinue
} else { $null }

Write-Host "  [8/18] Pending updates..." -ForegroundColor DarkCyan
$pendingUpdates = @()
try {
    $wuSession  = New-Object -ComObject Microsoft.Update.Session
    $wuSearcher = $wuSession.CreateUpdateSearcher()
    $wuResult   = $wuSearcher.Search("IsInstalled=0 and Type='Software'")
    $pendingUpdates = $wuResult.Updates
} catch {}

Write-Host "  [9/18] Installed software..." -ForegroundColor DarkCyan
$regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$installedApps = $regPaths |
    ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
    Where-Object   { $_.DisplayName -and $_.DisplayName.Trim() -ne '' } |
    Select-Object  DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object    DisplayName -Unique

Write-Host "  [10/18] Startup & services..." -ForegroundColor DarkCyan
$startupKeys = @()
foreach ($path in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')) {
    $key = Get-ItemProperty $path -ErrorAction SilentlyContinue
    if ($key) {
        $key.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
            ForEach-Object {
                $startupKeys += [PSCustomObject]@{ Hive=$path; Name=$_.Name; Command=$_.Value }
            }
    }
}
$startupFolderItems = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp') |
    ForEach-Object { Get-ChildItem $_ -ErrorAction SilentlyContinue }

$svcRunning = Get-Service | Where-Object { $_.Status -eq 'Running'  } | Sort-Object DisplayName
$svcStopped = Get-Service | Where-Object {
    $_.Status -eq 'Stopped' -and $_.StartType -eq 'Automatic' } | Sort-Object DisplayName

Write-Host "  [11/18] Scheduled tasks..." -ForegroundColor DarkCyan
$schedTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notmatch '\\Microsoft\\' } |
    Sort-Object TaskPath,TaskName

Write-Host "  [12/18] Event logs..." -ForegroundColor DarkCyan
$since     = (Get-Date).AddHours(-24)
$evtSystem = Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2,3;StartTime=$since} `
             -MaxEvents 30 -ErrorAction SilentlyContinue
$evtApp    = Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2,3;StartTime=$since} `
             -MaxEvents 30 -ErrorAction SilentlyContinue

Write-Host "  [13/18] Performance..." -ForegroundColor DarkCyan
$procByCpu = Get-Process | Sort-Object CPU        -Descending | Select-Object -First 15
$procByRam = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 15
$pageFile  = Get-CimInstance Win32_PageFileUsage

Write-Host "  [14/18] System integrity..." -ForegroundColor DarkCyan
$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
$cbsLog   = "$env:SystemRoot\Logs\CBS\CBS.log"
$cbsTail  = if (Test-Path $cbsLog) { Get-Content $cbsLog -Tail 20 } else { @() }

Write-Host "  [15/18] Shares & remote..." -ForegroundColor DarkCyan
$smbShares = Get-SmbShare -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -notmatch '^\w\$$' }
$rdpReg    = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
             -ErrorAction SilentlyContinue
$winrmSvc  = Get-Service WinRM -ErrorAction SilentlyContinue

Write-Host "  [16/18] Virtualisation..." -ForegroundColor DarkCyan
$hypervFeat = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All `
              -ErrorAction SilentlyContinue
$wslList    = wsl --list --quiet 2>$null
$dockerPs   = docker ps 2>$null

Write-Host "  [17/18] Browsers & printers..." -ForegroundColor DarkCyan
$browserDefs = [ordered]@{
    Chrome  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    Edge    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    Firefox = "$env:APPDATA\Mozilla\Firefox\Profiles"
    Brave   = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    Opera   = "$env:APPDATA\Opera Software\Opera Stable"
}
$browsersFound = $browserDefs.GetEnumerator() | Where-Object { Test-Path $_.Value } |
    ForEach-Object {
        $sz = [math]::Round((Get-ChildItem $_.Value -Recurse -File -ErrorAction SilentlyContinue |
               Measure-Object Length -Sum).Sum / 1MB, 0)
        [PSCustomObject]@{ Browser=$_.Key; Path=$_.Value; SizeMB=$sz }
    }
$printers = Get-CimInstance Win32_Printer

Write-Host "  [18/18] Building summary flags..." -ForegroundColor DarkCyan
$issues  = [System.Collections.Generic.List[PSCustomObject]]::new()
$notices = [System.Collections.Generic.List[PSCustomObject]]::new()

function AddIssue($sev, $msg) {
    $issues.Add([PSCustomObject]@{ Severity=$sev; Message=$msg })
}

if ($mpStatus -and -not $mpStatus.AntivirusEnabled)          { AddIssue 'critical' 'Windows Defender Antivirus is DISABLED' }
if ($mpStatus -and -not $mpStatus.RealTimeProtectionEnabled) { AddIssue 'critical' 'Real-Time Protection is DISABLED' }
if ($upDays -gt 30)  { AddIssue 'warning' "System has not been rebooted in $upDays days" }
if ($upDays -gt 7)   { $notices.Add([PSCustomObject]@{ Message="Uptime is $upDays days" }) }

$cVol = $logVols | Where-Object { $_.DeviceID -eq 'C:' }
if ($cVol -and $cVol.Size -gt 0) {
    $freePct = [math]::Round($cVol.FreeSpace / $cVol.Size * 100, 0)
    if ($freePct -lt 10) { AddIssue 'critical' "C: drive critically low on space ($freePct% free)" }
    elseif ($freePct -lt 20) { AddIssue 'warning' "C: drive low on space ($freePct% free)" }
}

if ($svcStopped.Count -gt 3) {
    AddIssue 'warning' "$($svcStopped.Count) auto-start services are currently stopped"
}
if ($pendingUpdates.Count -gt 0) {
    AddIssue 'warning' "$($pendingUpdates.Count) Windows updates pending"
}
if (-not $isAdmin) {
    AddIssue 'warning' 'Script not run as Administrator - some sections may be incomplete'
}
foreach ($sd in $smartDisks) {
    if ($sd.HealthStatus -ne 'Healthy') {
        AddIssue 'critical' "Disk '$($sd.FriendlyName)' health: $($sd.HealthStatus)"
    }
}

# -------------------------------------------------------------------------------
# HTML HELPERS
# -------------------------------------------------------------------------------
function HE($s) {
    if ($null -eq $s) { return '' }
    [string]$s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

function TRow([string[]]$cells, [string]$class='') {
    $tds = ($cells | ForEach-Object { "<td>$(HE $_)</td>" }) -join ''
    "<tr$(if($class){" class='$class'"})>$tds</tr>"
}

function KVTable([System.Collections.Specialized.OrderedDictionary]$data) {
    $rows = ($data.GetEnumerator() | ForEach-Object {
        "<tr><td class='kv-key'>$(HE $_.Key)</td><td>$(HE $_.Value)</td></tr>"
    }) -join ''
    "<table class='kv'><tbody>$rows</tbody></table>"
}

function SectionHtml($id, $title, $icon, $content) {
    @"
<section id="$id">
  <div class="section-header" onclick="toggleSection('$id')">
    <span class="section-icon">$icon</span>
    <h2>$title</h2>
    <span class="toggle-arrow" id="arrow-$id">&#9660;</span>
  </div>
  <div class="section-body" id="body-$id">$content</div>
</section>
"@
}

function SubHtml($title, $content) {
    "<div class='subsection'><h3>$title</h3>$content</div>"
}

function PctBar($pct) {
    $colour = if ($pct -ge 90) { '#e74c3c' } elseif ($pct -ge 75) { '#f39c12' } else { '#27ae60' }
    "<div class='bar-wrap'><div class='bar-fill' style='width:${pct}%;background:$colour'></div>" +
    "<span class='bar-label'>${pct}%</span></div>"
}

# -------------------------------------------------------------------------------
# BUILD SECTION CONTENT
# -------------------------------------------------------------------------------

# SUMMARY
$summaryHtml = ''
if ($issues.Count -eq 0) {
    $summaryHtml += "<div class='alert ok'><strong>No issues detected.</strong> System appears healthy.</div>"
} else {
    foreach ($iss in ($issues | Sort-Object { if($_.Severity -eq 'critical'){0}else{1} })) {
        $cls = if ($iss.Severity -eq 'critical') { 'critical' } else { 'warning' }
        $lbl = if ($iss.Severity -eq 'critical') { 'CRITICAL' } else { 'WARNING' }
        $summaryHtml += "<div class='alert $cls'><strong>${lbl}:</strong> $(HE $iss.Message)</div>"
    }
}
foreach ($n in $notices) {
    $summaryHtml += "<div class='alert notice'><strong>NOTE:</strong> $(HE $n.Message)</div>"
}
$summaryHtml += "<p class='meta'>Host: <strong>$($env:COMPUTERNAME)</strong> &nbsp;|&nbsp; " +
    "User: $($env:USERDOMAIN)\$($env:USERNAME) &nbsp;|&nbsp; " +
    "Elevated: $(if($isAdmin){'Yes'}else{'No'}) &nbsp;|&nbsp; Generated: $ReportDate</p>"

# OS
$osKV = [ordered]@{
    'OS Name'              = $os.Caption
    'Version / Build'      = "$($os.Version)  (Build $($os.BuildNumber))"
    'Architecture'         = $os.OSArchitecture
    'Install Date'         = ($os.InstallDate | Get-Date -Format 'yyyy-MM-dd')
    'Last Boot'            = ($os.LastBootUpTime | Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    'Uptime'               = "$upDays days"
    'Registered Owner'     = $os.RegisteredUser
    'Organisation'         = $cs.PrimaryOwnerName
    'Domain / Workgroup'   = if ($cs.PartOfDomain) { $cs.Domain } else { "WORKGROUP: $($cs.Workgroup)" }
    'BIOS'                 = "$($bios.Manufacturer) $($bios.SMBIOSBIOSVersion)"
    'BIOS Date'            = ($bios.ReleaseDate | Get-Date -Format 'yyyy-MM-dd')
    'Activation'           = $licStatus
    'Product Key (last 5)' = if ($lic) { $lic.PartialProductKey } else { 'N/A' }
}
$osHtml = KVTable $osKV

# HARDWARE
$cpuKV = [ordered]@{
    'Processor'       = $cpu.Name.Trim()
    'Cores / Threads' = "$($cpu.NumberOfCores) cores / $($cpu.NumberOfLogicalProcessors) logical"
    'Base Speed'      = "$($cpu.MaxClockSpeed) MHz"
    'Socket'          = $cpu.SocketDesignation
    'Current Load'    = "$($cpu.LoadPercentage)%"
}
$memKV = [ordered]@{
    'Total RAM' = "$ramGB GB"
    'Used'      = "$usedGB GB"
    'Free'      = "$freeGB GB"
}
$mbKV = [ordered]@{
    'Manufacturer' = $mb.Manufacturer
    'Product'      = $mb.Product
    'Serial'       = $mb.SerialNumber
}

$dimmRows = ($dimms | ForEach-Object {
    $sz = [math]::Round($_.Capacity / 1GB, 0)
    TRow @($_.DeviceLocator, "$sz GB", $_.MemoryType, "$($_.Speed) MHz", $_.Manufacturer)
}) -join ''
$dimmTable = "<table><thead><tr><th>Slot</th><th>Size</th><th>Type</th><th>Speed</th><th>Maker</th></tr></thead>" +
             "<tbody>$dimmRows</tbody></table>"

$gpuRows = ($gpus | ForEach-Object {
    $vram = if ($_.AdapterRAM) { "$([math]::Round($_.AdapterRAM/1MB)) MB" } else { 'N/A' }
    TRow @($_.Name, $vram, $_.DriverVersion)
}) -join ''
$gpuTable = "<table><thead><tr><th>GPU</th><th>VRAM</th><th>Driver</th></tr></thead><tbody>$gpuRows</tbody></table>"

$monRows = ($monitors | ForEach-Object {
    $mfr  = [System.Text.Encoding]::ASCII.GetString($_.ManufacturerName -ne 0).Trim()
    $prod = [System.Text.Encoding]::ASCII.GetString($_.UserFriendlyName  -ne 0).Trim()
    TRow @($mfr, $prod)
}) -join ''
$monTable = if ($monRows) {
    "<table><thead><tr><th>Manufacturer</th><th>Model</th></tr></thead><tbody>$monRows</tbody></table>"
} else { "<p class='muted'>No monitor data available.</p>" }

$hwHtml  = (SubHtml 'CPU'         (KVTable $cpuKV)) +
           (SubHtml 'Memory'      ((KVTable $memKV) + $dimmTable)) +
           (SubHtml 'Motherboard' (KVTable $mbKV)) +
           (SubHtml 'GPU(s)'      $gpuTable) +
           (SubHtml 'Monitors'    $monTable) +
           (SubHtml 'Sound'       (($sound | ForEach-Object { "<div>$(HE $_.Name)</div>" }) -join ''))

# STORAGE
$sdRows = ($smartDisks | ForEach-Object {
    $h   = $_.HealthStatus
    $cls = if ($h -eq 'Healthy') { 'ok' } elseif ($h -eq 'Warning') { 'warn' } else { 'crit' }
    $sz  = if ($_.Size) { "$([math]::Round($_.Size/1GB,1)) GB" } else { 'N/A' }
    "<tr><td>$(HE $_.FriendlyName)</td><td>$(HE $_.MediaType)</td><td>$sz</td>" +
    "<td>$(HE $_.BusType)</td><td><span class='badge $cls'>$h</span></td>" +
    "<td>$(HE $_.OperationalStatus)</td></tr>"
}) -join ''
$sdTable = if ($sdRows) {
    "<table><thead><tr><th>Drive</th><th>Type</th><th>Size</th><th>Bus</th><th>Health</th><th>Status</th></tr></thead>" +
    "<tbody>$sdRows</tbody></table>"
} else {
    "<p class='muted'>Get-PhysicalDisk data not available (requires Storage module).</p>"
}

$smartRows = ($smartDetails | ForEach-Object {
    $temp  = if ($_.Temperature)    { "$($_.Temperature) C" }    else { 'N/A' }
    $hours = if ($_.PowerOnHours)   { "$($_.PowerOnHours) hrs" } else { 'N/A' }
    $reads = if ($_.ReadErrorsTotal){ $_.ReadErrorsTotal }        else { '0' }
    $wear  = if ($_.Wear)           { "$($_.Wear)%" }             else { 'N/A' }
    "<tr><td>$(HE $_.DeviceId)</td><td>$temp</td><td>$hours</td><td>$reads</td><td>$wear</td></tr>"
}) -join ''
$smartTable = if ($smartRows) {
    "<table><thead><tr><th>Device</th><th>Temperature</th><th>Power-On Hours</th><th>Read Errors</th><th>Wear</th></tr></thead>" +
    "<tbody>$smartRows</tbody></table>"
} else { "<p class='muted'>SMART counters not available on this system (common on VMs and some NVMe configs).</p>" }

$volRows = ($logVols | ForEach-Object {
    $tGB     = [math]::Round($_.Size / 1GB, 1)
    $fGB     = [math]::Round($_.FreeSpace / 1GB, 1)
    $usedPct = if ($_.Size -gt 0) { [math]::Round(($_.Size - $_.FreeSpace)/$_.Size*100,0) } else { 0 }
    $typeStr = switch ($_.DriveType) { 2{'Removable'} 3{'Fixed'} 4{'Network'} 5{'CD-ROM'} default{$_} }
    "<tr><td>$(HE $_.DeviceID)</td><td>$(HE $_.VolumeName)</td><td>$typeStr</td>" +
    "<td>$tGB GB</td><td>$fGB GB</td><td>$(PctBar $usedPct)</td></tr>"
}) -join ''
$volTable = "<table><thead><tr><th>Drive</th><th>Label</th><th>Type</th><th>Total</th><th>Free</th><th>Used</th></tr></thead>" +
            "<tbody>$volRows</tbody></table>"

$profRows = ($profileFolders | ForEach-Object {
    $gb = [math]::Round($_.Bytes / 1GB, 2)
    TRow @($_.Folder, "$gb GB")
}) -join ''
$profTable = "<table><thead><tr><th>Folder</th><th>Size</th></tr></thead><tbody>$profRows</tbody></table>"

$docsHtml = "<p class='muted'>Path: $(HE $docsPath)</p>"
$docsHtml += "<table><thead><tr><th>Folder / Subfolder</th><th>Size</th></tr></thead><tbody>"
foreach ($df in $docsFolders) {
    $gb = [math]::Round($df.Bytes / 1GB, 2)
    $docsHtml += "<tr class='folder-row'><td><strong>$(HE $df.Name)</strong></td><td>$gb GB</td></tr>"
    foreach ($sub in $df.SubFolders) {
        $sgb = [math]::Round($sub.Bytes / 1GB, 2)
        $docsHtml += "<tr><td>&nbsp;&nbsp;&nbsp;&nbsp;&rsaquo; $(HE $sub.Name)</td><td>$sgb GB</td></tr>"
    }
}
$docsHtml += "</tbody></table>"
if ($docsFiles) {
    $docsHtml += "<br><table><thead><tr><th>File at Root</th><th>Size</th><th>Modified</th></tr></thead><tbody>"
    foreach ($f in $docsFiles) {
        $mb2 = [math]::Round($f.Length / 1MB, 2)
        $docsHtml += "<tr><td>$(HE $f.Name)</td><td>$mb2 MB</td>" +
                     "<td>$($f.LastWriteTime | Get-Date -Format 'yyyy-MM-dd')</td></tr>"
    }
    $docsHtml += "</tbody></table>"
}

$storageHtml = (SubHtml 'Physical Disks - Health'              $sdTable) +
               (SubHtml 'SMART Reliability Counters'           $smartTable) +
               (SubHtml 'Logical Volumes'                      $volTable) +
               (SubHtml 'Top 20 Largest Profile Folders'       $profTable) +
               (SubHtml 'Documents Folder Tree'                $docsHtml)

# NETWORK
$netRows = ($netAdapters | ForEach-Object {
    "<tr><td>$(HE $_.Description)</td><td>$(HE ($_.IPAddress -join ', '))</td>" +
    "<td>$(HE ($_.DefaultIPGateway -join ', '))</td>" +
    "<td>$(HE ($_.DNSServerSearchOrder -join ', '))</td>" +
    "<td>$(HE $_.MACAddress)</td>" +
    "<td>$(if($_.DHCPEnabled){'DHCP'}else{'Static'})</td></tr>"
}) -join ''
$netTable = "<table><thead><tr><th>Adapter</th><th>IP(s)</th><th>Gateway</th><th>DNS</th><th>MAC</th><th>Mode</th></tr></thead>" +
            "<tbody>$netRows</tbody></table>"

$connRows = ($tcpConns | ForEach-Object {
    $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name
    TRow @("$($_.LocalAddress):$($_.LocalPort)", "$($_.RemoteAddress):$($_.RemotePort)", $_.OwningProcess, $proc)
}) -join ''
$connTable = "<table><thead><tr><th>Local</th><th>Remote</th><th>PID</th><th>Process</th></tr></thead>" +
             "<tbody>$connRows</tbody></table>"

$lisRows = ($tcpListen | Sort-Object LocalPort -Unique | ForEach-Object {
    $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name
    TRow @($_.LocalPort, $_.OwningProcess, $proc)
}) -join ''
$lisTable = "<table><thead><tr><th>Port</th><th>PID</th><th>Process</th></tr></thead><tbody>$lisRows</tbody></table>"

$wifiHtml = if ($wifiRaw) {
    $profiles = $wifiRaw | Where-Object { $_ -match 'All User Profile' }
    if ($profiles) { "<ul>$(($profiles | ForEach-Object { "<li>$(HE $_.Trim())</li>" }) -join '')</ul>" }
    else { "<p class='muted'>No saved Wi-Fi profiles.</p>" }
} else { "<p class='muted'>No Wi-Fi adapter detected.</p>" }

$netHtml = (SubHtml 'Adapters'                          $netTable) +
           (SubHtml 'Established Connections (top 40)'  $connTable) +
           (SubHtml 'Listening Ports'                   $lisTable) +
           (SubHtml 'Saved Wi-Fi Profiles'              $wifiHtml)

# SECURITY
$defKV = if ($mpStatus) { [ordered]@{
    'Antivirus Enabled'    = $mpStatus.AntivirusEnabled
    'Real-Time Protection' = $mpStatus.RealTimeProtectionEnabled
    'AV Signature Date'    = ($mpStatus.AntivirusSignatureLastUpdated | Get-Date -Format 'yyyy-MM-dd')
    'Tamper Protection'    = $mpStatus.IsTamperProtected
    'Behaviour Monitoring' = $mpStatus.BehaviorMonitorEnabled
    'Network Inspection'   = $mpStatus.NisEnabled
}} else { [ordered]@{ 'Status' = 'Windows Defender data unavailable' } }

$fwRows = ($fwProfiles | ForEach-Object {
    $cls = if ($_.Enabled) { 'ok' } else { 'crit' }
    "<tr><td>$(HE $_.Name)</td>" +
    "<td><span class='badge $cls'>$(if($_.Enabled){'Enabled'}else{'DISABLED'})</span></td>" +
    "<td>$(HE $_.DefaultInboundAction)</td><td>$(HE $_.DefaultOutboundAction)</td></tr>"
}) -join ''
$fwTable = "<table><thead><tr><th>Profile</th><th>State</th><th>Inbound</th><th>Outbound</th></tr></thead>" +
           "<tbody>$fwRows</tbody></table>"

$blHtml = if ($blVolumes) {
    $rows = ($blVolumes | ForEach-Object {
        $cls = if ($_.ProtectionStatus -eq 'On') { 'ok' } else { 'warn' }
        "<tr><td>$(HE $_.MountPoint)</td>" +
        "<td><span class='badge $cls'>$(HE $_.ProtectionStatus)</span></td>" +
        "<td>$(HE $_.EncryptionMethod)</td><td>$($_.EncryptionPercentage)%</td></tr>"
    }) -join ''
    "<table><thead><tr><th>Volume</th><th>Protection</th><th>Method</th><th>Encrypted</th></tr></thead>" +
    "<tbody>$rows</tbody></table>"
} else { "<p class='muted'>BitLocker cmdlets not available.</p>" }

$uacKV = if ($uacReg) { [ordered]@{
    'EnableLUA'                  = $uacReg.EnableLUA
    'ConsentPromptBehaviorAdmin' = $uacReg.ConsentPromptBehaviorAdmin
}} else { [ordered]@{ 'Status'='N/A' } }

$userRows = ($localUsers | ForEach-Object {
    $last = if ($_.LastLogon) { $_.LastLogon | Get-Date -Format 'yyyy-MM-dd' } else { 'Never' }
    $cls  = if (-not $_.Enabled) { 'muted-row' } else { '' }
    $enBadge = if ($_.Enabled) { "<span class='badge ok'>Active</span>" } else { "<span class='badge muted'>Disabled</span>" }
    "<tr class='$cls'><td>$(HE $_.Name)</td><td>$enBadge</td><td>$(HE $_.PasswordExpires)</td><td>$last</td></tr>"
}) -join ''
$userTable = "<table><thead><tr><th>Username</th><th>Status</th><th>Password Expires</th><th>Last Logon</th></tr></thead>" +
             "<tbody>$userRows</tbody></table>"

$failHtml = if ($failedLogons) {
    $rows = ($failedLogons | ForEach-Object {
        $xml  = [xml]$_.ToXml()
        $acct = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $src  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress'     }).'#text'
        TRow @($_.TimeCreated.ToString('yyyy-MM-dd HH:mm'), $acct, $src)
    }) -join ''
    if ($rows) {
        "<table><thead><tr><th>Time</th><th>Account</th><th>Source IP</th></tr></thead><tbody>$rows</tbody></table>"
    } else { "<p class='ok-text'>No failed logons in the Security log.</p>" }
} else { "<p class='muted'>$(if($isAdmin){'No failed logons.'}else{'Requires Administrator.'})</p>" }

$updHtml = if ($pendingUpdates.Count -eq 0) {
    "<p class='ok-text'>No pending updates.</p>"
} else {
    $rows = ($pendingUpdates | ForEach-Object { "<tr><td>$(HE $_.Title)</td></tr>" }) -join ''
    "<p class='warn-text'>$($pendingUpdates.Count) update(s) pending:</p>" +
    "<table><thead><tr><th>Update</th></tr></thead><tbody>$rows</tbody></table>"
}

$secHtml = (SubHtml 'Windows Defender'         (KVTable $defKV)) +
           (SubHtml 'Firewall Profiles'        $fwTable) +
           (SubHtml 'BitLocker'                $blHtml) +
           (SubHtml 'UAC'                      (KVTable $uacKV)) +
           (SubHtml 'Pending Windows Updates'  $updHtml) +
           (SubHtml 'Local User Accounts'      $userTable) +
           (SubHtml 'Recent Failed Logons'     $failHtml)

# SOFTWARE
$appRows = ($installedApps | ForEach-Object {
    TRow @($_.DisplayName, $_.DisplayVersion, $_.Publisher, $_.InstallDate)
}) -join ''
$softHtml = "<p class='muted'>$($installedApps.Count) applications installed.</p>" +
    "<table><thead><tr><th>Name</th><th>Version</th><th>Publisher</th><th>Install Date</th></tr></thead>" +
    "<tbody>$appRows</tbody></table>"

# STARTUP
$startRows = ($startupKeys | ForEach-Object {
    TRow @($_.Name, $_.Command, ($_.Hive -replace 'HKLM:\\','HKLM\' -replace 'HKCU:\\','HKCU\'))
}) -join ''
$startTable = if ($startRows) {
    "<table><thead><tr><th>Name</th><th>Command</th><th>Hive</th></tr></thead><tbody>$startRows</tbody></table>"
} else { "<p class='muted'>No registry startup entries found.</p>" }
$sfHtml = if ($startupFolderItems) {
    "<ul>$(($startupFolderItems | ForEach-Object { "<li>$(HE $_.FullName)</li>" }) -join '')</ul>"
} else { "<p class='muted'>No startup folder items.</p>" }
$startHtml = (SubHtml 'Registry Run Keys' $startTable) + (SubHtml 'Startup Folders' $sfHtml)

# SERVICES
$svcRunRows = ($svcRunning | ForEach-Object {
    TRow @($_.DisplayName, $_.Name, $_.StartType)
}) -join ''
$svcRunTable = "<table><thead><tr><th>Display Name</th><th>Service Name</th><th>Start Type</th></tr></thead>" +
               "<tbody>$svcRunRows</tbody></table>"
$svcStopRows = ($svcStopped | ForEach-Object {
    "<tr class='warn-row'><td>$(HE $_.DisplayName)</td><td>$(HE $_.Name)</td></tr>"
}) -join ''
$svcStopTable = if ($svcStopRows) {
    "<table><thead><tr><th>Display Name</th><th>Service Name</th></tr></thead><tbody>$svcStopRows</tbody></table>"
} else { "<p class='ok-text'>No auto-start services are stopped.</p>" }
$svcHtml = (SubHtml "Running Services ($($svcRunning.Count))"          $svcRunTable) +
           (SubHtml "Stopped Auto-Start Services ($($svcStopped.Count))" $svcStopTable)

# SCHEDULED TASKS
$taskRows = ($schedTasks | ForEach-Object {
    $act = ($_.Actions | Select-Object -First 1)
    $cmd = if ($act.Execute) { "$($act.Execute) $($act.Arguments)".Trim() } else { '' }
    TRow @("$($_.TaskPath)$($_.TaskName)", $_.State, $_.Author, $cmd)
}) -join ''
$taskHtml = if ($taskRows) {
    "<table><thead><tr><th>Task</th><th>State</th><th>Author</th><th>Command</th></tr></thead>" +
    "<tbody>$taskRows</tbody></table>"
} else { "<p class='muted'>No non-Microsoft enabled tasks found.</p>" }

# EVENT LOGS
function EvtTable($events) {
    if (-not $events) { return "<p class='muted'>No events in last 24 hours.</p>" }
    $rows = ($events | ForEach-Object {
        $lvl = switch ($_.Level) { 1{'CRITICAL'} 2{'ERROR'} 3{'WARNING'} default{'INFO'} }
        $cls = switch ($_.Level) { 1{'crit'} 2{'crit'} 3{'warn'} default{''} }
        $msg = (($_.Message -split "`n")[0]).Trim()
        "<tr><td>$($_.TimeCreated.ToString('HH:mm:ss'))</td>" +
        "<td><span class='badge $cls'>$lvl</span></td>" +
        "<td>$(HE $_.ProviderName)</td><td>$(HE $msg)</td></tr>"
    }) -join ''
    "<table><thead><tr><th>Time</th><th>Level</th><th>Source</th><th>Message</th></tr></thead>" +
    "<tbody>$rows</tbody></table>"
}
$evtHtml = (SubHtml 'System Log'      (EvtTable $evtSystem)) +
           (SubHtml 'Application Log' (EvtTable $evtApp))

# PERFORMANCE
$cpuPRows = ($procByCpu | ForEach-Object {
    TRow @($_.ProcessName, "$([math]::Round($_.CPU,1))s", "$([math]::Round($_.WorkingSet/1MB,0)) MB", $_.Id)
}) -join ''
$cpuPTable = "<table><thead><tr><th>Process</th><th>CPU Time</th><th>RAM</th><th>PID</th></tr></thead>" +
             "<tbody>$cpuPRows</tbody></table>"
$ramPRows = ($procByRam | ForEach-Object {
    TRow @($_.ProcessName, "$([math]::Round($_.WorkingSet/1MB,0)) MB", "$([math]::Round($_.CPU,1))s", $_.Id)
}) -join ''
$ramPTable = "<table><thead><tr><th>Process</th><th>RAM</th><th>CPU Time</th><th>PID</th></tr></thead>" +
             "<tbody>$ramPRows</tbody></table>"
$pfHtml   = ($pageFile | ForEach-Object {
    "<p>$(HE $_.Name) &mdash; Allocated: $($_.AllocatedBaseSize) MB | Peak: $($_.PeakUsage) MB</p>"
}) -join ''
$perfHtml = (SubHtml 'Top 15 by CPU' $cpuPTable) +
            (SubHtml 'Top 15 by RAM' $ramPTable) +
            (SubHtml 'Page File'     $pfHtml)

# INTEGRITY
$hfRows = ($hotfixes | ForEach-Object {
    TRow @(($_.InstalledOn | Get-Date -Format 'yyyy-MM-dd'), $_.HotFixID, $_.Description)
}) -join ''
$hfTable = "<table><thead><tr><th>Date</th><th>KB</th><th>Description</th></tr></thead><tbody>$hfRows</tbody></table>"
$cbsHtml = if ($cbsTail) {
    "<pre class='log'>$(($cbsTail | ForEach-Object { HE $_ }) -join "`n")</pre>"
} else { "<p class='muted'>CBS.log not accessible (needs Admin).</p>" }
$intHtml = (SubHtml 'Last 10 Hotfixes' $hfTable) + (SubHtml 'CBS Log (tail)' $cbsHtml)

# SHARES & REMOTE
$shareHtml = if ($smbShares) {
    $rows = ($smbShares | ForEach-Object { TRow @($_.Name, $_.Path, $_.Description) }) -join ''
    "<table><thead><tr><th>Share</th><th>Path</th><th>Description</th></tr></thead><tbody>$rows</tbody></table>"
} else { "<p class='muted'>No non-admin shares found.</p>" }
$remoteKV = [ordered]@{
    'RDP Enabled' = if ($rdpReg) { ($rdpReg.fDenyTSConnections -eq 0).ToString() } else { 'N/A' }
    'WinRM'       = "$($winrmSvc.Status)"
}
$remoteHtml = (SubHtml 'Shared Folders'       $shareHtml) +
              (SubHtml 'Remote Access Status' (KVTable $remoteKV))

# VIRTUALISATION
$virtKV = [ordered]@{
    'Hyper-V' = if ($hypervFeat) { "$($hypervFeat.State)" } else { 'N/A' }
}
$wslHtml = if ($wslList) {
    "<ul>$(($wslList | ForEach-Object { "<li>$(HE $_)</li>" }) -join '')</ul>"
} else { "<p class='muted'>WSL not installed or no distributions.</p>" }
$dockerHtml = if ($dockerPs) {
    "<pre class='log'>$(($dockerPs | ForEach-Object { HE $_ }) -join "`n")</pre>"
} else { "<p class='muted'>Docker not running or not installed.</p>" }
$virtHtml = (SubHtml 'Hypervisor'        (KVTable $virtKV)) +
            (SubHtml 'WSL Distributions' $wslHtml) +
            (SubHtml 'Docker Containers' $dockerHtml)

# BROWSERS
$brRows = ($browsersFound | ForEach-Object { TRow @($_.Browser, $_.Path, "$($_.SizeMB) MB") }) -join ''
$brHtml = if ($brRows) {
    "<table><thead><tr><th>Browser</th><th>Profile Path</th><th>Size</th></tr></thead><tbody>$brRows</tbody></table>"
} else { "<p class='muted'>No browser profiles detected.</p>" }

# PRINTERS
$prtRows = ($printers | ForEach-Object {
    $def = if ($_.Default) { "<span class='badge ok'>Default</span>" } else { '' }
    "<tr><td>$(HE $_.Name)</td><td>$def</td><td>$(HE $_.PrinterStatus)</td><td>$(HE $_.PortName)</td></tr>"
}) -join ''
$prtHtml = if ($prtRows) {
    "<table><thead><tr><th>Name</th><th></th><th>Status</th><th>Port</th></tr></thead><tbody>$prtRows</tbody></table>"
} else { "<p class='muted'>No printers found.</p>" }

# -------------------------------------------------------------------------------
# FINAL HTML ASSEMBLY
# -------------------------------------------------------------------------------
$issueCount  = $issues.Count
$critCount   = ($issues | Where-Object { $_.Severity -eq 'critical' }).Count
$badgeColour = if ($issueCount -eq 0) { '#27ae60' } elseif ($critCount -gt 0) { '#e74c3c' } else { '#f39c12' }
$badgeText   = if ($issueCount -eq 0) { 'Healthy' } else { "$issueCount Issue$(if($issueCount -ne 1){'s'})" }

$navItems = @(
    @('summary',     'Summary',             '!'),
    @('os',          'Operating System',    'OS'),
    @('hardware',    'Hardware',            'HW'),
    @('storage',     'Storage & SMART',     'HDD'),
    @('network',     'Network',             'NET'),
    @('security',    'Security',            'SEC'),
    @('software',    'Installed Software',  'APP'),
    @('startup',     'Startup',             'RUN'),
    @('services',    'Services',            'SVC'),
    @('tasks',       'Sched. Tasks',        'TSK'),
    @('eventlogs',   'Event Logs',          'EVT'),
    @('performance', 'Performance',         'PERF'),
    @('integrity',   'System Integrity',    'INT'),
    @('remote',      'Shares & Remote',     'REM'),
    @('virt',        'Virtualisation',      'VM'),
    @('browsers',    'Browsers',            'WEB'),
    @('printers',    'Printers',            'PRT')
)
$navHtml = ($navItems | ForEach-Object {
    "<a href='#$($_[0])' onclick='scrollTo(""$($_[0])"");return false;'>$($_[1])</a>"
}) -join ''

$allSections =
    (SectionHtml 'summary'     'Summary & Health Flags'       '!' $summaryHtml) +
    (SectionHtml 'os'          'Operating System'             'OS' $osHtml) +
    (SectionHtml 'hardware'    'Hardware'                     'HW' $hwHtml) +
    (SectionHtml 'storage'     'Storage & SMART Health'       'HDD' $storageHtml) +
    (SectionHtml 'network'     'Network'                      'NET' $netHtml) +
    (SectionHtml 'security'    'Security'                     'SEC' $secHtml) +
    (SectionHtml 'software'    'Installed Software'           'APP' $softHtml) +
    (SectionHtml 'startup'     'Startup Programs'             'RUN' $startHtml) +
    (SectionHtml 'services'    'Services'                     'SVC' $svcHtml) +
    (SectionHtml 'tasks'       'Scheduled Tasks'              'TSK' $taskHtml) +
    (SectionHtml 'eventlogs'   'Event Logs (last 24h)'        'EVT' $evtHtml) +
    (SectionHtml 'performance' 'Performance Snapshot'         'PERF' $perfHtml) +
    (SectionHtml 'integrity'   'System Integrity'             'INT' $intHtml) +
    (SectionHtml 'remote'      'Shares & Remote Access'       'REM' $remoteHtml) +
    (SectionHtml 'virt'        'Virtualisation & Containers'  'VM' $virtHtml) +
    (SectionHtml 'browsers'    'Browser Profiles'             'WEB' $brHtml) +
    (SectionHtml 'printers'    'Printers'                     'PRT' $prtHtml)

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PC Assessment - $($env:COMPUTERNAME) - $ReportDate</title>
<style>
:root{--bg:#0f1117;--surface:#1a1d27;--surface2:#22263a;--border:#2e3350;
  --text:#e2e8f0;--muted:#8892a4;--accent:#4f8ef7;--ok:#27ae60;--warn:#f39c12;--crit:#e74c3c;--hover:#2a3050;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);
  font-size:14px;line-height:1.5;display:flex;min-height:100vh;}
nav{width:200px;min-width:200px;background:var(--surface);border-right:1px solid var(--border);
  position:fixed;top:0;left:0;height:100vh;overflow-y:auto;z-index:100;}
.nav-head{padding:1em;border-bottom:1px solid var(--border);}
.nav-head h1{font-size:13px;color:var(--accent);font-weight:700;text-transform:uppercase;letter-spacing:.04em;}
.nav-head p{font-size:11px;color:var(--muted);margin-top:.2em;}
nav a{display:block;padding:.4em 1.1em;color:var(--muted);text-decoration:none;font-size:12.5px;
  border-left:3px solid transparent;transition:all .15s;}
nav a:hover,nav a.active{background:var(--hover);color:var(--text);border-left-color:var(--accent);}
main{margin-left:200px;padding:1.8em 2.2em;width:100%;max-width:1350px;}
.report-header{background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:1.3em 1.8em;margin-bottom:1.3em;display:flex;align-items:center;gap:1.2em;}
.big-badge{background:$badgeColour;color:#fff;border-radius:7px;padding:.45em 1.1em;
  font-weight:700;font-size:15px;white-space:nowrap;}
.report-header h1{font-size:19px;font-weight:700;}
.report-header p{color:var(--muted);font-size:12px;margin-top:.25em;}
section{background:var(--surface);border:1px solid var(--border);border-radius:9px;margin-bottom:1.1em;overflow:hidden;}
.sec-head{display:flex;align-items:center;gap:.65em;padding:.85em 1.2em;cursor:pointer;
  user-select:none;background:var(--surface2);border-bottom:1px solid var(--border);transition:background .15s;}
.sec-head:hover{background:var(--hover);}
.sec-head h2{font-size:13.5px;font-weight:600;flex:1;}
.sec-icon{font-size:11px;background:var(--border);color:var(--muted);padding:.15em .4em;
  border-radius:3px;font-weight:700;letter-spacing:.03em;}
.arrow{color:var(--muted);font-size:11px;transition:transform .2s;}
.arrow.closed{transform:rotate(-90deg);}
.sec-body{padding:1.1em 1.3em;}
.sec-body.hidden{display:none;}
.sub{margin-bottom:1.3em;}
.sub h3{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--accent);
  margin-bottom:.55em;padding-bottom:.3em;border-bottom:1px solid var(--border);}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:.3em;}
th{background:var(--surface2);color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;
  letter-spacing:.05em;padding:.45em .75em;text-align:left;border-bottom:1px solid var(--border);}
td{padding:.4em .75em;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word;}
tr:last-child td{border-bottom:none;}
tr:hover td{background:var(--hover);}
table.kv td:first-child{color:var(--muted);width:210px;font-size:12px;white-space:nowrap;}
.folder-row td{font-weight:600;background:var(--surface2);}
.alert{padding:.65em .95em;border-radius:6px;margin-bottom:.55em;font-size:13px;border-left:4px solid;}
.alert.critical{background:rgba(231,76,60,.12);border-color:var(--crit);}
.alert.warning{background:rgba(243,156,18,.12);border-color:var(--warn);}
.alert.notice{background:rgba(79,142,247,.12);border-color:var(--accent);}
.alert.ok{background:rgba(39,174,96,.12);border-color:var(--ok);}
.badge{display:inline-block;padding:.12em .5em;border-radius:4px;font-size:11px;font-weight:600;}
.badge.ok{background:rgba(39,174,96,.2);color:#2ecc71;}
.badge.warn{background:rgba(243,156,18,.2);color:#f39c12;}
.badge.crit{background:rgba(231,76,60,.2);color:#e74c3c;}
.badge.muted{background:var(--surface2);color:var(--muted);}
.bar-wrap{background:var(--surface2);border-radius:3px;height:14px;position:relative;min-width:100px;overflow:hidden;}
.bar-fill{height:100%;border-radius:3px;}
.bar-label{position:absolute;right:4px;top:0;font-size:10px;line-height:14px;color:#fff;font-weight:600;}
pre.log{background:var(--surface2);border:1px solid var(--border);border-radius:5px;padding:.7em .9em;
  font-size:11.5px;white-space:pre-wrap;word-break:break-all;max-height:280px;overflow-y:auto;
  color:var(--muted);font-family:'Consolas','Courier New',monospace;}
.muted{color:var(--muted);}
.meta{color:var(--muted);font-size:11px;margin-top:.9em;}
.ok-text{color:var(--ok);font-weight:600;}
.warn-text{color:var(--warn);font-weight:600;}
.muted-row td{opacity:.5;}
.warn-row td{background:rgba(243,156,18,.06);}
ul{padding-left:1.3em;}
li{padding:.12em 0;font-size:13px;}
p{font-size:13px;margin:.25em 0;}
::-webkit-scrollbar{width:5px;height:5px;}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px;}
@media(max-width:800px){nav{display:none;}main{margin-left:0;padding:1em;}}
</style>
</head>
<body>
<nav>
  <div class="nav-head">
    <h1>PC Assessment</h1>
    <p>$($env:COMPUTERNAME)</p>
    <p style="margin-top:.4em"><span class="badge" style="background:$badgeColour;color:#fff;font-size:12px">$badgeText</span></p>
  </div>
  $navHtml
  <div style="padding:1em;font-size:10.5px;color:var(--muted);border-top:1px solid var(--border);margin-top:.4em">$ReportDate</div>
</nav>
<main>
  <div class="report-header">
    <span class="big-badge">$badgeText</span>
    <div>
      <h1>PC Assessment Report</h1>
      <p>$($env:COMPUTERNAME) &bull; $($env:USERDOMAIN)\$($env:USERNAME) &bull; $ReportDate</p>
      <p>Elevated: $(if($isAdmin){'Yes (Administrator)'}else{'No - rerun as Admin for complete data'})</p>
    </div>
  </div>
  $allSections
</main>
<script>
function toggleSection(id){
  var b=document.getElementById('body-'+id);
  var a=document.getElementById('arrow-'+id);
  var hidden=b.classList.toggle('hidden');
  a.classList.toggle('closed',hidden);
}
function scrollTo(id){
  var el=document.getElementById(id);
  if(el){el.scrollIntoView({behavior:'smooth',block:'start'});}
  document.querySelectorAll('nav a').forEach(function(a){a.classList.remove('active');});
  var lnk=document.querySelector('nav a[href="#'+id+'"]');
  if(lnk){lnk.classList.add('active');}
}
window.addEventListener('scroll',function(){
  var cur='';
  document.querySelectorAll('section[id]').forEach(function(s){
    if(window.scrollY>=s.offsetTop-120){cur=s.id;}
  });
  document.querySelectorAll('nav a').forEach(function(a){
    a.classList.toggle('active',a.getAttribute('href')==='#'+cur);
  });
});
</script>
</body>
</html>
"@

$html | Out-File -FilePath $ReportFile -Encoding UTF8 -NoNewline

Write-Host ""
Write-Host "  [OK] Assessment complete." -ForegroundColor Green
Write-Host "  HTML Report : $ReportFile" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Open with   : Invoke-Item '$ReportFile'" -ForegroundColor DarkCyan
Write-Host ""
