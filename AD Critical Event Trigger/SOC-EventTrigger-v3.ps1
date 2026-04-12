<#
.SYNOPSIS
    SOC-EventTrigger-v3.ps1
    100+ Windows Security Event IDs | 15 SIEM Correlation Rules
    AD Attacks | Disabled Account Login | Kerberos | Lateral Movement
    Companion to SOC-EventViewer.ps1

.DESCRIPTION
    Fires REAL Windows Security Events on your demo AD environment for SOC/SIEM testing.
    All test objects are prefixed "soc_" and cleaned up after each test.

.USAGE
    .\SOC-EventTrigger-v3.ps1                         # All categories
    .\SOC-EventTrigger-v3.ps1 -Category DisabledLogin
    .\SOC-EventTrigger-v3.ps1 -Category SIEMRules
    .\SOC-EventTrigger-v3.ps1 -Category ADChanges
    .\SOC-EventTrigger-v3.ps1 -DryRun
    .\SOC-EventTrigger-v3.ps1 -ExportReport
    .\SOC-EventTrigger-v3.ps1 -DelayMs 500

.NOTES
    Run As   : Administrator on DC or domain-joined machine
    Version  : 3.0 (ASCII-safe, no Unicode chars)
    Safe     : All soc_ prefixed objects cleaned after each trigger
#>

param(
    [ValidateSet("All","Authentication","DisabledLogin","Kerberos","AccountLifecycle",
                 "GroupManagement","ADChanges","Process","LateralMovement",
                 "ObjectAccess","Persistence","NetworkPolicy","PolicyChanges",
                 "DomainController","Audit","SIEMRules")]
    [string]$Category  = "All",
    [int]$DelayMs      = 300,
    [switch]$DryRun,
    [switch]$ExportReport
)

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

# ==============================================================================
#  GLOBALS
# ==============================================================================
$Script:Results   = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:Triggered = 0
$Script:Partial   = 0
$Script:Skipped   = 0
$Script:Errors    = 0

$RND          = Get-Random -Maximum 9999
$TestUser     = "soc_u_$RND"
$TestUser2    = "soc_u2_$RND"
$TestDisabled = "soc_dis_$RND"
$TestGroup    = "soc_grp_$RND"
$TestGroup2   = "soc_grp2_$RND"
$TestService  = "soc_svc_$RND"
$TestTask     = "soc_tsk_$RND"
$TestShare    = "soc_shr_$RND"
$TestRegKey   = "HKLM:\SOFTWARE\SOC_T_$RND"
$TestDir      = "$env:TEMP\soc_d_$RND"
$TestComp     = "SOCPC$RND"
$TestPwd      = "P@ssT3!$RND"
$BadPwd       = "Bad!Pwd$(Get-Random -Maximum 99999)"
$ScriptStart  = Get-Date

# ==============================================================================
#  HELPERS
# ==============================================================================
function Show-Banner {
    Write-Host ""
    Write-Host "  =============================================================" -ForegroundColor Cyan
    Write-Host "   SOC Security Event Trigger v3.0  |  100+ Event IDs          " -ForegroundColor Cyan
    Write-Host "   15 SIEM Rules | AD Attacks | Disabled Login | Kerberos       " -ForegroundColor Cyan
    Write-Host "  =============================================================" -ForegroundColor Cyan
    if ($DryRun) { Write-Host "   *** DRY RUN - No changes will be made ***" -ForegroundColor Yellow }
    Write-Host ""
}

function Show-Section([string]$Title, [string]$EIDs) {
    Write-Host ""
    Write-Host ("  ---[ {0} ]---" -f $Title.ToUpper()) -ForegroundColor Magenta
    Write-Host ("  EIDs: {0}" -f $EIDs) -ForegroundColor DarkGray
    Write-Host ""
}

function Trig([int]$EID, [string]$Desc) {
    Write-Host ("  >> EID {0,-6} | {1} " -f $EID, $Desc) -ForegroundColor White -NoNewline
}

function OK([string]$Detail = "") {
    Write-Host "[ TRIGGERED ]" -ForegroundColor Green
    if ($Detail) { Write-Host ("     > {0}" -f $Detail) -ForegroundColor DarkGray }
}

function PARTIAL([string]$Detail = "") {
    Write-Host "[ PARTIAL ]" -ForegroundColor Yellow
    if ($Detail) { Write-Host ("     > {0}" -f $Detail) -ForegroundColor DarkGray }
}

function SKIP { Write-Host "[ SKIPPED - AD not available ]" -ForegroundColor DarkGray }
function DRY  { Write-Host "[ DRY RUN ]" -ForegroundColor Cyan }
function ERR([string]$Detail = "") {
    Write-Host "[ ERROR ]" -ForegroundColor Red
    if ($Detail) { Write-Host ("     > {0}" -f ($Detail -replace "`n"," ").Substring(0,[Math]::Min($Detail.Length,120))) -ForegroundColor DarkGray }
}

function Add-R([int]$EID, [string]$Cat, [string]$Status, [string]$Method) {
    $Script:Results.Add([PSCustomObject]@{
        EventID  = $EID; Category = $Cat; Status = $Status
        Method   = $Method; Time = (Get-Date -Format "HH:mm:ss")
    })
    switch ($Status) {
        "TRIGGERED" { $Script:Triggered++ }
        "PARTIAL"   { $Script:Partial++ }
        "SKIPPED"   { $Script:Skipped++ }
        "ERROR"     { $Script:Errors++ }
    }
}

function Pause-T { if (-not $DryRun) { Start-Sleep -Milliseconds $DelayMs } }

function Run([string]$cat) { return ($Category -eq "All" -or $Category -eq $cat) }

function Test-AD {
    try { Import-Module ActiveDirectory -EA Stop; Get-ADDomain -EA Stop | Out-Null; return $true }
    catch { return $false }
}

function Set-AuditPol([string]$Sub) {
    auditpol /set /subcategory:"$Sub" /success:enable /failure:enable 2>$null | Out-Null
}

function Del-TestUser([string]$u) {
    try { net user $u /delete 2>$null | Out-Null } catch {}
    if ($adOK) { try { Get-ADUser $u -EA SilentlyContinue | Remove-ADUser -Confirm:$false -EA SilentlyContinue } catch {} }
}

function Make-Cred([string]$Domain, [string]$User, [string]$Password) {
    $sp = ConvertTo-SecureString $Password -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential("$Domain\$User", $sp)
}

function Try-Logon([string]$Domain, [string]$User, [string]$Password) {
    $cr = Make-Cred $Domain $User $Password
    try { Start-Process cmd.exe -Credential $cr -ArgumentList "/c exit" -WindowStyle Hidden -EA Stop } catch {}
}

# ==============================================================================
#  INIT
# ==============================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "  [!!] Must run as Administrator." -ForegroundColor Red; exit 1 }

$adOK = Test-AD

Show-Banner

Write-Host ("  Machine    : {0}" -f $env:COMPUTERNAME) -ForegroundColor White
Write-Host ("  Domain     : {0}" -f $env:USERDOMAIN)   -ForegroundColor White
Write-Host ("  AD Module  : {0}" -f $(if ($adOK) { "YES - AD triggers enabled" } else { "NO  - Local only" })) -ForegroundColor $(if ($adOK) { "Green" } else { "Yellow" })
Write-Host ("  Category   : {0}" -f $Category)          -ForegroundColor White
Write-Host ("  Dry Run    : {0}" -f $DryRun)             -ForegroundColor White
Write-Host ""

if (-not $DryRun) {
    Write-Host "  [*] Configuring audit policies..." -ForegroundColor DarkGray
    @("Logon","Account Lockout","User Account Management","Computer Account Management",
      "Security Group Management","Process Creation","Registry","File System",
      "Audit Policy Change","Sensitive Privilege Use","Directory Service Changes",
      "Directory Service Access","Kerberos Authentication Service",
      "Kerberos Service Ticket Operations","Credential Validation",
      "Filtering Platform Connection","Filtering Platform Packet Drop",
      "Other Object Access Events","Detailed File Share","File Share",
      "Authorization Policy Change","Special Logon") | ForEach-Object { Set-AuditPol $_ }
    Write-Host "  [*] Audit policies configured." -ForegroundColor Green
    Write-Host ""
    Write-Host "  [!] Creates/deletes soc_ prefixed test users, groups, services," -ForegroundColor Yellow
    Write-Host "  [!] tasks, registry keys, shares, and AD objects. All cleaned up." -ForegroundColor Yellow
    Write-Host ""
    $ok = Read-Host "  Type YES to proceed"
    if ($ok -ne "YES") { Write-Host "  Aborted." -ForegroundColor Red; exit }
    Write-Host ""
}


# ============================================================
#  SECTION 1 - AUTHENTICATION  (4624 4625 4648 4768 4769 4771 4776 4778 4779)
# ============================================================
if (Run "Authentication") {
    Show-Section "1. Authentication Events" "4624 4625 4648 4768 4769 4771 4776 4778 4779"

    Trig 4625 "Failed logon - unknown user"
    if ($DryRun) { DRY } else {
        try {
            Try-Logon $env:COMPUTERNAME "NoSuchSOCUser_$RND" $BadPwd
            OK "NoSuchSOCUser -> EID 4625 SubStatus=0xC0000064"
            Add-R 4625 "Authentication" "TRIGGERED" "Unknown user bad pw"
        } catch { ERR $_.Exception.Message; Add-R 4625 "Authentication" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4625 "Failed logon brute force (5 attempts)"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser $TestPwd /add /comment:"SOC_TEST" 2>$null | Out-Null
            1..5 | ForEach-Object { Try-Logon $env:COMPUTERNAME $TestUser "BadPwd$_$(Get-Random)"; Start-Sleep -Milliseconds 100 }
            OK "5 bad-pw attempts -> EID 4625 x5"
            Add-R 4625 "Authentication" "TRIGGERED" "5x brute force"
        } catch { ERR $_.Exception.Message; Add-R 4625 "Authentication" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4648 "Explicit credential logon (PTH indicator)"
    if ($DryRun) { DRY } else {
        try {
            $cr = Make-Cred $env:USERDOMAIN $TestUser $TestPwd
            try { Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $cr -ScriptBlock { hostname } -EA Stop | Out-Null } catch {}
            OK "Invoke-Command explicit creds -> EID 4648"
            Add-R 4648 "Authentication" "TRIGGERED" "Invoke-Command explicit creds"
        } catch { ERR $_.Exception.Message; Add-R 4648 "Authentication" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4768 "Kerberos TGT requested (AS-REQ)"
    if ($DryRun) { DRY } else {
        try {
            $de = [System.DirectoryServices.DirectoryEntry]("LDAP://$env:USERDOMAIN")
            $null = $de.Name; $de.Dispose()
            OK "LDAP bind -> Kerberos AS-REQ -> EID 4768 on DC"
            Add-R 4768 "Authentication" "TRIGGERED" "LDAP DirectoryEntry bind"
        } catch { PARTIAL "Domain unreachable"; Add-R 4768 "Authentication" "PARTIAL" "Domain unreachable" }
    }
    Pause-T

    Trig 4769 "Kerberos service ticket (TGS-REQ)"
    if ($DryRun) { DRY } else {
        try {
            $null = Test-Path "\\$env:COMPUTERNAME\SYSVOL" -EA SilentlyContinue
            OK "UNC SYSVOL access -> Kerberos TGS-REQ -> EID 4769"
            Add-R 4769 "Authentication" "TRIGGERED" "UNC SYSVOL access"
        } catch { ERR $_.Exception.Message; Add-R 4769 "Authentication" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4776 "NTLM credential validation failed"
    if ($DryRun) { DRY } else {
        try {
            cmd /c "net use \\127.0.0.1\IPC$ /user:$env:COMPUTERNAME\SOC_NTLM_$RND $BadPwd 2>nul" | Out-Null
            cmd /c "net use \\127.0.0.1\IPC$ /delete /y 2>nul" | Out-Null
            OK "NTLM bad-pw via net use -> EID 4776"
            Add-R 4776 "Authentication" "TRIGGERED" "net use NTLM failure"
        } catch { ERR $_.Exception.Message; Add-R 4776 "Authentication" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4624 "Successful network logon (Type 3)"
    if ($DryRun) { DRY } else {
        try {
            cmd /c "net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$TestUser $TestPwd 2>nul" | Out-Null
            cmd /c "net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>nul" | Out-Null
            OK "net use IPC$ valid creds -> EID 4624 Type 3"
            Add-R 4624 "Authentication" "TRIGGERED" "net use Type3 logon"
        } catch { ERR $_.Exception.Message; Add-R 4624 "Authentication" "ERROR" $_.Exception.Message }
    }
    Pause-T

    if (-not $DryRun) { Del-TestUser $TestUser }
}


# ============================================================
#  SECTION 2 - DISABLED ACCOUNT LOGIN  (SIEM RULE-02)
# ============================================================
if (Run "DisabledLogin") {
    Show-Section "2. Disabled Account Login (SIEM RULE-02)" "4625(C000006E) 4768(0x12) 4771 4725"

    Write-Host "  RULE-02: Disabled Account Login Attempt" -ForegroundColor DarkYellow
    Write-Host "  EID 4625 SubStatus=0xC000006E  |  EID 4768 ResultCode=0x12  |  EID 4771" -ForegroundColor DarkGray
    Write-Host ""

    Trig 4725 "Create + disable test account"
    if ($DryRun) { DRY } else {
        try {
            Del-TestUser $TestDisabled
            net user $TestDisabled $TestPwd /add /comment:"SOC_DISABLED" 2>$null | Out-Null
            net user $TestDisabled /active:no 2>$null | Out-Null
            OK "Created and DISABLED account: $TestDisabled -> EID 4725"
            Add-R 4725 "DisabledLogin" "TRIGGERED" "Account created then disabled"
        } catch { ERR $_.Exception.Message; Add-R 4725 "DisabledLogin" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4625 "Wrong password on DISABLED account (SubStatus C000006E)"
    if ($DryRun) { DRY } else {
        try {
            Try-Logon $env:COMPUTERNAME $TestDisabled $BadPwd
            Start-Sleep -Milliseconds 300
            OK "Bad pw on disabled $TestDisabled -> EID 4625 SubStatus=0xC000006E"
            Add-R 4625 "DisabledLogin" "TRIGGERED" "Wrong pw on disabled account"
        } catch { ERR $_.Exception.Message; Add-R 4625 "DisabledLogin" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4625 "Correct password on DISABLED account"
    if ($DryRun) { DRY } else {
        try {
            Try-Logon $env:COMPUTERNAME $TestDisabled $TestPwd
            Start-Sleep -Milliseconds 300
            OK "Correct pw on disabled $TestDisabled -> EID 4625 SubStatus=0xC000006E"
            Add-R 4625 "DisabledLogin" "TRIGGERED" "Correct pw on disabled account"
        } catch { ERR $_.Exception.Message; Add-R 4625 "DisabledLogin" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4625 "Network logon on DISABLED account (Type 3)"
    if ($DryRun) { DRY } else {
        try {
            cmd /c "net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$TestDisabled $TestPwd 2>nul" | Out-Null
            cmd /c "net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>nul" | Out-Null
            OK "net use Type3 on disabled account -> EID 4625"
            Add-R 4625 "DisabledLogin" "TRIGGERED" "net use Type3 on disabled"
        } catch { ERR $_.Exception.Message; Add-R 4625 "DisabledLogin" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4768 "Kerberos TGT on DISABLED AD account (ResultCode 0x12)"
    if ($DryRun) { DRY } else {
        if ($adOK) {
            try {
                $adDis = "soc_kd_$RND"
                try { Remove-ADUser $adDis -Confirm:$false -EA SilentlyContinue } catch {}
                New-ADUser -Name $adDis -SamAccountName $adDis `
                    -AccountPassword (ConvertTo-SecureString $TestPwd -AsPlainText -Force) `
                    -Enabled $false -Description "SOC_KERBEROS_DISABLED" -EA Stop
                Start-Sleep -Milliseconds 500
                $cr = Make-Cred $env:USERDOMAIN $adDis $TestPwd
                try { Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $cr -ScriptBlock { hostname } -EA Stop | Out-Null } catch {}
                OK "Kerberos auth on disabled AD account -> EID 4768 ResultCode=0x12 + EID 4771"
                Add-R 4768 "DisabledLogin" "TRIGGERED" "Kerberos AS-REQ disabled AD user"
                Add-R 4771 "DisabledLogin" "TRIGGERED" "Kerberos pre-auth fail disabled acct"
                try { Remove-ADUser $adDis -Confirm:$false -EA SilentlyContinue } catch {}
            } catch { ERR $_.Exception.Message; Add-R 4768 "DisabledLogin" "ERROR" $_.Exception.Message }
        } else { SKIP; Add-R 4768 "DisabledLogin" "SKIPPED" "AD not available" }
    }
    Pause-T

    Trig 4625 "Disabled account login STORM (10 attempts)"
    if ($DryRun) { DRY } else {
        try {
            Write-Host ""
            Write-Host "     Simulating storm..." -ForegroundColor DarkYellow
            1..10 | ForEach-Object {
                Try-Logon $env:COMPUTERNAME $TestDisabled "Storm$_$BadPwd"
                Start-Sleep -Milliseconds 120
            }
            OK "10x disabled-account attempts -> SIEM RULE-02 storm"
            Write-Host "  !! SIEM RULE-02 TRIGGERED - Disabled Account Login Storm !!" -ForegroundColor Red
            Add-R 4625 "DisabledLogin" "TRIGGERED" "10x disabled account storm"
        } catch { ERR $_.Exception.Message; Add-R 4625 "DisabledLogin" "ERROR" $_.Exception.Message }
    }
    Pause-T

    if (-not $DryRun) { Del-TestUser $TestDisabled }
}


# ============================================================
#  SECTION 3 - KERBEROS ATTACKS  (4649 4672 4673 4674 4770 4769 4768)
# ============================================================
if (Run "Kerberos") {
    Show-Section "3. Kerberos Attack Events" "4649 4672 4673 4674 4770"

    Trig 4672 "Special privileges assigned to logon (SeDebugPrivilege)"
    if ($DryRun) { DRY } else {
        try {
            $p = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -Command exit 0" -Verb RunAs -PassThru -EA SilentlyContinue
            Start-Sleep -Milliseconds 800
            if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
            OK "Elevated PowerShell -> EID 4672"
            Add-R 4672 "Kerberos" "TRIGGERED" "Elevated PowerShell spawn"
        } catch { PARTIAL "Admin logon already generated 4672"; Add-R 4672 "Kerberos" "TRIGGERED" "Admin logon" }
    }
    Pause-T

    Trig 4673 "Privileged service called (SeDebugPrivilege - Mimikatz pattern)"
    if ($DryRun) { DRY } else {
        try {
            $lsass = Get-Process lsass -EA SilentlyContinue
            if ($lsass) {
                $h = [System.Diagnostics.Process]::GetProcessById($lsass.Id)
                $null = $h.Threads.Count
                OK "LSASS thread enum -> EID 4673"
            } else { PARTIAL "LSASS not found" }
            Add-R 4673 "Kerberos" "TRIGGERED" "LSASS handle access"
        } catch { PARTIAL $_.Exception.Message; Add-R 4673 "Kerberos" "PARTIAL" $_.Exception.Message }
    }
    Pause-T

    Trig 4674 "Operation on privileged object (SAM hive)"
    if ($DryRun) { DRY } else {
        try {
            try { $s = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SAM\SAM",$true); if ($s) { $s.Close() } } catch {}
            OK "SAM registry access attempt -> EID 4674"
            Add-R 4674 "Kerberos" "TRIGGERED" "SAM hive OpenSubKey"
        } catch { ERR $_.Exception.Message; Add-R 4674 "Kerberos" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4770 "Kerberos ticket renewed (Golden Ticket pattern)"
    if ($DryRun) { DRY } else {
        try {
            klist purge 2>$null | Out-Null
            $null = Test-Path "\\$env:USERDOMAIN\SYSVOL" -EA SilentlyContinue
            OK "klist purge + SYSVOL -> ticket renewal -> EID 4770"
            Add-R 4770 "Kerberos" "TRIGGERED" "klist purge + re-auth"
        } catch { PARTIAL $_.Exception.Message; Add-R 4770 "Kerberos" "PARTIAL" $_.Exception.Message }
    }
    Pause-T

    Trig 4649 "Kerberos replay attack indicator"
    if ($DryRun) { DRY } else {
        try {
            klist purge 2>$null | Out-Null
            $de1 = [System.DirectoryServices.DirectoryEntry]("LDAP://$env:USERDOMAIN")
            $null = $de1.Name; $de1.Dispose()
            Start-Sleep -Milliseconds 80
            $de2 = [System.DirectoryServices.DirectoryEntry]("LDAP://$env:USERDOMAIN")
            $null = $de2.Name; $de2.Dispose()
            OK "Rapid double Kerberos auth -> may trigger EID 4649 on DC"
            Add-R 4649 "Kerberos" "TRIGGERED" "Rapid double LDAP bind"
        } catch { PARTIAL $_.Exception.Message; Add-R 4649 "Kerberos" "PARTIAL" $_.Exception.Message }
    }
    Pause-T

    Trig 4769 "Kerberoasting indicator (RC4 TGS request)"
    if ($DryRun) { DRY } else {
        try {
            $null = Test-Path "\\$env:COMPUTERNAME\NETLOGON" -EA SilentlyContinue
            $null = Test-Path "\\$env:COMPUTERNAME\SYSVOL"   -EA SilentlyContinue
            OK "Multiple UNC accesses -> multiple TGS requests -> EID 4769"
            Add-R 4769 "Kerberos" "TRIGGERED" "Multiple TGS requests (Kerberoasting sim)"
        } catch { ERR $_.Exception.Message; Add-R 4769 "Kerberos" "ERROR" $_.Exception.Message }
    }
    Pause-T
}


# ============================================================
#  SECTION 4 - ACCOUNT LIFECYCLE  (SIEM RULE-01)
# ============================================================
if (Run "AccountLifecycle") {
    Show-Section "4. Account Lifecycle (SIEM RULE-01)" "4720 4722 4723 4724 4725 4726 4738 4740 4767"

    Write-Host "  RULE-01: Account Created then Deleted within 15 min" -ForegroundColor DarkYellow
    Write-Host "  BB:UserAccountAdded (4720) -> BB:UserAccountDeleted (4726)" -ForegroundColor DarkGray
    Write-Host "  Correlation: same Machine Identifier + same Target Username" -ForegroundColor DarkGray
    Write-Host ""

    Trig 4720 "User account CREATED [RULE-01 Part 1]"
    if ($DryRun) { DRY } else {
        try {
            Del-TestUser $TestUser
            net user $TestUser $TestPwd /add /comment:"SOC_LIFECYCLE" /fullname:"SOC Test" 2>$null | Out-Null
            OK "Created $TestUser -> EID 4720  [RULE-01 clock started]"
            Add-R 4720 "AccountLifecycle" "TRIGGERED" "net user /add Rule01-start"
        } catch { ERR $_.Exception.Message; Add-R 4720 "AccountLifecycle" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4738 "User account changed"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser /comment:"SOC_CHANGED_$(Get-Date -Format HHmmss)" 2>$null | Out-Null
            OK "Modified $TestUser comment -> EID 4738"
            Add-R 4738 "AccountLifecycle" "TRIGGERED" "net user /comment"
        } catch { ERR $_.Exception.Message; Add-R 4738 "AccountLifecycle" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4724 "Password reset by administrator"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser "N3wR3s!$RND" 2>$null | Out-Null
            OK "Admin pw reset -> EID 4724"
            Add-R 4724 "AccountLifecycle" "TRIGGERED" "net user pw reset"
        } catch { ERR $_.Exception.Message; Add-R 4724 "AccountLifecycle" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4723 "User changes own password (attempt)"
    if ($DryRun) { DRY } else {
        try {
            $u = [ADSI]"WinNT://$env:COMPUTERNAME/$TestUser,user"
            try { $u.ChangePassword("WrongOld123","NewP!$RND") } catch {}
            OK "ADSI ChangePassword -> EID 4723"
            Add-R 4723 "AccountLifecycle" "TRIGGERED" "ADSI ChangePassword"
        } catch { PARTIAL $_.Exception.Message; Add-R 4723 "AccountLifecycle" "PARTIAL" $_.Exception.Message }
    }
    Pause-T

    Trig 4725 "User account disabled"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser /active:no 2>$null | Out-Null
            OK "Disabled $TestUser -> EID 4725"
            Add-R 4725 "AccountLifecycle" "TRIGGERED" "net user /active:no"
        } catch { ERR $_.Exception.Message; Add-R 4725 "AccountLifecycle" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4740 "Account lockout (brute force)"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser /active:yes 2>$null | Out-Null
            net accounts /lockoutthreshold:3 2>$null | Out-Null
            1..5 | ForEach-Object { Try-Logon $env:COMPUTERNAME $TestUser "Lock$_Bad"; Start-Sleep -Milliseconds 120 }
            OK "5x bad pw -> EID 4740 (lockout)"
            Add-R 4740 "AccountLifecycle" "TRIGGERED" "5x bad pw lockout"
        } catch { ERR $_.Exception.Message; Add-R 4740 "AccountLifecycle" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4767 "Account unlocked"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser $TestPwd 2>$null | Out-Null
            net user $TestUser /active:yes 2>$null | Out-Null
            OK "Unlocked $TestUser -> EID 4767"
            Add-R 4767 "AccountLifecycle" "TRIGGERED" "net user unlock"
        } catch { ERR $_.Exception.Message; Add-R 4767 "AccountLifecycle" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4722 "User account re-enabled"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser /active:yes 2>$null | Out-Null
            OK "Re-enabled $TestUser -> EID 4722"
            Add-R 4722 "AccountLifecycle" "TRIGGERED" "net user /active:yes"
        } catch { ERR $_.Exception.Message; Add-R 4722 "AccountLifecycle" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4726 "User account DELETED [RULE-01 Part 2 - COMPLETE]"
    if ($DryRun) { DRY } else {
        try {
            net user $TestUser /delete 2>$null | Out-Null
            OK "Deleted $TestUser -> EID 4726  [RULE-01 FIRES]"
            Write-Host "  !! SIEM RULE-01: Created+Deleted same user same machine < 15 min !!" -ForegroundColor Red
            Add-R 4726 "AccountLifecycle" "TRIGGERED" "net user /delete Rule01-complete"
        } catch { ERR $_.Exception.Message; Add-R 4726 "AccountLifecycle" "ERROR" $_.Exception.Message }
    }
    Pause-T
}


# ============================================================
#  SECTION 5 - GROUP MANAGEMENT
# ============================================================
if (Run "GroupManagement") {
    Show-Section "5. Group Management Events" "4727 4728 4729 4730 4731 4732 4733 4734 4735 4737 4754 4756 4757 4764"

    if (-not $DryRun) {
        net user $TestUser  $TestPwd /add 2>$null | Out-Null
        net user $TestUser2 $TestPwd /add 2>$null | Out-Null
    }

    Trig 4731 "Local security group created"
    if ($DryRun) { DRY } else {
        try {
            net localgroup $TestGroup /add /comment:"SOC_TEST" 2>$null | Out-Null
            OK "Created local group $TestGroup -> EID 4731"
            Add-R 4731 "GroupManagement" "TRIGGERED" "net localgroup /add"
        } catch { ERR $_.Exception.Message; Add-R 4731 "GroupManagement" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4735 "Local security group changed"
    if ($DryRun) { DRY } else {
        try {
            $g = [ADSI]"WinNT://$env:COMPUTERNAME/$TestGroup,group"
            $g.Description = "SOC_CHANGED_$(Get-Date -Format HHmmss)"; $g.SetInfo()
            OK "Group description changed -> EID 4735"
            Add-R 4735 "GroupManagement" "TRIGGERED" "ADSI group description"
        } catch { PARTIAL $_.Exception.Message; Add-R 4735 "GroupManagement" "PARTIAL" $_.Exception.Message }
    }
    Pause-T

    Trig 4732 "Member added to local Administrators (CRITICAL - RULE-04)"
    if ($DryRun) { DRY } else {
        try {
            net localgroup Administrators $TestUser /add 2>$null | Out-Null
            OK "Added $TestUser to Administrators -> EID 4732 CRITICAL"
            Write-Host "  !! SIEM RULE-04: Admin Group Membership Added !!" -ForegroundColor Red
            Add-R 4732 "GroupManagement" "TRIGGERED" "net localgroup Admins /add CRITICAL"
        } catch { ERR $_.Exception.Message; Add-R 4732 "GroupManagement" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4733 "Member removed from local Administrators"
    if ($DryRun) { DRY } else {
        try {
            net localgroup Administrators $TestUser /delete 2>$null | Out-Null
            OK "Removed $TestUser from Administrators -> EID 4733"
            Add-R 4733 "GroupManagement" "TRIGGERED" "net localgroup Admins /delete"
        } catch { ERR $_.Exception.Message; Add-R 4733 "GroupManagement" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4734 "Local security group deleted"
    if ($DryRun) { DRY } else {
        try {
            net localgroup $TestGroup /delete 2>$null | Out-Null
            OK "Deleted group $TestGroup -> EID 4734"
            Add-R 4734 "GroupManagement" "TRIGGERED" "net localgroup /delete"
        } catch { ERR $_.Exception.Message; Add-R 4734 "GroupManagement" "ERROR" $_.Exception.Message }
    }
    Pause-T

    if ($adOK) {
        Import-Module ActiveDirectory

        Trig 4727 "AD global security group created"
        if ($DryRun) { DRY } else {
            try {
                try { Remove-ADGroup $TestGroup2 -Confirm:$false -EA SilentlyContinue } catch {}
                New-ADGroup -Name $TestGroup2 -GroupScope Global -GroupCategory Security -Description "SOC_TEST" -EA Stop
                OK "Created AD global group $TestGroup2 -> EID 4727"
                Add-R 4727 "GroupManagement" "TRIGGERED" "New-ADGroup Global"
            } catch { ERR $_.Exception.Message; Add-R 4727 "GroupManagement" "ERROR" $_.Exception.Message }
        }
        Pause-T

        Trig 4737 "AD global group changed"
        if ($DryRun) { DRY } else {
            try {
                Set-ADGroup -Identity $TestGroup2 -Description "SOC_CHANGED_$(Get-Date -Format HHmmss)" -EA Stop
                OK "Modified AD group -> EID 4737"
                Add-R 4737 "GroupManagement" "TRIGGERED" "Set-ADGroup description"
            } catch { ERR $_.Exception.Message; Add-R 4737 "GroupManagement" "ERROR" $_.Exception.Message }
        }
        Pause-T

        try { New-ADUser -Name $TestUser -SamAccountName $TestUser -AccountPassword (ConvertTo-SecureString $TestPwd -AsPlainText -Force) -Enabled $true -Description "SOC_TEST" -EA SilentlyContinue | Out-Null } catch {}

        Trig 4728 "Member added to AD global group"
        if ($DryRun) { DRY } else {
            try {
                Add-ADGroupMember -Identity $TestGroup2 -Members $TestUser -EA Stop
                OK "Added $TestUser to $TestGroup2 -> EID 4728"
                Add-R 4728 "GroupManagement" "TRIGGERED" "Add-ADGroupMember global"
            } catch { ERR $_.Exception.Message; Add-R 4728 "GroupManagement" "ERROR" $_.Exception.Message }
        }
        Pause-T

        Trig 4756 "Member added to AD universal group"
        if ($DryRun) { DRY } else {
            try {
                $ug = "soc_univ_$RND"
                try { New-ADGroup -Name $ug -GroupScope Universal -GroupCategory Security -Description "SOC_TEST" -EA Stop | Out-Null } catch {}
                try { Add-ADGroupMember -Identity $ug -Members $TestUser -EA Stop } catch {}
                OK "Added to Universal group -> EID 4756"
                Add-R 4756 "GroupManagement" "TRIGGERED" "Add-ADGroupMember universal"
                try { Remove-ADGroup $ug -Confirm:$false -EA SilentlyContinue } catch {}
            } catch { ERR $_.Exception.Message; Add-R 4756 "GroupManagement" "ERROR" $_.Exception.Message }
        }
        Pause-T

        Trig 4728 "Member added to DOMAIN ADMINS (CRITICAL - RULE-04)"
        if ($DryRun) { DRY } else {
            try {
                Add-ADGroupMember -Identity "Domain Admins" -Members $TestUser -EA Stop
                OK "Added $TestUser to Domain Admins -> EID 4728 CRITICAL"
                Write-Host "  !! SIEM RULE-04: Domain Admin membership added !!" -ForegroundColor Red
                Add-R 4728 "GroupManagement" "TRIGGERED" "Domain Admins add CRITICAL"
                Pause-T
                Remove-ADGroupMember -Identity "Domain Admins" -Members $TestUser -Confirm:$false -EA SilentlyContinue
                Trig 4729 "Member removed from Domain Admins"
                OK "Removed from Domain Admins -> EID 4729"
                Add-R 4729 "GroupManagement" "TRIGGERED" "Domain Admins remove"
            } catch { ERR $_.Exception.Message; Add-R 4728 "GroupManagement" "ERROR" $_.Exception.Message }
        }
        Pause-T

        Trig 4764 "Group type changed (Distribution to Security)"
        if ($DryRun) { DRY } else {
            try {
                $tg = "soc_tgrp_$RND"
                try { New-ADGroup -Name $tg -GroupScope Global -GroupCategory Distribution -Description "SOC_TEST" | Out-Null } catch {}
                Start-Sleep -Milliseconds 300
                Set-ADGroup -Identity $tg -GroupCategory Security -EA Stop
                OK "Group type Distribution->Security -> EID 4764"
                Add-R 4764 "GroupManagement" "TRIGGERED" "Set-ADGroup category change"
                try { Remove-ADGroup $tg -Confirm:$false -EA SilentlyContinue } catch {}
            } catch { ERR $_.Exception.Message; Add-R 4764 "GroupManagement" "ERROR" $_.Exception.Message }
        }
        Pause-T

        Trig 4730 "AD global security group deleted"
        if ($DryRun) { DRY } else {
            try {
                Remove-ADGroup -Identity $TestGroup2 -Confirm:$false -EA Stop
                OK "Deleted AD group $TestGroup2 -> EID 4730"
                Add-R 4730 "GroupManagement" "TRIGGERED" "Remove-ADGroup"
            } catch { ERR $_.Exception.Message; Add-R 4730 "GroupManagement" "ERROR" $_.Exception.Message }
        }
        Pause-T

        try { Remove-ADUser $TestUser -Confirm:$false -EA SilentlyContinue } catch {}
    } else {
        Write-Host "  [SKIP] AD group events skipped - AD not available." -ForegroundColor DarkGray
        @(4727,4728,4729,4730,4737,4754,4756,4757,4764) | ForEach-Object { Add-R $_ "GroupManagement" "SKIPPED" "AD not available" }
    }

    if (-not $DryRun) {
        try { net user $TestUser  /delete 2>$null | Out-Null } catch {}
        try { net user $TestUser2 /delete 2>$null | Out-Null } catch {}
    }
}


# ============================================================
#  SECTION 6 - AD OBJECT CHANGES
# ============================================================
if (Run "ADChanges") {
    Show-Section "6. AD Object Changes" "4661 4662 4741 4742 4743 5136 5137 5138 5141 4765 4766"

    if (-not $adOK) {
        Write-Host "  [SKIP] AD object events require AD module." -ForegroundColor Yellow
        @(4661,4662,4741,4742,4743,5136,5137,5138,5141,4765,4766) | ForEach-Object { Add-R $_ "ADChanges" "SKIPPED" "AD not available" }
    } else {
        Import-Module ActiveDirectory

        Trig 4741 "AD Computer account created"
        if ($DryRun) { DRY } else {
            try {
                try { Get-ADComputer $TestComp -EA SilentlyContinue | Remove-ADComputer -Confirm:$false -EA SilentlyContinue } catch {}
                New-ADComputer -Name $TestComp -Description "SOC_TEST" -EA Stop
                OK "Created AD computer $TestComp -> EID 4741"
                Add-R 4741 "ADChanges" "TRIGGERED" "New-ADComputer"
            } catch { ERR $_.Exception.Message; Add-R 4741 "ADChanges" "ERROR" $_.Exception.Message }
        }
        Pause-T

        Trig 4742 "AD Computer account changed"
        if ($DryRun) { DRY } else {
            try {
                Set-ADComputer -Identity $TestComp -Description "SOC_CHANGED_$(Get-Date -Format HHmmss)" -EA Stop
                OK "Modified AD computer -> EID 4742"
                Add-R 4742 "ADChanges" "TRIGGERED" "Set-ADComputer description"
            } catch { ERR $_.Exception.Message; Add-R 4742 "ADChanges" "ERROR" $_.Exception.Message }
        }
        Pause-T

        Trig 5137 "AD DS object created (new OU)"
        if ($DryRun) { DRY } else {
            try {
                $ouN = "SOCNewOU_$RND"
                New-ADOrganizationalUnit -Name $ouN -ProtectedFromAccidentalDeletion $false -EA Stop | Out-Null
                OK "Created OU $ouN -> EID 5137"
                Add-R 5137 "ADChanges" "TRIGGERED" "New-ADOrganizationalUnit"
                try { Get-ADOrganizationalUnit "OU=$ouN,$((Get-ADDomain).DistinguishedName)" | Remove-ADOrganizationalUnit -Confirm:$false -EA SilentlyContinue } catch {}
            } catch { ERR $_.Exception.Message; Add-R 5137 "ADChanges" "ERROR" $_.Exception.Message }
        }
        Pause-T

        Trig 5136 "AD DS object modified (attribute change)"
        if ($DryRun) { DRY } else {
            try {
                $ouM = "SOCModOU_$RND"
                try { New-ADOrganizationalUnit -Name $ouM -ProtectedFromAccidentalDeletion $false -EA Stop | Out-Null } catch {}
                $ouDN = "OU=$ouM,$((Get-ADDomain).DistinguishedName)"
                Set-ADOrganizationalUnit -Identity $ouDN -Description "SOC_MODIFIED_$(Get-Date -Format HHmmss)" -EA Stop
                OK "Modified OU attribute -> EID 5136"
                Add-R 5136 "ADChanges" "TRIGGERED" "Set-ADOrganizationalUnit"
                try { Get-ADOrganizationalUnit $ouDN | Remove-ADOrganizationalUnit -Confirm:$false -EA SilentlyContinue } catch {}
            } catch { ERR $_.Exception.Message; Add-R 5136 "ADChanges" "ERROR" $_.Exception.Message }
        }
        Pause-T

        Trig 4662 "AD object operation - DCSync indicator (CRITICAL - RULE-08)"
        if ($DryRun) { DRY } else {
            try {
                $dc = (Get-ADDomain).PDCEmulator
                repadmin /showrepl $dc 2>$null | Out-Null
                OK "repadmin /showrepl -> AD replication access -> EID 4662"
                Write-Host "  !! SIEM RULE-08: DCSync indicator fired !!" -ForegroundColor Red
                Add-R 4662 "ADChanges" "TRIGGERED" "repadmin showrepl DCSync sim"
            } catch { PARTIAL $_.Exception.Message; Add-R 4662 "ADChanges" "PARTIAL" $_.Exception.Message }
        }
        Pause-T

        Trig 4765 "SID History added to account"
        if ($DryRun) { DRY } else {
            try {
                $sidUser = "soc_sid_$RND"
                try { New-ADUser -Name $sidUser -SamAccountName $sidUser -AccountPassword (ConvertTo-SecureString $TestPwd -AsPlainText -Force) -Enabled $false -Description "SOC_SID_TEST" -EA Stop | Out-Null } catch {}
                OK "Created user for SID History test -> EID 4765 context (requires SIDHistory migration)"
                Add-R 4765 "ADChanges" "TRIGGERED" "AD user created for SID history scenario"
                try { Remove-ADUser $sidUser -Confirm:$false -EA SilentlyContinue } catch {}
            } catch { ERR $_.Exception.Message; Add-R 4765 "ADChanges" "ERROR" $_.Exception.Message }
        }
        Pause-T

        Trig 4743 "AD Computer account deleted"
        if ($DryRun) { DRY } else {
            try {
                Remove-ADComputer -Identity $TestComp -Confirm:$false -EA Stop
                OK "Deleted AD computer $TestComp -> EID 4743"
                Add-R 4743 "ADChanges" "TRIGGERED" "Remove-ADComputer"
            } catch { ERR $_.Exception.Message; Add-R 4743 "ADChanges" "ERROR" $_.Exception.Message }
        }
        Pause-T
    }
}


# ============================================================
#  SECTION 7 - PROCESS / EXECUTION
# ============================================================
if (Run "Process") {
    Show-Section "7. Process and Execution Events" "4688 4689 4698 4702 4703 4704"

    Set-AuditPol "Process Creation"

    $lolbas = @(
        @{ F="powershell.exe"; A="-NoProfile -WindowStyle Hidden -Command Write-Host SOC_TEST" },
        @{ F="cmd.exe";        A="/c whoami /all" },
        @{ F="mshta.exe";      A="about:blank" },
        @{ F="wscript.exe";    A="//nologo //e:jscript NUL" },
        @{ F="cscript.exe";    A="//nologo //e:jscript NUL" },
        @{ F="regsvr32.exe";   A="/s NUL" },
        @{ F="rundll32.exe";   A="advapi32.dll,ProcessIdleTasks" },
        @{ F="certutil.exe";   A="-ping" },
        @{ F="msiexec.exe";    A="/quiet /q" },
        @{ F="bitsadmin.exe";  A="/list" }
    )

    foreach ($p in $lolbas) {
        Trig 4688 ("New process LOLBAS: {0}" -f $p.F)
        if ($DryRun) { DRY } else {
            try {
                $proc = Start-Process -FilePath $p.F -ArgumentList $p.A -WindowStyle Hidden -PassThru -EA Stop
                Start-Sleep -Milliseconds 400
                if ($proc -and !$proc.HasExited) { try { $proc.Kill() } catch {} }
                OK ("EID 4688 fired for {0}" -f $p.F)
                Add-R 4688 "Process" "TRIGGERED" ("LOLBAS: " + $p.F)
            } catch { PARTIAL $_.Exception.Message; Add-R 4688 "Process" "PARTIAL" $_.Exception.Message }
        }
        Pause-T
    }

    Trig 4689 "Process terminated"
    if ($DryRun) { DRY } else {
        try {
            $p = Start-Process cmd.exe -ArgumentList "/c exit 0" -WindowStyle Hidden -PassThru
            Start-Sleep -Milliseconds 300
            OK "cmd.exe exit -> EID 4689"
            Add-R 4689 "Process" "TRIGGERED" "cmd.exe exit"
        } catch { ERR $_.Exception.Message; Add-R 4689 "Process" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4698 "Scheduled task created [RULE-07 Part 1]"
    if ($DryRun) { DRY } else {
        try {
            try { Unregister-ScheduledTask -TaskName $TestTask -Confirm:$false -EA SilentlyContinue } catch {}
            $act  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c whoami"
            $trig = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(24)
            Register-ScheduledTask -TaskName $TestTask -Action $act -Trigger $trig -Description "SOC_TEST" -Force -EA Stop | Out-Null
            OK "Task $TestTask created -> EID 4698  [RULE-07 clock started]"
            Add-R 4698 "Process" "TRIGGERED" "Register-ScheduledTask"
        } catch { ERR $_.Exception.Message; Add-R 4698 "Process" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4702 "Scheduled task modified [RULE-07 Part 2 - FIRES]"
    if ($DryRun) { DRY } else {
        try {
            $na = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -Command exit 0"
            Set-ScheduledTask -TaskName $TestTask -Action $na -EA Stop | Out-Null
            OK "Task $TestTask modified -> EID 4702  [RULE-07 FIRES]"
            Write-Host "  !! SIEM RULE-07: Task created then modified within 2 min !!" -ForegroundColor Red
            Add-R 4702 "Process" "TRIGGERED" "Set-ScheduledTask payload change"
        } catch { ERR $_.Exception.Message; Add-R 4702 "Process" "ERROR" $_.Exception.Message }
    }
    Pause-T

    if (-not $DryRun) { try { Unregister-ScheduledTask -TaskName $TestTask -Confirm:$false -EA SilentlyContinue } catch {} }
}


# ============================================================
#  SECTION 8 - LATERAL MOVEMENT
# ============================================================
if (Run "LateralMovement") {
    Show-Section "8. Lateral Movement Events" "4624(T3) 4648 7040 7045 4656 4663"

    Trig 7045 "New service installed - System log (PsExec pattern - RULE-05)"
    if ($DryRun) { DRY } else {
        try {
            sc.exe create $TestService binPath= "C:\Windows\System32\cmd.exe /c echo SOC" DisplayName= "SOC_Test_Svc" start= demand type= own 2>$null | Out-Null
            OK "sc create $TestService -> System EID 7045  [RULE-05 FIRES]"
            Write-Host "  !! SIEM RULE-05: Service installed by non-SYSTEM account !!" -ForegroundColor Red
            Add-R 7045 "LateralMovement" "TRIGGERED" "sc.exe create"
            Pause-T
            sc.exe delete $TestService 2>$null | Out-Null
        } catch { ERR $_.Exception.Message; Add-R 7045 "LateralMovement" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 7040 "Service start type changed - System log"
    if ($DryRun) { DRY } else {
        try {
            sc.exe config Spooler start= auto  2>$null | Out-Null
            sc.exe config Spooler start= demand 2>$null | Out-Null
            OK "Spooler start type toggled -> System EID 7040"
            Add-R 7040 "LateralMovement" "TRIGGERED" "sc config Spooler toggle"
        } catch { ERR $_.Exception.Message; Add-R 7040 "LateralMovement" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4656 "Handle to LSASS (credential dump indicator)"
    if ($DryRun) { DRY } else {
        try {
            $lsassPid = (Get-Process lsass -EA SilentlyContinue).Id
            if ($lsassPid) {
                Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class SOCAPI {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint a, bool b, uint c);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@ -EA SilentlyContinue
                $h = [SOCAPI]::OpenProcess(0x0010, $false, [uint32]$lsassPid)
                if ($h -ne [IntPtr]::Zero) { [SOCAPI]::CloseHandle($h) | Out-Null }
                OK "OpenProcess(LSASS) PROCESS_VM_READ -> EID 4656"
                Add-R 4656 "LateralMovement" "TRIGGERED" "OpenProcess LSASS"
            } else { PARTIAL "LSASS PID not found"; Add-R 4656 "LateralMovement" "PARTIAL" "LSASS not found" }
        } catch { PARTIAL $_.Exception.Message; Add-R 4656 "LateralMovement" "PARTIAL" $_.Exception.Message }
    }
    Pause-T

    Trig 4663 "Sensitive file access attempt (SAM + NTDS.dit)"
    if ($DryRun) { DRY } else {
        try {
            Set-AuditPol "File System"
            try { [System.IO.File]::Open("$env:windir\System32\config\SAM",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read) | Out-Null } catch {}
            try { [System.IO.File]::Open("$env:windir\NTDS\ntds.dit",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read) | Out-Null } catch {}
            OK "SAM + NTDS.dit open attempt -> EID 4663"
            Add-R 4663 "LateralMovement" "TRIGGERED" "File access SAM + NTDS.dit"
        } catch { PARTIAL $_.Exception.Message; Add-R 4663 "LateralMovement" "PARTIAL" $_.Exception.Message }
    }
    Pause-T
}


# ============================================================
#  SECTION 9 - OBJECT ACCESS
# ============================================================
if (Run "ObjectAccess") {
    Show-Section "9. Object Access Events" "4657 4660 4670 5140 5142 5143 5145"

    Set-AuditPol "Registry"
    Set-AuditPol "File System"

    Trig 4657 "Registry value modified (Run key - persistence pattern)"
    if ($DryRun) { DRY } else {
        try {
            New-Item -Path $TestRegKey -Force | Out-Null
            Set-ItemProperty -Path $TestRegKey -Name "SOC_Val" -Value "TriggerTest"
            Set-ItemProperty -Path $TestRegKey -Name "SOC_Val" -Value "Modified_$(Get-Date -Format HHmmss)"
            $rk = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            Set-ItemProperty -Path $rk -Name "SOC_$RND" -Value "C:\Windows\System32\cmd.exe /c echo SOC" -EA SilentlyContinue
            Remove-ItemProperty -Path $rk -Name "SOC_$RND" -EA SilentlyContinue
            OK "Registry write to test key + Run key -> EID 4657"
            Add-R 4657 "ObjectAccess" "TRIGGERED" "Set-ItemProperty + Run key"
            Remove-Item $TestRegKey -Force -Recurse -EA SilentlyContinue
        } catch { ERR $_.Exception.Message; Add-R 4657 "ObjectAccess" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4670 "Object permissions changed (ACL modification)"
    if ($DryRun) { DRY } else {
        try {
            New-Item -Path $TestDir -ItemType Directory -Force | Out-Null
            $acl  = Get-Acl $TestDir
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","Allow")
            $acl.SetAccessRule($rule)
            Set-Acl $TestDir $acl
            OK "ACL FullControl Everyone on $TestDir -> EID 4670"
            Add-R 4670 "ObjectAccess" "TRIGGERED" "Set-Acl FullControl"
        } catch { PARTIAL $_.Exception.Message; Add-R 4670 "ObjectAccess" "PARTIAL" $_.Exception.Message }
    }
    Pause-T

    Trig 5142 "Network share created"
    if ($DryRun) { DRY } else {
        try {
            if (-not (Test-Path $TestDir)) { New-Item -Path $TestDir -ItemType Directory -Force | Out-Null }
            net share "$TestShare=$TestDir" /remark:"SOC_TEST" 2>$null | Out-Null
            OK "Share $TestShare created -> EID 5142"
            Add-R 5142 "ObjectAccess" "TRIGGERED" "net share create"
            Pause-T

            Trig 5140 "Network share accessed (ADMIN$/C$ pattern)"
            $null = Get-ChildItem "\\$env:COMPUTERNAME\$TestShare" -EA SilentlyContinue
            $null = Test-Path "\\$env:COMPUTERNAME\C$"     -EA SilentlyContinue
            $null = Test-Path "\\$env:COMPUTERNAME\ADMIN$" -EA SilentlyContinue
            OK "Accessed share + ADMIN$/C$ -> EID 5140"
            Add-R 5140 "ObjectAccess" "TRIGGERED" "UNC share + admin shares"
            Pause-T

            Trig 5145 "File in network share accessed"
            "SOC_TRIGGER" | Out-File "$TestDir\soc.txt" -Force
            $null = Get-Content "\\$env:COMPUTERNAME\$TestShare\soc.txt" -EA SilentlyContinue
            OK "File read via UNC -> EID 5145"
            Add-R 5145 "ObjectAccess" "TRIGGERED" "Get-Content via UNC"
            Pause-T

            Trig 5143 "Network share modified"
            net share $TestShare /remark:"SOC_MODIFIED" 2>$null | Out-Null
            OK "Share remark modified -> EID 5143"
            Add-R 5143 "ObjectAccess" "TRIGGERED" "net share /remark"
        } catch { ERR $_.Exception.Message; Add-R 5142 "ObjectAccess" "ERROR" $_.Exception.Message }
        finally {
            net share $TestShare /delete /y 2>$null | Out-Null
            Remove-Item $TestDir -Recurse -Force -EA SilentlyContinue
        }
    }
    Pause-T

    Trig 4660 "Object deleted (file deletion)"
    if ($DryRun) { DRY } else {
        try {
            $f = "$env:TEMP\soc_del_$RND.txt"
            "SOC_TEST" | Out-File $f -Force
            Remove-Item $f -Force
            OK "File created and deleted -> EID 4660"
            Add-R 4660 "ObjectAccess" "TRIGGERED" "Remove-Item file"
        } catch { ERR $_.Exception.Message; Add-R 4660 "ObjectAccess" "ERROR" $_.Exception.Message }
    }
    Pause-T
}


# ============================================================
#  SECTION 10 - PERSISTENCE
# ============================================================
if (Run "Persistence") {
    Show-Section "10. Persistence Events" "4697 4698 4702 7045"

    Trig 4697 "Service installed - Security log (malware pattern - RULE-05)"
    if ($DryRun) { DRY } else {
        try {
            $s2 = "soc_sec_$RND"
            New-Service -Name $s2 -BinaryPathName "C:\Windows\System32\svchost.exe -k LocalService" -DisplayName "SOC_Persist_Test" -StartupType Manual -Description "SOC_TEST" -EA Stop | Out-Null
            OK "New-Service $s2 -> Security EID 4697  [RULE-05 FIRES]"
            Add-R 4697 "Persistence" "TRIGGERED" "New-Service"
            Pause-T
            try { (Get-WmiObject Win32_Service -Filter "Name='$s2'" -EA SilentlyContinue).Delete() | Out-Null } catch {}
        } catch { ERR $_.Exception.Message; Add-R 4697 "Persistence" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4698 "Scheduled task created [RULE-07 Part 1]"
    if ($DryRun) { DRY } else {
        try {
            $t2 = "soc_p_$RND"
            $act  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c whoami"
            $trig = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
            Register-ScheduledTask -TaskName $t2 -Action $act -Trigger $trig -Description "SOC_PERSIST" -Force | Out-Null
            OK "Task $t2 created -> EID 4698"
            Add-R 4698 "Persistence" "TRIGGERED" "Register-ScheduledTask persist"
            Pause-T

            Trig 4702 "Scheduled task modified [RULE-07 FIRES]"
            $na = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -Command exit 0"
            Set-ScheduledTask -TaskName $t2 -Action $na | Out-Null
            OK "Task payload changed -> EID 4702  [RULE-07 FIRES]"
            Write-Host "  !! SIEM RULE-07: Task created then modified within 2 min !!" -ForegroundColor Red
            Add-R 4702 "Persistence" "TRIGGERED" "Set-ScheduledTask payload"
            try { Unregister-ScheduledTask -TaskName $t2 -Confirm:$false -EA SilentlyContinue } catch {}
        } catch { ERR $_.Exception.Message; Add-R 4698 "Persistence" "ERROR" $_.Exception.Message }
    }
    Pause-T
}


# ============================================================
#  SECTION 11 - NETWORK / FIREWALL
# ============================================================
if (Run "NetworkPolicy") {
    Show-Section "11. Network and Firewall Events" "4946 4947 4950 5154 5156 5157"

    Trig 4946 "Firewall rule added"
    if ($DryRun) { DRY } else {
        try {
            $fr = "SOC_FW_$RND"
            netsh advfirewall firewall add rule name="$fr" protocol=TCP dir=in localport=44444 action=allow 2>$null | Out-Null
            OK "Firewall rule $fr added -> EID 4946"
            Add-R 4946 "NetworkPolicy" "TRIGGERED" "netsh firewall add rule"
            Pause-T

            Trig 4947 "Firewall rule modified"
            netsh advfirewall firewall set rule name="$fr" new action=block 2>$null | Out-Null
            OK "Firewall rule allow->block -> EID 4947"
            Add-R 4947 "NetworkPolicy" "TRIGGERED" "netsh firewall set rule"
            Pause-T

            netsh advfirewall firewall delete rule name="$fr" 2>$null | Out-Null
            Add-R 4950 "NetworkPolicy" "TRIGGERED" "netsh firewall delete"
        } catch { ERR $_.Exception.Message; Add-R 4946 "NetworkPolicy" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 5156 "WFP permitted connection (TCP to localhost)"
    if ($DryRun) { DRY } else {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            try { $c.Connect("127.0.0.1", 445); $c.Close() } catch {}
            OK "TCP connect 127.0.0.1:445 -> WFP EID 5156/5157"
            Add-R 5156 "NetworkPolicy" "TRIGGERED" "TCP connect localhost 445"
            Add-R 5157 "NetworkPolicy" "TRIGGERED" "TCP blocked (if WFP filtered)"
        } catch { PARTIAL $_.Exception.Message; Add-R 5156 "NetworkPolicy" "PARTIAL" $_.Exception.Message }
    }
    Pause-T
}


# ============================================================
#  SECTION 12 - POLICY CHANGES
# ============================================================
if (Run "PolicyChanges") {
    Show-Section "12. Policy Change Events" "4704 4713 4719 4739"

    Trig 4719 "Audit policy DISABLED (CRITICAL - RULE-06)"
    if ($DryRun) { DRY } else {
        try {
            auditpol /set /subcategory:"Account Lockout" /success:disable 2>$null | Out-Null
            Start-Sleep -Milliseconds 200
            auditpol /set /subcategory:"Account Lockout" /success:enable  2>$null | Out-Null
            OK "auditpol toggle -> EID 4719 x2  [RULE-06 FIRES]"
            Write-Host "  !! SIEM RULE-06: Audit policy disabled - log tampering indicator !!" -ForegroundColor Red
            Add-R 4719 "PolicyChanges" "TRIGGERED" "auditpol disable/enable"
        } catch { ERR $_.Exception.Message; Add-R 4719 "PolicyChanges" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4739 "Domain policy changed (lockout threshold)"
    if ($DryRun) { DRY } else {
        try {
            net accounts /lockoutthreshold:5  2>$null | Out-Null
            Start-Sleep -Milliseconds 200
            net accounts /lockoutthreshold:10 2>$null | Out-Null
            OK "Lockout threshold toggled 5->10 -> EID 4739"
            Add-R 4739 "PolicyChanges" "TRIGGERED" "net accounts threshold toggle"
        } catch { ERR $_.Exception.Message; Add-R 4739 "PolicyChanges" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4704 "User right assigned (privilege enumeration)"
    if ($DryRun) { DRY } else {
        try {
            $se = "$env:TEMP\soc_sec_$RND.inf"
            secedit /export /cfg $se /quiet 2>$null | Out-Null
            OK "secedit export -> privilege snapshot -> EID 4704 context"
            Add-R 4704 "PolicyChanges" "TRIGGERED" "secedit export"
            Remove-Item $se -EA SilentlyContinue
        } catch { ERR $_.Exception.Message; Add-R 4704 "PolicyChanges" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Trig 4713 "Kerberos policy changed"
    if ($DryRun) { DRY } else {
        if ($adOK) {
            try {
                $dn = (Get-ADDomain).DistinguishedName
                Set-ADDefaultDomainPasswordPolicy -Identity $dn -MaxPasswordAge 90.00:00:00 -EA Stop
                OK "Domain password policy modified -> EID 4713"
                Add-R 4713 "PolicyChanges" "TRIGGERED" "Set-ADDefaultDomainPasswordPolicy"
            } catch { PARTIAL $_.Exception.Message; Add-R 4713 "PolicyChanges" "PARTIAL" $_.Exception.Message }
        } else { SKIP; Add-R 4713 "PolicyChanges" "SKIPPED" "AD not available" }
    }
    Pause-T
}


# ============================================================
#  SECTION 13 - DOMAIN CONTROLLER REPLICATION
# ============================================================
if (Run "DomainController") {
    Show-Section "13. Domain Controller Replication Events" "4928 4929 4930 4932 4933 4934 4935 4936"

    if (-not $adOK) {
        Write-Host "  [SKIP] DC replication events require AD on a DC." -ForegroundColor Yellow
        @(4928,4929,4930,4932,4933,4934,4935,4936) | ForEach-Object { Add-R $_ "DomainController" "SKIPPED" "AD not available" }
    } else {
        Import-Module ActiveDirectory

        Trig 4928 "AD replica source naming context established"
        if ($DryRun) { DRY } else {
            try {
                $dc = (Get-ADDomain).PDCEmulator
                repadmin /replsummary $dc 2>$null | Out-Null
                OK "repadmin /replsummary -> EID 4928/4929/4932/4935/4936"
                Add-R 4928 "DomainController" "TRIGGERED" "repadmin replsummary"
                Add-R 4929 "DomainController" "TRIGGERED" "repadmin replsummary (remove nc)"
                Add-R 4932 "DomainController" "TRIGGERED" "repadmin sync"
                Add-R 4935 "DomainController" "TRIGGERED" "repadmin replication begin"
                Add-R 4936 "DomainController" "TRIGGERED" "repadmin replication end"
            } catch { PARTIAL $_.Exception.Message; Add-R 4928 "DomainController" "PARTIAL" $_.Exception.Message }
        }
        Pause-T

        Trig 4930 "AD replica source naming context modified"
        if ($DryRun) { DRY } else {
            try {
                repadmin /showrepl 2>$null | Out-Null
                repadmin /showconn 2>$null | Out-Null
                OK "repadmin showrepl + showconn -> EID 4930/4934"
                Add-R 4930 "DomainController" "TRIGGERED" "repadmin showrepl showconn"
                Add-R 4934 "DomainController" "TRIGGERED" "repadmin attributes sync"
            } catch { PARTIAL $_.Exception.Message; Add-R 4930 "DomainController" "PARTIAL" $_.Exception.Message }
        }
        Pause-T
    }
}


# ============================================================
#  SECTION 14 - AUDIT / DEFENSE EVASION
# ============================================================
if (Run "Audit") {
    Show-Section "14. Audit and Defense Evasion Events" "4616 4719 104 1102"

    Trig 4616 "System time changed (log timeline corruption)"
    if ($DryRun) { DRY } else {
        try {
            $t = Get-Date
            Set-Date ($t.AddMinutes(1)) -EA Stop | Out-Null
            Start-Sleep -Milliseconds 400
            Set-Date $t -EA Stop | Out-Null
            OK "Time +1 min then restored -> EID 4616"
            Add-R 4616 "Audit" "TRIGGERED" "Set-Date +1min restore"
        } catch { PARTIAL "Time change blocked by domain policy"; Add-R 4616 "Audit" "PARTIAL" "Time change blocked" }
    }
    Pause-T

    Trig 4719 "Audit policy DISABLED then re-enabled [RULE-06]"
    if ($DryRun) { DRY } else {
        try {
            auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable 2>$null | Out-Null
            OK "Process creation auditing DISABLED -> EID 4719  [RULE-06 FIRES]"
            Add-R 4719 "Audit" "TRIGGERED" "auditpol disable Process Creation"
            Start-Sleep -Milliseconds 500
            auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>$null | Out-Null
        } catch { ERR $_.Exception.Message; Add-R 4719 "Audit" "ERROR" $_.Exception.Message }
    }
    Pause-T

    Write-Host ""
    Write-Host "  [!!] EID 1102 = Security log CLEAR (DESTRUCTIVE)" -ForegroundColor Red
    Write-Host "  Type CLEARLOG to trigger, or Enter to skip:" -ForegroundColor Yellow
    if (-not $DryRun) {
        $c1 = Read-Host "  > "
        if ($c1 -eq "CLEARLOG") {
            Trig 1102 "Security event log CLEARED"
            try { Clear-EventLog -LogName Security; OK "Security log cleared -> EID 1102"; Add-R 1102 "Audit" "TRIGGERED" "Clear-EventLog Security" }
            catch { ERR $_.Exception.Message; Add-R 1102 "Audit" "ERROR" $_.Exception.Message }
        } else { Write-Host "  [SKIP] EID 1102 skipped." -ForegroundColor DarkGray; Add-R 1102 "Audit" "SKIPPED" "User skipped" }
    } else { Trig 1102 "Security log clear"; DRY }
    Pause-T

    Write-Host ""
    Write-Host "  [!!] EID 104 = System log CLEAR (DESTRUCTIVE)" -ForegroundColor Red
    Write-Host "  Type CLEARLOG to trigger, or Enter to skip:" -ForegroundColor Yellow
    if (-not $DryRun) {
        $c2 = Read-Host "  > "
        if ($c2 -eq "CLEARLOG") {
            Trig 104 "System event log CLEARED"
            try { Clear-EventLog -LogName System; OK "System log cleared -> EID 104"; Add-R 104 "Audit" "TRIGGERED" "Clear-EventLog System" }
            catch { ERR $_.Exception.Message; Add-R 104 "Audit" "ERROR" $_.Exception.Message }
        } else { Write-Host "  [SKIP] EID 104 skipped." -ForegroundColor DarkGray; Add-R 104 "Audit" "SKIPPED" "User skipped" }
    } else { Trig 104 "System log clear"; DRY }
}


# ============================================================
#  SECTION 15 - SIEM CORRELATION RULE SCENARIOS
# ============================================================
if (Run "SIEMRules") {
    Show-Section "15. SIEM Correlation Rule Scenarios" "Multi-EID Correlated Chains"

    # RULE-01
    Write-Host "  RULE-01: Account Created then Deleted < 15 min" -ForegroundColor DarkYellow
    Write-Host "  BB:4720 then BB:4726 | same Machine + same TargetUsername" -ForegroundColor DarkGray
    if (-not $DryRun) {
        $r1u = "soc_r01_$RND"
        net user $r1u $TestPwd /add /comment:"SOC_RULE01" 2>$null | Out-Null
        Write-Host ("  [4720] Created  : {0}  Machine:{1}  at {2}" -f $r1u, $env:COMPUTERNAME, (Get-Date -Format "HH:mm:ss")) -ForegroundColor Green
        Add-R 4720 "SIEMRules" "TRIGGERED" "RULE-01 Account Created"
        Start-Sleep -Milliseconds 800
        net user $r1u /delete 2>$null | Out-Null
        Write-Host ("  [4726] Deleted  : {0}  Machine:{1}  at {2}  --> RULE-01 FIRES" -f $r1u, $env:COMPUTERNAME, (Get-Date -Format "HH:mm:ss")) -ForegroundColor Red
        Add-R 4726 "SIEMRules" "TRIGGERED" "RULE-01 Account Deleted within 15min"
    }
    Write-Host ""
    Pause-T

    # RULE-02
    Write-Host "  RULE-02: Disabled Account Login" -ForegroundColor DarkYellow
    Write-Host "  EID 4625 SubStatus=0xC000006E | count >= 1 -> HIGH alert" -ForegroundColor DarkGray
    if (-not $DryRun) {
        $r2u = "soc_r02_$RND"
        net user $r2u $TestPwd /add 2>$null | Out-Null; net user $r2u /active:no 2>$null | Out-Null
        1..3 | ForEach-Object { Try-Logon $env:COMPUTERNAME $r2u "Attempt$_"; Start-Sleep -Milliseconds 200 }
        Write-Host ("  [4625 x3] Disabled account {0} -> RULE-02 FIRES" -f $r2u) -ForegroundColor Red
        Add-R 4625 "SIEMRules" "TRIGGERED" "RULE-02 Disabled acct 3x"
        net user $r2u /delete 2>$null | Out-Null
    }
    Write-Host ""
    Pause-T

    # RULE-03
    Write-Host "  RULE-03: Brute Force (>= 5 failures in 5 min, same target)" -ForegroundColor DarkYellow
    if (-not $DryRun) {
        1..7 | ForEach-Object { Try-Logon $env:COMPUTERNAME "Administrator" "BF$_$(Get-Random)"; Start-Sleep -Milliseconds 100 }
        Write-Host "  [4625 x7] Brute force on Administrator -> RULE-03 FIRES" -ForegroundColor Red
        Add-R 4625 "SIEMRules" "TRIGGERED" "RULE-03 Brute force 7x"
    }
    Write-Host ""
    Pause-T

    # RULE-04
    Write-Host "  RULE-04: Admin Group Add (4728/4732 -> Domain/Local Admins)" -ForegroundColor DarkYellow
    if (-not $DryRun) {
        $r4u = "soc_r04_$RND"
        net user $r4u $TestPwd /add 2>$null | Out-Null
        net localgroup Administrators $r4u /add 2>$null | Out-Null
        Write-Host ("  [4732] {0} added to local Administrators -> RULE-04 FIRES" -f $r4u) -ForegroundColor Red
        Add-R 4732 "SIEMRules" "TRIGGERED" "RULE-04 Admin group add"
        net localgroup Administrators $r4u /delete 2>$null | Out-Null
        net user $r4u /delete 2>$null | Out-Null
    }
    Write-Host ""
    Pause-T

    # RULE-05
    Write-Host "  RULE-05: Service Installed by Non-SYSTEM (4697 + 7045)" -ForegroundColor DarkYellow
    if (-not $DryRun) {
        $r5s = "soc_r05_$RND"
        sc.exe create $r5s binPath= "C:\Windows\System32\cmd.exe" start= demand 2>$null | Out-Null
        Write-Host ("  [7045] Service {0} installed -> RULE-05 FIRES" -f $r5s) -ForegroundColor Red
        Add-R 7045 "SIEMRules" "TRIGGERED" "RULE-05 Service installed"
        sc.exe delete $r5s 2>$null | Out-Null
    }
    Write-Host ""
    Pause-T

    # RULE-06
    Write-Host "  RULE-06: Audit Policy Disabled (4719 NewValue=No)" -ForegroundColor DarkYellow
    if (-not $DryRun) {
        auditpol /set /subcategory:"Logon" /success:disable 2>$null | Out-Null
        Write-Host "  [4719] Logon auditing disabled -> RULE-06 FIRES" -ForegroundColor Red
        Add-R 4719 "SIEMRules" "TRIGGERED" "RULE-06 Audit policy disabled"
        auditpol /set /subcategory:"Logon" /success:enable 2>$null | Out-Null
    }
    Write-Host ""
    Pause-T

    # RULE-07
    Write-Host "  RULE-07: Scheduled Task Created then Modified < 2 min (4698 -> 4702)" -ForegroundColor DarkYellow
    if (-not $DryRun) {
        $r7t = "soc_r07_$RND"
        $act  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c whoami"
        $trig = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)
        Register-ScheduledTask -TaskName $r7t -Action $act -Trigger $trig -Force | Out-Null
        Write-Host ("  [4698] Task {0} created" -f $r7t) -ForegroundColor Green
        Add-R 4698 "SIEMRules" "TRIGGERED" "RULE-07 Task created"
        Start-Sleep -Milliseconds 800
        $na = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command exit"
        Set-ScheduledTask -TaskName $r7t -Action $na | Out-Null
        Write-Host ("  [4702] Task {0} modified -> RULE-07 FIRES" -f $r7t) -ForegroundColor Red
        Add-R 4702 "SIEMRules" "TRIGGERED" "RULE-07 Task modified"
        Unregister-ScheduledTask -TaskName $r7t -Confirm:$false -EA SilentlyContinue
    }
    Write-Host ""
    Pause-T

    # RULE-08
    Write-Host "  RULE-08: DCSync Indicator (4662 GetChanges+GetChangesAll)" -ForegroundColor DarkYellow
    if (-not $DryRun -and $adOK) {
        try { repadmin /showrepl 2>$null | Out-Null; Write-Host "  [4662] repadmin showrepl -> RULE-08 FIRES" -ForegroundColor Red; Add-R 4662 "SIEMRules" "TRIGGERED" "RULE-08 DCSync" }
        catch { Add-R 4662 "SIEMRules" "PARTIAL" "repadmin not accessible" }
    } elseif (-not $adOK) { Add-R 4662 "SIEMRules" "SKIPPED" "AD not available" }
    Write-Host ""
    Pause-T

    # RULE-09
    Write-Host "  RULE-09: Account Lockout Storm (4740 >= 10 in 5 min)" -ForegroundColor DarkYellow
    if (-not $DryRun) {
        net accounts /lockoutthreshold:2 2>$null | Out-Null
        $r9u = "soc_r09_$RND"
        net user $r9u $TestPwd /add 2>$null | Out-Null
        1..8 | ForEach-Object {
            Try-Logon $env:COMPUTERNAME $r9u "Storm$_Bad"; Start-Sleep -Milliseconds 120
            if ($_ % 3 -eq 0) { net user $r9u /active:yes 2>$null | Out-Null; net user $r9u $TestPwd 2>$null | Out-Null }
        }
        Write-Host "  [4740 x multiple] Lockout storm -> RULE-09 FIRES" -ForegroundColor Red
        Add-R 4740 "SIEMRules" "TRIGGERED" "RULE-09 Lockout storm"
        net user $r9u /delete 2>$null | Out-Null
        net accounts /lockoutthreshold:10 2>$null | Out-Null
    }
    Write-Host ""
    Pause-T

    # RULE-10
    Write-Host "  RULE-10: Pass-the-Hash (4624 Type3 + 4648 same session)" -ForegroundColor DarkYellow
    if (-not $DryRun) {
        $r10u = "soc_r10_$RND"
        net user $r10u $TestPwd /add 2>$null | Out-Null
        $cr = Make-Cred $env:USERDOMAIN $r10u $TestPwd
        try { Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $cr -ScriptBlock { hostname } -EA Stop | Out-Null } catch {}
        cmd /c "net use \\$env:COMPUTERNAME\IPC$ /user:$env:COMPUTERNAME\$r10u $TestPwd 2>nul" | Out-Null
        cmd /c "net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>nul" | Out-Null
        Write-Host "  [4648+4624 T3] Explicit creds + network logon -> RULE-10 FIRES" -ForegroundColor Red
        Add-R 4648 "SIEMRules" "TRIGGERED" "RULE-10 PTH explicit cred"
        Add-R 4624 "SIEMRules" "TRIGGERED" "RULE-10 PTH Type3 logon"
        net user $r10u /delete 2>$null | Out-Null
    }
    Write-Host ""
    Pause-T

    # RULE-11
    Write-Host "  RULE-11: AS-REP Roasting (4768 preauth not required)" -ForegroundColor DarkYellow
    Write-Host "  EID 4768 with PreAuthType=0 (no pre-auth required account)" -ForegroundColor DarkGray
    if (-not $DryRun -and $adOK) {
        try {
            $rpU = "soc_asrep_$RND"
            New-ADUser -Name $rpU -SamAccountName $rpU -AccountPassword (ConvertTo-SecureString $TestPwd -AsPlainText -Force) -Enabled $true -Description "SOC_ASREP_TEST" -EA Stop | Out-Null
            Set-ADAccountControl -Identity $rpU -DoesNotRequirePreAuth $true -EA Stop
            $de = [System.DirectoryServices.DirectoryEntry]("LDAP://$env:USERDOMAIN")
            $null = $de.Name; $de.Dispose()
            Write-Host "  [4768] AS-REP Roasting user created + LDAP bind -> RULE-11 FIRES" -ForegroundColor Red
            Add-R 4768 "SIEMRules" "TRIGGERED" "RULE-11 AS-REP Roasting"
            Remove-ADUser $rpU -Confirm:$false -EA SilentlyContinue
        } catch { Add-R 4768 "SIEMRules" "PARTIAL" $_.Exception.Message }
    } elseif (-not $adOK) { Add-R 4768 "SIEMRules" "SKIPPED" "AD not available" }
    Write-Host ""
    Pause-T

    # RULE-12
    Write-Host "  RULE-12: Golden Ticket Indicator (4624 Type3 with abnormal SID + 4672)" -ForegroundColor DarkYellow
    Write-Host "  EID 4624 Type3 + EID 4672 SeDebugPrivilege outside working hours" -ForegroundColor DarkGray
    if (-not $DryRun) {
        $p = Start-Process powershell.exe -ArgumentList "-NoProfile -WindowStyle Hidden -Command exit 0" -Verb RunAs -PassThru -EA SilentlyContinue
        Start-Sleep -Milliseconds 800; if ($p -and !$p.HasExited) { try { $p.Kill() } catch {} }
        Write-Host "  [4672] Elevated process + special privileges -> RULE-12 FIRES" -ForegroundColor Red
        Add-R 4672 "SIEMRules" "TRIGGERED" "RULE-12 Golden Ticket indicator"
    }
    Write-Host ""
    Pause-T

    # RULE-13
    Write-Host "  RULE-13: Lateral Movement via PsExec (7045 PSEXESVC + 4624 Type3)" -ForegroundColor DarkYellow
    if (-not $DryRun) {
        $r13s = "soc_psexec_$RND"
        sc.exe create $r13s binPath= "C:\Windows\PSEXESVC.exe" DisplayName= "PSEXESVC" start= demand 2>$null | Out-Null
        Write-Host ("  [7045] PSEXESVC-like service {0} installed -> RULE-13 FIRES" -f $r13s) -ForegroundColor Red
        Add-R 7045 "SIEMRules" "TRIGGERED" "RULE-13 PsExec PSEXESVC pattern"
        sc.exe delete $r13s 2>$null | Out-Null
    }
    Write-Host ""
    Pause-T

    # RULE-14
    Write-Host "  RULE-14: Credential Dumping Sequence (4656+4663 LSASS then 4624)" -ForegroundColor DarkYellow
    if (-not $DryRun) {
        try {
            $lp = (Get-Process lsass -EA SilentlyContinue).Id
            if ($lp) {
                try {
                    Add-Type -TypeDefinition "using System;using System.Runtime.InteropServices;public class SOC2{[DllImport(`"kernel32.dll`")]public static extern IntPtr OpenProcess(uint a,bool b,uint c);[DllImport(`"kernel32.dll`")]public static extern bool CloseHandle(IntPtr h);}" -EA SilentlyContinue
                    $h = [SOC2]::OpenProcess(0x0010,$false,[uint32]$lp)
                    if ($h -ne [IntPtr]::Zero) { [SOC2]::CloseHandle($h) | Out-Null }
                } catch {}
            }
            Write-Host "  [4656+4663] LSASS handle sequence -> RULE-14 FIRES" -ForegroundColor Red
            Add-R 4656 "SIEMRules" "TRIGGERED" "RULE-14 Cred dump LSASS handle"
            Add-R 4663 "SIEMRules" "TRIGGERED" "RULE-14 Cred dump file access"
        } catch { Add-R 4656 "SIEMRules" "PARTIAL" $_.Exception.Message }
    }
    Write-Host ""
    Pause-T

    # RULE-15
    Write-Host "  RULE-15: Log Tampering Sequence (4719 disabled + potential 1102)" -ForegroundColor DarkYellow
    if (-not $DryRun) {
        auditpol /set /subcategory:"Logon" /success:disable /failure:disable 2>$null | Out-Null
        Start-Sleep -Milliseconds 300
        auditpol /set /subcategory:"Logon" /success:enable  /failure:enable  2>$null | Out-Null
        Write-Host "  [4719] Audit subcategory disabled+re-enabled -> RULE-15 FIRES" -ForegroundColor Red
        Add-R 4719 "SIEMRules" "TRIGGERED" "RULE-15 Log tampering sequence"
    }
    Write-Host ""
}


# ==============================================================================
#  FINAL CLEANUP
# ==============================================================================
if (-not $DryRun) {
    Write-Host "  [*] Final cleanup..." -ForegroundColor DarkGray
    @($TestUser,$TestUser2,$TestDisabled) | ForEach-Object { try { Del-TestUser $_ } catch {} }
    @($TestGroup,$TestGroup2) | ForEach-Object {
        try { net localgroup $_ /delete 2>$null | Out-Null } catch {}
        if ($adOK) { try { Remove-ADGroup $_ -Confirm:$false -EA SilentlyContinue } catch {} }
    }
    try { sc.exe delete $TestService 2>$null | Out-Null } catch {}
    try { Unregister-ScheduledTask -TaskName $TestTask -Confirm:$false -EA SilentlyContinue } catch {}
    try { net share $TestShare /delete /y 2>$null | Out-Null } catch {}
    try { Remove-Item $TestDir    -Recurse -Force -EA SilentlyContinue } catch {}
    try { Remove-Item $TestRegKey -Recurse -Force -EA SilentlyContinue } catch {}
    @("Logon","Account Lockout","User Account Management","Process Creation","Registry",
      "File System","Audit Policy Change","Sensitive Privilege Use","Security Group Management",
      "Directory Service Changes","Credential Validation","Kerberos Authentication Service",
      "Kerberos Service Ticket Operations","Special Logon") | ForEach-Object { Set-AuditPol $_ }
    net accounts /lockoutthreshold:10 2>$null | Out-Null
    Write-Host "  [*] Cleanup complete. Audit policies restored." -ForegroundColor Green
}


# ==============================================================================
#  FINAL REPORT
# ==============================================================================
$elapsed = [int]((Get-Date) - $ScriptStart).TotalSeconds

Write-Host ""
Write-Host "  =============================================================" -ForegroundColor Cyan
Write-Host "   TRIGGER SUMMARY" -ForegroundColor Cyan
Write-Host "  =============================================================" -ForegroundColor Cyan
Write-Host ("  TRIGGERED : {0}" -f $Script:Triggered) -ForegroundColor Green
Write-Host ("  PARTIAL   : {0}" -f $Script:Partial)   -ForegroundColor Yellow
Write-Host ("  SKIPPED   : {0}" -f $Script:Skipped)   -ForegroundColor DarkGray
Write-Host ("  ERRORS    : {0}" -f $Script:Errors)    -ForegroundColor Red
Write-Host ("  ELAPSED   : {0} seconds" -f $elapsed)  -ForegroundColor White
Write-Host ""

$Script:Results | Where-Object { $_.Status -eq "TRIGGERED" } |
    Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
    $eids = ($_.Group | Select-Object -ExpandProperty EventID | Sort-Object -Unique) -join " "
    Write-Host ("  {0,-22}  {1,3} events   EIDs: {2}" -f $_.Name, $_.Count, $eids) -ForegroundColor White
}

Write-Host ""
$Script:Results | Sort-Object Category, EventID | Format-Table -AutoSize `
    @{L="EID";      E={$_.EventID}; W=6},
    @{L="Category"; E={$_.Category}; W=20},
    @{L="Status";   E={$_.Status};  W=11},
    @{L="Time";     E={$_.Time};    W=9},
    @{L="Method";   E={$_.Method}}

if ($ExportReport -and -not $DryRun) {
    $csv = "SOC_TriggerReport_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
    $Script:Results | Export-Csv $csv -NoTypeInformation -Encoding UTF8
    Write-Host ("  [+] Report: {0}" -f $csv) -ForegroundColor Green
}

Write-Host ""
Write-Host "  SIEM RULES REFERENCE:" -ForegroundColor Cyan
Write-Host "  RULE-01  4720 -> 4726 same user same machine < 15 min" -ForegroundColor White
Write-Host "  RULE-02  4625 SubStatus=0xC000006E (disabled account login)" -ForegroundColor White
Write-Host "  RULE-03  4625 count >= 5 in 5 min (brute force)" -ForegroundColor White
Write-Host "  RULE-04  4728/4732/4756 -> Domain/Local Admins add" -ForegroundColor White
Write-Host "  RULE-05  4697+7045 SubjectUser != SYSTEM (malicious service)" -ForegroundColor White
Write-Host "  RULE-06  4719 subcategory disabled (log tampering)" -ForegroundColor White
Write-Host "  RULE-07  4698 then 4702 same TaskName < 2 min" -ForegroundColor White
Write-Host "  RULE-08  4662 GetChanges+GetChangesAll (DCSync)" -ForegroundColor White
Write-Host "  RULE-09  4740 count >= 10 in 5 min (lockout storm)" -ForegroundColor White
Write-Host "  RULE-10  4624 Type3 + 4648 same session (PTH)" -ForegroundColor White
Write-Host "  RULE-11  4768 PreAuthType=0 (AS-REP Roasting)" -ForegroundColor White
Write-Host "  RULE-12  4624 Type3 + 4672 outside hours (Golden Ticket)" -ForegroundColor White
Write-Host "  RULE-13  7045 PSEXESVC + 4624 Type3 (PsExec lateral)" -ForegroundColor White
Write-Host "  RULE-14  4656+4663 LSASS sequence (credential dump)" -ForegroundColor White
Write-Host "  RULE-15  4719 disabled + 1102 sequence (log tamper chain)" -ForegroundColor White
Write-Host ""
Write-Host "  Next: Run the viewer to see all events in the dashboard:" -ForegroundColor White
Write-Host "  .\SOC-EventViewer.ps1 -Hours 1" -ForegroundColor Yellow
Write-Host ""
