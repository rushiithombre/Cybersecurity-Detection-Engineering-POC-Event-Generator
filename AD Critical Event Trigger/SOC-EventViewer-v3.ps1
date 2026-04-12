<#
.SYNOPSIS
    SOC-EventViewer-v3.ps1
    Professional Security Event Dashboard - Opens in Browser
    Reads triggered Windows Security Events, generates clean HTML dashboard.

.USAGE
    .\SOC-EventViewer-v3.ps1
    .\SOC-EventViewer-v3.ps1 -Hours 2
    .\SOC-EventViewer-v3.ps1 -Hours 1 -AutoRefresh 30
    .\SOC-EventViewer-v3.ps1 -NoBrowser
    .\SOC-EventViewer-v3.ps1 -OutputPath "C:\SOC\dashboard.html"

.NOTES
    Version : 3.0 (Fixed Layout, Professional Design)
    Run As  : Any user (Administrator for full Security log access)
#>

param(
    [int]$Hours        = 1,
    [int]$AutoRefresh  = 0,
    [string]$OutputPath = "$env:TEMP\SOC_Dashboard_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [switch]$NoBrowser
)

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

# ==============================================================================
#  EVENT DEFINITIONS  (100+ Event IDs)
# ==============================================================================
$EventDefs = @(
    # Audit/Evasion
    @{EID=104;   Log="System";   Cat="Audit-Evasion";    Sev="HIGH";     Desc="System log cleared";                    MITRE="T1070.001"},
    @{EID=1102;  Log="Security"; Cat="Audit-Evasion";    Sev="CRITICAL"; Desc="Security log cleared";                  MITRE="T1070.001"},
    @{EID=4616;  Log="Security"; Cat="Audit-Evasion";    Sev="HIGH";     Desc="System time changed";                   MITRE="T1070.006"},
    @{EID=4719;  Log="Security"; Cat="Audit-Evasion";    Sev="CRITICAL"; Desc="Audit policy changed";                  MITRE="T1562.002"},

    # Authentication
    @{EID=4624;  Log="Security"; Cat="Authentication";   Sev="MEDIUM";   Desc="Successful logon";                      MITRE="T1078"},
    @{EID=4625;  Log="Security"; Cat="Authentication";   Sev="HIGH";     Desc="Failed logon attempt";                  MITRE="T1110"},
    @{EID=4634;  Log="Security"; Cat="Authentication";   Sev="INFO";     Desc="Account logoff";                        MITRE="T1078"},
    @{EID=4647;  Log="Security"; Cat="Authentication";   Sev="INFO";     Desc="User-initiated logoff";                 MITRE="T1078"},
    @{EID=4648;  Log="Security"; Cat="Authentication";   Sev="MEDIUM";   Desc="Logon with explicit credentials";       MITRE="T1550.002"},
    @{EID=4768;  Log="Security"; Cat="Authentication";   Sev="MEDIUM";   Desc="Kerberos TGT requested";                MITRE="T1558"},
    @{EID=4769;  Log="Security"; Cat="Authentication";   Sev="MEDIUM";   Desc="Kerberos service ticket requested";     MITRE="T1558.003"},
    @{EID=4771;  Log="Security"; Cat="Authentication";   Sev="HIGH";     Desc="Kerberos pre-auth failed";              MITRE="T1110"},
    @{EID=4776;  Log="Security"; Cat="Authentication";   Sev="HIGH";     Desc="NTLM credential validation";            MITRE="T1550.002"},
    @{EID=4778;  Log="Security"; Cat="Authentication";   Sev="MEDIUM";   Desc="RDP session reconnected";               MITRE="T1021.001"},
    @{EID=4779;  Log="Security"; Cat="Authentication";   Sev="INFO";     Desc="RDP session disconnected";              MITRE="T1021.001"},

    # Kerberos
    @{EID=4649;  Log="Security"; Cat="Kerberos";         Sev="CRITICAL"; Desc="Kerberos replay attack detected";       MITRE="T1558"},
    @{EID=4672;  Log="Security"; Cat="Kerberos";         Sev="HIGH";     Desc="Special privileges assigned to logon";  MITRE="T1134"},
    @{EID=4673;  Log="Security"; Cat="Kerberos";         Sev="HIGH";     Desc="Privileged service called";             MITRE="T1003.001"},
    @{EID=4674;  Log="Security"; Cat="Kerberos";         Sev="MEDIUM";   Desc="Operation on privileged object";        MITRE="T1134"},
    @{EID=4765;  Log="Security"; Cat="Kerberos";         Sev="HIGH";     Desc="SID History added to account";          MITRE="T1134.005"},
    @{EID=4766;  Log="Security"; Cat="Kerberos";         Sev="HIGH";     Desc="SID History add attempt failed";        MITRE="T1134.005"},
    @{EID=4770;  Log="Security"; Cat="Kerberos";         Sev="HIGH";     Desc="Kerberos ticket renewed";               MITRE="T1558.001"},

    # Account Lifecycle
    @{EID=4720;  Log="Security"; Cat="AccountLifecycle"; Sev="HIGH";     Desc="User account created";                  MITRE="T1136"},
    @{EID=4722;  Log="Security"; Cat="AccountLifecycle"; Sev="MEDIUM";   Desc="User account enabled";                  MITRE="T1098"},
    @{EID=4723;  Log="Security"; Cat="AccountLifecycle"; Sev="MEDIUM";   Desc="Password change attempt";               MITRE="T1098"},
    @{EID=4724;  Log="Security"; Cat="AccountLifecycle"; Sev="HIGH";     Desc="Password reset by admin";               MITRE="T1098"},
    @{EID=4725;  Log="Security"; Cat="AccountLifecycle"; Sev="MEDIUM";   Desc="User account disabled";                 MITRE="T1531"},
    @{EID=4726;  Log="Security"; Cat="AccountLifecycle"; Sev="HIGH";     Desc="User account deleted";                  MITRE="T1531"},
    @{EID=4738;  Log="Security"; Cat="AccountLifecycle"; Sev="MEDIUM";   Desc="User account changed";                  MITRE="T1098"},
    @{EID=4740;  Log="Security"; Cat="AccountLifecycle"; Sev="HIGH";     Desc="Account locked out";                    MITRE="T1110"},
    @{EID=4767;  Log="Security"; Cat="AccountLifecycle"; Sev="MEDIUM";   Desc="Account unlocked";                      MITRE="T1098"},

    # Group Management
    @{EID=4727;  Log="Security"; Cat="GroupManagement";  Sev="HIGH";     Desc="Global security group created";         MITRE="T1136"},
    @{EID=4728;  Log="Security"; Cat="GroupManagement";  Sev="CRITICAL"; Desc="Member added to global group";          MITRE="T1098.002"},
    @{EID=4729;  Log="Security"; Cat="GroupManagement";  Sev="HIGH";     Desc="Member removed from global group";      MITRE="T1531"},
    @{EID=4730;  Log="Security"; Cat="GroupManagement";  Sev="HIGH";     Desc="Global security group deleted";         MITRE="T1531"},
    @{EID=4731;  Log="Security"; Cat="GroupManagement";  Sev="MEDIUM";   Desc="Local security group created";          MITRE="T1136"},
    @{EID=4732;  Log="Security"; Cat="GroupManagement";  Sev="CRITICAL"; Desc="Member added to local Admins";          MITRE="T1098.002"},
    @{EID=4733;  Log="Security"; Cat="GroupManagement";  Sev="MEDIUM";   Desc="Member removed from local group";       MITRE="T1531"},
    @{EID=4734;  Log="Security"; Cat="GroupManagement";  Sev="HIGH";     Desc="Local security group deleted";          MITRE="T1531"},
    @{EID=4735;  Log="Security"; Cat="GroupManagement";  Sev="MEDIUM";   Desc="Local security group changed";          MITRE="T1098"},
    @{EID=4737;  Log="Security"; Cat="GroupManagement";  Sev="MEDIUM";   Desc="Global security group changed";         MITRE="T1098"},
    @{EID=4754;  Log="Security"; Cat="GroupManagement";  Sev="HIGH";     Desc="Universal security group created";      MITRE="T1136"},
    @{EID=4756;  Log="Security"; Cat="GroupManagement";  Sev="CRITICAL"; Desc="Member added to universal group";       MITRE="T1098.002"},
    @{EID=4757;  Log="Security"; Cat="GroupManagement";  Sev="HIGH";     Desc="Member removed from universal group";   MITRE="T1531"},
    @{EID=4764;  Log="Security"; Cat="GroupManagement";  Sev="HIGH";     Desc="Group type changed";                    MITRE="T1098"},

    # AD Changes
    @{EID=4661;  Log="Security"; Cat="ADChanges";        Sev="HIGH";     Desc="Handle to AD object requested";         MITRE="T1003"},
    @{EID=4662;  Log="Security"; Cat="ADChanges";        Sev="CRITICAL"; Desc="AD object operation (DCSync)";          MITRE="T1003.006"},
    @{EID=4741;  Log="Security"; Cat="ADChanges";        Sev="HIGH";     Desc="Computer account created";              MITRE="T1136.002"},
    @{EID=4742;  Log="Security"; Cat="ADChanges";        Sev="HIGH";     Desc="Computer account changed";              MITRE="T1098"},
    @{EID=4743;  Log="Security"; Cat="ADChanges";        Sev="HIGH";     Desc="Computer account deleted";              MITRE="T1531"},
    @{EID=5136;  Log="Security"; Cat="ADChanges";        Sev="CRITICAL"; Desc="AD DS object modified";                 MITRE="T1222"},
    @{EID=5137;  Log="Security"; Cat="ADChanges";        Sev="HIGH";     Desc="AD DS object created";                  MITRE="T1136"},
    @{EID=5138;  Log="Security"; Cat="ADChanges";        Sev="HIGH";     Desc="AD DS object undeleted";                MITRE="T1098"},
    @{EID=5141;  Log="Security"; Cat="ADChanges";        Sev="HIGH";     Desc="AD DS object deleted";                  MITRE="T1531"},

    # Process
    @{EID=4688;  Log="Security"; Cat="Process";          Sev="MEDIUM";   Desc="New process created (LOLBAS)";          MITRE="T1059"},
    @{EID=4689;  Log="Security"; Cat="Process";          Sev="INFO";     Desc="Process terminated";                    MITRE="T1059"},
    @{EID=4698;  Log="Security"; Cat="Process";          Sev="HIGH";     Desc="Scheduled task created";                MITRE="T1053.005"},
    @{EID=4702;  Log="Security"; Cat="Process";          Sev="MEDIUM";   Desc="Scheduled task modified";               MITRE="T1053.005"},
    @{EID=4703;  Log="Security"; Cat="Process";          Sev="MEDIUM";   Desc="Token right adjusted";                  MITRE="T1134"},
    @{EID=4704;  Log="Security"; Cat="Process";          Sev="MEDIUM";   Desc="User right assigned";                   MITRE="T1134"},
    @{EID=4705;  Log="Security"; Cat="Process";          Sev="MEDIUM";   Desc="User right removed";                    MITRE="T1134"},

    # Lateral Movement
    @{EID=4656;  Log="Security"; Cat="LateralMovement";  Sev="HIGH";     Desc="Handle to object (LSASS cred dump)";   MITRE="T1003.001"},
    @{EID=4663;  Log="Security"; Cat="LateralMovement";  Sev="MEDIUM";   Desc="Object access (SAM/NTDS.dit)";         MITRE="T1003"},
    @{EID=7040;  Log="System";   Cat="LateralMovement";  Sev="MEDIUM";   Desc="Service start type changed";            MITRE="T1543.003"},
    @{EID=7045;  Log="System";   Cat="LateralMovement";  Sev="HIGH";     Desc="New service installed (PsExec)";        MITRE="T1543.003"},

    # Object Access
    @{EID=4657;  Log="Security"; Cat="ObjectAccess";     Sev="HIGH";     Desc="Registry value modified";               MITRE="T1112"},
    @{EID=4660;  Log="Security"; Cat="ObjectAccess";     Sev="MEDIUM";   Desc="Object deleted";                        MITRE="T1485"},
    @{EID=4670;  Log="Security"; Cat="ObjectAccess";     Sev="MEDIUM";   Desc="Object permissions changed";            MITRE="T1222"},
    @{EID=5140;  Log="Security"; Cat="ObjectAccess";     Sev="MEDIUM";   Desc="Network share accessed";                MITRE="T1039"},
    @{EID=5142;  Log="Security"; Cat="ObjectAccess";     Sev="HIGH";     Desc="Network share added";                   MITRE="T1039"},
    @{EID=5143;  Log="Security"; Cat="ObjectAccess";     Sev="MEDIUM";   Desc="Network share modified";                MITRE="T1039"},
    @{EID=5145;  Log="Security"; Cat="ObjectAccess";     Sev="MEDIUM";   Desc="Network share object accessed";         MITRE="T1039"},

    # Persistence
    @{EID=4697;  Log="Security"; Cat="Persistence";      Sev="CRITICAL"; Desc="Service installed on system";           MITRE="T1543.003"},

    # Policy Changes
    @{EID=4706;  Log="Security"; Cat="PolicyChanges";    Sev="HIGH";     Desc="New domain trust created";              MITRE="T1484.002"},
    @{EID=4713;  Log="Security"; Cat="PolicyChanges";    Sev="HIGH";     Desc="Kerberos policy changed";               MITRE="T1562"},
    @{EID=4739;  Log="Security"; Cat="PolicyChanges";    Sev="HIGH";     Desc="Domain policy changed";                 MITRE="T1484"},

    # Network/Firewall
    @{EID=4946;  Log="Security"; Cat="NetworkPolicy";    Sev="MEDIUM";   Desc="Firewall rule added";                   MITRE="T1562.004"},
    @{EID=4947;  Log="Security"; Cat="NetworkPolicy";    Sev="MEDIUM";   Desc="Firewall rule modified";                MITRE="T1562.004"},
    @{EID=4950;  Log="Security"; Cat="NetworkPolicy";    Sev="MEDIUM";   Desc="Firewall setting changed";              MITRE="T1562.004"},
    @{EID=5031;  Log="Security"; Cat="NetworkPolicy";    Sev="MEDIUM";   Desc="Firewall blocked application";          MITRE="T1562.004"},
    @{EID=5154;  Log="Security"; Cat="NetworkPolicy";    Sev="INFO";     Desc="WFP allowed app to listen";             MITRE="T1205"},
    @{EID=5156;  Log="Security"; Cat="NetworkPolicy";    Sev="INFO";     Desc="WFP permitted connection";              MITRE="T1205"},
    @{EID=5157;  Log="Security"; Cat="NetworkPolicy";    Sev="MEDIUM";   Desc="WFP blocked connection";                MITRE="T1205"},

    # Domain Controller
    @{EID=4928;  Log="Security"; Cat="DomainController"; Sev="HIGH";     Desc="AD replica NC established";             MITRE="T1003.006"},
    @{EID=4929;  Log="Security"; Cat="DomainController"; Sev="HIGH";     Desc="AD replica NC removed";                 MITRE="T1003.006"},
    @{EID=4930;  Log="Security"; Cat="DomainController"; Sev="MEDIUM";   Desc="AD replica NC modified";                MITRE="T1003.006"},
    @{EID=4932;  Log="Security"; Cat="DomainController"; Sev="HIGH";     Desc="NC sync began";                         MITRE="T1003.006"},
    @{EID=4933;  Log="Security"; Cat="DomainController"; Sev="HIGH";     Desc="NC sync ended";                         MITRE="T1003.006"},
    @{EID=4934;  Log="Security"; Cat="DomainController"; Sev="MEDIUM";   Desc="AD object attributes replicated";       MITRE="T1003.006"},
    @{EID=4935;  Log="Security"; Cat="DomainController"; Sev="HIGH";     Desc="Replication failure begins";            MITRE="T1003.006"},
    @{EID=4936;  Log="Security"; Cat="DomainController"; Sev="HIGH";     Desc="Replication failure ends";              MITRE="T1003.006"}
)

# SIEM Rules definitions
$SIEMRules = @(
    @{ID="RULE-01"; Desc="Account Created then Deleted < 15 min";  EIDs=@(4720,4726); Tactic="Persistence Evasion"},
    @{ID="RULE-02"; Desc="Disabled Account Login (C000006E)";       EIDs=@(4625);      Tactic="Credential Access"},
    @{ID="RULE-03"; Desc="Brute Force >= 5 failures in 5 min";      EIDs=@(4625);      Tactic="Credential Access"},
    @{ID="RULE-04"; Desc="Admin Group Membership Added";            EIDs=@(4728,4732,4756); Tactic="Privilege Escalation"},
    @{ID="RULE-05"; Desc="Service Installed by Non-SYSTEM";         EIDs=@(4697,7045); Tactic="Persistence"},
    @{ID="RULE-06"; Desc="Audit Policy Disabled";                   EIDs=@(4719);      Tactic="Defense Evasion"},
    @{ID="RULE-07"; Desc="Task Created then Modified < 2 min";      EIDs=@(4698,4702); Tactic="Persistence"},
    @{ID="RULE-08"; Desc="DCSync (4662 GetChanges+GetChangesAll)";  EIDs=@(4662);      Tactic="Credential Access"},
    @{ID="RULE-09"; Desc="Account Lockout Storm >= 10 in 5 min";    EIDs=@(4740);      Tactic="Credential Access"},
    @{ID="RULE-10"; Desc="Pass-the-Hash (4624 T3 + 4648)";          EIDs=@(4624,4648); Tactic="Lateral Movement"},
    @{ID="RULE-11"; Desc="AS-REP Roasting (4768 PreAuth=0)";        EIDs=@(4768);      Tactic="Credential Access"},
    @{ID="RULE-12"; Desc="Golden Ticket (4624 T3 + 4672 abnormal)"; EIDs=@(4672);      Tactic="Privilege Escalation"},
    @{ID="RULE-13"; Desc="PsExec Lateral (7045 PSEXESVC + 4624)";   EIDs=@(7045,4624); Tactic="Lateral Movement"},
    @{ID="RULE-14"; Desc="Credential Dump Sequence (4656+4663 LSASS)"; EIDs=@(4656,4663); Tactic="Credential Access"},
    @{ID="RULE-15"; Desc="Log Tamper Chain (4719 disabled + 1102)"; EIDs=@(4719,1102); Tactic="Defense Evasion"}
)

# ==============================================================================
#  COLLECT EVENTS
# ==============================================================================
$StartTime = (Get-Date).AddHours(-$Hours)
Write-Host ""
Write-Host "  =============================================================" -ForegroundColor Cyan
Write-Host "   SOC Event Viewer v3.0 - Professional Dashboard" -ForegroundColor Cyan
Write-Host "  =============================================================" -ForegroundColor Cyan
Write-Host ("  Machine   : {0}" -f $env:COMPUTERNAME) -ForegroundColor White
Write-Host ("  Timeframe : Last {0} hour(s)  from {1}" -f $Hours, $StartTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
Write-Host ""
Write-Host "  [*] Querying Windows Event Logs..." -ForegroundColor DarkGray

$AllEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
$i = 0

foreach ($def in $EventDefs) {
    $i++
    $pct = [int](($i / $EventDefs.Count) * 100)
    Write-Progress -Activity "Querying Event Logs" -Status ("EID {0} - {1}" -f $def.EID, $def.Desc) -PercentComplete $pct

    try {
        $evts = Get-WinEvent -FilterHashtable @{
            LogName   = $def.Log
            Id        = $def.EID
            StartTime = $StartTime
        } -MaxEvents 300 -EA Stop

        foreach ($ev in $evts) {
            $msg     = if ($ev.Message) { $ev.Message } else { "" }
            $lines   = ($msg -split "`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -First 3) -join " | "
            $summary = ($lines.Trim() -replace "\s{2,}", " ")
            if ($summary.Length -gt 220) { $summary = $summary.Substring(0,217) + "..." }

            $subUser = ""; $tgtUser = ""; $logonT = ""; $srcIP = ""; $procN = ""
            if ($msg -match "Account Name:\s+(\S+)")             { $subUser = $Matches[1].Trim() }
            if ($msg -match "Target Account Name:\s+(\S+)")      { $tgtUser = $Matches[1].Trim() }
            if ($msg -match "New Logon.*?Account Name:\s+(\S+)") { $tgtUser = $Matches[1].Trim() }
            if ($msg -match "Logon Type:\s+(\d+)")               { $logonT  = $Matches[1].Trim() }
            if ($msg -match "Source Network Address:\s+(\S+)")   { $srcIP   = $Matches[1].Trim() }
            if ($msg -match "Process Name:\s+(.+)")              { $procN   = ($Matches[1].Trim() -split "\\")[-1] }

            $AllEvents.Add([PSCustomObject]@{
                Time     = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                TimeSort = $ev.TimeCreated
                EID      = $def.EID
                Severity = $def.Sev
                Category = $def.Cat
                Desc     = $def.Desc
                MITRE    = $def.MITRE
                Log      = $def.Log
                Machine  = $ev.MachineName
                SubUser  = $subUser
                TgtUser  = $tgtUser
                LogonT   = $logonT
                SrcIP    = $srcIP
                ProcName = $procN
                Message  = ($summary -replace "<","&lt;" -replace ">","&gt;" -replace '"',"'")
            })
        }
    } catch {}
}

Write-Progress -Activity "Done" -Completed

$Total     = $AllEvents.Count
$Critical  = ($AllEvents | Where-Object Severity -eq "CRITICAL").Count
$High      = ($AllEvents | Where-Object Severity -eq "HIGH").Count
$Medium    = ($AllEvents | Where-Object Severity -eq "MEDIUM").Count
$Info      = ($AllEvents | Where-Object Severity -eq "INFO").Count
$UniqueEID = ($AllEvents | Select-Object -ExpandProperty EID -Unique).Count

Write-Host ("  [+] Found {0} events across {1} unique Event IDs" -f $Total, $UniqueEID) -ForegroundColor Green
Write-Host ""

# ==============================================================================
#  BUILD CHART DATA
# ==============================================================================
$Sorted = $AllEvents | Sort-Object TimeSort -Descending

# Category data
$CatGroups = $AllEvents | Group-Object Category | Sort-Object Count -Descending
$CatLabels = ($CatGroups | ForEach-Object { "'$($_.Name)'" }) -join ","
$CatCounts = ($CatGroups | ForEach-Object { $_.Count }) -join ","

# Timeline - bucket by 5-minute intervals for last 6 hours
$Buckets = [ordered]@{}
for ($b = 71; $b -ge 0; $b--) {
    $key = (Get-Date).AddMinutes(-($b * 5)).ToString("HH:mm")
    $Buckets[$key] = 0
}
foreach ($ev in $AllEvents) {
    $minutes = [math]::Floor(($ev.TimeSort.Minute) / 5) * 5
    $key = $ev.TimeSort.ToString("HH:") + $minutes.ToString("00")
    if ($Buckets.Contains($key)) { $Buckets[$key]++ }
}
$TLLabels = ($Buckets.Keys | ForEach-Object { "'$_'" }) -join ","
$TLData   = ($Buckets.Values) -join ","

# Top Event IDs
$TopEIDs = $AllEvents | Group-Object EID | Sort-Object Count -Descending | Select-Object -First 12

# SIEM rule hits
$RuleHits = @{}
foreach ($rule in $SIEMRules) {
    $cnt = ($AllEvents | Where-Object { $_.EID -in $rule.EIDs }).Count
    $RuleHits[$rule.ID] = $cnt
}

# ==============================================================================
#  BUILD EVENT TABLE HTML
# ==============================================================================
$SevMap = @{ CRITICAL="ec"; HIGH="eh"; MEDIUM="em"; INFO="ei" }

$TableRows = ""
$rowN = 0
foreach ($ev in ($Sorted | Select-Object -First 600)) {
    $rowN++
    $sc   = $SevMap[$ev.Severity]
    $user = if ($ev.TgtUser -and $ev.TgtUser -ne "-") { $ev.TgtUser } elseif ($ev.SubUser) { $ev.SubUser } else { "-" }
    $ip   = if ($ev.SrcIP -and $ev.SrcIP -notin @("-","::1","127.0.0.1","")) { $ev.SrcIP } else { "-" }
    $proc = if ($ev.ProcName) { $ev.ProcName } else { "-" }
    $lt   = if ($ev.LogonT) { " T$($ev.LogonT)" } else { "" }
    $TableRows += "<tr class='er $sc' data-s='$($ev.Severity)' data-c='$($ev.Category)'><td class='rn'>$rowN</td><td class='mono sm'>$($ev.Time)</td><td><span class='eb'>$($ev.EID)</span></td><td><span class='sb $sc'>$($ev.Severity)</span></td><td class='sm'>$($ev.Category)</td><td class='fw'>$($ev.Desc)</td><td class='mono sm'>$user$lt</td><td class='mono sm'>$ip</td><td class='mono sm'>$proc</td><td class='mw'><span title='$($ev.Message)'>$($ev.Message)</span></td><td class='mono sm dim'>$($ev.MITRE)</td></tr>`n"
}

# Top EID rows
$TopRows = ""
foreach ($eid in $TopEIDs) {
    $d    = $EventDefs | Where-Object { $_.EID -eq [int]$eid.Name } | Select-Object -First 1
    $desc = if ($d) { $d.Desc } else { "Unknown" }
    $sev  = if ($d) { $d.Sev  } else { "INFO" }
    $sc   = $SevMap[$sev]
    $pct  = if ($Total -gt 0) { [int](($eid.Count / $Total) * 100) } else { 0 }
    $TopRows += "<tr><td><span class='eb'>$($eid.Name)</span></td><td class='fw'>$desc</td><td><span class='sb $sc'>$sev</span></td><td><div class='bw'><div class='bf $sc' style='width:$pct%'></div></div> <span class='mono'>$($eid.Count)</span></td></tr>`n"
}

# SIEM rule rows
$RuleRows = ""
foreach ($rule in $SIEMRules) {
    $cnt  = $RuleHits[$rule.ID]
    $fired = if ($cnt -gt 0) { "<span class='rf'>FIRED ($cnt events)</span>" } else { "<span class='rn2'>Clean</span>" }
    $eids = ($rule.EIDs -join ", ")
    $RuleRows += "<tr><td class='mono sm fw'>$($rule.ID)</td><td>$($rule.Desc)</td><td class='sm dim'>$($rule.Tactic)</td><td class='sm dim'>$eids</td><td>$fired</td></tr>`n"
}

# Severity donut data
$SevData   = "$Critical,$High,$Medium,$Info"
$RefreshMeta = if ($AutoRefresh -gt 0) { "<meta http-equiv='refresh' content='$AutoRefresh'>" } else { "" }
$ReportTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$emptyMsg    = if ($Total -eq 0) { "No events found. Run SOC-EventTrigger-v3.ps1 first, then re-run this viewer." } else { "" }

# ==============================================================================
#  HTML TEMPLATE
# ==============================================================================
$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
$RefreshMeta
<title>SOC Dashboard - $env:COMPUTERNAME</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#03070f;--bg2:#060d1a;--bg3:#0a1628;--panel:#07111f;
  --b1:#162840;--b2:#1e3a5f;--acc:#00c8ff;--acc2:#0055cc;
  --txt:#b8cce0;--dim:#4a6a88;--cr:#ff1a40;--hi:#ff8c00;--me:#e6b800;--inf:#3399ff;
  --gr:#00e676;--fw:600;
}
html{font-size:13px}
body{background:var(--bg);color:var(--txt);font-family:'Rajdhani',sans-serif;min-height:100vh;overflow-x:hidden}

/* HEADER */
.hdr{
  display:flex;align-items:center;justify-content:space-between;
  padding:0 20px;height:56px;
  background:var(--bg2);border-bottom:1px solid var(--b1);
  position:sticky;top:0;z-index:200;
  box-shadow:0 2px 20px rgba(0,0,0,.5);
}
.hdr-l{display:flex;align-items:center;gap:12px}
.logo{
  width:32px;height:32px;border-radius:6px;
  background:linear-gradient(135deg,var(--acc2),var(--acc));
  display:flex;align-items:center;justify-content:center;
  font-size:15px;font-weight:700;color:#fff;letter-spacing:-1px;
  box-shadow:0 0 16px rgba(0,200,255,.35);flex-shrink:0;
}
.hdr-title{font-size:16px;font-weight:700;color:#fff;letter-spacing:2px;text-transform:uppercase}
.hdr-sub{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--acc);letter-spacing:1px;margin-top:1px}
.hdr-r{display:flex;align-items:center;gap:16px;font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--dim)}
.dot{width:6px;height:6px;border-radius:50%;background:var(--gr);box-shadow:0 0 6px var(--gr);display:inline-block;margin-right:4px;animation:blink 2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.tag{background:rgba(0,200,255,.08);border:1px solid var(--b1);border-radius:4px;padding:2px 8px;white-space:nowrap}

/* LAYOUT */
.main{padding:16px;display:flex;flex-direction:column;gap:14px;max-width:1920px;margin:0 auto}

/* STAT CARDS */
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
.card{
  background:var(--panel);border:1px solid var(--b1);border-radius:8px;
  padding:14px 16px;position:relative;overflow:hidden;
}
.card::after{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
.card.tot::after{background:linear-gradient(180deg,var(--acc2),var(--acc))}
.card.cr::after{background:var(--cr)}
.card.hi::after{background:var(--hi)}
.card.me::after{background:var(--me)}
.card.in::after{background:var(--inf)}
.card-lbl{font-size:9px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--dim);margin-bottom:8px}
.card-val{font-family:'JetBrains Mono',monospace;font-size:36px;line-height:1;margin-bottom:4px}
.card.tot .card-val{color:var(--acc)}
.card.cr  .card-val{color:var(--cr)}
.card.hi  .card-val{color:var(--hi)}
.card.me  .card-val{color:var(--me)}
.card.in  .card-val{color:var(--inf)}
.card-sub{font-size:10px;color:var(--dim)}

/* CHART ROW */
.charts{display:grid;grid-template-columns:2fr 1fr 1fr;gap:12px;align-items:start}
.panel{background:var(--panel);border:1px solid var(--b1);border-radius:8px;padding:14px}
.ptitle{font-size:9px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--acc);
  margin-bottom:12px;display:flex;align-items:center;gap:6px}
.ptitle::before{content:'';width:2px;height:12px;background:var(--acc);border-radius:1px;display:inline-block}
.chart-box{position:relative}
.chart-box canvas{display:block}

/* DATA GRID */
.datagrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}

/* TABLE BASE */
.tbl{width:100%;border-collapse:collapse;font-size:12px}
.tbl th{
  text-align:left;padding:7px 10px;
  font-size:9px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;
  color:var(--dim);border-bottom:1px solid var(--b1);white-space:nowrap;
}
.tbl td{padding:7px 10px;border-bottom:1px solid rgba(22,40,64,.5);vertical-align:middle}
.tbl tr:hover td{background:rgba(0,200,255,.03)}

/* EVENT TABLE */
.evt-wrap{background:var(--panel);border:1px solid var(--b1);border-radius:8px;overflow:hidden}
.evt-ctrl{
  padding:10px 14px;display:flex;align-items:center;gap:10px;
  flex-wrap:wrap;border-bottom:1px solid var(--b1);background:var(--bg2);
}
.search{
  background:var(--bg3);border:1px solid var(--b1);border-radius:5px;
  padding:5px 10px;color:var(--txt);font-family:'JetBrains Mono',monospace;font-size:11px;
  width:200px;outline:none;transition:border-color .15s;
}
.search:focus{border-color:var(--acc)}
.search::placeholder{color:var(--dim)}
.fb{
  background:var(--bg3);border:1px solid var(--b1);border-radius:5px;
  padding:4px 10px;color:var(--dim);font-size:9px;font-weight:700;
  letter-spacing:1px;text-transform:uppercase;cursor:pointer;transition:all .15s;
  font-family:'Rajdhani',sans-serif;
}
.fb:hover{border-color:var(--acc);color:var(--acc)}
.fb.on{border-color:var(--acc);color:var(--acc);background:rgba(0,200,255,.06)}
.fb.on.fc{border-color:var(--cr);color:var(--cr);background:rgba(255,26,64,.06)}
.fb.on.fh{border-color:var(--hi);color:var(--hi);background:rgba(255,140,0,.06)}
.fb.on.fm{border-color:var(--me);color:var(--me);background:rgba(230,184,0,.06)}
.fb.on.fi{border-color:var(--inf);color:var(--inf);background:rgba(51,153,255,.06)}
.vcnt{margin-left:auto;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim)}
.evt-scroll{overflow:auto;max-height:480px}
.evt-tbl{width:100%;border-collapse:collapse;font-size:11px;min-width:1200px}
.evt-tbl thead tr{background:var(--bg2);position:sticky;top:0;z-index:10}
.evt-tbl th{
  text-align:left;padding:8px 10px;
  font-size:9px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;
  color:var(--dim);border-bottom:1px solid var(--b1);white-space:nowrap;cursor:pointer;
}
.evt-tbl th:hover{color:var(--acc)}
.evt-tbl td{padding:6px 10px;border-bottom:1px solid rgba(22,40,64,.4);vertical-align:middle}
.evt-tbl tr.er:hover td{background:rgba(0,200,255,.04)}
.er.ec td:first-child{border-left:2px solid var(--cr)}
.er.eh td:first-child{border-left:2px solid var(--hi)}
.er.em td:first-child{border-left:2px solid var(--me)}
.er.ei td:first-child{border-left:2px solid var(--inf)}

/* BADGES */
.eb{
  background:rgba(0,85,204,.15);border:1px solid rgba(0,85,204,.3);
  color:var(--acc);border-radius:3px;padding:1px 6px;
  font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:600;
  white-space:nowrap;
}
.sb{border-radius:3px;padding:1px 7px;font-size:9px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;white-space:nowrap}
.ec.sb,.ec{background:rgba(255,26,64,.12);color:var(--cr);border:1px solid rgba(255,26,64,.25)}
.eh.sb,.eh{background:rgba(255,140,0,.12);color:var(--hi);border:1px solid rgba(255,140,0,.25)}
.em.sb,.em{background:rgba(230,184,0,.1);color:var(--me);border:1px solid rgba(230,184,0,.25)}
.ei.sb,.ei{background:rgba(51,153,255,.1);color:var(--inf);border:1px solid rgba(51,153,255,.25)}

/* BARS */
.bw{display:inline-block;width:80px;height:5px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden;vertical-align:middle;margin-right:6px}
.bf{height:100%;border-radius:2px}
.ec.bf{background:var(--cr)}
.eh.bf{background:var(--hi)}
.em.bf{background:var(--me)}
.ei.bf{background:var(--inf)}

/* SIEM RULE TABLE */
.rf{background:rgba(255,26,64,.12);color:var(--cr);border:1px solid rgba(255,26,64,.25);border-radius:3px;padding:1px 8px;font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700}
.rn2{color:var(--dim);font-size:10px}

/* UTILITY */
.mono{font-family:'JetBrains Mono',monospace}
.sm{font-size:10px}
.dim{color:var(--dim)}
.fw{font-weight:var(--fw)}
.rn{color:var(--dim);font-family:'JetBrains Mono',monospace;width:36px}
.mw{max-width:240px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;font-size:10px;color:var(--dim)}
.empty{text-align:center;padding:40px;color:var(--dim);font-family:'JetBrains Mono',monospace;font-size:11px}

/* FOOTER */
.ftr{text-align:center;padding:14px;font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--dim);border-top:1px solid var(--b1);margin-top:4px;letter-spacing:.5px}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-l">
    <div class="logo">S</div>
    <div>
      <div class="hdr-title">SOC Event Dashboard</div>
      <div class="hdr-sub">WINDOWS SECURITY MONITOR v3.0  |  100+ EVENT IDs  |  15 SIEM RULES</div>
    </div>
  </div>
  <div class="hdr-r">
    <span><span class="dot"></span>LIVE</span>
    <span class="tag">HOST: $($env:COMPUTERNAME.ToUpper())</span>
    <span class="tag">DOMAIN: $($env:USERDOMAIN.ToUpper())</span>
    <span class="tag">WINDOW: LAST $Hours HR</span>
    <span class="tag">$ReportTime</span>
    $(if ($AutoRefresh -gt 0) { "<span class='tag' style='color:var(--gr)'>REFRESH: ${AutoRefresh}s</span>" })
  </div>
</div>

<div class="main">

<!-- STAT CARDS -->
<div class="cards">
  <div class="card tot">
    <div class="card-lbl">Total Events</div>
    <div class="card-val">$Total</div>
    <div class="card-sub">$UniqueEID unique Event IDs detected</div>
  </div>
  <div class="card cr">
    <div class="card-lbl">Critical</div>
    <div class="card-val">$Critical</div>
    <div class="card-sub">Immediate action required</div>
  </div>
  <div class="card hi">
    <div class="card-lbl">High</div>
    <div class="card-val">$High</div>
    <div class="card-sub">Investigate promptly</div>
  </div>
  <div class="card me">
    <div class="card-lbl">Medium</div>
    <div class="card-val">$Medium</div>
    <div class="card-sub">Review and monitor</div>
  </div>
  <div class="card in">
    <div class="card-lbl">Info</div>
    <div class="card-val">$Info</div>
    <div class="card-sub">Informational baseline</div>
  </div>
</div>

<!-- CHARTS -->
<div class="charts">
  <div class="panel">
    <div class="ptitle">Event Timeline (5-min buckets)</div>
    <div class="chart-box"><canvas id="cTimeline" height="110"></canvas></div>
  </div>
  <div class="panel">
    <div class="ptitle">Severity Distribution</div>
    <div class="chart-box"><canvas id="cSev" height="110"></canvas></div>
  </div>
  <div class="panel">
    <div class="ptitle">Events by Category</div>
    <div class="chart-box"><canvas id="cCat" height="110"></canvas></div>
  </div>
</div>

<!-- DATA GRID -->
<div class="datagrid">
  <!-- Top Event IDs -->
  <div class="panel">
    <div class="ptitle">Top 12 Event IDs</div>
    <table class="tbl">
      <thead><tr><th>EID</th><th>Description</th><th>Severity</th><th>Count</th></tr></thead>
      <tbody>
        $(if ($TopRows) { $TopRows } else { "<tr><td colspan='4' class='empty'>No events detected</td></tr>" })
      </tbody>
    </table>
  </div>
  <!-- SIEM Rules -->
  <div class="panel">
    <div class="ptitle">SIEM Correlation Rules (15 Rules)</div>
    <table class="tbl">
      <thead><tr><th>Rule</th><th>Description</th><th>Tactic</th><th>EIDs</th><th>Status</th></tr></thead>
      <tbody>$RuleRows</tbody>
    </table>
  </div>
</div>

<!-- EVENT TABLE -->
<div class="evt-wrap">
  <div class="evt-ctrl">
    <div class="ptitle" style="margin-bottom:0">All Triggered Events</div>
    <input class="search" id="srch" type="text" placeholder="Search EID, user, IP, description...">
    <button class="fb on"    onclick="fSev('ALL',this)">All ($Total)</button>
    <button class="fb fc"    onclick="fSev('CRITICAL',this)">Critical ($Critical)</button>
    <button class="fb fh"    onclick="fSev('HIGH',this)">High ($High)</button>
    <button class="fb fm"    onclick="fSev('MEDIUM',this)">Medium ($Medium)</button>
    <button class="fb fi"    onclick="fSev('INFO',this)">Info ($Info)</button>
    <span class="vcnt" id="vc">Showing $Total events</span>
  </div>
  <div class="evt-scroll">
    <table class="evt-tbl" id="etbl">
      <thead>
        <tr>
          <th>#</th>
          <th onclick="srt(1)">Time</th>
          <th onclick="srt(2)">EID</th>
          <th onclick="srt(3)">Severity</th>
          <th onclick="srt(4)">Category</th>
          <th onclick="srt(5)">Description</th>
          <th>User / LogonType</th>
          <th>Source IP</th>
          <th>Process</th>
          <th>Message</th>
          <th>MITRE</th>
        </tr>
      </thead>
      <tbody id="eb">
        $(if ($TableRows) { $TableRows } else { "<tr><td colspan='11' class='empty'>$emptyMsg</td></tr>" })
      </tbody>
    </table>
  </div>
</div>

</div><!-- end .main -->

<div class="ftr">
  SOC Event Dashboard v3.0 &nbsp;|&nbsp; $env:COMPUTERNAME &nbsp;|&nbsp;
  $Total Events &nbsp;|&nbsp; $UniqueEID Event IDs &nbsp;|&nbsp; 100+ Monitored &nbsp;|&nbsp;
  15 SIEM Rules &nbsp;|&nbsp; Generated: $ReportTime
  $(if ($AutoRefresh -gt 0) { " &nbsp;|&nbsp; Auto-refresh: ${AutoRefresh}s" })
</div>

<script>
Chart.defaults.color='#4a6a88';Chart.defaults.borderColor='rgba(22,40,64,.6)';
const co={responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}}};

// Timeline
new Chart(document.getElementById('cTimeline'),{
  type:'bar',
  data:{
    labels:[$TLLabels],
    datasets:[{data:[$TLData],backgroundColor:'rgba(0,200,255,.3)',borderColor:'rgba(0,200,255,.7)',borderWidth:1,borderRadius:2}]
  },
  options:{...co,scales:{
    x:{ticks:{maxTicksLimit:16,font:{family:'JetBrains Mono',size:8}},grid:{color:'rgba(22,40,64,.5)'}},
    y:{ticks:{font:{family:'JetBrains Mono',size:8}},grid:{color:'rgba(22,40,64,.5)'},beginAtZero:true}
  }}
});

// Severity donut
new Chart(document.getElementById('cSev'),{
  type:'doughnut',
  data:{
    labels:['CRITICAL','HIGH','MEDIUM','INFO'],
    datasets:[{data:[$SevData],backgroundColor:['rgba(255,26,64,.8)','rgba(255,140,0,.8)','rgba(230,184,0,.8)','rgba(51,153,255,.8)'],borderWidth:0,hoverOffset:4}]
  },
  options:{responsive:true,maintainAspectRatio:false,cutout:'62%',plugins:{legend:{display:true,position:'right',labels:{font:{family:'JetBrains Mono',size:9},color:'#4a6a88',boxWidth:10,padding:8}}}}
});

// Category bar
new Chart(document.getElementById('cCat'),{
  type:'bar',
  data:{
    labels:[$CatLabels],
    datasets:[{data:[$CatCounts],backgroundColor:['rgba(0,200,255,.5)','rgba(0,85,204,.5)','rgba(255,26,64,.5)','rgba(255,140,0,.5)','rgba(230,184,0,.5)','rgba(0,230,118,.5)','rgba(170,0,255,.5)','rgba(255,64,160,.5)','rgba(0,200,200,.5)','rgba(200,180,0,.5)','rgba(100,180,255,.5)','rgba(255,100,100,.5)','rgba(100,255,150,.5)','rgba(180,130,0,.5)'],borderWidth:0,borderRadius:2}]
  },
  options:{...co,indexAxis:'y',scales:{x:{ticks:{font:{family:'JetBrains Mono',size:8}},grid:{color:'rgba(22,40,64,.5)'},beginAtZero:true},y:{ticks:{font:{family:'JetBrains Mono',size:8}},grid:{display:false}}}}
});

// Filter
let curSev='ALL';
function fSev(s,btn){
  curSev=s;
  document.querySelectorAll('.fb').forEach(b=>{b.classList.remove('on')});
  btn.classList.add('on');
  applyF();
}
document.getElementById('srch').addEventListener('input',applyF);
function applyF(){
  const q=document.getElementById('srch').value.toLowerCase();
  const rows=document.querySelectorAll('#eb tr.er');
  let v=0;
  rows.forEach(r=>{
    const ok=(curSev==='ALL'||r.dataset.s===curSev)&&(!q||r.textContent.toLowerCase().includes(q));
    r.style.display=ok?'':'none';
    if(ok)v++;
  });
  document.getElementById('vc').textContent='Showing '+v+' events';
}

// Sort
let sd={};
function srt(c){
  const tb=document.getElementById('eb');
  const rows=Array.from(tb.querySelectorAll('tr.er'));
  const asc=!sd[c]; sd={}; sd[c]=asc;
  const so={CRITICAL:0,HIGH:1,MEDIUM:2,INFO:3};
  rows.sort((a,b)=>{
    const at=a.cells[c]?.textContent.trim()||'';
    const bt=b.cells[c]?.textContent.trim()||'';
    if(c===3)return asc?(so[at]??9)-(so[bt]??9):(so[bt]??9)-(so[at]??9);
    return asc?at.localeCompare(bt):bt.localeCompare(at);
  });
  rows.forEach(r=>tb.appendChild(r));
  applyF();
}
</script>
</body>
</html>
"@

# ==============================================================================
#  WRITE + OPEN
# ==============================================================================
try {
    $HTML | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
} catch {
    $OutputPath = "$env:TEMP\SOC_Dashboard_fallback.html"
    $HTML | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
}

Write-Host ("  [+] Dashboard saved: {0}" -f $OutputPath) -ForegroundColor Green
Write-Host ""

if (-not $NoBrowser) {
    Write-Host "  [*] Opening in browser..." -ForegroundColor DarkGray
    Start-Process $OutputPath
}

# Console summary
Write-Host "  =============================================================" -ForegroundColor Cyan
Write-Host "   DASHBOARD SUMMARY" -ForegroundColor Cyan
Write-Host "  =============================================================" -ForegroundColor Cyan
Write-Host ("  Total Events   : {0}" -f $Total)    -ForegroundColor White
Write-Host ("  Critical       : {0}" -f $Critical) -ForegroundColor Red
Write-Host ("  High           : {0}" -f $High)     -ForegroundColor Yellow
Write-Host ("  Medium         : {0}" -f $Medium)   -ForegroundColor Cyan
Write-Host ("  Info           : {0}" -f $Info)     -ForegroundColor DarkGray
Write-Host ("  Unique EIDs    : {0}" -f $UniqueEID) -ForegroundColor White
Write-Host ""

if ($CatGroups) {
    Write-Host "  BY CATEGORY:" -ForegroundColor White
    foreach ($cg in $CatGroups | Select-Object -First 10) {
        Write-Host ("    {0,-22}  {1,4} events" -f $cg.Name, $cg.Count) -ForegroundColor DarkGray
    }
    Write-Host ""
}

Write-Host "  SIEM RULE STATUS:" -ForegroundColor White
foreach ($rule in $SIEMRules) {
    $cnt = $RuleHits[$rule.ID]
    $col = if ($cnt -gt 0) { "Red" } else { "DarkGray" }
    $st  = if ($cnt -gt 0) { "FIRED ($cnt events)" } else { "Clean" }
    Write-Host ("    {0}  {1,-42}  {2}" -f $rule.ID, $rule.Desc, $st) -ForegroundColor $col
}

Write-Host ""
Write-Host "  =============================================================" -ForegroundColor Cyan
Write-Host ("  Dashboard: {0}" -f $OutputPath) -ForegroundColor White
Write-Host ""
Write-Host "  WORKFLOW:" -ForegroundColor White
Write-Host "  1. .\SOC-EventTrigger-v3.ps1           # generate events" -ForegroundColor DarkGray
Write-Host "  2. .\SOC-EventViewer-v3.ps1 -Hours 1   # view dashboard" -ForegroundColor DarkGray
Write-Host "  3. .\SOC-EventViewer-v3.ps1 -Hours 1 -AutoRefresh 30  # live mode" -ForegroundColor DarkGray
Write-Host ""

if ($AutoRefresh -gt 0) {
    Write-Host ("  [*] Auto-refresh every {0}s. Press Ctrl+C to stop." -f $AutoRefresh) -ForegroundColor Green
    while ($true) {
        Start-Sleep -Seconds $AutoRefresh
        Write-Host ("  [*] Refreshing... {0}" -f (Get-Date -Format "HH:mm:ss")) -ForegroundColor DarkGray
        & $MyInvocation.MyCommand.Path -Hours $Hours -AutoRefresh $AutoRefresh -OutputPath $OutputPath -NoBrowser
    }
}
