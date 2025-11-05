#!/usr/bin/env bash
# RHEL 9 Host Survey (read-only)
# Writes results to /var/tmp/host_survey_YYYYmmddHHMMSS and emits summary.json

set -Eeuo pipefail

TS="$(date +%Y%m%d%H%M%S)"
OUTDIR="/var/tmp/host_survey_${TS}"
mkdir -p "$OUTDIR"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }

cmd_out() {
  # $1 -> output file, $2.. -> command
  local outfile="$1"; shift
  {
    echo "### CMD: $*"
    echo "### TS_UTC: $(date -u +%FT%TZ)"
    "$@" 2>&1 || true
  } > "${OUTDIR}/${outfile}"
}

json_bool() { [[ "$1" == "true" ]] && echo true || echo false; }

# ---------- Core facts ----------
HOSTNAME="$(hostname -f 2>/dev/null || hostname || echo unknown)"
OSREL="$(cat /etc/redhat-release 2>/dev/null || echo unknown)"
KERNEL="$(uname -r 2>/dev/null || echo unknown)"
CPU_COUNT="$(nproc 2>/dev/null || echo 0)"
UPTIME_SECONDS="$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)"
MEM_TOTAL_BYTES="$(awk '/MemTotal/ {print $2*1024}' /proc/meminfo 2>/dev/null || echo 0)"

SELINUX_MODE="$(getenforce 2>/dev/null || echo unknown)"
SELINUX_POLICY="$(sestatus 2>/dev/null | awk -F': ' '/Loaded policy name/ {print $2}' || true)"
FIPS_RAW="$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)"
if [[ "$FIPS_RAW" == "1" ]]; then FIPS=true; else FIPS=false; fi

# RHEL 9 specifics
CGROUPV2=false
[[ -f /sys/fs/cgroup/cgroup.controllers ]] && CGROUPV2=true
LOCKDOWN="$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "unknown")"
if systemctl is-active --quiet firewalld; then FW_ACTIVE=true; else FW_ACTIVE=false; fi
if systemctl is-active --quiet auditd; then AUDITD_ACTIVE=true; else AUDITD_ACTIVE=false; fi
if systemctl is-active --quiet systemd-oomd; then OOMD_ACTIVE=true; else OOMD_ACTIVE=false; fi
if systemctl is-active --quiet fapolicyd; then FAPOLICYD_ACTIVE=true; else FAPOLICYD_ACTIVE=false; fi
if systemctl is-active --quiet chronyd; then CHRONY_ACTIVE=true; else CHRONY_ACTIVE=false; fi

# ---------- Collections (safe reads) ----------
cmd_out os.txt               bash -lc 'hostnamectl; echo; cat /etc/redhat-release'
cmd_out kernel.txt           bash -lc 'uname -a; echo; grubby --default-kernel 2>/dev/null || true'
cmd_out cpu.txt              bash -lc 'lscpu || cat /proc/cpuinfo'
cmd_out memory.txt           bash -lc 'free -h; echo; cat /proc/meminfo'
cmd_out disks_lsblk.json     bash -lc 'lsblk -O -J || lsblk -O'
cmd_out df.txt               bash -lc 'df -PT --total'
cmd_out lvm.json             bash -lc 'vgs --reportformat json 2>/dev/null; echo; lvs --reportformat json 2>/dev/null || true'

cmd_out network.txt          bash -lc 'ip -br addr; echo; ip -4 route; echo; ip -6 route || true'
cmd_out nmcli.txt            bash -lc 'nmcli -t general status 2>/dev/null || true'
cmd_out ethtool.txt          bash -lc 'for i in /sys/class/net/*; do n=$(basename "$i"); ethtool "$n" 2>/dev/null || true; echo; done'

cmd_out selinux.txt          bash -lc 'sestatus 2>/dev/null || true; echo; cat /etc/selinux/config 2>/dev/null || true'
cmd_out fips.txt             bash -lc 'cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0'
cmd_out lockdown.txt         bash -lc 'cat /sys/kernel/security/lockdown 2>/dev/null || echo "unavailable"'
cmd_out cgroups.txt          bash -lc 'mount | grep cgroup || true; echo; ls /sys/fs/cgroup 2>/dev/null || true'

cmd_out firewalld.txt        bash -lc 'systemctl status --no-pager firewalld 2>/dev/null || true; echo; firewall-cmd --state 2>/dev/null || true; echo; firewall-cmd --get-active-zones 2>/dev/null || true; echo; firewall-cmd --list-all 2>/dev/null || true'
cmd_out auditd.txt           bash -lc 'systemctl status --no-pager auditd 2>/dev/null || true; echo; auditctl -s 2>/dev/null || true; echo; augenrules --check 2>/dev/null || true'
cmd_out tuned.txt            bash -lc 'tuned-adm active 2>/dev/null || true'
cmd_out chrony.txt           bash -lc 'systemctl status --no-pager chronyd 2>/dev/null || true; echo; chronyc sources -v 2>/dev/null || true'

cmd_out repos.txt            bash -lc 'dnf repolist -v 2>/dev/null || true'
cmd_out security_updates.txt bash -lc 'dnf -q updateinfo list security --available 2>/dev/null || true'
cmd_out subscription.txt     bash -lc 'subscription-manager status 2>/dev/null || echo "subscription-manager not installed"'

cmd_out podman.txt           bash -lc 'podman version 2>/dev/null || true; echo; podman ps --all --format json 2>/dev/null || true'
cmd_out containers.txt       bash -lc 'podman info 2>/dev/null || true; echo; buildah version 2>/dev/null || true'
cmd_out kmods.txt            bash -lc 'lsmod | sort'
cmd_out services_running.txt bash -lc 'systemctl list-units --type=service --state=running --no-pager --all'
cmd_out fapolicyd.txt        bash -lc 'systemctl status --no-pager fapolicyd 2>/dev/null || true; echo; fapolicyd-cli --verbose 2>/dev/null || true'

# ---------- Summary JSON ----------
SUMMARY="${OUTDIR}/summary.json"
{
  printf '{\n'
  printf '  "hostname": %q,\n'        "$HOSTNAME"
  printf '  "os_release": %q,\n'       "$OSREL"
  printf '  "kernel": %q,\n'           "$KERNEL"
  printf '  "cpu_count": %s,\n'        "$CPU_COUNT"
  printf '  "mem_total_bytes": %s,\n'  "$MEM_TOTAL_BYTES"
  printf '  "uptime_seconds": %s,\n'   "$UPTIME_SECONDS"
  printf '  "selinux_mode": %q,\n'     "$SELINUX_MODE"
  printf '  "selinux_policy": %q,\n'   "$SELINUX_POLICY"
  printf '  "fips_enabled": %s,\n'     "$(json_bool "$FIPS")"
  printf '  "cgroup_v2": %s,\n'        "$(json_bool "$CGROUPV2")"
  printf '  "kernel_lockdown": %q,\n'  "$LOCKDOWN"
  printf '  "firewalld_active": %s,\n' "$(json_bool "$FW_ACTIVE")"
  printf '  "auditd_active": %s,\n'    "$(json_bool "$AUDITD_ACTIVE")"
  printf '  "chronyd_active": %s,\n'   "$(json_bool "$CHRONY_ACTIVE")"
  printf '  "fapolicyd_active": %s,\n' "$(json_bool "$FAPOLICYD_ACTIVE")"
  printf '  "systemd_oomd_active": %s,\n' "$(json_bool "$OOMD_ACTIVE")"
  printf '  "survey_time_utc": %q\n'   "$(date -u +%FT%TZ)"
  printf '}\n'
} > "$SUMMARY"

log "Survey complete. Output dir: $OUTDIR"
echo "OUTPUT_DIR=$OUTDIR"
