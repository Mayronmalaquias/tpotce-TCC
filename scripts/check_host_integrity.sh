#!/usr/bin/env bash
# Manual evidence collection; does not create or replace the FIM baseline.
set -uo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run with sudo' >&2; exit 2; }
REPORTS_DIR=${REPORTS_DIR:-/var/lib/beeia-integrity/audits}
mkdir -p "$REPORTS_DIR" || exit 2
REPORT_FILE=$(mktemp "$REPORTS_DIR/host-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX.log") || exit 2
exec > >(tee "$REPORT_FILE") 2>&1
status=0
collect() {
    printf '\n--- %s ---\n' "$1"
    shift
    "$@"
    rc=$?
    if [[ $rc -ne 0 ]]; then
        printf 'Command returned %s; investigate, not a clean result.\n' "$rc"
        status=2
    fi
}
echo 'Evidence collection only: no conclusion that this host is uncompromised.'
collect 'UTC date' date -u
collect 'Kernel' uname -a
collect 'UID 0 accounts' awk -F: '$3 == 0 {print $1}' /etc/passwd
collect 'Recent logins' last -n 20
collect 'Listening sockets' ss -tulpn
collect 'Established connections' ss -tp state established
collect 'Timers' systemctl list-timers --all --no-pager
collect 'Enabled services' systemctl list-unit-files --state=enabled --no-pager
collect 'Cron metadata' find /etc/cron.d /etc/cron.daily /var/spool/cron -ls
if command -v rpm >/dev/null; then
    collect 'RPM package verification (local database)' rpm -Va
elif command -v debsums >/dev/null; then
    collect 'Package checksums (local database; not trusted installation evidence)' debsums -s -a
else
    collect 'Package verification (local database)' dpkg --verify
fi
if command -v docker >/dev/null; then
    collect 'Docker containers' docker ps -a --no-trunc
    containers=$(docker ps -aq) || status=2
    for container in $containers; do
        collect 'Container containment (socket :ro does not restrict Docker API)' docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} readonly={{.HostConfig.ReadonlyRootfs}} network={{.HostConfig.NetworkMode}} caps={{json .HostConfig.CapAdd}} mounts={{json .Mounts}}' "$container"
    done
fi
if command -v nft >/dev/null; then
    collect 'nftables rules' nft list ruleset
fi
if command -v iptables-save >/dev/null; then
    collect 'iptables rules' iptables-save
fi
if [[ -f /opt/beeia-security/host_integrity.py ]]; then
    collect 'Comparison with existing baseline' python3 /opt/beeia-security/host_integrity.py check
else
    echo 'FIM not installed: follow md-usotcc/seguranca-host.md'
    status=2
fi
echo "Report: $REPORT_FILE"
echo 'Review the output even when commands succeed. Export evidence outside this VM.'
exit "$status"
