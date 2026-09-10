#!/usr/bin/env bash
# Install only. Baseline creation and activation are explicit subsequent steps.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo' >&2; exit 2; }
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
command -v python3 >/dev/null
command -v systemctl >/dev/null
install -d -m 0700 /var/lib/beeia-integrity
install -d -m 0755 /opt/beeia-security
install -m 0755 "$SOURCE_DIR/host_integrity.py" /opt/beeia-security/host_integrity.py
install -m 0644 "$SOURCE_DIR/systemd/beeia-integrity.service" /etc/systemd/system/
install -m 0644 "$SOURCE_DIR/systemd/beeia-integrity.timer" /etc/systemd/system/
systemctl daemon-reload
echo 'Installed. Audit the host, then initialize once and enable the timer; see md-usotcc/seguranca-host.md.'
