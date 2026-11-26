#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
install -d /usr/local/lib/omarchy-fit /var/lib/omarchy-fit /etc/omarchy-fit
install -m 0644 "$ROOT/fitd.py" /usr/local/lib/omarchy-fit/fitd.py
install -m 0644 "$ROOT/systemd/omarchy-fit.service" /etc/systemd/system/omarchy-fit.service
if ! grep -q 'omarchy-fit tmpfs' /etc/fstab 2>/dev/null; then
  printf '\n# omarchy-fit tmpfs\ntmpfs /tmp tmpfs rw,nosuid,nodev,noatime,size=1G,mode=1777 0 0\n' >> /etc/fstab
fi
if ! findmnt -n /tmp | grep -q tmpfs; then
  mount -t tmpfs -o rw,nosuid,nodev,noatime,size=1G,mode=1777 tmpfs /tmp || true
fi
systemctl daemon-reload
systemctl enable --now omarchy-fit.service
echo "omarchy-fit installed"
