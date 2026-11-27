#!/bin/sh
# Install the fit on the guest. POSIX sh, LF line endings.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
LIB=/usr/local/lib/omarchy-fit
STATE=/var/lib/omarchy-fit
MODULES="config.py sigs.py cgraph.py taxonomy.py polytope.py hierarchy.py prestage.py trfeed.py fitd.py"

install -d "$LIB" "$STATE" /etc/omarchy-fit
for m in $MODULES; do
  install -m 0644 "$ROOT/$m" "$LIB/$m"
done
install -m 0644 "$ROOT/systemd/omarchy-fit.service" /etc/systemd/system/omarchy-fit.service
install -m 0755 "$ROOT/verify.py" "$LIB/verify.py"

# /tmp on tmpfs. Tagged so a re-run is a no-op and so removal is obvious.
if ! grep -q 'omarchy-fit tmpfs' /etc/fstab 2>/dev/null; then
  printf '\n# omarchy-fit tmpfs\ntmpfs /tmp tmpfs rw,nosuid,nodev,noatime,size=1G,mode=1777 0 0\n' >> /etc/fstab
fi
if ! findmnt -n /tmp | grep -q tmpfs; then
  mount -t tmpfs -o rw,nosuid,nodev,noatime,size=1G,mode=1777 tmpfs /tmp || true
fi

systemctl daemon-reload
systemctl enable --now omarchy-fit.service

if python3 "$LIB/verify.py" --quiet; then
  echo "omarchy-fit installed; module self-check passed"
else
  echo "omarchy-fit installed; module self-check FAILED (run: python3 $LIB/verify.py)"
fi

echo "reboot the guest once so /tmp mounts from fstab"
