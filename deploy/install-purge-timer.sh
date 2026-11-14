#!/bin/bash
# Install, or bring up to date, the daily purge of the phones' activity log.
# Both deploy scripts send this folder's purge-device-logs.*.tftpl beside the
# code and run this as root on every deploy, so a server built before the
# purge existed gets it on its next one:
#
#   install-purge-timer.sh APP_DIR TEMPLATE_DIR
#
# The purge runs as gunicorn does, its user and group read from systemd, so it
# follows gunicorn when the signer's separation moves it to its own user
# (signer/deploy/README.md). Units that already match are left alone.
# SYSTEMD_DIR names another folder for the units, for the tests.
set -euo pipefail

APP_DIR=$1
TEMPLATES=$2
UNITS=${SYSTEMD_DIR:-/etc/systemd/system}

APP_USER=$(systemctl show -p User --value gunicorn.service)
APP_GROUP=$(systemctl show -p Group --value gunicorn.service)
case "$APP_USER" in
    ""|root|0)
        echo "install-purge-timer: gunicorn.service names no user other than root;" >&2
        echo "install-purge-timer: the purge would run as root, so it is not installed." >&2
        exit 1 ;;
esac
APP_GROUP=${APP_GROUP:-$APP_USER}

changed=""
for unit in purge-device-logs.service purge-device-logs.timer; do
    rendered=$(mktemp)
    sed -e "s|\${app_dir}|$APP_DIR|g" -e "s|\${app_user}|$APP_USER|g" \
        -e "s|\${app_group}|$APP_GROUP|g" "$TEMPLATES/$unit.tftpl" \
        | tr -d '\r' > "$rendered"
    if ! cmp -s "$rendered" "$UNITS/$unit"; then
        install -m 0644 "$rendered" "$UNITS/$unit"
        changed="$changed $unit"
    fi
    rm -f "$rendered"
done

[ -z "$changed" ] || systemctl daemon-reload
systemctl enable --now purge-device-logs.timer
if [ -n "$changed" ]; then
    echo "    purge-device-logs: installed$changed, running as $APP_USER:$APP_GROUP"
else
    echo "    purge-device-logs: up to date, running as $APP_USER:$APP_GROUP"
fi
echo "    next run: $(systemctl show -p NextElapseUSecRealtime --value purge-device-logs.timer)"
