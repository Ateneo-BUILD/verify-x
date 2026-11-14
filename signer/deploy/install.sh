#!/bin/sh
# Install or update the credential signer on a verify host. Run as root from
# a verify checkout, naming the user gunicorn runs as:
#
#   sudo sh signer/deploy/install.sh verify-app
#
# Or, for a signer on a host of its own that dials out to the site and
# long-polls it for jobs (README.md, "Poll mode"), with no app user here:
#
#   sudo sh signer/deploy/install.sh --poll
#
# The signer only. Moving gunicorn off ec2-user is a separate, reviewed step
# (README.md, "Before the signer protects anything"), because the app tree
# and the deploy scripts move with it.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
APP_USER=${1:?"name the user gunicorn runs as, e.g. verify-app, or --poll"}
POLL=""
if [ "$APP_USER" = "--poll" ]; then
    POLL=1
    APP_USER=""
else
    id "$APP_USER" >/dev/null 2>&1 || { echo "no user $APP_USER" >&2; exit 1; }
fi
SRC=$(cd "$(dirname "$0")/../.." && pwd)

getent group cl03-operators >/dev/null || groupadd --system cl03-operators
# The app socket's group: the app user may connect, and the signer is in it
# without being in the app user's own group (cl03-signer.service). A poll
# host has no app socket and nobody in it, but the unit names the group.
getent group cl03-signer-app >/dev/null || groupadd --system cl03-signer-app
if [ -n "$APP_USER" ]; then
    usermod -aG cl03-signer-app "$APP_USER"
fi
id cl03-signer >/dev/null 2>&1 || useradd --system --home-dir /var/lib/cl03-signer \
    --shell /sbin/nologin cl03-signer

# Code: root-owned, so neither the app user nor cl03-signer can rewrite it.
# Staged whole beside the running copy, then swapped in, so the old code is
# never half replaced; the restart below follows.
install -d -o root -g root -m 0755 /opt/cl03-signer
STAGE=$(mktemp -d /opt/cl03-signer/.stage.XXXXXX)
cp -R "$SRC/signer" "$SRC/ovcrypto" "$STAGE/"
find "$STAGE" -name __pycache__ -prune -exec rm -rf {} +
# Which commit, for `cl03signer status` and Setup: from a checkout, or from
# signer/COMMIT, which `git archive` fills in (.gitattributes).
COMMIT=$( { git -c safe.directory="$SRC" -C "$SRC" rev-parse HEAD 2>/dev/null \
    || sed -n 1p "$SRC/signer/COMMIT" 2>/dev/null || true; } | tr -d '\r')
case "$COMMIT" in *[!0-9a-f]*) COMMIT="" ;; esac
[ "${#COMMIT}" -eq 40 ] || COMMIT=""
printf '%s\n' "$COMMIT" > "$STAGE/COMMIT"
chown -R root:root "$STAGE"
chmod 0755 "$STAGE"
# An update first checks the new code against the live policy, as an
# operator does after editing it: a policy the new code refuses (a held or
# legacy key's changed window, say) keeps the old code running.
if systemctl is-active --quiet cl03-signer && [ -x /opt/cl03-signer/venv/bin/python ]; then
    if ! (cd "$STAGE" && runuser -u cl03-signer -- /opt/cl03-signer/venv/bin/python \
            -m signer check --config /etc/cl03-signer/policy.toml); then
        rm -rf "$STAGE"
        echo "The new code would not start with /etc/cl03-signer/policy.toml:" >&2
        echo "nothing was changed. Fix the policy, or install other code." >&2
        exit 1
    fi
fi
for part in signer ovcrypto; do
    rm -rf "/opt/cl03-signer/$part.old"
    if [ -e "/opt/cl03-signer/$part" ]; then
        mv "/opt/cl03-signer/$part" "/opt/cl03-signer/$part.old"
    fi
    mv "$STAGE/$part" "/opt/cl03-signer/$part"
done
mv "$STAGE/COMMIT" /opt/cl03-signer/COMMIT
chmod 0644 /opt/cl03-signer/COMMIT
rm -rf "$STAGE" /opt/cl03-signer/signer.old /opt/cl03-signer/ovcrypto.old
# Python 3.11 or later (tomllib reads the policy). Amazon Linux 2023's
# python3 is 3.9, with 3.11 beside it; a venv made with an older one is
# replaced.
new_enough='import sys; sys.exit(sys.version_info < (3, 11))'
PY=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "$new_enough"; then
        PY=$(command -v "$candidate")
        break
    fi
done
[ -n "$PY" ] || { echo "the signer needs Python 3.11 or later" >&2; exit 1; }
if ! { [ -x /opt/cl03-signer/venv/bin/python ] \
        && /opt/cl03-signer/venv/bin/python -c "$new_enough"; }; then
    rm -rf /opt/cl03-signer/venv
    "$PY" -m venv /opt/cl03-signer/venv
fi
/opt/cl03-signer/venv/bin/pip install --quiet -r "$SRC/signer/deploy/requirements.txt"
cat > /usr/local/bin/cl03signer <<'SH'
#!/bin/sh
cd /opt/cl03-signer && exec /opt/cl03-signer/venv/bin/python -m signer.cli "$@"
SH
chmod 0755 /usr/local/bin/cl03signer

# Policy and secrets: root-owned, readable by cl03-signer only through systemd.
install -d -o root -g cl03-signer -m 0750 /etc/cl03-signer
install -d -o root -g root -m 0700 /etc/cl03-signer/credstore
[ -f /etc/cl03-signer/policy.toml ] || install -o root -g cl03-signer -m 0640 \
    "$SRC/signer/deploy/policy.example.toml" /etc/cl03-signer/policy.toml

install -o root -g root -m 0644 "$SRC/signer/deploy/cl03-signer.service" \
    "$SRC/signer/deploy/cl03-signer-reconcile.service" \
    "$SRC/signer/deploy/cl03-signer-reconcile.timer" /etc/systemd/system/
if [ -n "$POLL" ]; then
    # The poll key, as a credential only the signer reads.
    install -d -o root -g root -m 0755 /etc/systemd/system/cl03-signer.service.d
    install -o root -g root -m 0644 "$SRC/signer/deploy/poll.conf" \
        /etc/systemd/system/cl03-signer.service.d/poll.conf
fi
systemctl daemon-reload

# An update replaces the code under a running signer: restart it, so the
# serving signer and the next reconcile run the same code. A policy it
# cannot load keeps it stopped, alerted once: check it first with
# `python -m signer check` (README.md, "After editing policy.toml").
if systemctl is-active --quiet cl03-signer; then
    systemctl restart cl03-signer
    echo "Restarted cl03-signer on the new code."
    exit 0
fi
echo "Installed. Next: edit /etc/cl03-signer/policy.toml, put the issuing CA"
echo "and the credstore files in place, then: systemctl enable --now cl03-signer"
echo "cl03-signer-reconcile.timer."
if [ -n "$POLL" ]; then
    echo "Poll mode: transport = \"poll\" and site_url under [runtime], and the"
    echo "site's SIGNER_QUEUE_KEY in /etc/cl03-signer/credstore/poll-key."
else
    echo "Restart gunicorn so $APP_USER is in cl03-signer-app."
fi
