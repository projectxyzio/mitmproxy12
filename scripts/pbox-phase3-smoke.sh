#!/bin/bash
# Phase 3 runtime smoke for patched mitmproxy12 on pbox-style hosts.
#
# Usage (on a pbox after push):
#   source ~/headspinio-pboxagent/source-envs.sh
#   pyenv activate mitm12
#   bash ~/headspinio-pboxagent/mitmproxy12/scripts/pbox-phase3-smoke.sh
#
# Or from a local editable checkout:
#   bash scripts/pbox-phase3-smoke.sh

set -euo pipefail

realpath() {
    [[ $1 = /* ]] && echo "$1" || echo "$PWD/${1#./}"
}

SCRIPT_DIR=$(dirname "$(realpath "$0")")
MITM_ROOT=$(dirname "$SCRIPT_DIR")
CONFDIR=$(mktemp -d /tmp/mitm12-phase3-confdir.XXXXXX)
export CONFDIR
PORT=18999
MITMDUMP_PID=""

cleanup() {
    if [[ -n "$MITMDUMP_PID" ]] && kill -0 "$MITMDUMP_PID" 2>/dev/null; then
        kill "$MITMDUMP_PID" 2>/dev/null || true
        wait "$MITMDUMP_PID" 2>/dev/null || true
    fi
    rm -rf "$CONFDIR"
}
trap cleanup EXIT

if ! command -v mitmdump >/dev/null 2>&1; then
    echo "mitmdump not found in PATH; activate the mitm12 pyenv first." >&2
    exit 1
fi

echo "== mitmdump version =="
mitmdump --version

echo "== confdir compatibility =="
python - <<'PY'
from pathlib import Path
import os
import sys

from cryptography.hazmat.primitives import serialization

from mitmproxy import certs

confdir = Path(os.environ["CONFDIR"])
key, ca = certs.create_ca(organization="mitmproxy", cn="mitmproxy", key_size=2048)
pem_path = confdir / "mitmproxy-ca.pem"
pem_path.write_bytes(
    key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    + ca.public_bytes(serialization.Encoding.PEM)
)
store = certs.CertStore.from_store(confdir, "mitmproxy", 2048)
assert store.default_ca.cn == "mitmproxy"
print(f"loaded CA from {confdir}")
PY

echo "== mitmdump startup =="
mitmdump --set "confdir=$CONFDIR" --listen-host 127.0.0.1 --listen-port "$PORT" >/tmp/mitm12-phase3-smoke.log 2>&1 &
MITMDUMP_PID=$!

for _ in $(seq 1 50); do
    if ! kill -0 "$MITMDUMP_PID" 2>/dev/null; then
        echo "mitmdump exited early; log:" >&2
        cat /tmp/mitm12-phase3-smoke.log >&2 || true
        exit 1
    fi
    if python - <<PY
import socket
s = socket.socket()
s.settimeout(0.2)
try:
    s.connect(("127.0.0.1", $PORT))
except OSError:
    raise SystemExit(1)
finally:
    s.close()
PY
    then
        echo "mitmdump listening on 127.0.0.1:$PORT"
        echo "Phase 3 smoke passed (repo: $MITM_ROOT)"
        exit 0
    fi
    sleep 0.1
done

echo "mitmdump did not open port $PORT in time; log:" >&2
cat /tmp/mitm12-phase3-smoke.log >&2 || true
exit 1
