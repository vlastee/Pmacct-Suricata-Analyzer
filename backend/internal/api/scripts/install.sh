#!/usr/bin/env bash
# pmacct-agent installer (Linux). Generated command from the Agents page looks like:
#   curl -sk https://SERVER/api/v1/agent/install.sh | sudo bash -s -- --server https://SERVER \
#        --token ENROLL_TOKEN --ca-fingerprint AA:BB:… --ca-pin base64… [--capture auto] [--send-cmdline]
# Trust model: the CA is fetched without TLS validation, then checked against --ca-fingerprint
# (given out-of-band by the UI); everything after that is downloaded with that CA only, the
# binary is checksum-verified, and the agent re-verifies --ca-pin at enrollment.
set -euo pipefail
SERVER=""; TOKEN=""; FP=""; PIN=""; CAPTURE="auto"; CMDLINE=""; SPOOL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --ca-fingerprint) FP="$2"; shift 2 ;;
    --ca-pin) PIN="$2"; shift 2 ;;
    --capture) CAPTURE="$2"; shift 2 ;;
    --send-cmdline) CMDLINE="--send-cmdline"; shift ;;
    --spool-dir) SPOOL="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$SERVER" ] && [ -n "$TOKEN" ] || { echo "usage: --server URL --token TOKEN [--ca-fingerprint FP] [--ca-pin PIN] [--capture auto|poll|ebpf] [--send-cmdline] [--spool-dir DIR]" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }
SERVER="${SERVER%/}"
case "$(uname -m)" in x86_64|amd64) TARGET=linux-amd64 ;; *) echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;; esac
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CURL=(curl -fsSL)
case "$SERVER" in
  https://*)
    curl -fsSk "$SERVER/api/v1/tls/ca" -o "$TMP/ca.pem"
    if [ -n "$FP" ]; then
      GOT="$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "$TMP/ca.pem" | grep -v -- '-----' | base64 -d | sha256sum | cut -d' ' -f1 | tr 'a-f' 'A-F')"
      WANT="$(printf '%s' "$FP" | tr -d ':' | tr 'a-f' 'A-F')"
      [ "$GOT" = "$WANT" ] || { echo "CA fingerprint mismatch: server presented $GOT, expected $WANT — aborting" >&2; exit 1; }
      echo "CA fingerprint verified"
    else
      echo "WARNING: no --ca-fingerprint given; trusting the fetched CA on first use"
    fi
    CURL=(curl -fsSL --cacert "$TMP/ca.pem")
    ;;
  http://*) echo "WARNING: plain http — the enrollment token crosses the network in clear" ;;
esac
echo "downloading pmacct-agent ($TARGET)…"
"${CURL[@]}" "$SERVER/api/v1/agent/download/$TARGET" -o "$TMP/pmacct-agent"
SUM="$("${CURL[@]}" "$SERVER/api/v1/agent/download/$TARGET.sha256" | cut -d' ' -f1)"
echo "$SUM  $TMP/pmacct-agent" | sha256sum -c - >/dev/null || { echo "checksum mismatch — aborting" >&2; exit 1; }
if systemctl is-active --quiet pmacct-agent 2>/dev/null; then systemctl stop pmacct-agent; fi
install -m 0755 "$TMP/pmacct-agent" /usr/local/bin/pmacct-agent
PINARG=(); [ -n "$PIN" ] && PINARG=(--ca-pin "$PIN")
SPOOLARG=(); [ -n "$SPOOL" ] && SPOOLARG=(--spool-dir "$SPOOL")
/usr/local/bin/pmacct-agent enroll --server "$SERVER" --token "$TOKEN" "${PINARG[@]}" --capture "$CAPTURE" $CMDLINE "${SPOOLARG[@]}"
/usr/local/bin/pmacct-agent install
echo "done — the agent should appear online on the Agents page within a minute"
