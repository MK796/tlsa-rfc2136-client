#!/usr/bin/env bash
set -euo pipefail
umask 077

# ---- configuration (override via environment) ----
LOG_TAG="${LOG_TAG:-certbot-tlsa-rfc2136}"
LOG_FILE="${LOG_FILE:-/var/log/tlsa-rfc2136-hook.log}"
LOCK_FILE="${LOCK_FILE:-/run/tlsa-rfc2136-hook.lock}"

TLSA_CMD="${TLSA_CMD:-tlsa-rfc2136-client}"

TLSA_CONFIG_FILE="${TLSA_CONFIG_FILE:-/etc/tlsa-rfc2136/config.json}"
TLSA_PROFILE="${TLSA_PROFILE:-default}"

TLSA_PORT="${TLSA_PORT:-443}"
TLSA_TRANSPORT="${TLSA_TRANSPORT:-tcp}"
TLSA_TTL="${TLSA_TTL:-3600}"

TLSA_MODE="${TLSA_MODE:-auto-sensible}"
TLSA_TUPLES="${TLSA_TUPLES:-default}"

# Live check is intentionally OFF by default for hook automation.
TLSA_LIVE_CHECK="${TLSA_LIVE_CHECK:-0}"

# If STRICT=1, propagate "--tool exit code 2" as 2 (monitoring can catch).
STRICT="${STRICT:-0}"

# Retry behavior
MAX_RETRIES="${MAX_RETRIES:-3}"
BACKOFF_S="${BACKOFF_S:-2 5 10}"

log() {
  local msg="$1"
  # to file
  printf '%s %s\n' "$(date -Is)" "$msg" >>"$LOG_FILE"
  # to syslog if available
  if command -v logger >/dev/null 2>&1; then
    logger -t "$LOG_TAG" -- "$msg" || true
  fi
}

die() {
  local msg="$1"
  log "ERROR: $msg"
  echo "ERROR: $msg" >&2
  exit 1
}

# ---- ensure we're in a certbot deploy-hook context ----
if [[ -z "${RENEWED_LINEAGE:-}" || -z "${RENEWED_DOMAINS:-}" ]]; then
  # Not a certbot deploy-hook call; exit successfully to avoid breaking unrelated runs.
  log "Not running in a certbot deploy-hook context (missing RENEWED_LINEAGE/RENEWED_DOMAINS). Skipping."
  exit 0
fi

# Lock to avoid parallel runs (rare, but safe)
exec 9>"$LOCK_FILE"
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || { log "Another hook run is in progress. Skipping."; exit 0; }
fi

# Determine host: default to first domain in RENEWED_DOMAINS unless TLSA_HOST is set
TLSA_HOST="${TLSA_HOST:-$(awk '{print $1}' <<<"$RENEWED_DOMAINS")}"
TLSA_CERT_PATH="${TLSA_CERT_PATH:-$RENEWED_LINEAGE}"

# Basic validation
command -v "$TLSA_CMD" >/dev/null 2>&1 || die "Command not found: $TLSA_CMD (did you install the pip package / entrypoint?)"
[[ -r "$TLSA_CONFIG_FILE" ]] || die "Config file not readable: $TLSA_CONFIG_FILE (must exist and contain TSIG profile)"

# Do not print secrets; only reference config
log "Starting TLSA update for lineage=$RENEWED_LINEAGE domains='$RENEWED_DOMAINS' host=$TLSA_HOST port=$TLSA_PORT/$TLSA_TRANSPORT ttl=$TLSA_TTL profile=$TLSA_PROFILE tuples=$TLSA_TUPLES"

base_args=(
  "--mode" "$TLSA_MODE"
  "--tuples" "$TLSA_TUPLES"
  "--config-file" "$TLSA_CONFIG_FILE"
  "--profile" "$TLSA_PROFILE"
  "--cert-path" "$TLSA_CERT_PATH"
  "--host" "$TLSA_HOST"
  "--port" "$TLSA_PORT"
  "--transport" "$TLSA_TRANSPORT"
  "--ttl" "$TLSA_TTL"
  "--no-export"
)

if [[ "$TLSA_LIVE_CHECK" == "1" ]]; then
  base_args+=("--live-check")
else
  base_args+=("--no-live-check")
fi

# helper to run with logging
run_tool() {
  set +e
  "$TLSA_CMD" "${base_args[@]}" >>"$LOG_FILE" 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

# retries
attempt=1
rc=0
for backoff in $BACKOFF_S; do
  rc="$(run_tool)"
  if [[ "$rc" == "0" ]]; then
    log "TLSA update succeeded (exit 0)."
    exit 0
  fi

  if [[ "$rc" == "2" ]]; then
    # Verification problems: log, optionally re-validate once after backoff
    log "TLSA tool reported verification mismatch (exit 2). Will run one validate-only pass after ${backoff}s."
    sleep "$backoff"
    set +e
    "$TLSA_CMD" \
      --validate-only "${base_args[@]}" >>"$LOG_FILE" 2>&1
    vrc=$?
    set -e
    log "validate-only finished with exit=$vrc"
    if [[ "$STRICT" == "1" ]]; then
      exit 2
    fi
    exit 0
  fi

  if [[ "$rc" == "130" ]]; then
    log "TLSA tool aborted by user (exit 130) - unexpected in certbot hook. Exiting 1."
    exit 1
  fi

  # rc == 1 or other: transient? retry
  log "TLSA tool failed (exit $rc) on attempt $attempt. Retrying in ${backoff}s."
  attempt=$((attempt + 1))
  if [[ "$attempt" -gt "$MAX_RETRIES" ]]; then
    break
  fi
  sleep "$backoff"
done

log "TLSA update ultimately failed (exit $rc) after retries."
exit 1
