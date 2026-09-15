#!/usr/bin/env bash

set -euo pipefail

source "${WYN_HOME}/conf/wyn.conf"
source "${WYN_HOME}/libs/core.sh"
source "${WYN_HOME}/libs/readme.sh"

DRY_RUN="${DRY_RUN:-false}"

usage() {
  printf "Usage: firewall.sh [options]\n\n"
  printf "Installs and enables UFW (default deny incoming / allow outgoing) and\n"
  printf "opens the required ports for each critical service in the README.\n\n"
  printf "Options:\n"
  printf "  -n, --dry-run     Preview rules without applying\n"
  printf "  -h, --help        Show help\n"
  exit 0
}

run_ufw() {
  if [ "$DRY_RUN" = true ]; then
    echo "  [dry] ufw $*"
    return 0
  fi
  ufw "$@"
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage ;;
    -n|--dry-run) DRY_RUN=true ;;
    *) die "unknown opt: $1" ;;
  esac
  shift
done

if ! readme_load; then
  die "could not read README - firewall unchanged"
fi
[ "$CRITICAL_SERVICES_VALID" = true ] \
  || die "README has no Critical Services section - firewall unchanged"

declare -a planned=()
for svc in $CRITICAL_SERVICES; do
  rules=$(resolve_service_rules "$svc" || true)
  [ -n "$rules" ] || die "no port mapping for critical service '$svc' - firewall unchanged"
  for rule in $rules; do planned+=("$rule|$svc"); done
done

if ! command -v ufw >/dev/null 2>&1; then
  if [ "$DRY_RUN" = true ]; then
    echo "  [dry] install ufw"
  else
    echo "installing ufw"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y ufw >/dev/null
  fi
fi

run_ufw default deny incoming
run_ufw default allow outgoing
run_ufw --force enable

for item in "${planned[@]}"; do
  rule="${item%%|*}"; svc="${item#*|}"
  echo "  allow $rule ($svc)"
  run_ufw allow "$rule"
done

if [ "$DRY_RUN" != true ]; then
  echo "ufw status:"
  ufw status verbose
fi
