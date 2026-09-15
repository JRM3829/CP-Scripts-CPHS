#!/usr/bin/env bash

set -euo pipefail

source "${WYN_HOME}/libs/core.sh"

RULES_SRC="${WYN_AUDIT_RULES_SRC:-${WYN_HOME}/conf/audit/audit.rules}"
RULES_TARGET="${WYN_AUDIT_RULES_TARGET:-/etc/audit/rules.d/audit.rules}"
AUDIT_ROOT="${WYN_AUDIT_ROOT:-}"

installed() { dpkg -s auditd >/dev/null 2>&1; }

render_rules() {
  local line path
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ ^-w[[:space:]]+([^[:space:]]+) ]]; then
      path="${BASH_REMATCH[1]}"
      [ -e "${AUDIT_ROOT}${path}" ] || continue
    fi
    printf '%s\n' "$line"
  done < "$RULES_SRC"
}

rules_installed() { cmp -s <(render_rules) "$RULES_TARGET"; }

loaded() {
  auditctl -s 2>/dev/null | grep -q "enabled 2" && return 0
  auditctl -l 2>/dev/null | grep -q "audit_config" && return 0
  return 1
}

case "${1:-}" in
  installed) installed ;;
  install)
    installed || DEBIAN_FRONTEND=noninteractive apt-get install -y auditd >/dev/null 2>&1
    mkdir -p /etc/audit/rules.d
    ;;
  render-rules) render_rules ;;
  rules-installed) rules_installed ;;
  install-rules)
    tmp=$(mktemp)
    trap 'rm -f "$tmp"' EXIT
    render_rules > "$tmp"
    install -m 600 "$tmp" "$RULES_TARGET"
    ;;
  loaded) loaded ;;
  load)
    loaded && exit 0
    pgrep -x auditd >/dev/null 2>&1 || service auditd start >/dev/null 2>&1 || true
    pgrep -x auditd >/dev/null 2>&1 || { warn "auditd not running"; exit 1; }
    augenrules --check
    augenrules --load
    loaded
    ;;
  status)
    printf 'rules: %s\n' "$RULES_TARGET"
    auditctl -l 2>&1 || true
    auditctl -s 2>&1 || true
    ;;
  *) echo "usage: audit.sh {installed|install|render-rules|rules-installed|install-rules|loaded|load|status}" >&2; exit 2 ;;
esac
