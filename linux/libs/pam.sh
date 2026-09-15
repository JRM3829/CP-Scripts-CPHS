#!/usr/bin/env bash

set -uo pipefail

# pam jump offset
success_value() {
  case "$1" in
    *common-password*) echo 1; return 0 ;;
  esac
  local f="$1" seen=0 count=0 line
  while IFS= read -r line; do
    line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//')
    case "$line" in ""|\#*) continue ;; esac
    if [ "$seen" -eq 0 ]; then
      case "$line" in *pam_unix.so*) seen=1 ;; esac
      continue
    fi
    case "$line" in *pam_deny.so*|*pam_faillock.so*) break ;; esac
    count=$((count + 1))
  done < "$f"
  echo $((count + 1))
}

render() {
  printf '%s' "$2" | sed "s|\[success=@ default=ignore\]|[success=$(success_value "$1") default=ignore]|"
}

enforce() {
  local f="$1" tpl="$2" line ln
  [ -f "$f" ] || return 1
  line=$(render "$f" "$tpl")
  ln=$(awk '/pam_unix\.so/ && !d { print NR; d=1 }' "$f")
  [ -n "$ln" ] || return 0
  sed -i "${ln}s|.*|${line}|" "$f"
}

check() {
  local f="$1" tpl="${2:-}"
  [ -f "$f" ] || return 1
  if [ -n "$tpl" ]; then
    grep -Fxq "$(render "$f" "$tpl")" "$f"
  else
    local n
    n=$(success_value "$f")
    grep -qE "^[[:space:]]*(auth|password)[[:space:]]+\[success=${n} default=ignore\][[:space:]]+pam_unix\.so" "$f"
  fi
}

align() {
  local f n
  for f in "$@"; do
    [ -f "$f" ] || continue
    n=$(success_value "$f")
    sed -i -E "s/^([[:space:]]*(auth|password)[[:space:]]+)\[success=[0-9]+ default=ignore\]([[:space:]]+pam_unix\.so)/\1[success=${n} default=ignore]\3/" "$f" || return 1
  done
  return 0
}

case "${1:-}" in
  value) shift; success_value "$1" ;;
  enforce) shift; enforce "$@" ;;
  check) shift; check "$@" ;;
  align) shift; align "$@" ;;
  *) echo "usage: pam.sh value|enforce|check|align <file...> [template]" >&2; exit 2 ;;
esac
