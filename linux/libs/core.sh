#!/usr/bin/env bash

export DRY_RUN="${DRY_RUN:-false}"

warn() { printf '%s\n' "$1" >&2; }
die() { warn "$1"; exit 1; }

confirm() {
  local d="${2:-y}" a
  case "$d" in n|N|no) printf '%s [y/N] ' "$1" ;; *) printf '%s [Y/n] ' "$1" ;; esac
  read -r a || return 1
  case "${a,,}" in
    y|yes) return 0 ;;
    n|no) return 1 ;;
    "") case "$d" in n|N|no) return 1 ;; *) return 0 ;; esac ;;
    *) return 1 ;;
  esac
}

in_list() {
  local i="$1" e; shift
  for e in "$@"; do case "$i" in $e) return 0 ;; esac; done
  return 1
}

# include disguised home accounts
interactive_accounts() {
  local uid_min=1000 uid_max=60000
  if [ -r /etc/login.defs ]; then
    uid_min=$(awk '$1 == "UID_MIN" {print $2; exit}' /etc/login.defs); uid_min=${uid_min:-1000}
    uid_max=$(awk '$1 == "UID_MAX" {print $2; exit}' /etc/login.defs); uid_max=${uid_max:-60000}
  fi
  awk -F: '
    ($3 == 0 && $1 != "root") ||
    ($1 != "nobody" && (($3 >= min && $3 <= max) ||
      $6 ~ "^/home/")) {
      print $1
    }
  ' min="$uid_min" max="$uid_max" "${1:-/etc/passwd}"
}

ps_field() { ps -p "$1" -o "$2=" 2>/dev/null | tr -d ' ' || true; }

pkg_manager() {
  local m
  for m in apt-get dnf pacman zypper yum; do
    command -v "$m" >/dev/null 2>&1 && { printf '%s' "$m"; return 0; }
  done
  return 1
}

pkg_install() {
  local p="$1" m
  m=$(pkg_manager) || return 1
  case "$m" in
    apt-get)
      sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$p"
      ;;
    dnf)    sudo dnf install -y -q "$p" ;;
    pacman) sudo pacman -S --noconfirm --needed "$p" ;;
    zypper) sudo zypper install -y -q "$p" ;;
    yum)    sudo yum install -y -q "$p" ;;
  esac
}

pkg_remove() {
  local p="$1"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get purge -y "$p" >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf remove -y "$p" >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum remove -y "$p" >/dev/null 2>&1 || true
  fi
}

pkg_owner() {
  local p="$1" o=""
  if command -v dpkg >/dev/null 2>&1; then
    o=$(dpkg -S "$p" 2>/dev/null | head -1 | cut -d: -f1 | cut -d, -f1)
    case "$o" in ""|*" "*) ;; *) printf '%s' "$o"; return 0 ;; esac
  fi
  if command -v rpm >/dev/null 2>&1; then
    o=$(rpm -qf "$p" 2>/dev/null | head -1)
    case "$o" in ""|*" "*) ;; *) printf '%s' "$o"; return 0 ;; esac
  fi
  if command -v pacman >/dev/null 2>&1; then
    o=$(pacman -Qoq "$p" 2>/dev/null | head -1)
    case "$o" in ""|*" "*) ;; *) printf '%s' "$o"; return 0 ;; esac
  fi
  return 0
}

has_pkg_db() { command -v dpkg >/dev/null 2>&1 || command -v rpm >/dev/null 2>&1 || command -v pacman >/dev/null 2>&1; }

get_pid_from_port() {
  local p="$1" pid
  pid=$(sudo lsof -ti tcp:"$p" -sTCP:LISTEN 2>/dev/null | head -1)
  [ -z "$pid" ] && pid=$(sudo ss -tulpn 2>/dev/null | grep -w LISTEN | grep -E "[:,]$p[[:space:]]" | grep -oP 'pid=\K[0-9]+' | head -1)
  [ -n "$pid" ] || die "no listener on port $p"
  printf '%s' "$pid"
}

resolve_target() {
  local t="$1" pid
  case "$t" in
    :*) get_pid_from_port "${t#:}" ;;
    *[!0-9]*)
      pid=$(pgrep -x "$t" 2>/dev/null | head -1)
      [ -n "$pid" ] || die "no proc $t"
      printf '%s' "$pid"
      ;;
    *) [ -d "/proc/$t" ] || die "no pid $t"; printf '%s' "$t" ;;
  esac
}

require_tool() { command -v "$1" >/dev/null 2>&1 || return 1; }

validate_pid() { [ "$1" -eq "$1" ] 2>/dev/null || die "bad pid $1"; [ -d "/proc/$1" ] || die "pid $1 dead"; }

list_listeners() {
  local proto state recv send addr peer rest port svc pid path key
  declare -A seen=()
  while read -r proto state recv send addr peer rest; do
    [ -n "$addr" ] || continue
    port="${addr##*:}"
    case "$port" in ''|*[!0-9]*) continue ;; esac
    svc=$(printf '%s' "$rest" | sed -nE 's/.*users:\(\("([^"]+)".*/\1/p')
    pid=$(printf '%s' "$rest" | sed -nE 's/.*pid=([0-9]+).*/\1/p')
    svc="${svc:--}"; pid="${pid:--}"
    key="$proto|$port|$pid"
    [ -n "${seen[$key]:-}" ] && continue
    seen[$key]=1
    path=-
    case "$pid" in *[!0-9]*|'') ;; *) path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo -) ;; esac
    printf '%s|%s|%s|%s|%s|%s\n' "$proto" "$port" "$addr" "$svc" "$pid" "$path"
  done < <(ss -H -lntup 2>/dev/null || true)
}

# outbound excludes listener ports
list_outgoing_connections() {
  local proto state recv send local_ep remote_ep rest port svc pid path
  declare -A listeners=() seen=()
  while IFS='|' read -r proto port _; do listeners["$proto|$port"]=1; done < <(list_listeners)

  while read -r proto state recv send local_ep remote_ep rest; do
    [ "$state" = ESTAB ] || continue
    case "$remote_ep" in 127.*:*|\[::1\]:*|::1:*|"*:*"|"") continue ;; esac
    port="${local_ep##*:}"
    [ -z "${listeners[$proto|$port]:-}" ] || continue
    svc=$(printf '%s' "$rest" | sed -nE 's/.*users:\(\("([^"]+)".*/\1/p')
    pid=$(printf '%s' "$rest" | sed -nE 's/.*pid=([0-9]+).*/\1/p')
    svc="${svc:--}"; pid="${pid:--}"
    [ -z "${seen[$proto|$remote_ep|$pid]:-}" ] || continue
    seen["$proto|$remote_ep|$pid"]=1
    path=-
    case "$pid" in *[!0-9]*|'') ;; *) path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo -) ;; esac
    printf '%s|%s|%s|%s|%s|%s\n' "$proto" "$local_ep" "$remote_ep" "$svc" "$pid" "$path"
  done < <(ss -H -tunp 2>/dev/null || true)
}
