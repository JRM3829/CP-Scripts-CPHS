#!/usr/bin/env bash

source "${WYN_HOME}/conf/wyn.conf"
source "${WYN_HOME}/libs/core.sh"

get_process_name() {
  local n
  n=$(ps_field "$1" comm)
  printf '%s' "${n:-unknown}"
}

# never prompt for sudo
get_process_bin() {
  local b
  b=$(readlink -f "/proc/$1/exe" 2>/dev/null) && [ -n "$b" ] && { printf '%s' "$b"; return 0; }
  b=$(sudo -n readlink -f "/proc/$1/exe" 2>/dev/null) && [ -n "$b" ] && { printf '%s' "$b"; return 0; }
  printf '%s' unknown
}

# retain deleted suffix
get_process_exe_link() {
  local b
  b=$(readlink "/proc/$1/exe" 2>/dev/null) && [ -n "$b" ] && { printf '%s' "$b"; return 0; }
  b=$(sudo -n readlink "/proc/$1/exe" 2>/dev/null) && [ -n "$b" ] && { printf '%s' "$b"; return 0; }
  printf '%s' unknown
}

can_inspect_procs() { [ "$(id -u)" = 0 ] || sudo -n true 2>/dev/null; }

is_kernel_thread() { [ ! -s "/proc/$1/cmdline" ]; }

get_process_cmdline() {
  [ -r "/proc/$1/cmdline" ] || return 1
  tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null || true
}

get_process_cwd() {
  readlink -f "/proc/$1/cwd" 2>/dev/null \
    || sudo -n readlink -f "/proc/$1/cwd" 2>/dev/null
}

get_process_argv() {
  [ -r "/proc/$1/cmdline" ] && { cat "/proc/$1/cmdline"; return; }
  sudo -n cat "/proc/$1/cmdline" 2>/dev/null
}

payload_result() {
  local interpreter="$1" kind="$2" value="$3" hits=""
  if [ "$kind" = inline ]; then
    # risk.sh may not be sourced
    declare -F scan_text_content >/dev/null && hits=$(scan_text_content "$value" || true)
    value="<inline:${4}:$(printf '%s' "$value" | sha256sum | cut -c1-12)>"
  fi
  printf '%s|%s|%s|%s\n' "$interpreter" "$kind" "$value" "${hits//|//}"
}

script_path() {
  local cwd="$1" arg="$2" path
  case "$arg" in /*) path="$arg" ;; *) path="$cwd/$arg" ;; esac
  path=$(readlink -m -- "$path" 2>/dev/null) || return 1
  [ -f "$path" ] && { printf '%s' "$path"; return; }
  case "${path,,}" in *.sh|*.bash|*.zsh|*.ksh|*.py|*.pyw|*.pl|*.php|*.rb|*.js|*.mjs|*.cjs|*.lua|*.tcl) printf '%s' "$path" ;; *) return 1 ;; esac
}

# interpreter|kind|payload|matches
resolve_interpreted_payload() {
  local exe="$1" cwd="$2" interpreter type=other arg path
  shift 2
  interpreter=$(basename "$exe"); interpreter="${interpreter,,}"
  if [[ "$interpreter" =~ ^(python|pypy)([0-9]+(\.[0-9]+)*)?$ ]]; then type=python
  elif [[ "$interpreter" =~ ^perl([0-9]+(\.[0-9]+)*)?$ ]]; then type=perl
  elif [[ "$interpreter" =~ ^php([0-9]+(\.[0-9]+)*)?$ ]]; then type=php
  elif [[ "$interpreter" =~ ^ruby([0-9]+(\.[0-9]+)*)?$ ]]; then type=ruby
  elif [[ "$interpreter" =~ ^node(js)?([0-9]+(\.[0-9]+)*)?$ ]]; then type=node
  elif [[ "$interpreter" =~ ^lua([0-9]+(\.[0-9]+)*)?$ ]]; then type=lua
  elif [[ "$interpreter" =~ ^(tclsh|wish)([0-9]+(\.[0-9]+)*)?$ ]]; then type=tcl
  else case "$interpreter" in sh|bash|dash|zsh|ksh|ash|fish) type=shell ;; esac
  fi

  while [ $# -gt 0 ]; do
    arg="$1"; shift
    case "$type" in
      python)
        case "$arg" in
          -c) [ $# -gt 0 ] && payload_result "$interpreter" inline "$1" -c; return ;;
          -c?*) payload_result "$interpreter" inline "${arg#-c}" -c; return ;;
          -m|-m?*|-) return 1 ;;
          -W|-X|--check-hash-based-pycs) [ $# -gt 0 ] && shift; continue ;;
        esac ;;
      shell)
        case "$arg" in
          -c) [ $# -gt 0 ] && payload_result "$interpreter" inline "$1" -c; return ;;
          -c?*) payload_result "$interpreter" inline "${arg#-c}" -c; return ;;
          -O|+O|--rcfile|--init-file) [ $# -gt 0 ] && shift; continue ;;
        esac ;;
      perl)
        case "$arg" in
          -e) [ $# -gt 0 ] && payload_result "$interpreter" inline "$1" -e; return ;;
          -e?*) payload_result "$interpreter" inline "${arg#-e}" -e; return ;;
          -I|-M|-m) [ $# -gt 0 ] && shift; continue ;;
        esac ;;
      php)
        case "$arg" in
          -r) [ $# -gt 0 ] && payload_result "$interpreter" inline "$1" -r; return ;;
          -r?*) payload_result "$interpreter" inline "${arg#-r}" -r; return ;;
          -f) [ $# -gt 0 ] && { path=$(script_path "$cwd" "$1") || return 1; payload_result "$interpreter" file "$path"; }; return ;;
          -d|-c) [ $# -gt 0 ] && shift; continue ;;
        esac ;;
      ruby|node|lua)
        case "$arg" in
          -e|--eval) [ $# -gt 0 ] && payload_result "$interpreter" inline "$1" "$arg"; return ;;
          -e?*) payload_result "$interpreter" inline "${arg#-e}" -e; return ;;
          --eval=*) payload_result "$interpreter" inline "${arg#*=}" --eval; return ;;
          -r|--require|-l) [ $# -gt 0 ] && shift; continue ;;
          -p|--print)
            if [ "$type" = node ]; then [ $# -gt 0 ] && payload_result "$interpreter" inline "$1" "$arg"; return; fi
            continue ;;
        esac ;;
      tcl) case "$arg" in -encoding) [ $# -gt 0 ] && shift; continue ;; esac ;;
    esac
    case "$arg" in --) continue ;; -*) continue ;; esac

    path=$(script_path "$cwd" "$arg" 2>/dev/null || true)
    if [ -n "$path" ]; then
      if [ "$type" != other ] \
          || { [ -f "$path" ] && head -c 2 "$path" 2>/dev/null | grep -qx '#!'; }; then
        payload_result "$interpreter" file "$path"
        return
      fi
    fi
  done
  return 1
}

get_process_payload() {
  local pid="$1" exe cwd _ kind payload _hits
  local -a argv=()
  exe=$(get_process_bin "$pid")
  cwd=$(get_process_cwd "$pid") || return 1
  mapfile -d '' -t argv < <(get_process_argv "$pid")
  [ ${#argv[@]} -gt 1 ] || return 1
  IFS='|' read -r _ kind payload _hits < <(resolve_interpreted_payload "$exe" "$cwd" "${argv[@]:1}")
  [ "$kind" = file ] && printf '%s' "$payload"
}

get_process_env_var() {
  [ -d "/proc/$1" ] || return 0
  sudo -n cat "/proc/$1/environ" 2>/dev/null | tr '\0' '\n' | grep -m1 "^$2=" | cut -d= -f2- || true
}

is_self_or_ancestor() {
  local p="$1" c=$$
  while :; do
    [ "$c" = "$p" ] && return 0
    [ "$c" -le 1 ] && return 1
    c=$(awk '{print $4}' "/proc/$c/stat" 2>/dev/null || echo 1)
  done
}

# group walks stop at these so a target never drags in the session or init
PROTECTED_NAMES=(
  systemd init kthreadd systemd-journal dbus-daemon polkitd
  sddm gdm lightdm xdg-desktop-por gnome-shell kwin kwin_wayland
  bash zsh sh fish ash dash
  tmux screen
  konsole alacritty gnome-terminal kitty xfce4-terminal wezterm xterm
  sudo pkexec doas
)

# prints root first, then the rest of the group
build_process_group() {
  local t="$1" root="$1" ppid depth=0 p child
  while [ "$depth" -lt 15 ]; do
    ppid=$(ps_field "$root" ppid)
    case "$ppid" in ''|0|1|2) break ;; esac
    in_list "$(get_process_name "$ppid")" "${PROTECTED_NAMES[@]}" && break
    root="$ppid"; depth=$((depth + 1))
  done
  [ -d "/proc/$t" ] || die "no pid $t"

  local -a all=() stack=("$root")
  declare -A seen=()
  while [ ${#stack[@]} -gt 0 ] && [ ${#all[@]} -lt 150 ]; do
    p="${stack[0]}"; stack=("${stack[@]:1}")
    [ -n "${seen[$p]:-}" ] && continue
    seen[$p]=1; all+=("$p")
    for child in $(ps -eo pid,ppid | awk -v x="$p" '$2 == x {print $1}'); do
      in_list "$(get_process_name "$child")" "${PROTECTED_NAMES[@]}" || stack+=("$child")
    done
  done

  printf '%s' "$root"
  for p in $(printf '%s\n' "${all[@]}" | sort -nu); do
    case "$p" in 0|1|2|"$root") continue ;; esac
    case "$(get_process_name "$p")" in systemd|init) continue ;; esac
    printf ' %s' "$p"
  done
  printf '\n'
}
