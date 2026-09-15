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
    declare -F scan_text_content >/dev/null && hits=$(scan_text_content "$value" 2>/dev/null || true)
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

# legacy python file lookup
python_payload_from_args() {
  local result interpreter kind payload _hits
  interpreter=$(basename "$1")
  [[ "$interpreter" =~ ^(python|pypy)([0-9]+(\.[0-9]+)*)?$ ]] || return 1
  result=$(resolve_interpreted_payload "$@") || return 1
  IFS='|' read -r _ kind payload _hits <<< "$result"
  [ "$kind" = file ] && [ -f "$payload" ] && printf '%s' "$payload"
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

if ! declare -p PROTECTED_NAMES &>/dev/null; then
    readonly -a PROTECTED_NAMES=(
        "systemd" "init" "kthreadd" "systemd-journal" "dbus-daemon" "polkitd"
        "sddm" "gdm" "lightdm" "xdg-desktop-por" "gnome-shell" "kwin" "kwin_wayland"
        "bash" "zsh" "sh" "fish" "ash" "dash"
        "tmux" "screen"
        "konsole" "alacritty" "gnome-terminal" "kitty" "xfce4-terminal" "wezterm" "xterm"
        "sudo" "pkexec" "doas"
    )
fi

is_protected() {
  local n="$1" p
  for p in "${PROTECTED_NAMES[@]}"; do
    [ "$n" = "$p" ] && return 0
  done
  return 1
}

build_process_group() {
  local t="$1" max_up=15 max_down=150 current root ppid pname
  current="$t"; root="$current"; local depth=0
  while [ "$depth" -lt "$max_up" ]; do
    ppid=$(ps -o ppid= -p "$current" 2>/dev/null | tr -d ' ' || true)
    if [ -z "$ppid" ] || [ "$ppid" = "1" ] || [ "$ppid" = "2" ] || [ "$ppid" = "0" ]; then
      break
    fi
    pname=$(get_process_name "$ppid")
    is_protected "$pname" && break
    root="$ppid"; current="$ppid"; depth=$((depth + 1))
  done
  [ -d "/proc/$t" ] || die "no pid $t"

  local -a all=()
  declare -A seen=()
  local child cname p
  local -a stack=("$root")
  while [ ${#stack[@]} -gt 0 ]; do
    p="${stack[0]}"; stack=("${stack[@]:1}")
    [ ${#all[@]} -ge "$max_down" ] && break
    [ -n "${seen[$p]:-}" ] && continue
    seen[$p]=1; all+=("$p")
    for child in $(ps -eo pid,ppid | awk -v x="$p" '$2 == x {print $1}' || true); do
      cname=$(get_process_name "$child")
      is_protected "$cname" || stack+=("$child")
    done
  done

  local -a f=()
  for p in "${all[@]}"; do
    [ "$p" = "1" ] || [ "$p" = "2" ] || [ "$p" = "0" ] && continue
    pname=$(get_process_name "$p")
    [ "$pname" = "systemd" ] || [ "$pname" = "init" ] || f+=("$p")
  done

  local -a u
  mapfile -t u < <(printf '%s\n' "${f[@]}" | sort -nu)
  printf '%s' "$root"
  for p in "${u[@]}"; do
    [ "$p" = "$root" ] || printf ' %s' "$p"
  done
  printf '\n'
}

print_tree() {
  local t="$1" r="$2"; shift 2
  declare -A m=()
  local g rp
  for g in "$@"; do m[$g]=1; done
  rp=$(ps -o ppid= -p "$r" 2>/dev/null | tr -d ' ' || true)
  [ -n "$rp" ] && [ "$rp" != 1 ] && [ "$rp" != 2 ] && rp=""

  walk() {
    local n="$1" i="$2" name c tag=""
    name=$(get_process_name "$n")
    [ "$n" = "$t" ] && tag=" [target]"
    printf '%s%s (%s)%s\n' "$i" "$name" "$n" "$tag"
    for c in $(ps -eo pid,ppid | awk -v x="$n" '$2 == x {print $1}' || true); do
      [ -n "${m[$c]:-}" ] && walk "$c" "$i  "
    done
  }

  if [ -n "$rp" ]; then
    printf '%s (%s) [system process]\n' "$(get_process_name "$rp")" "$rp"
    walk "$r" "  "
  else
    walk "$r" ""
  fi
}
