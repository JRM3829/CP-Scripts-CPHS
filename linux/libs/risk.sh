#!/usr/bin/env bash

source "${WYN_HOME}/conf/wyn.conf"
source "${WYN_HOME}/libs/core.sh"
source "${WYN_HOME}/libs/tree.sh"

# preserve partial prompts
_read_socket() {
  local h="$1" p="$2" total="$3" wait="$4" send="${5:-}"
  timeout "$total" bash -c "
    exec 3<>/dev/tcp/${h}/${p} 2>/dev/null || exit 0
    { ${send}; } >&3 2>/dev/null || true
    timeout ${wait} cat <&3 2>/dev/null || true
  " 2>/dev/null || true
}

grab_service_banner() {
  local p="$1" h="${2:-127.0.0.1}" raw b
  raw=$(_read_socket "$h" "$p" "${BANNER_TIMEOUT:-3}" "${BANNER_READ_TIMEOUT:-1}" "printf '\r\n'")
  b=$(printf '%s' "$raw" | head -c 300 | tr -d '\r' | tr '\n' ' ' \
        | tr -cd '[:print:]' | sed 's/[[:space:]]\{1,\}/ /g; s/^ //; s/ $//')
  [ -n "$b" ] && printf '%s' "$b" || printf 'silent'
}

# strongest match wins
check_banner_risk() {
  local b="$1" sig score name pat hi=0 hit=""
  [ -n "$b" ] && [ "$b" != "silent" ] || return 1
  for sig in "${SUSPICIOUS_BANNER_SIGNATURES[@]:-}"; do
    score="${sig%%:*}"; sig="${sig#*:}"
    name="${sig%%:*}"; pat="${sig#*:}"
    [ -n "$pat" ] || continue
    if printf '%s' "$b" | grep -iqE "$pat" 2>/dev/null; then
      [ "$score" -gt "$hi" ] && { hi="$score"; hit="$name"; }
    fi
  done
  [ "$hi" -gt 0 ] || return 1
  printf '%s|%s' "$hi" "$hit"
}

# distinguish execution from echo
probe_port() {
  local p="$1" h="${2:-127.0.0.1}" a b expect out
  a=$(( (RANDOM % 400) + 100 ))
  b=$(( (RANDOM % 400) + 100 ))
  expect="WYN$((a * b))"
  out=$(_read_socket "$h" "$p" "${PROBE_TIMEOUT:-6}" "${PROBE_READ_TIMEOUT:-2}" \
        "printf '\r\n'; sleep 0.3; printf 'id\n'; sleep 0.3; printf 'echo WYN\$((${a}*${b}))\n'; sleep 0.3")
  printf '%s' "$out" \
    | sed "s/${expect}/<EXEC_PROOF>/g" \
    | tr -cd '[:print:]\n' | sed '/^[[:space:]]*$/d' || true
}

classify_probe() {
  local x="$1" first id_line last v=""
  [ -n "$x" ] || { echo "silent"; return 0; }

  case "$x" in
    *"<EXEC_PROOF>"*) echo "REVERSE/BIND SHELL - executed our command"; return 0 ;;
  esac
  id_line=$(printf '%s' "$x" | grep -iE "uid=[0-9]+\(.*gid=[0-9]+\(" | head -1)
  [ -n "$id_line" ] && { echo "REVERSE/BIND SHELL - ran id (${id_line})"; return 0; }

  case "$x" in
    *'WYN$(('*) echo "echo/reflector service - mirrors input, did not execute"; return 0 ;;
  esac

  first=$(printf '%s' "$x" | head -1)
  case "$first" in
    HTTP/*) v="HTTP service: ${first}" ;;
    SSH-*) v="SSH server: ${first}" ;;
    220*) v="FTP/SMTP greeting: ${first}" ;;
    221*) v="SMTP goodbye: ${first}" ;;
    PONG*) v="Redis server: ${first}" ;;
    *"BEGIN CERTIFICATE"*) v="TLS service (handshake)" ;;
  esac
  [ -n "$v" ] && { printf '%s\n' "$v"; return 0; }

  last=$(printf '%s' "$x" | tail -1)
  if printf '%s' "$last" | grep -qE '^[^[:space:]]{0,64}[#$%>][[:space:]]*$'; then
    echo "SHELL PROMPT - interactive prompt (${last})"
    return 0
  fi
  echo "unrecognized: ${first}"
}

file_is_packaged() { [ -n "$(pkg_owner "$1" 2>/dev/null)" ]; }

exe_in_writable_dir() { in_list "$1" "${WRITABLE_EXEC_DIRS[@]:-}"; }

exe_hidden_path() { case "$1" in */.*) return 0 ;; *) return 1 ;; esac; }

# comm truncates after 15
exe_name_mismatch() {
  local comm="$1" bin="$2" base
  [ -n "$comm" ] && [ -n "$bin" ] && [ "$bin" != unknown ] || return 1
  base=$(basename "$bin")
  [ "$base" = "$comm" ] && return 1
  case "$comm:$base" in sh:dash|sh:bash|python3:python3.*|python:python*) return 1 ;; esac
  [ "${base:0:15}" = "$comm" ] && return 1
  return 0
}

pkg_file_tampered() {
  local f="$1" pkg
  pkg=$(pkg_owner "$f" 2>/dev/null) || return 1
  [ -n "$pkg" ] || return 1
  if command -v dpkg >/dev/null 2>&1; then
    dpkg --verify "$pkg" 2>/dev/null | awk '$1 ~ /^..5/ {print $NF}' | grep -qxF "$f"
  elif command -v rpm >/dev/null 2>&1; then
    rpm -V "$pkg" 2>/dev/null | awk '$1 ~ /^..5/ {print $NF}' | grep -qxF "$f"
  else
    return 1
  fi
}

scan_file_content() {
  local f="$1" sz re hits
  [ -f "$f" ] && [ -r "$f" ] || return 1
  sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
  [ "$sz" -gt 0 ] && [ "$sz" -le "${MAX_SCAN_BYTES:-20971520}" ] || return 1
  re=$(IFS='|'; printf '%s' "${MALWARE_CONTENT_SIGNATURES[*]:-}")
  [ -n "$re" ] || return 1
  hits=$(LC_ALL=C grep -aoEm 20 "$re" "$f" 2>/dev/null | sort -u | head -4 | paste -sd, -)
  [ -n "$hits" ] || return 1
  printf '%s' "$hits"
}

scan_text_content() {
  local re hits
  re=$(IFS='|'; printf '%s' "${MALWARE_CONTENT_SIGNATURES[*]:-}")
  [ -n "$re" ] || return 1
  hits=$(LC_ALL=C grep -aoEm 20 "$re" <<< "$1" 2>/dev/null | sort -u | head -4 | paste -sd, -)
  [ -n "$hits" ] || return 1
  printf '%s' "$hits"
}

persistence_refs() {
  local needle="$1"
  [ -n "$needle" ] && [ "$needle" != unknown ] || return 1
  local hits
  hits=$(grep -rlsF -- "$needle" "${PERSISTENCE_PATHS[@]}" /home/*/.config/autostart \
           /home/*/.bashrc /home/*/.profile /root/.bashrc /var/spool/cron/crontabs \
           2>/dev/null | head -3 | paste -sd, -)
  [ -n "$hits" ] || return 1
  printf '%s' "$hits"
}

risk_signals() {
  local pid="$1" mode="$2" net_info="${3:-}" user pcomm tty pname bin link lp ep sw payload
  local packaged=false perms caps hits refs
  user=$(ps_field "$pid" user)
  pcomm=$(ps_field "$pid" comm)
  tty=$(ps_field "$pid" tty)
  bin=$(get_process_bin "$pid")
  link=$(get_process_exe_link "$pid")

  if { [ -z "$tty" ] || [ "$tty" = "?" ]; } && [ -n "$net_info" ]; then
    echo "20|STEALTH_NETWORK|${tty}"
  fi
  [ "$user" = root ] && echo "10|ROOT|${user}"
  case "$pcomm" in bash|zsh|sh) echo "15|SHELL_PARENT|${pcomm}" ;; esac

  case "$link" in
    *memfd:*) echo "85|MEMFD_EXEC|$link" ;;
    *" (deleted)") echo "60|DELETED_BIN|$link" ;;
  esac
  if [ "$bin" = unknown ]; then
    if can_inspect_procs && ! is_kernel_thread "$pid"; then
      echo "30|UNKNOWN_BIN|exe unresolvable"
    fi
  else
    exe_in_writable_dir "$bin" && echo "60|TEMP_EXEC|$bin"
    exe_hidden_path "$bin" && echo "45|HIDDEN_PATH|$bin"
    exe_name_mismatch "$pcomm" "$bin" && echo "50|MASQUERADE|${pcomm} != $(basename "$bin")"
  fi

  [ "$mode" = aggregate ] || return 0

  pname=$(get_process_name "$pid")
  for sw in "${SOFTWARE_BLACKLIST[@]:-}"; do
    case "$pname $bin" in *"$sw"*) echo "60|BLACKLISTED_SOFTWARE|$pname"; break ;; esac
  done
  lp=$(get_process_env_var "$pid" LD_PRELOAD)
  [ -n "$lp" ] && echo "70|LD_PRELOAD|$lp"
  if [ "$user" = root ]; then
    ep=$(get_process_env_var "$pid" PATH)
    case "$ep" in
      *"/home/"*|*"/tmp"*|*"/var/tmp"*) echo "40|PATH_HIJACK|$ep" ;;
    esac
  fi

  [ -f "$bin" ] || return 0
  if ! has_pkg_db; then
    packaged=true   # unknown provenance isn't suspicious
  elif file_is_packaged "$bin"; then
    packaged=true
    pkg_file_tampered "$bin" && echo "80|PKG_TAMPER|$bin"
  else
    echo "35|UNPACKAGED|$bin"
  fi

  if [ "$packaged" = false ] && { [ -u "$bin" ] || [ -g "$bin" ]; }; then
    perms=$(stat -c %a "$bin" 2>/dev/null || echo "?")
    echo "55|SETUID_BIN|mode $perms"
  fi
  if command -v getcap >/dev/null 2>&1 && [ "$packaged" = false ]; then
    caps=$(getcap "$bin" 2>/dev/null)
    [ -n "$caps" ] && echo "45|FILE_CAPS|$caps"
  fi

  if [ "$packaged" = false ]; then
    hits=$(scan_file_content "$bin") && echo "65|CONTENT_MATCH|$hits"
  fi
  payload=$(get_process_payload "$pid" 2>/dev/null || true)
  if [ -n "$payload" ] && refs=$(persistence_refs "$payload"); then
    echo "50|PERSISTENCE|$refs"
  elif [ "$packaged" = false ]; then
    refs=$(persistence_refs "$bin") && echo "50|PERSISTENCE|$refs"
  fi
}

is_trusted_name() {
  local pname="$1" bin="$2"
  in_list "$pname" "${WHITELIST[@]:-}" 2>/dev/null || return 1
  [ -f "$bin" ] || return 1
  exe_in_writable_dir "$bin" && return 1
  exe_name_mismatch "$pname" "$bin" && return 1
  has_pkg_db || return 0
  file_is_packaged "$bin"
}

FLAG_HELP="
BLACKLISTED_SOFTWARE|attack tool running
MEMFD_EXEC|fileless exec, binary exists only in memory
PKG_TAMPER|package file modified since install (trojanized)
LD_PRELOAD|library injection set (possible rootkit)
CONTENT_MATCH|malware indicators inside the binary
DELETED_BIN|binary deleted after launch
TEMP_EXEC|runs from a user-writable dir
HIDDEN_PATH|binary in a dotted/hidden dir
MASQUERADE|process name does not match its binary
UNPACKAGED|no package owns this binary
PERSISTENCE|wired to restart via cron/systemd/profile
SETUID_BIN|setuid/setgid and unpackaged
FILE_CAPS|file capabilities on unpackaged binary
PATH_HIJACK|root PATH includes writable dir
STEALTH_NETWORK|networked with no controlling terminal
SHELL_ON_SOCKET|a listening socket ran our command (backdoor)
BANNER_RISK|shell-like banner on a listening socket
UNKNOWN_BIN|binary path unresolvable
SHELL_PARENT|launched from an interactive shell
ROOT|running as root
"

flag_help() {
  local h
  h=$(printf '%s' "$FLAG_HELP" | grep -m1 "^$1|" | cut -d'|' -f2)
  printf '%s' "${h:-$1}"
}

# combine weak signals
malware_verdict() {
  local score="$1" flags="$2" f
  for f in MEMFD_EXEC PKG_TAMPER LD_PRELOAD CONTENT_MATCH BLACKLISTED_SOFTWARE SHELL_ON_SOCKET; do
    case "$flags" in *"$f"*) echo "MALWARE"; return 0 ;; esac
  done
  case "$flags" in
    *TEMP_EXEC*|*HIDDEN_PATH*|*DELETED_BIN*)
      case "$flags" in
        *MASQUERADE*|*PERSISTENCE*|*STEALTH_NETWORK*|*SETUID_BIN*|*FILE_CAPS*|*BLACKLIST_PORT*)
          echo "MALWARE"; return 0 ;;
      esac ;;
  esac
  if [ "$score" -ge 70 ]; then echo "LIKELY MALWARE"
  elif [ "$score" -ge "${HIGH_RISK_THRESHOLD:-50}" ]; then echo "SUSPICIOUS"
  elif [ "$score" -ge 30 ]; then echo "UNUSUAL"
  else echo "CLEAN"
  fi
}

risk_engine() {
  local pid="$1" mode="${2:-process}" net_info="${3:-}" score=0 w f d
  local -a flags=()
  while IFS='|' read -r w f d; do
    [ -n "$f" ] || continue
    score=$((score + w))
    if [ "$f" = BLACKLIST_PORT ]; then
      flags+=("[${f}(${d})]")
    else
      flags+=("[${f}]")
    fi
  done < <(risk_signals "$pid" "$mode" "$net_info")
  printf '%s|%s\n' "$score" "${flags[*]}"
}
