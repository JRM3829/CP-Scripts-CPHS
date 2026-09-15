#!/usr/bin/env bash

source "${WYN_HOME}/conf/wyn.conf"
source "${WYN_HOME}/libs/core.sh"
source "${WYN_HOME}/libs/readme.sh"
source "${WYN_HOME}/libs/risk.sh"

finding() { printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4"; }

whitelisted_path() {
  local f="$1" p
  case "$f" in "$WYN_HOME"|"$WYN_HOME"/*|"${WYN_HOME}.zip") return 0 ;; esac
  for p in "${CLEANUP_WHITELIST[@]:-}"; do
    [ -n "$p" ] && case "$f" in $p) return 0 ;; esac
  done
  return 1
}

suspicious_cmd() {
  printf '%s' "$1" | grep -qE '/\.|/tmp/|/var/tmp/|/dev/shm|/dev/tcp|(^|[^a-z])nc([^a-z]|$)|ncat|base64|wget[[:space:]]|curl[[:space:]]|python[0-9]*[[:space:]]+-c|perl[[:space:]]+-e|chmod[[:space:]]+[0-7]*777|>[[:space:]]*/dev/null[[:space:]]*2>&1[[:space:]]*&'
}

benign_cron() {
  local n b
  n=$(basename "$1")
  for b in "${CRON_BENIGN[@]:-}"; do
    [ "$n" = "$b" ] && return 0
  done
  return 1
}

cron_shared_file() {
  local f="$1" p
  for p in "${CRON_SHARED_FILES[@]:-}"; do
    [ -n "$p" ] && case "$f" in $p) return 0 ;; esac
  done
  return 1
}

persistence_file_is_shared() {
  cron_shared_file "$1" && return 0
  case "$1" in
    /etc/profile|/etc/bash.bashrc|/etc/rc.local|/etc/ld.so.preload|/root/.bashrc|/root/.profile|/home/*/.bashrc|/home/*/.profile) return 0 ;;
  esac
  return 1
}

scan_cron() {
  local f line owner perms act
  local -a paths=("$@")
  [ ${#paths[@]} -gt 0 ] || paths=("${CRON_PATHS[@]}")
  while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$f" ] || continue
    benign_cron "$f" && continue

    owner=$(stat -c %U "$f" 2>/dev/null || echo "?")
    perms=$(stat -c %a "$f" 2>/dev/null || echo "?")
    case "$f" in
      */spool/cron/*) ;;   # non-root ownership expected
      *) [ "$owner" != root ] && [ "$owner" != "?" ] \
           && finding cron "$f" "owned by ${owner}, not root" none ;;
    esac
    case "$perms" in
      *[2367]) finding cron "$f" "world-writable (${perms})" none ;;
    esac

    cron_shared_file "$f" && act=rmline || act=rm
    while IFS= read -r line; do
      case "$line" in ''|\#*|[A-Z]*=*) continue ;; esac
      suspicious_cmd "$line" && finding cron "$f" "$line" "$act"
    done < "$f"
  done < <(find "${paths[@]}" -type f 2>/dev/null)
}

scan_autostart() {
  local f exe
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    exe=$(grep -m1 -i '^[[:space:]]*Exec=' "$f" 2>/dev/null | sed -E 's/^[[:space:]]*Exec=[[:space:]]*//' || true)
    case "$f" in
      /root/.config/autostart/*) finding autostart "$f" "root autostart${exe:+: $exe}" rm ;;
      *) [ -n "$exe" ] && suspicious_cmd "$exe" && finding autostart "$f" "runs: $exe" rm ;;
    esac
  done < <(find /root/.config/autostart /home/*/.config/autostart -maxdepth 1 -name '*.desktop' -type f 2>/dev/null)
}

scan_media() {
  local f e
  [ "${#ARTIFACT_EXTS[@]}" -gt 0 ] || return 0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    whitelisted_path "$f" && continue
    for e in "${ARTIFACT_EXTS[@]}"; do
      [ -n "$e" ] || continue
      case "${f,,}" in
        *".${e,,}") finding media "$f" "prohibited file (.${e,,})" rm; break ;;
      esac
    done
  done < <(find /home /root -xdev -type f -not -path '*/.*' 2>/dev/null)
}

scan_software() {
  local sw crit="${CRITICAL_SERVICES:-}"
  for sw in "${SOFTWARE_BLACKLIST[@]:-}"; do
    [ -n "$sw" ] || continue
    printf '%s' "$crit" | grep -qiw "$sw" && continue
    readme_authorizes "$sw" && continue
    if command -v "$sw" >/dev/null 2>&1 || pkg_installed "$sw"; then
      finding software "$sw" "hacking tool installed" purge
    fi
  done
}

scan_network() {
  local proto port addr svc pid path crit allowed rule p action detail
  while IFS='|' read -r proto port addr svc pid path; do
    case "$addr" in 127.*|"[::1]":*|::1:*) continue ;; esac
    allowed=false
    for crit in ${CRITICAL_SERVICES:-}; do
      for rule in $(resolve_service_rules "$crit"); do
        p="${rule%/*}"
        [ "$p" = "$port" ] && [ "${rule#*/}" = "$proto" ] && service_matches "$svc" "$crit" && allowed=true
      done
    done
    [ "$allowed" = true ] && continue
    readme_authorizes "$svc" && continue
    action=none
    case "$pid" in *[!0-9]*|'') ;; *) action=process ;; esac
    detail="$proto $addr ($svc"
    [ "$path" = - ] || detail+=", $path"
    finding network "$pid" "$detail)" "$action"
  done < <(list_listeners)
}

scan_outgoing() {
  local proto local_ep remote_ep svc pid bin payload score flags why detail
  while IFS='|' read -r proto local_ep remote_ep svc pid bin; do
    case "$pid" in *[!0-9]*|'') continue ;; esac
    ! is_self_or_ancestor "$pid" && ! is_kernel_thread "$pid" || continue
    [ "$bin" != - ] || bin=$(get_process_bin "$pid")
    is_trusted_name "$svc" "$bin" && continue

    why=""
    case "$svc" in
      sh|bash|dash|zsh|ksh|fish|nc|ncat|netcat|socat) why="shell-like process" ;;
      python*|pypy*|perl|ruby|php*|node) why="interpreter connected externally" ;;
    esac
    payload=$(get_process_payload "$pid" 2>/dev/null || true)
    if [ -z "$why" ] && [ -n "$payload" ] && [ -z "$(pkg_owner "$payload")" ]; then
      why="unpackaged payload $payload"
    fi
    IFS='|' read -r score flags < <(risk_engine "$pid" aggregate connected)
    [ -n "$why" ] || [ "$score" -ge "$HIGH_RISK_THRESHOLD" ] || continue

    detail="$proto $local_ep -> $remote_ep ($svc"
    [ "$bin" = - ] || detail+=", $bin"
    detail+=")${why:+; $why}${flags:+; risk $score $flags}"
    finding outgoing "$pid" "$detail" none
  done < <(list_outgoing_connections)
}

scan_processes() {
  local user pid name args bin net risk flags
  while read -r user pid name args; do
    [ -n "$pid" ] && ! is_self_or_ancestor "$pid" && ! is_kernel_thread "$pid" || continue
    case "$args" in *"$WYN_HOME"*|*"./wyn"*) continue ;; esac
    readme_authorizes "$name" && continue
    bin=$(get_process_bin "$pid")
    is_trusted_name "$name" "$bin" && continue
    net=$(lsof -a -p "$pid" -i -P -n 2>/dev/null || true)
    IFS='|' read -r risk flags < <(risk_engine "$pid" aggregate "$net")
    [ "$risk" -ge "$HIGH_RISK_THRESHOLD" ] || continue
    finding process "$pid" "$name as $user: risk $risk $flags" process
  done < <(ps -eo user=,pid=,comm=,args=)
}

suspicious_payload_ancestry() {
  local pid="$1" p name bin depth=0
  p=$(ps_field "$pid" ppid)
  while [ -n "$p" ] && [ "$p" -gt 1 ] 2>/dev/null && [ "$depth" -lt 4 ]; do
    name=$(ps_field "$p" comm)
    case "$name" in nc|ncat|netcat|socat) printf '%s' "$name"; return 0 ;; esac
    bin=$(get_process_bin "$p")
    if [ "$bin" != unknown ] && { exe_in_writable_dir "$bin" || exe_hidden_path "$bin"; }; then
      printf '%s' "$name"
      return 0
    fi
    p=$(ps_field "$p" ppid); depth=$((depth + 1))
  done
  return 1
}

scan_payloads() {
  local pid exe cwd interpreter kind payload hits user owner package refs tty ancestor score detail mode
  local -a argv=() why=()
  declare -A connected=()
  while IFS='|' read -r _ _ _ _ pid _; do case "$pid" in ''|*[!0-9]*) ;; *) connected[$pid]=1 ;; esac; done < <(list_outgoing_connections)

  while read -r pid; do
    [ -n "$pid" ] && ! is_self_or_ancestor "$pid" && ! is_kernel_thread "$pid" || continue
    exe=$(get_process_bin "$pid"); cwd=$(get_process_cwd "$pid" 2>/dev/null || true)
    [ -n "$cwd" ] || continue
    argv=(); mapfile -d '' -t argv < <(get_process_argv "$pid")
    [ ${#argv[@]} -gt 1 ] || continue
    IFS='|' read -r interpreter kind payload hits < <(resolve_interpreted_payload "$exe" "$cwd" "${argv[@]:1}" 2>/dev/null || true)
    [ -n "$payload" ] || continue

    score=0; why=(); user=$(ps_field "$pid" user); tty=$(ps_field "$pid" tty)
    if [ -n "$hits" ]; then why+=("malicious content: $hits"); score=$((score + 80)); fi
    if [ "$kind" = file ]; then
      if [ -f "$payload" ]; then
        owner=$(stat -c %U "$payload" 2>/dev/null || echo unknown)
        package=$(pkg_owner "$payload" 2>/dev/null || true)
        if [ -n "$package" ]; then
          package="packaged:$package"
        elif has_pkg_db; then
          package=unpackaged; why+=(unpackaged); score=$((score + 25))
        else
          package=unknown
        fi
        hits=$(scan_file_content "$payload" 2>/dev/null || true)
        if [ -n "$hits" ]; then why+=("malicious content: ${hits//|//}"); score=$((score + 80)); fi
        exe_hidden_path "$payload" && { why+=("hidden path"); score=$((score + 35)); }
        exe_in_writable_dir "$payload" && { why+=("writable/temporary location"); score=$((score + 35)); }
        mode=$(stat -c %a "$payload" 2>/dev/null || true)
        case "$mode" in *[2367]) why+=("world-writable mode $mode"); score=$((score + 35)) ;; esac
        [ "$user" = root ] && [ "$owner" != root ] && [ "$owner" != unknown ] && { why+=("root runs $owner-owned script"); score=$((score + 35)); }
        refs=$(persistence_refs "$payload" 2>/dev/null || true)
        [ -n "$refs" ] && { why+=("persistence: $refs"); score=$((score + 60)); }
      else
        owner=missing; package=missing; why+=("missing payload file"); score=$((score + 45))
      fi
    else
      owner=n/a; package=n/a
    fi
    [ -n "${connected[$pid]:-}" ] && { why+=("outgoing traffic"); score=$((score + 40)); }
    if [ -z "$tty" ] || [ "$tty" = "?" ]; then why+=("background execution"); score=$((score + 10)); fi
    ancestor=$(suspicious_payload_ancestry "$pid" 2>/dev/null || true)
    [ -n "$ancestor" ] && { why+=("suspicious ancestor $ancestor"); score=$((score + 30)); }
    [ "$score" -ge 20 ] || continue
    detail="interpreter $interpreter; payload $payload; owner $owner; package $package; risk $score; reasons: $(IFS=', '; echo "${why[*]}")"
    finding payload "$pid" "$detail" none
  done < <(ps -eo pid=)
}

pkg_installed() {
  local p="$1"
  if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed"
  elif command -v rpm >/dev/null 2>&1; then
    rpm -q "$p" >/dev/null 2>&1
  else
    return 1
  fi
}

scan_sshkeys() {
  local f
  while IFS= read -r f; do
    [ -n "$f" ] && finding sshkey "$f" "authorized_keys (possible backdoor)" rm
  done < <(find /root /home -xdev -name authorized_keys -type f 2>/dev/null)
}

scan_hidden() {
  local f
  while IFS= read -r f; do
    [ -n "$f" ] && ! whitelisted_path "$f" && finding hidden "$f" "hidden executable" rm
  done < <(find /home /root /tmp /var/tmp /opt /usr/local -xdev -type f -name '.*' -perm -111 2>/dev/null)

  while IFS= read -r f; do
    [ -n "$f" ] && finding hidden "$f" "script in world-writable dir" rm
  done < <(find /tmp /var/tmp -xdev -type f \( -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.rb' \) 2>/dev/null)

  while IFS= read -r f; do
    [ -n "$f" ] && ! whitelisted_path "$f" && finding hidden "$f" "suspicious filename" rm
  done < <(find /tmp /var/tmp /home /opt /usr/local -xdev -type f \
             \( -iname '*backdoor*' -o -iname '*malware*' -o -iname '*keylog*' \
                -o -iname '*ransomware*' -o -iname '*payload*' -o -iname '*reverse_shell*' \) 2>/dev/null)

  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in /srv/ftp/*) continue ;; esac
    [ -n "$(pkg_owner "$f")" ] || finding hidden "$f" "unpackaged software archive" rm
  done < <(find /opt /usr/local /srv /var/www -xdev -type f \
             \( -iname '*.zip' -o -iname '*.tar' -o -iname '*.tgz' -o -iname '*.tar.gz' \
                -o -iname '*.tar.bz2' -o -iname '*.tar.xz' -o -iname '*.7z' -o -iname '*.rar' \) 2>/dev/null)
}

scan_accounts() {
  local u authorized
  while IFS=: read -r u _ uid _; do
    [ "$u" = root ] && continue
    [ "$uid" = 0 ] && finding account "$u" "non-root account with UID 0" none
  done < /etc/passwd

  while IFS=: read -r u pw _; do
    [ -z "$pw" ] && finding account "$u" "empty password" none
  done < /etc/shadow 2>/dev/null

  [ -n "${ADMINS:-}${USERS:-}${PROTECTED_USER:-}" ] || return 0
  authorized="${PROTECTED_USER:-} ${ADMINS:-} ${USERS:-}"

  while read -r u; do
    [ -n "$u" ] || continue
    [ "$u" = root ] && continue
    printf '%s' "$authorized" | grep -qw "$u" && continue
    finding account "$u" "not in readme authorized list" userdel
  done < <(interactive_accounts)

  while read -r u; do
    [ -n "$u" ] || continue
    [ "$u" = root ] && continue
    printf '%s %s' "${PROTECTED_USER:-}" "${ADMINS:-}" | grep -qw "$u" && continue
    printf '%s' "$authorized" | grep -qw "$u" || continue    # unauthorized accounts already reported
    finding sudo "$u" "has sudo but readme lists them as a standard user" desudo
  done < <(getent group sudo admin 2>/dev/null | awk -F: '{gsub(/,/, "\n", $4); print $4}')
}

# preserve file inode
remove_cron_line() {
  local f="$1" line="$2" tmp
  [ -f "$f" ] && [ -w "$f" ] || return 1
  tmp=$(mktemp) || return 1
  grep -vFx -- "$line" "$f" > "$tmp" 2>/dev/null || true
  cat "$tmp" > "$f"
  rm -f "$tmp"
}

expand_selection() {
  local spec="$1" max="$2" tok a b n
  for tok in $spec; do
    case "$tok" in
      a|A|all) seq 1 "$max"; return 0 ;;
      *-*)
        a="${tok%%-*}"; b="${tok##*-}"
        case "$a$b" in ''|*[!0-9]*) continue ;; esac
        [ "$a" -le "$b" ] || continue
        for ((n = a; n <= b; n++)); do
          [ "$n" -ge 1 ] && [ "$n" -le "$max" ] && echo "$n"
        done
        ;;
      *)
        case "$tok" in ''|*[!0-9]*) continue ;; esac
        [ "$tok" -ge 1 ] && [ "$tok" -le "$max" ] && echo "$tok"
        ;;
    esac
  done
}

scan_all() {
  local only="${1:-}" s cats
  for s in cron autostart media software network outgoing processes payloads sshkeys hidden accounts; do
    case "$s" in
      sshkeys)  cats="sshkey" ;;
      accounts) cats="account sudo" ;;
      processes) cats="process" ;;
      payloads)  cats="payload" ;;
      *)        cats="$s" ;;
    esac
    [ -n "$only" ] && ! printf '%s' "$cats" | grep -qw "$only" && continue
    "scan_${s}"
  done
}
