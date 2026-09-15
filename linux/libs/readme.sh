#!/usr/bin/env bash

GROUP_ADD_USERS=""
GROUP_ADD_GROUP=""
README_TEXT=""
AUTH_LIST_VALID=false
CRITICAL_SERVICES_VALID=false
README_PASSWORD_USERS=()
README_PASSWORD_VALUES=()

valid_account_name() {
  [ "${#1}" -le 32 ] && [[ "$1" =~ ^[a-z_][a-z0-9_.-]*[$]?$ ]]
}

parse_readme_passwords() {
  local text="$1" line lower section="" current="" value names
  README_PASSWORD_USERS=(); README_PASSWORD_VALUES=()
  names=$(printf '%s\n%s\n' "$ADMINS" "$USERS")
  while IFS= read -r line; do
    lower="${line,,}"
    case "$lower" in
      *authorized\ administrators*) section=accounts; current=""; continue ;;
      *authorized\ users*) section=accounts; current=""; continue ;;
      *critical\ services*|*competition\ guidelines*|*forensics\ question*|tasks:*|notes:*) section=""; current=""; continue ;;
    esac
    [ "$section" = accounts ] || continue
    line=$(printf '%s' "$line" | sed -E 's/\(you\)//Ig; s/^[[:space:]]*[-*•]?[[:space:]]*//; s/[[:space:]]+$//')
    lower="${line,,}"
    case "$lower" in
      password:*)
        value="${line#*:}"; value="${value#"${value%%[![:space:]]*}"}"
        if [ -n "$current" ] && [ -n "$value" ]; then
          README_PASSWORD_USERS+=("$current")
          README_PASSWORD_VALUES+=("$value")
        fi
        ;;
      *)
        if valid_account_name "$line" && grep -Fxq -- "$line" <<< "$names"; then current="$line"; else current=""; fi
        ;;
    esac
  done <<< "$text"
}

find_readme() {
  local extra="${SUDO_USER:-}" dir f
  local -a dirs=("/home/${extra}/Desktop" "$HOME/Desktop" /home/*/Desktop /root/Desktop)
  if [ -n "${WYN_README:-}" ]; then
    printf '%s' "$WYN_README"
    return 0
  fi
  # ignore invocation directory
  for dir in "${dirs[@]}"; do
    [ -d "$dir" ] || continue
    f=$(find -L "$dir" -maxdepth 1 -type f -iname 'readme.desktop' -print -quit 2>/dev/null)
    [ -n "$f" ] && { printf '%s' "$f"; return 0; }
  done
  # desktop html fallback
  for dir in "${dirs[@]}"; do
    [ -d "$dir" ] || continue
    while IFS= read -r f; do
      grep -Eqi 'authorized (administrators|users)|critical services' "$f" 2>/dev/null \
        && { printf '%s' "$f"; return 0; }
    done < <(find -L "$dir" -maxdepth 1 -type f \( \
      -iname '*readme*.html' -o -iname '*readme*.htm' \
      -o -iname 'authorized_users*.html' -o -iname 'authorized_users*.htm' \
      -o -iname 'authorized-users*.html' -o -iname 'authorized-users*.htm' \
    \) 2>/dev/null)
  done
  return 1
}

extract_url() {
  local u
  u=$(grep -oE '^[[:space:]]*URL=[[:space:]]*[a-zA-Z0-9+.-]*://[^"[:space:]]+' "$1" \
      | sed -E 's/^[[:space:]]*URL=[[:space:]]*//' | head -1 || true)
  [ -z "$u" ] && u=$(grep -oE '[a-zA-Z][a-zA-Z0-9+.-]*://[^"[:space:]]+' "$1" | head -1 || true)
  printf '%s' "$u"
}

fetch_page() {
  local u="$1" page
  case "$u" in
    file://*) cat "${u#file://}" 2>/dev/null || true; return 0 ;;
  esac
  [ -f "$u" ] && { cat "$u" 2>/dev/null || true; return 0; }
  if command -v wget >/dev/null 2>&1; then
    page=$(wget -qO- "$u" 2>/dev/null || true)
    [ -n "$page" ] && { printf '%s\n' "$page"; return 0; }
  fi
  command -v curl >/dev/null 2>&1 && curl -fsSL "$u" 2>/dev/null || true
}

sanitize_html() {
  local page body
  page=$(sed -n '1,$p')
  body=$(printf '%s\n' "$page" | sed -n '/<body\b/,/<\/body>/Ip')
  [ -n "$body" ] || body="$page"
  printf '%s\n' "$body" \
    | sed '/<script\b/,/<\/script>/Id; /<style\b/,/<\/style>/Id' \
    | sed 's/<br[[:space:]]*\/?>/\n/Ig; s/<[^>]*>//g; s/&quot;/"/g; s/&#8220;/"/g; s/&#8221;/"/g; s/&#8216;/'"'"'/g; s/&#8217;/'"'"'/g; s/&nbsp;/ /g; s/&amp;/\&/g'
}

to_text() {
  local page="$1" block extra
  block=$(printf '%s\n' "$page" | sed -n '/<[[:space:]]*pre[^>]*>/,/<\/pre>/p')
  if [ -z "$block" ]; then
    block="$page"
  else
    extra=$(printf '%s\n' "$page" \
      | sed 's/<br[[:space:]]*\/?>/\n/Ig' \
      | sed 's/&nbsp;/ /g' \
      | sed 's/&quot;/"/g' \
      | sed 's/<[^>]*>//g' \
      | awk 'tolower($0) ~ /^[[:space:]]*critical services/ {f=1} f && tolower($0) ~ /^[[:space:]]*(authorized administrators|authorized users)/ {f=0} f {print}')
    [ -n "$extra" ] && block="${extra}"$'\n'"${block}"
  fi
  printf '%s\n' "$block" \
    | sed 's/<br[[:space:]]*\/?>/\n/Ig' \
    | sed 's/&nbsp;/ /g' \
    | sed 's/&quot;/"/g' \
    | sed 's/&#8220;/"/g; s/&#8221;/"/g; s/&#8216;/'"'"'/g; s/&#8217;/'"'"'/g; s/&amp;/\&/g' \
    | sed 's/<[^>]*>//g'
}

normalize_service() {
  local line="${1,,}" token
  token=$(printf '%s' "$line" | sed -nE 's/.*\(([a-z0-9._-]+)\).*/\1/p')
  if [ -z "$token" ]; then
    for token in $line; do
      token="${token//[^a-z0-9._-]/}"
      case "$token" in
        ssh|sshd|openssh|ftp|vsftpd|proftpd|pure-ftpd|http|https|apache|apache2|httpd|nginx|lighttpd|smtp|postfix|dovecot|imap|pop3|dns|bind|bind9|named|mysql|mariadb|mysqld|postgres|postgresql|samba|smb|smbd|nmbd|cups|cupsd|ntp|ntpd|chrony|dhcp|ldap|ldaps|rdp|xrdp) break ;;
        *) token="" ;;
      esac
    done
  fi
  if [ -z "$token" ]; then
    token=$(printf '%s' "$line" | awk 'NF == 1 && $1 ~ /^[a-z0-9._-]+$/ {print $1}')
  fi
  if [ -z "$token" ]; then
    case "$line" in
      *secure*shell*|*ssh*server*) token=ssh ;;
      *ftp*server*|*file*transfer*protocol*) token=ftp ;;
      *web*server*) token=http ;;
      *mail*server*) token=smtp ;;
      *file*sharing*|*samba*) token=samba ;;
      *database*server*) token=database ;;
    esac
  fi
  [ -n "$token" ] && printf '%s\n' "$token"
}

parse_auth_list() {
  local text="$1"
  AUTH_LIST_VALID=false
  CRITICAL_SERVICES_VALID=false
  if awk 'BEGIN{a=0;u=0} tolower($0) ~ /^[[:space:]]*authorized administrators/{a=1} tolower($0) ~ /^[[:space:]]*authorized users/{u=1} END{exit !(a&&u)}' <<< "$text"; then
    AUTH_LIST_VALID=true
  fi
  grep -Eqi '^[[:space:]]*critical services' <<< "$text" && CRITICAL_SERVICES_VALID=true

  PROTECTED_USER=$(awk '
    tolower($0) ~ /\(you\)/ {
      gsub(/\(you\)/, "", $0)
      gsub(/^[-*•]+[[:space:]]*/, "", $0)
      gsub(/[[:space:]]+/, " ", $0)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
      if (NF && $1 ~ /^[a-z_][a-z0-9_.-]*[$]?$/ && length($1) <= 32) { print $1; exit }
    }
  ' <<< "$text")

  ADMINS=$(awk '
    tolower($0) ~ /^[[:space:]]*authorized administrators/ {flag=1; next}
    tolower($0) ~ /^[[:space:]]*authorized users/ {flag=0; next}
    flag && tolower($0) ~ /^[[:space:]]*(critical services|competition|forensics|guidelines|tasks?|notes?)([[:space:]:]|$)/ {flag=0; next}
    flag {
      if (!NF) next
      if (tolower($1) ~ /^password:?$/) next
      if ($0 ~ /user[[:space:]]+"[^"]+"/) next
      gsub(/\(you\)/, "", $0)
      gsub(/^[-*•]+[[:space:]]*/, "", $0)
      gsub(/[[:space:]]+/, " ", $0)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
      if (NF == 1 && $0 ~ /^[a-z_][a-z0-9_.-]*[$]?$/ && length($0) <= 32) print $1
    }
  ' <<< "$text")

  USERS=$(awk '
    tolower($0) ~ /^[[:space:]]*authorized users/ {flag=1; next}
    tolower($0) ~ /^[[:space:]]*authorized administrators/ {flag=0; next}
    flag && tolower($0) ~ /^[[:space:]]*(critical services|competition|forensics|guidelines|tasks?|notes?)([[:space:]:]|$)/ {flag=0; next}
    flag {
      if (!NF) next
      if (tolower($1) ~ /^password:?$/) next
      if ($0 ~ /user[[:space:]]+"[^"]+"/) next
      gsub(/\(you\)/, "", $0)
      gsub(/^[-*•]+[[:space:]]*/, "", $0)
      gsub(/[[:space:]]+/, " ", $0)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
      if (NF == 1 && $0 ~ /^[a-z_][a-z0-9_.-]*[$]?$/ && length($0) <= 32) print $1
    }
  ' <<< "$text")

  CRITICAL_SERVICES=$(awk '
    tolower($0) ~ /^[[:space:]]*critical services/ {
      flag=1
      sub(/^[[:space:]]*[Cc]ritical[[:space:]]+[Ss]ervices[[:space:]]*:?[[:space:]]*/, "")
      if (NF && $1 !~ /^password:?$/) print
      next
    }
    tolower($0) ~ /^[[:space:]]*(authorized administrators|authorized users)/ {flag=0}
    flag && tolower($0) ~ /^[[:space:]]*(competition|forensics|guidelines|tasks?|notes?)([[:space:]:]|$)/ {flag=0; next}
    flag && NF {
      if (tolower($1) ~ /^password:?$/) next
      gsub(/^[-*•]+[[:space:]]*/, "", $0)
      gsub(/[[:space:]]+/, " ", $0)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
      print
    }
  ' <<< "$text" | while IFS= read -r line; do normalize_service "$line" || true; done | awk '!seen[$0]++')
  parse_readme_passwords "$text"
}

parse_group_membership() {
  local page="$1" plain flat gsent members u
  GROUP_ADD_USERS=""
  GROUP_ADD_GROUP=""
  [ -n "$page" ] || return 1
  plain=$(printf '%s\n' "$page" | sanitize_html)
  flat=$(printf '%s\n' "$plain" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')

  gsent=$(printf '%s' "$flat" | grep -ioE 'create (a )?group[^.]*add[^.]*members?[^.]*' | head -1 || true)
  if [ -n "$gsent" ]; then
    GROUP_ADD_GROUP=$(printf '%s' "$gsent" | sed -nE 's/.*[Gg]roup (called|named)[[:space:]]+"?([A-Za-z0-9._-]+)"?.*/\2/p')
    members=$(printf '%s' "$gsent" | sed -nE 's/.*[Mm]embers?[^:]*:[[:space:]]*(.*)$/\1/p')
    while IFS= read -r u; do
      u=$(printf '%s' "$u" | sed -E 's/^[[:space:]]*(and[[:space:]]+)?//; s/[[:space:]]+$//')
      case "$u" in ''|*[!a-z0-9._-]*|[!a-z_]*) continue ;; esac
      [ "${#u}" -le 32 ] || continue
      GROUP_ADD_USERS+="${GROUP_ADD_USERS:+$'\n'}$u"
    done < <(printf '%s\n' "$members" | tr ',' '\n')
  else
    # legacy group wording
    gsent=$(printf '%s' "$flat" | tr '.' '\n' \
      | grep -iE '\<add(ed|ing)?\>' | grep -iE '\<group\>' \
      | grep -oE '"[^"]+"[^"]*"[^"]+"' | head -1 || true)
    GROUP_ADD_USERS=$(printf '%s' "$gsent" | grep -oE '"[^"]+"' | sed -n 1p | tr -d '"')
    GROUP_ADD_GROUP=$(printf '%s' "$gsent" | grep -oE '"[^"]+"' | sed -n 2p | tr -d '"')
  fi

  while IFS= read -r u; do
    case "$u" in ''|*[!a-z0-9._-]*|[!a-z_]*) GROUP_ADD_USERS=""; break ;; esac
    [ "${#u}" -le 32 ] || { GROUP_ADD_USERS=""; break; }
  done <<< "$GROUP_ADD_USERS"
  case "$GROUP_ADD_GROUP" in ''|*[!a-z0-9._-]*|[!a-z_]*) GROUP_ADD_GROUP="" ;; esac
  [ "${#GROUP_ADD_GROUP}" -le 32 ] || GROUP_ADD_GROUP=""
  [ -n "$GROUP_ADD_USERS" ] && [ -n "$GROUP_ADD_GROUP" ]
}

readme_service_required() {
  printf '%s\n' "${CRITICAL_SERVICES:-}" | grep -Fxiq "$1"
}

canonical_service() {
  case "${1,,}" in
    ssh|sshd|openssh|openssh-server) echo ssh ;;
    ftp|vsftpd|proftpd|pure-ftpd) echo ftp ;;
    web|http|https|apache|apache2|httpd|nginx|lighttpd) echo web ;;
    mail|smtp|postfix) echo mail ;;
    imap|dovecot) echo imap ;;
    pop3) echo pop3 ;;
    dns|bind|bind9|named) echo dns ;;
    mysql|mariadb|mysqld|database) echo mysql ;;
    postgres|postgresql) echo postgresql ;;
    samba|smb|smbd|nmbd) echo samba ;;
    cups|cupsd|ipp) echo cups ;;
    ntp|ntpd|chrony) echo ntp ;;
    dhcp|dhcpd) echo dhcp ;;
    ldap|slapd) echo ldap ;;
    ldaps) echo ldaps ;;
    rdp|xrdp) echo rdp ;;
    *) printf '%s\n' "${1,,}" ;;
  esac
}

service_matches() {
  [ "$(canonical_service "$1")" = "$(canonical_service "$2")" ]
}

resolve_service_rules() {
  local svc rule
  svc=$(canonical_service "$1")
  case "$svc" in
    ssh) echo 22/tcp ;;
    ftp) echo 20/tcp 21/tcp ;;
    web) echo 80/tcp 443/tcp ;;
    mail) echo 25/tcp 465/tcp 587/tcp ;;
    imap) echo 143/tcp 993/tcp ;;
    pop3) echo 110/tcp 995/tcp ;;
    dns) echo 53/tcp 53/udp ;;
    mysql) echo 3306/tcp ;;
    postgresql) echo 5432/tcp ;;
    samba) echo 137/udp 138/udp 139/tcp 445/tcp ;;
    cups) echo 631/tcp 631/udp ;;
    ntp) echo 123/udp ;;
    dhcp) echo 67/udp 68/udp ;;
    ldap) echo 389/tcp 389/udp ;;
    ldaps) echo 636/tcp ;;
    rdp) echo 3389/tcp 3389/udp ;;
    *)
      rule=$(awk -v svc="$svc" '
        $1 !~ /^#/ {
          if ($1 == svc) {print $2; exit}
          for (i=3; i<=NF; i++) if ($i == svc) {print $2; exit}
        }
      ' /etc/services 2>/dev/null)
      [ -n "$rule" ] && printf '%s\n' "$rule"
      ;;
  esac
  return 0
}

readme_authorizes() {
  local item="${1,,}"
  tr '.' '\n' <<< "${README_TEXT:-}" | awk -v item="$item" '
    {
      line=tolower($0)
      hit=0; n=split(line, words, /[^a-z0-9._-]+/)
      for (i=1; i<=n; i++) if (words[i] == item) hit=1
      compact_item=item; gsub(/[^a-z0-9]/, "", compact_item)
      for (i=1; i<=n; i++) {
        compact=words[i]; gsub(/[^a-z0-9]/, "", compact)
        if (compact == compact_item) hit=1
        if (i<n) {
          compact=words[i] words[i+1]; gsub(/[^a-z0-9]/, "", compact)
          if (compact == compact_item) hit=1
        }
      }
      if (hit && line !~ /(unauthoriz|not authorized|prohibited|must be removed)/ &&
          line ~ /(authoriz|approved|permitted|required|critical service|must remain|do not stop|do not disable)/) found=1
    }
    END {exit !found}
  '
}

readme_load() {
  local r="" page url text
  PROTECTED_USER=""; ADMINS=""; USERS=""; CRITICAL_SERVICES=""; README_TEXT=""
  AUTH_LIST_VALID=false; CRITICAL_SERVICES_VALID=false
  README_PASSWORD_USERS=(); README_PASSWORD_VALUES=()
  GROUP_ADD_USERS=""; GROUP_ADD_GROUP=""
  r=$(find_readme) || return 1
  case "$r" in
    *.desktop|*.Desktop|*.DESKTOP) url=$(extract_url "$r") ;;
    *) url="$r" ;;
  esac
  [ -n "$url" ] || return 1
  page=$(fetch_page "$url")
  [ -n "$page" ] || return 1
  README_TEXT=$(printf '%s\n' "$page" | sanitize_html)
  text=$(to_text "$page")
  parse_auth_list "$text"
  parse_group_membership "$page"
  [ -n "$ADMINS" ] || [ -n "$USERS" ] || [ -n "$PROTECTED_USER" ] || [ -n "$CRITICAL_SERVICES" ]
}
