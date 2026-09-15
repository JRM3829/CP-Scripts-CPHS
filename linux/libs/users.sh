#!/usr/bin/env bash

set -euo pipefail

source "${WYN_HOME}/conf/wyn.conf"
source "${WYN_HOME}/libs/core.sh"
source "${WYN_HOME}/libs/readme.sh"

AUTO_YES=false
DRY_RUN="${DRY_RUN:-false}"
DELETE_UNAUTHORIZED=true
USER_PASSWORD="${USER_PASSWORD:-}"
URL_ARG=""
FORCE=false

usage() { echo "usage: users.sh [-y] [-n] [-l] [-F] [-u URL|PATH] [-p PW]" >&2; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage ;;
    -y|--yes) AUTO_YES=true ;;
    -n|--dry-run) DRY_RUN=true ;;
    -l|--lock) DELETE_UNAUTHORIZED=false ;;
    -F|--force) FORCE=true ;;
    -u|--url) [ $# -ge 2 ] || die "--url needs a value"; URL_ARG="$2"; shift ;;
    -p|--password) [ $# -ge 2 ] || die "--password needs a value"; USER_PASSWORD="$2"; shift ;;
    *) die "unknown opt: $1" ;;
  esac
  shift
done

if [ -n "$URL_ARG" ]; then
  page=$(fetch_page "$URL_ARG")
else
  readme_path=$(find_readme) || die "CyberPatriot README not found (pass --url <URL or path>)"
  case "$readme_path" in
    *.desktop|*.Desktop|*.DESKTOP) url=$(extract_url "$readme_path") ;;
    *) url="$readme_path" ;;
  esac
  [ -n "$url" ] || die "no link in $readme_path (pass --url <URL or path>)"
  page=$(fetch_page "$url")
fi
[ -n "$page" ] || die "failed to fetch authorized-users list"

text=$(to_text "$page")
parse_auth_list "$text"
# group tasks optional
parse_group_membership "$page" || true

[ "$AUTH_LIST_VALID" = true ] \
  || die "authorized account sections are incomplete - no account changes made"
if [ -z "$PROTECTED_USER" ]; then
  if [ "$FORCE" = true ]; then
    warn "no '(you)' marker - no protected user (continuing: --force)"
  else
    die "no protected user detected (no '(you)' marker in README) - rerun with --force to proceed without one"
  fi
fi

authorized_list="$PROTECTED_USER $ADMINS $USERS"
declare -a CREATE_ADMIN=() CREATE_USER=() GRANT_SUDO=() DEMOTE=()
declare -a CHANGE_PW=() UNLOCK=() LOCK_ACCT=() DELETE_ACCT=()
declare -A TARGET_PASSWORD=()
for i in "${!README_PASSWORD_USERS[@]}"; do
  TARGET_PASSWORD["${README_PASSWORD_USERS[$i]}"]="${README_PASSWORD_VALUES[$i]}"
done
for u in $ADMINS; do
  [ "$u" = "$PROTECTED_USER" ] && continue
  [ -n "$USER_PASSWORD" ] && TARGET_PASSWORD["$u"]="$USER_PASSWORD"
  if id "$u" >/dev/null 2>&1; then
    groups "$u" 2>/dev/null | grep -qw sudo || GRANT_SUDO+=("$u")
    [ -n "${TARGET_PASSWORD[$u]:-}" ] && CHANGE_PW+=("$u")
    passwd -S "$u" 2>/dev/null | awk '{print $2}' | grep -q '^L$' && UNLOCK+=("$u")
  else
    CREATE_ADMIN+=("$u")
    GRANT_SUDO+=("$u")
    [ -n "${TARGET_PASSWORD[$u]:-}" ] && CHANGE_PW+=("$u")
  fi
done
for u in $USERS; do
  [ "$u" = "$PROTECTED_USER" ] && continue
  if id "$u" >/dev/null 2>&1; then
    groups "$u" 2>/dev/null | grep -qw sudo && DEMOTE+=("$u")
  else
    CREATE_USER+=("$u")
  fi
done
while read -r u; do
  [ -z "$u" ] && continue
  [ "$u" = root ] && continue
  [ "$u" = "$PROTECTED_USER" ] && continue
  echo "$authorized_list" | grep -qw "$u" && continue
  if [ "$DELETE_UNAUTHORIZED" = true ]; then
    DELETE_ACCT+=("$u")
  else
    LOCK_ACCT+=("$u")
  fi
done < <(interactive_accounts)

GM_CREATE_GROUP=""
declare -a GM_CREATE_USERS=() GM_ADD_MEMBERS=()
if [ -n "$GROUP_ADD_GROUP" ] && [ -n "$GROUP_ADD_USERS" ]; then
  getent group "$GROUP_ADD_GROUP" >/dev/null 2>&1 || GM_CREATE_GROUP="$GROUP_ADD_GROUP"
  for u in $GROUP_ADD_USERS; do
    printf '%s\n' $authorized_list | grep -Fxq -- "$u" \
      || { warn "group task names non-authorized user '$u' - skipping member"; continue; }
    id "$u" >/dev/null 2>&1 || GM_CREATE_USERS+=("$u")
    groups "$u" 2>/dev/null | grep -qw "$GROUP_ADD_GROUP" || GM_ADD_MEMBERS+=("$u")
  done
elif [ -n "$GROUP_ADD_USERS" ]; then
  warn "group task: found members but no group - skipping"
elif [ -n "$GROUP_ADD_GROUP" ]; then
  warn "group task: found group \"$GROUP_ADD_GROUP\" but no user - skipping"
fi

echo "[authorized accounts preview]"
[ -n "$PROTECTED_USER" ] && echo "  protected (you): $PROTECTED_USER"
echo "  admins: ${ADMINS//$'\n'/ }"
echo "  users:  ${USERS//$'\n'/ }"
echo "  critical services: ${CRITICAL_SERVICES//$'\n'/ }"
[ ${#CREATE_ADMIN[@]} -gt 0 ] && echo "  create (admin):  ${CREATE_ADMIN[*]}"
[ ${#CREATE_USER[@]} -gt 0 ] && echo "  create (user):   ${CREATE_USER[*]}"
[ ${#GRANT_SUDO[@]} -gt 0 ] && echo "  grant sudo:      ${GRANT_SUDO[*]}"
[ ${#DEMOTE[@]} -gt 0 ] && echo "  demote:          ${DEMOTE[*]}"
[ ${#CHANGE_PW[@]} -gt 0 ] && echo "  change pw:       ${CHANGE_PW[*]}"
[ ${#UNLOCK[@]} -gt 0 ] && echo "  unlock:          ${UNLOCK[*]}"
[ ${#LOCK_ACCT[@]} -gt 0 ] && echo "  lock:            ${LOCK_ACCT[*]}"
[ ${#DELETE_ACCT[@]} -gt 0 ] && echo "  delete:          ${DELETE_ACCT[*]}"
if [ ${#GM_ADD_MEMBERS[@]} -gt 0 ]; then
  echo "  add to group:    ${GM_ADD_MEMBERS[*]} -> $GROUP_ADD_GROUP (create-group=$([ -n "$GM_CREATE_GROUP" ] && echo yes || echo no), create-users=${#GM_CREATE_USERS[@]})"
fi
if [ ${#CREATE_ADMIN[@]} -eq 0 ] && [ ${#CREATE_USER[@]} -eq 0 ] && [ ${#GRANT_SUDO[@]} -eq 0 ] \
   && [ ${#DEMOTE[@]} -eq 0 ] && [ ${#CHANGE_PW[@]} -eq 0 ] && [ ${#UNLOCK[@]} -eq 0 ] \
   && [ ${#LOCK_ACCT[@]} -eq 0 ] && [ ${#DELETE_ACCT[@]} -eq 0 ] && [ ${#GM_ADD_MEMBERS[@]} -eq 0 ]; then
  echo "  none - accounts already match"
fi

[ "$DRY_RUN" = true ] && { echo "dry run - no changes"; exit 0; }
if [ "$AUTO_YES" != true ] && ! confirm "apply these changes?"; then
  echo "skipped"
  exit 0
fi

for u in "${CREATE_ADMIN[@]}"; do
  if useradd -m -s /bin/bash "$u"; then echo "  created admin: $u"; else warn "  failed create admin: $u"; fi
done
for u in "${CREATE_USER[@]}"; do
  if useradd -m -s /bin/bash "$u"; then echo "  created user: $u"; else warn "  failed create user: $u"; fi
done
for u in "${GRANT_SUDO[@]}"; do
  if usermod -aG sudo "$u" >/dev/null 2>&1; then echo "  granted sudo: $u"; else warn "  failed sudo: $u"; fi
done
for u in "${DEMOTE[@]}"; do
  if gpasswd -d "$u" sudo >/dev/null 2>&1; then echo "  demoted: $u"; else warn "  failed demote: $u"; fi
done
if [ ${#CHANGE_PW[@]} -gt 0 ]; then
  if ! "${WYN_HOME}/libs/pam.sh" check /etc/pam.d/common-password 'password [success=@ default=ignore] pam_unix.so obscure sha512 minlen=10 remember=3'; then
    "${WYN_HOME}/libs/pam.sh" enforce /etc/pam.d/common-password 'password [success=@ default=ignore] pam_unix.so obscure sha512 minlen=10 remember=3'
  fi
  for u in "${CHANGE_PW[@]}"; do
      pw="${TARGET_PASSWORD[$u]}"
      if printf '%s:%s\n' "$u" "$pw" | chpasswd >/dev/null 2>&1; then
        passwd -u "$u" >/dev/null 2>&1 || true
        echo "  changed pw: $u"
      elif command -v openssl >/dev/null 2>&1; then
        usermod -p "$(openssl passwd -6 "$pw")" "$u" 2>/dev/null \
          && { passwd -u "$u" >/dev/null 2>&1 || true; echo "  changed pw (bypass): $u"; } \
          || warn "  failed pw: $u"
      else
        warn "  failed pw: $u"
      fi
  done
fi
for u in "${LOCK_ACCT[@]}"; do
  if passwd -l "$u" >/dev/null 2>&1; then echo "  locked: $u"; else warn "  failed lock: $u"; fi
done
for u in "${DELETE_ACCT[@]}"; do
  [ "$u" = root ] && { warn "  refusing to delete built-in account: root"; continue; }
  if userdel -rf "$u" >/dev/null 2>&1; then echo "  deleted: $u"; else warn "  failed delete: $u"; fi
done

if [ ${#GM_ADD_MEMBERS[@]} -gt 0 ]; then
  getent group "$GROUP_ADD_GROUP" >/dev/null 2>&1 || { groupadd "$GROUP_ADD_GROUP" && echo "  created group: $GROUP_ADD_GROUP"; }
  for u in "${GM_ADD_MEMBERS[@]}"; do
    id "$u" >/dev/null 2>&1 || { useradd -m -s /bin/bash "$u" && echo "  created user: $u"; }
    usermod -aG "$GROUP_ADD_GROUP" "$u" >/dev/null 2>&1 \
      && echo "  added $u to $GROUP_ADD_GROUP" || warn "  failed add $u to $GROUP_ADD_GROUP"
  done
fi
echo "users synced"
