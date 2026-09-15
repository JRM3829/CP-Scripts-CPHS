#!/usr/bin/env bash

set -euo pipefail

source "${WYN_HOME}/conf/wyn.conf"
source "${WYN_HOME}/libs/core.sh"

AUTO_YES=false
DRY_RUN="${DRY_RUN:-false}"
MINT_INFO="${WYN_MINT_INFO:-/etc/linuxmint/info}"
OS_RELEASE="${WYN_OS_RELEASE:-/etc/os-release}"
MINTSOURCES_ROOT="${WYN_MINTSOURCES_ROOT:-/usr/share/mintsources}"
APT_SOURCES_DIR="${WYN_APT_SOURCES_DIR:-/etc/apt/sources.list.d}"

ini_value() {
  awk -F= -v section="[$1]" -v key="$2" '
    $0 == section {inside=1; next}
    /^\[/ {inside=0}
    inside {
      name=$1
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
      if (name == key) {
        sub(/^[^=]*=[[:space:]]*/, "")
        print
        exit
      }
    }
  ' "$3"
}

restore_mint_sources() {
  local os_codename mint_dir config template target codename base mirror base_mirror rendered
  os_codename=$(sed -nE 's/^VERSION_CODENAME="?([^"[:space:]]+)"?.*/\1/p' "$OS_RELEASE" | head -1)
  mint_dir="${MINTSOURCES_ROOT}/${os_codename}"
  config="${mint_dir}/mintsources.conf"
  template="${mint_dir}/official-package-repositories.list"
  target="${APT_SOURCES_DIR}/official-package-repositories.list"
  if [ -z "$os_codename" ] || [ ! -r "$config" ] || [ ! -r "$template" ]; then
    warn "Linux Mint repository defaults unavailable; sources unchanged"
    return 0
  fi
  codename=$(ini_value general codename "$config")
  base=$(ini_value general base_codename "$config")
  mirror=$(ini_value mirrors default "$config")
  base_mirror=$(ini_value mirrors base_default "$config")
  if [ -z "$codename" ] || [ -z "$base" ] || [ -z "$mirror" ] || [ -z "$base_mirror" ]; then
    warn "Linux Mint repository defaults incomplete; sources unchanged"
    return 0
  fi
  rendered=$(sed -e "s|\$codename|${codename}|g" \
    -e "s|\$basecodename|${base}|g" \
    -e 's|$optionalcomponents||g' \
    -e "s|\$mirror|${mirror}|g" \
    -e "s|\$basemirror|${base_mirror}|g" "$template")
  [ ! -f "$target" ] || [ "$(cat "$target")" != "$rendered" ] || return 0
  mkdir -p "$APT_SOURCES_DIR"
  [ ! -f "$target" ] || [ -e "${target}.wyn.bak" ] || cp -a "$target" "${target}.wyn.bak"
  printf '%s\n' "$rendered" > "$target"
  echo "restored Linux Mint official repositories"
}

usage() {
  printf 'Usage: update.sh [-y|--yes] [-n|--dry-run]\n\n'
  printf 'Updates from the currently configured repositories. -y is noninteractive.\n'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage ;;
    -y|--yes) AUTO_YES=true ;;
    -n|--dry-run) DRY_RUN=true ;;
    *) die "unknown opt: $1" ;;
  esac
  shift
done

DISTRO=ubuntu
[ -f "$MINT_INFO" ] && DISTRO=mint
if [ "$DISTRO" = ubuntu ] && [ -f "$OS_RELEASE" ]; then
  . "$OS_RELEASE"
  [ "${ID:-ubuntu}" = linuxmint ] && DISTRO=mint
fi
if [ "$DISTRO" = mint ]; then
  echo "detected: mint (official repositories repaired)"
else
  echo "detected: ubuntu (existing repositories preserved)"
fi

yes_args=()
[ "$AUTO_YES" = true ] && yes_args=(-y)

if [ "$DRY_RUN" = true ]; then
  [ "$DISTRO" != mint ] || echo "  [dry] restore Linux Mint official repositories from installed defaults"
  echo "  [dry] apt-get update"
  echo "  [dry] apt-get full-upgrade ${yes_args[*]} (keep local configuration)"
  if [ "$DISTRO" = mint ]; then
    echo "  [dry] mintupdate-automation upgrade enable"
  else
    echo "  [dry] install and enable unattended-upgrades"
  fi
  if command -v snap >/dev/null 2>&1; then
    echo "  [dry] report snap refresh holds/list and run snap refresh"
  fi
  echo "  [dry] report held and upgradable apt packages"
  exit 0
fi

[ "$DISTRO" != mint ] || restore_mint_sources
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get \
  -o Dpkg::Options::=--force-confold full-upgrade "${yes_args[@]}"

if [ "$DISTRO" = mint ]; then
  mintupdate-automation upgrade enable 2>/dev/null || warn "mintupdate-automation unavailable"
else
  DEBIAN_FRONTEND=noninteractive apt-get install "${yes_args[@]}" unattended-upgrades
  dpkg-reconfigure -f noninteractive unattended-upgrades 2>/dev/null || true
  systemctl enable --now unattended-upgrades 2>/dev/null || warn "could not enable unattended-upgrades"
fi

if command -v snap >/dev/null 2>&1; then
  echo "[snap held/upgradable]"
  snap get system refresh.hold 2>/dev/null || true
  snap refresh --list 2>/dev/null || true
  snap refresh || warn "snap refresh failed"
fi

echo "[apt held]"
apt-mark showhold 2>/dev/null || true
echo "[apt upgradable]"
apt list --upgradable 2>/dev/null || true
echo "updates applied"
