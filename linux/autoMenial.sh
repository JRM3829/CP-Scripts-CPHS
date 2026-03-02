#!/bin/bash

echo "=== Auto Menial Labor ==="

# Formatting: "<file> | <search_pattern> | <replacement_line>"
updates=(
    # --- IPv4 Hardening ---
    "/etc/sysctl.conf | net.ipv4.tcp_syncookies | net.ipv4.tcp_syncookies = 1"
    "/etc/sysctl.conf | net.ipv4.ip_forward | net.ipv4.ip_forward = 0"
    "/etc/sysctl.conf | kernel.randomize_va_space | kernel.randomize_va_space = 2"

    # --- Password Aging ---
    "/etc/login.defs | PASS_MAX_DAYS | PASS_MAX_DAYS   30"
    "/etc/login.defs | PASS_MIN_DAYS | PASS_MIN_DAYS   10"
    "/etc/login.defs | PASS_WARN_AGE | PASS_WARN_AGE   7"

    # --- SSH Hardening ---
    "/etc/ssh/sshd_config | PermitRootLogin | PermitRootLogin no"
)

for entry in "${updates[@]}"; do
    # Using 'cut' with a custom delimiter
    FILE=$(echo "$entry"    | cut -d '|' -f1 | xargs)
    SEARCH=$(echo "$entry"  | cut -d '|' -f2 | xargs)
    REPLACE=$(echo "$entry" | cut -d '|' -f3- | xargs)

    if [ ! -f "$FILE" ]; then
        echo "Skipping: $FILE (Not found)"
        continue
    fi

    echo "[*] Processing: $FILE"
	# BackUp
    cp "$FILE" "$FILE.bak.$(date +%M%S)"

    if grep -iq "^#* *$SEARCH" "$FILE"; then
        sudo sed -i "s|^#* *$SEARCH.*|$REPLACE|" "$FILE"
        echo "    → Updated: $SEARCH"
    else
        echo "$REPLACE" | sudo tee -a "$FILE" > /dev/null
        echo "    → Appended: $REPLACE"
    fi
done

sudo sysctl -p > /dev/null
echo "=== Hardening Complete ==="





