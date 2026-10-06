#!/bin/bash
# otp_xor.sh - decrypt/encrypt a hex one-time pad via XOR

read -rp "Ciphertext (hex): " cipher
read -rp "One-time pad (hex): " pad

# strip whitespace and optional 0x prefix, lowercase
cipher=$(echo "${cipher#0x}" | tr -d '[:space:]' | tr 'A-F' 'a-f')
pad=$(echo "${pad#0x}" | tr -d '[:space:]' | tr 'A-F' 'a-f')

if (( ${#cipher} % 2 )); then
  echo "Error: ciphertext has an odd number of hex digits." >&2; exit 1
fi
if (( ${#pad} < ${#cipher} )); then
  echo "Error: pad (${#pad} hex digits) is shorter than ciphertext (${#cipher})." >&2; exit 1
fi

out=""
for ((i = 0; i < ${#cipher}; i += 2)); do
  b=$(( 0x${cipher:i:2} ^ 0x${pad:i:2} ))
  out+=$(printf '%02x' "$b")
done

echo "Plaintext (hex): $out"
echo -n "Plaintext (text): "
echo -e "$(echo "$out" | sed 's/../\\x&/g')"
echo
