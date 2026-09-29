#!/bin/bash
# otp_decrypt.sh - decrypt an A-Z one-time pad

read -rp "Ciphertext: " cipher
read -rp "One-time pad: " pad

# Keep only letters and convert to uppercase (ignores spaces, digits, punctuation)
cipher=$(echo "$cipher" | tr -cd 'A-Za-z' | tr 'a-z' 'A-Z')
pad=$(echo "$pad" | tr -cd 'A-Za-z' | tr 'a-z' 'A-Z')

if (( ${#pad} < ${#cipher} )); then
  echo "Error: pad (${#pad} letters) is shorter than ciphertext (${#cipher} letters)." >&2
  exit 1
fi

plain=""
for ((i = 0; i < ${#cipher}; i++)); do
  c=$(printf '%d' "'${cipher:i:1}")   # ASCII code of ciphertext letter
  k=$(printf '%d' "'${pad:i:1}")      # ASCII code of pad letter
  p=$(( (c - k + 26) % 26 + 65 ))     # subtract mod 26, map back to A-Z
  plain+=$(printf "\\$(printf '%03o' "$p")")
done

echo "Plaintext: $plain"