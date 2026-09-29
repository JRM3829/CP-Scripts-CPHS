#!/bin/bash
# otp_decrypt.sh - decrypt an A-Z one-time pad (plain = cipher - pad mod 26)

alpha=ABCDEFGHIJKLMNOPQRSTUVWXYZ

read -rp "Ciphertext: " cipher
read -rp "One-time pad: " pad

# Uppercase, strip carriage returns; pad keeps letters only
cipher=$(printf '%s' "${cipher^^}" | tr -d '\r')
pad=$(printf '%s' "${pad^^}" | tr -cd 'A-Z')

# Count letters in the ciphertext
letters=$(printf '%s' "$cipher" | tr -cd 'A-Z')
if (( ${#pad} < ${#letters} )); then
  echo "Error: pad has ${#pad} letters but ciphertext has ${#letters}." >&2
  exit 1
fi

plain=""
j=0
for ((i = 0; i < ${#cipher}; i++)); do
  ch=${cipher:i:1}
  if [[ $ch == [A-Z] ]]; then
    k=${pad:j:1}; ((j++))
    c=${alpha%%"$ch"*}; c=${#c}     # index of cipher letter (A=0)
    kk=${alpha%%"$k"*}; kk=${#kk}   # index of pad letter
    plain+=${alpha:(c - kk + 26) % 26:1}
  else
    plain+=$ch                      # keep spaces/punctuation as-is
  fi
done

echo "Letters in ciphertext: ${#letters}"
echo "Letters used from pad: $j"
echo "Plaintext: $plain"
