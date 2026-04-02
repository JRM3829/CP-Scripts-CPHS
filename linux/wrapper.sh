#!/bin/bash
ORIG_DIR="$(pwd)/original"
BIN_DIR="$(pwd)/binaries/bin"
TOOLKIT_LIBS="$(pwd)/binaries/libs"
LOG_FILE="$(pwd)/wrapper.log"

mkdir -p "$ORIG_DIR"

for script in wyn *.sh; do
    [[ ! -e "$script" ]] && continue
    [[ -d "$script" ]] && continue
    [[ "$script" == "$(basename "$0")" ]] && continue
    
    grep -q "LD_LIBRARY_PATH" "$script" 2>/dev/null && continue

    echo "Wrapping $script..."
    mv "$script" "$ORIG_DIR/$script"

    cat <<EOF > "$script"
#!/bin/bash
echo "\$(date) - Running \$0" >> "$LOG_FILE"

export PATH="$BIN_DIR:\$PATH"
APP_NAME="\$(basename "\$0")"
LIB_PATH="$TOOLKIT_LIBS/\$APP_NAME"
export LD_LIBRARY_PATH="\$LIB_PATH:\$LD_LIBRARY_PATH"
if [ -f "\$LIB_PATH/ld-linux.so" ]; then
    exec "\$LIB_PATH/ld-linux.so" --library-path "\$LIB_PATH" "$ORIG_DIR/\$APP_NAME" "\$@"
else
    exec "$ORIG_DIR/\$APP_NAME" "\$@"
fi
EOF

    chmod +x "$script"

    if [[ "$script" == "wyn" ]]; then
        echo "Linking 'wyn' to /usr/local/bin..."
        sudo ln -sf "$(pwd)/wyn" "/usr/local/bin/wyn"
    fi
done

echo "Wrapped! All scripts now prioritize $BIN_DIR"
