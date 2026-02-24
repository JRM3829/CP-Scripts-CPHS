#!/bin/bash
NORMAL=false
SCAN_TYPE=""
SHOW_ENV=false
DRY_RUN=false
TARGET_OR_QUERY=""
REMOVE_TARGET=""
CHECK_PACKAGE=false
RUN_SCRIPT=""

usage() {
    echo "Usage: wyn [options] or wyn [target/search]"
    echo "Options:"
    echo "  -scan (ports|pid)     Scan for all open listening ports or top processes."
    echo "  -n, --normal          Show raw, unformatted output (use with -scan)."
    echo "  -e                    Environment ONLY mode: Show only variables for a PID."
    echo "  -pack                 Identify the package owner for a PID or :PORT."
    echo "  -r (PID|:PORT)        Remove: Stop, disable, delete service, and purge package."
    echo "  -dry-run              Use with -r to see what would happen without acting."
    echo "  -scripts [name|help]  Run remote hardening scripts or show available scripts."
    echo ""
    echo "Analyze:"
    echo "  wyn <PID>             Analyze a specific Process ID (e.g., wyn 1234)."
    echo "  wyn <:PORT>           Analyze the process on a Port (e.g., wyn :80)."
    echo "  wyn <STRING>          Search through ports and PIDs for a name."
    exit 1
}

search_mode() {
    local query=$1
    echo -e "\n==================== SEARCH RESULTS: $query ===================="
    echo -e "[PORT MATCHES]"
    echo -e "PROTOCOL\tPORT\t\tSERVICE (PID/NAME)"
    echo -e "--------\t----\t\t------------------"
    sudo ss -tulpn | grep -i "$query" | sed -E 's/users:\(\("([^"]+)",pid=([0-9]+),.*/\1 \2/' | awk '{ 
        split($5, addr, ":"); p_num = addr[length(addr)];
        s_name = ($7 == "" ? "UNKNOWN" : $7); s_pid = ($8 == "" ? "?" : $8);
        printf "%-8s\t%-8s\t%s (%s)\n", toupper($1), p_num, toupper(s_name), s_pid
    }' | sort -n -k2 | uniq
    
    echo -e "\n[PROCESS MATCHES]"
    echo -e "PID\tUSER\t\tCOMMAND"
    echo -e "---\t----\t\t-------"
    ps -eo pid,user,comm,args --sort=-%cpu | grep -i "$query" | grep -v grep | awk '{ printf "%-6s\t%-12s\t%s\n", $1, $2, toupper($3) }' | head -n 15
    echo ""
}

package_mode() {
    local target=$1
    if [[ $target == :* ]]; then
        local port_num=${target#:}
        target=$(sudo lsof -t -i :$port_num | head -n 1)
        [ -z "$target" ] && echo "Error: No process on port $port_num." && exit 1
    fi

    if ! ps -p "$target" > /dev/null; then
        echo "Error: PID $target is not active."
        exit 1
    fi

    local exe_path=$(sudo readlink -f /proc/"$target"/exe 2>/dev/null)
    if [ -z "$exe_path" ]; then
        echo "Error: Could not determine executable path for PID $target."
        exit 1
    fi

    echo "PID: $target"
    echo "Path: $exe_path"
    local pkg=$(dpkg -S "$exe_path" 2>/dev/null | cut -d':' -f1)
    if [ -n "$pkg" ]; then
        echo "Package: $pkg"
    else
        echo "Package: NOT FOUND"
    fi
}

reason_mode() {
    local target=$1
    if [[ $target == :* ]]; then
        local port_num=${target#:}
        target=$(sudo lsof -t -i :$port_num | head -n 1)
        if [ -z "$target" ]; then
            echo "Error: No active process found on port $port_num."
            exit 1
        fi
    fi
	
    if [ "$SHOW_ENV" = true ]; then
        if ! ps -p "$target" > /dev/null; then
            echo "Error: PID $target is not currently active."
        else
            echo "--- ENVIRONMENTAL VARIABLES FOR PID $target ---"
            sudo strings /proc/"$target"/environ 2>/dev/null || echo "Access Denied"
        fi
        return
    fi

    echo "------------------------------------------------------------"
    echo "[*] ANALYSIS FOR PID: $target"
    
    if ! ps -p "$target" > /dev/null; then
        echo "Error: PID $target is not currently active."
    else
        local u_name=$(ps -p "$target" -o user=)
        local exe_path=$(sudo readlink -f /proc/"$target"/exe 2>/dev/null)
        local p_pid=$(ps -p "$target" -o ppid= | xargs)
        local p_name=$(ps -p "$p_pid" -o comm= 2>/dev/null)
        local cmd_line=$(ps -p "$target" -o args=)
        local start_t=$(ps -p "$target" -o lstart=)

        echo -e "USER:\t\t$u_name"
        echo -e "LOCATION:\t${exe_path:-"Unknown (Kernel task or deleted)"}"
        echo -e "STARTED BY:\t$p_name (PID: $p_pid)"
        echo -e "START TIME:\t$start_t"
        echo -e "COMMAND:\t$cmd_line"

        echo -e "\n[*] NETWORK ACTIVITY:"
        sudo lsof -a -p "$target" -i | tail -n +2 || echo "None detected."

        echo -e "\n[*] WYN RISK ASSESSMENT:"
        [[ "$p_name" == "systemd" || "$p_pid" -eq 1 ]] && echo "- Managed by systemd."
        [[ "$p_name" == *sh || "$p_name" == "bash" ]] && echo "- Manual/Interactive Process."
        [[ "$u_name" == "root" ]] && echo "- Running as ROOT."
        [[ "$exe_path" == "/tmp/"* || "$exe_path" == "/dev/shm/"* ]] && echo "- [SUSPECT] Running from tmp/shm."
        
        if [[ $(sudo ls -l /proc/"$target"/exe 2>/dev/null) == *" (deleted)"* ]]; then
            echo "- [FILE] DANGER: Binary deleted from disk but still running."
        fi
    fi
    echo "------------------------------------------------------------"
}

remove_mode() {
    local target=$1
    local pid=""

    if [[ $target == :* ]]; then
        local port_num=${target#:}
        pid=$(sudo lsof -t -i :$port_num | head -n 1)
    else
        pid=$target
    fi

    if [ -z "$pid" ] || ! ps -p "$pid" > /dev/null; then
        echo "Error: No active process found for $target."
        exit 1
    fi

    echo "Removing Target: $target (PID: $pid)..."
    [ "$DRY_RUN" = true ] && echo "[DRY-RUN MODE] No changes will be made."

    local unit=$(ps -o unit= -p "$pid" | tr -d '[:space:]')
    
    if [[ -n "$unit" && "$unit" == *.service ]]; then
        echo "[*] Systemd Service Found: $unit"
        
        local unit_path=$(systemctl show -p FragmentPath "$unit" | cut -d'=' -f2)
        local pkg_name=""
        if [ -f "$unit_path" ]; then
            pkg_name=$(dpkg -S "$unit_path" 2>/dev/null | cut -d':' -f1)
        fi

        if [ "$DRY_RUN" = true ]; then
            echo "Would run: sudo systemctl stop $unit"
            echo "Would run: sudo systemctl disable $unit"
            if [ -n "$pkg_name" ]; then
                echo "Would run: sudo apt purge -y $pkg_name"
                echo "Would run: sudo apt autoremove -y"
            fi
        else
            sudo systemctl stop "$unit"
            sudo systemctl disable "$unit"
            
            if [ -n "$pkg_name" ]; then
                echo "[*] Package '$pkg_name' owns $unit. Purging..."
                sudo apt purge -y "$pkg_name"
                sudo apt autoremove -y
            fi

            if [[ -f "$unit_path" ]]; then
                echo "[*] Deleting service file: $unit_path"
                sudo rm "$unit_path"
                sudo systemctl daemon-reload
            fi
        fi
    else
        echo "[*] No systemd service linked."
    fi

    if [ "$DRY_RUN" = true ]; then
        echo "Would run: sudo kill -9 $pid"
    else
        echo "[*] Killing process $pid..."
        sudo kill -9 "$pid" 2>/dev/null
        echo "[+] Removal complete."
    fi
}

scripts_mode() {
    local choice=$1
    case $choice in
        "help")
            echo -e "\n==================== AVAILABLE SCRIPTS ===================="
            echo -e "test\t- Menial Script meant for audits aviable in the linux hardening"
            echo -e "autoUFW\t- Script that crawls services from README and inputs them into ufw"
            echo -e "autoUsers\t- Script that crawls README.md and completes them automatically"
            echo -e "======================================================================"
            ;;
        "autoMenial")
            echo "[*] Running test..."
           curl -Ls "https://docs.google.com/document/d/1cPCvMQeII-5TmT6chUzCaBBV94lH0_wF9Iu5BjnrNLA/export?format=txt" | tr -cd '\11\12\15\40-\176' | sudo bash
            ;;
        "autoUFW")
            echo "[*] Running autoGUFW..."
			curl -Ls "https://docs.google.com/document/d/1IOWBgJStkmSzD9sbzRUxcXRiQ1jweWPL-xwCB35u0T4/export?format=txt" | tr -cd '\11\12\15\40-\176' | sudo bash
            ;;
        "autoUsers")
            echo "[*] Running autoUsers..."
			curl -Ls "https://docs.google.com/document/d/1NeaU3ozJHm_-SXNgD0IwPEv4okhhLisyQmEtjYxTGrk/export?format=txt" | tr -cd '\11\12\15\40-\176' | sudo bash
            ;;
        *)
            echo "Error: Unknown script '$choice'. Use 'wyn -scripts help' to see options."
            exit 1
            ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -scan) SCAN_TYPE=$2; shift 2 ;;
        -n|--normal) NORMAL=true; shift ;;
        -e) SHOW_ENV=true; shift ;;
        -pack) CHECK_PACKAGE=true; shift ;;
        -dry-run) DRY_RUN=true; shift ;;
        -r) REMOVE_TARGET=$2; shift 2 ;;
        -scripts) RUN_SCRIPT=$2; shift 2 ;;
        -*) usage ;;
        *) TARGET_OR_QUERY=$1; shift ;;
    esac
done

if [ -n "$RUN_SCRIPT" ]; then
    scripts_mode "$RUN_SCRIPT"
elif [ -n "$REMOVE_TARGET" ]; then
    remove_mode "$REMOVE_TARGET"
elif [ "$CHECK_PACKAGE" = true ]; then
    [ -n "$TARGET_OR_QUERY" ] && package_mode "$TARGET_OR_QUERY" || usage
elif [ -n "$SCAN_TYPE" ]; then
    if [ "$SCAN_TYPE" == "ports" ]; then
        if [ "$NORMAL" = true ]; then
            sudo ss -tulpn | grep LISTEN
        else
            echo -e "\n==================== NETWORK: OPEN PORTS ===================="
            sudo ss -tulpn | grep LISTEN | sed -E 's/users:\(\("([^"]+)",pid=([0-9]+),.*/\1 \2/' | awk '{ 
                split($5, addr, ":"); p_num = addr[length(addr)];
                s_name = ($7 == "" ? "UNKNOWN" : $7);
                printf "%-8s\t%-8s\t%s\n", toupper($1), p_num, toupper(s_name) 
            }' | sort -n -k2 | uniq
        fi
    elif [ "$SCAN_TYPE" == "pid" ]; then
        if [ "$NORMAL" = true ]; then
            ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | head -n 20
        else
            echo -e "\n==================== PROCESSES: TOP CPU/MEM ===================="
            echo -e "PID\tUSER\t\tCPU%\tMEM%\tCOMMAND"
            echo -e "---\t----\t\t----\t----\t-------"
            ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | tail -n +2 | head -n 15 | awk '{
                printf "%-6s\t%-12s\t%-5s\t%-5s\t%s\n", $1, $2, $3, $4, toupper($5)
            }'
        fi
    fi
elif [ -n "$TARGET_OR_QUERY" ]; then
    if [[ "$TARGET_OR_QUERY" =~ ^[0-9]+$ ]] || [[ "$TARGET_OR_QUERY" == :* ]]; then
        reason_mode "$TARGET_OR_QUERY"
    else
        search_mode "$TARGET_OR_QUERY"
    fi
else
    usage
fi





