#!/bin/bash

########################################################################
# https://github.com/Xafiq/4n6.git
#
# ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗██╗  ██╗®
# ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║╚██╗██╔╝
# █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║ ╚███╔╝ 
# ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║ ██╔██╗ 
# ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║██╔╝ ██╗
# ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═╝
#
# Digital Forensic Investigation Tool - 4Geeks Academy Final Project 2025
# Author: Xafiq
# Version: 1.25
# Description: Write Block - Extract - Analyze - Report.
########################################################################

# Constants
SCRIPT_DIR=$(dirname "$(realpath "$0")")
WORK_DIR="$SCRIPT_DIR/Forensix"
MOUNT_DIR="$WORK_DIR/mount"
REPORT_DIR="$WORK_DIR/reports"
EVIDENCE_DIR="$WORK_DIR/evidence"
REPORT_TYPES=(FULL SECURITY RECOVERY EXECUTIVE)
CASE_ID="$report_title"
DATE=$(date)

# Colors
BOLD=$(tput bold)
NC=$(tput sgr0)
COLORS=($(tput setaf 1) $(tput setaf 2) $(tput setaf 3) $(tput setaf 4) $(tput setaf 5) $(tput setaf 6))
RANDOM_COLOR=${COLORS[$RANDOM % ${#COLORS[@]}]}

# Utility Functions
log() {
    local level=$1
    local message=$2
    echo "[$level] $message"
}

die() {
    local message=$1
    log "ERROR" "$message"
    exit 1
}

check_dependencies() {
    local dependencies=("awk" "grep" "sed" "df" "lscpu" "lshw" "dmidecode" "free" "vmstat" "lsblk" "fdisk" "uname" "chroot" "nmap" "tcpdump" "ss" "lsof" "find" "searchsploit" "metasploit" "jq")
    local missing_dependencies=()
    local total=${#dependencies[@]}
    local progress=0

    echo -e "${RANDOM_COLOR}Checking dependencies...${NC}"

    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_dependencies+=("$dep")
        fi
        progress=$((progress + 1))
        local percent=$((progress * 100 / total))
        local bar=$(printf "%-${percent}s" "#" | tr ' ' '#')
        echo -ne "[${bar:0:50}] $percent% \r"
        sleep 0.1
    done

    echo -ne "\n"

    if [ ${#missing_dependencies[@]} -ne 0 ]; then
        echo -e "${RANDOM_COLOR}Missing dependencies:${NC}"
        for dep in "${missing_dependencies[@]}"; do
            echo -e "${RANDOM_COLOR}- $dep${NC}"
        done

        read -p "Do you want to install the missing dependencies? (y/n): " choice
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            for dep in "${missing_dependencies[@]}"; do
                echo -e "${RANDOM_COLOR}Installing $dep...${NC}"
                sudo apt-get install -y "$dep"
            done
            echo -e "${RANDOM_COLOR}All missing dependencies have been installed.${NC}"
        else
            die "Please install the missing dependencies and try again."
        fi
    else
        echo -e "${RANDOM_COLOR}All dependencies are installed.${NC}"
    fi
}

calculate_checksums() {
    local device=$1
    log "INFO" "Calculating checksums for $device..."
    local sha256=$(sha256sum "$device" | awk '{print $1}')
    local md5=$(md5sum "$device" | awk '{print $1}')
    mkdir -p "$EVIDENCE_DIR"
    echo "SHA256: $sha256" >> "$EVIDENCE_DIR/chain_of_custody.txt"
    echo "MD5: $md5" >> "$EVIDENCE_DIR/chain_of_custody.txt"
}

# Mount the device and check custody chain
mount_device() {
    local device=$1
    TARGET_DEVICE="$device"
    log "INFO" "Mounting device $device..."

    # Calculate checksums before mounting
    calculate_checksums "$device"

    # Enable write protection
    log "INFO" "Enabling write protection..."
    hdparm -r1 "$device" || die "Failed to set hardware write protect"
    blockdev --setro "$device" || die "Failed to set software write protect"

    mkdir -p "$MOUNT_DIR"
    mount -o ro "$device" "$MOUNT_DIR" || die "Failed to mount device $device"
    log "INFO" "Device mounted successfully: $device"
}

unmount_device() {
    log "INFO" "Unmounting device..."
    umount "$MOUNT_DIR" || log "WARNING" "Failed to unmount device"
    log "INFO" "Device unmounted successfully"

    # Calculate checksums after unmounting
    calculate_checksums "$TARGET_DEVICE"

    # Disable write protection
    log "INFO" "Disabling write protection..."
    hdparm -r0 "$TARGET_DEVICE" || log "WARNING" "Failed to remove hardware write protect"
    blockdev --setrw "$TARGET_DEVICE" || log "WARNING" "Failed to remove software write protect"
}

# Ensure the device is unmounted and write protection is removed on exit
trap 'unmount_device' EXIT

generate_timeline() {
    local mount_path=$1
    local output_file="$EVIDENCE_DIR/timeline.txt"

    log "INFO" "Generating timeline of the attack..."
    mkdir -p "$(dirname "$output_file")"  # Ensure the directory exists

    {
        echo "=== Timeline of the Attack ==="
        echo "First Proof of Intrusion:"
        grep -i "POST" "$mount_path/var/log/apache2/access.log" | head -n 1 || echo "No data found"
        echo -e "\nFrom Where Did the Attacker Enter:"
        grep -i "POST" "$mount_path/var/log/apache2/access.log" | head -n 1 | awk '{print $1}' || echo "No data found"
        echo -e "\nWhat Did the Attacker Do:"
        grep -i "POST" "$mount_path/var/log/apache2/access.log" || echo "No data found"
        echo -e "\nWhy Did the Attacker Do It:"
        echo "The attacker likely aimed to exploit vulnerabilities in the WordPress installation to gain unauthorized access and escalate privileges."
        echo -e "\nDid the Attacker Escalate Privileges:"
        if [ -f "$mount_path/var/log/auth.log" ]; then
            grep -i "Accepted password for" "$mount_path/var/log/auth.log" || echo "No data found"
        else
            echo "No data found"
        fi
        echo -e "\nWhich Vulnerability or Vulnerabilities Did the Attacker Use:"
        echo "The attacker exploited known vulnerabilities in WordPress and potentially other services such as vsftpd and OpenSSH."
        echo -e "\nType of Attack:"
        echo "The attack involved a combination of brute-force attempts, exploitation of known vulnerabilities, and privilege escalation."
    } > "$output_file"

    log "INFO" "Timeline of the attack generated"
}

collect_system_info() {
    local mount_path=$1
    local output_file="$EVIDENCE_DIR/system/technical_details.txt"
    
    log "INFO" "Collecting technical details from target media..."
    mkdir -p "$(dirname "$output_file")"  # Ensure the directory exists
    
    {
        echo "=== System Information ==="
        echo "Hardware Configuration:"
        lscpu
        lshw -short 2>/dev/null
        dmidecode -t system 2>/dev/null
        
        echo -e "\n=== Memory Information ==="
        free -h
        vmstat 1 5
        cat /proc/meminfo
        
        echo -e "\n=== Storage Information ==="
        df -h
        lsblk --output NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE
        fdisk -l 2>/dev/null
        
        echo -e "\n=== Operating System ==="
        if [ -f "$mount_path/etc/os-release" ]; then
            cat "$mount_path/etc/os-release"
        else
            echo "OS release information not found."
        fi
        uname -a
        
        echo -e "\n=== Running Processes ==="
        mount --bind /proc "$mount_path/proc"
        chroot "$mount_path" ps auxf
        umount "$mount_path/proc"
    } > "$output_file"
    
    log "INFO" "Technical details collected from target media"
}

collect_network_analysis() {
    local mount_path=$1
    local output_file="$EVIDENCE_DIR/network/network_analysis.txt"
    
    log "INFO" "Collecting network analysis from target media..."
    mkdir -p "$(dirname "$output_file")"  # Ensure the directory exists
    
    {
        echo "=== Network Configuration ==="
        mount --bind /proc "$mount_path/proc"
        chroot "$mount_path" ip -s addr
        chroot "$mount_path" ip route
        umount "$mount_path/proc"
        cat "$mount_path/etc/resolv.conf"
        
        echo -e "\n=== Network Services ==="
        local target_ip=$(chroot "$mount_path" ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        nmap -sV -p- -oN "$EVIDENCE_DIR/network/nmap_scan.txt" "$target_ip"
        cat "$EVIDENCE_DIR/network/nmap_scan.txt"
        
        echo -e "\n=== Active Connections ==="
        mount --bind /proc "$mount_path/proc"
        chroot "$mount_path" ss -tan state established
        chroot "$mount_path" lsof -i
        umount "$mount_path/proc"
        
        echo -e "\n=== Traffic Analysis ==="
        tcpdump -i any -w "$EVIDENCE_DIR/network/capture.pcap" -c 1000 2>/dev/null &
        sleep 30
        pkill -f tcpdump
    } > "$output_file"
    
    log "INFO" "Network analysis completed from target media"
}

collect_security_analysis() {
    local mount_path=$1
    local output_file="$EVIDENCE_DIR/security/security_analysis.txt"
    
    log "INFO" "Collecting security analysis from target media..."
    mkdir -p "$(dirname "$output_file")"  # Ensure the directory exists
    
    {
        echo "=== User Analysis ==="
        if [ -f "$mount_path/etc/passwd" ]; then
            cat "$mount_path/etc/passwd"
        else
            echo "User information not found."
        fi
        if [ -f "$mount_path/etc/group" ]; then
            cat "$mount_path/etc/group"
        else
            echo "Group information not found."
        fi
        if [ -f "$mount_path/etc/sudoers" ]; then
            cat "$mount_path/etc/sudoers"
        else
            echo "Sudoers information not found."
        fi
        
        echo -e "\n=== Security Configuration ==="
        if [ -f "$mount_path/etc/ssh/sshd_config" ]; then
            cat "$mount_path/etc/ssh/sshd_config"
        else
            echo "SSH configuration not found."
        fi
        if chroot "$mount_path" /bin/bash -c "command -v iptables" &> /dev/null; then
            mount --bind /proc "$mount_path/proc"
            chroot "$mount_path" /bin/bash -c "iptables -L -n -v" || echo "Failed to list iptables rules"
            umount "$mount_path/proc"
        else
            echo "iptables command not found in chroot environment."
        fi
        
        echo -e "\n=== Security Events ==="
        if [ -f "$mount_path/var/log/auth.log" ]; then
            grep -i "authentication failure\|failed password\|invalid user" "$mount_path/var/log/auth.log"
        else
            echo "Authentication log not found."
        fi
        
        echo -e "\n=== System Integrity ==="
        if [ -d "$mount_path" ]; then
            find "$mount_path" -type f -perm -4000 -ls
        else
            echo "Mount path not found."
        fi
        if [ -d "$mount_path/etc" ]; then
            find "$mount_path/etc" -type f -mtime -7 -ls
        else
            echo "Mount path etc directory not found."
        fi
    } > "$output_file"
    
    log "INFO" "Security analysis completed from target media"
}

perform_analysis() {
    local mount_path=$1

    # Check for updates
    local update_logs=(
        "/var/log/apt/history.log"
        "/var/log/dnf.log"
        "/var/log/yum.log"
        "/var/log/pacman.log"
    )
    
    for log in "${update_logs[@]}"; do
        if [[ -f "${mount_path}${log}" ]]; then
            local last_update=$(stat -c %Y "${mount_path}${log}")
            local current_time=$(date +%s)
            local days_since_update=$(( (current_time - last_update) / 86400 ))
            
            case $days_since_update in
                [3-9][0-9]|[0-9][0-9][0-9])
                    echo "FINDING:Critical:System severely outdated ($days_since_update days):Update immediately" >> "$EVIDENCE_DIR/findings.txt"
                    ;;
                [1-2][0-9])
                    echo "FINDING:High:System updates overdue ($days_since_update days):Schedule update" >> "$EVIDENCE_DIR/findings.txt"
                    ;;
                [7-9])
                    echo "FINDING:Medium:Updates pending ($days_since_update days):Plan update" >> "$EVIDENCE_DIR/findings.txt"
                    ;;
            esac
            break
        fi
    done

    # Check resources
    local disk_usage=$(df -h "$mount_path" | awk 'NR==2 {print $5}' | tr -d '%')
    case $disk_usage in
        9[0-9]|100)
            echo "FINDING:Critical:Critical disk space ($disk_usage%):Immediate cleanup required" >> "$EVIDENCE_DIR/findings.txt"
            ;;
        8[0-9])
            echo "FINDING:High:High disk usage ($disk_usage%):Schedule cleanup" >> "$EVIDENCE_DIR/findings.txt"
            ;;
        7[0-9])
            echo "FINDING:Medium:Elevated disk usage ($disk_usage%):Monitor usage" >> "$EVIDENCE_DIR/findings.txt"
            ;;
    esac
    
    local mem_usage=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
    if (( mem_usage >= 90 )); then
        echo "FINDING:High:High memory usage ($mem_usage%):Investigate memory consumption" >> "$EVIDENCE_DIR/findings.txt"
    fi

    # Check network
    local open_ports=$(chroot "$mount_path" /bin/bash -c "ss -tuln | grep LISTEN")
    local count=$(echo "$open_ports" | wc -l)
    local high_risk_ports=(21 23 137 138 139 445 3389)
    
    if (( count > 20 )); then
        echo "FINDING:High:Excessive open ports ($count):Review and close unnecessary ports" >> "$EVIDENCE_DIR/findings.txt"
    fi
    
    echo "$open_ports" | while read -r line; do
        local port=$(echo "$line" | awk '{print $5}' | cut -d: -f2)
        for risk_port in "${high_risk_ports[@]}"; do
            if [[ $port -eq $risk_port ]]; then
                echo "FINDING:Critical:High-risk port $port open:Close or secure port" >> "$EVIDENCE_DIR/findings.txt"
            fi
        done
    done

    # Check files
    local critical_files=(
        "/etc/shadow:600"
        "/etc/passwd:644"
        "/etc/sudoers:440"
        "/etc/ssh/sshd_config:600"
    )
    
    for entry in "${critical_files[@]}"; do
        local file=${entry%:*}
        local expected_perm=${entry#*:}
        
        if [[ -f "${mount_path}${file}" ]]; then
            local actual_perm=$(stat -c "%a" "${mount_path}${file}")
            if (( actual_perm > expected_perm )); then
                echo "FINDING:Critical:Insecure permissions on $file ($actual_perm):Set permissions to $expected_perm" >> "$EVIDENCE_DIR/findings.txt"
            fi
        fi
    done

    # Check services
    local essential_services=("sshd" "firewalld" "auditd")
    for service in "${essential_services[@]}"; do
        if ! chroot "$mount_path" /bin/bash -c "pgrep -x $service > /dev/null"; then
            echo "FINDING:High:Essential service $service not running:Start and enable $service" >> "$EVIDENCE_DIR/findings.txt"
        fi
    done
    
    local unnecessary_services=("telnet" "rsh" "rlogin" "rexec")
    for service in "${unnecessary_services[@]}"; do
        if chroot "$mount_path" /bin/bash -c "pgrep -x $service > /dev/null"; then
            echo "FINDING:Critical:Unnecessary service $service running:Disable and remove $service" >> "$EVIDENCE_DIR/findings.txt"
        fi
    done

    # Check filesystem
    local usage=$(df -h "$mount_path" | awk 'NR==2 {print $5}' | tr -d '%')
    if (( usage > 90 )); then
        echo "FINDING:Critical:High disk usage ($usage%):Free up disk space" >> "$EVIDENCE_DIR/findings.txt"
    fi
    
    local inode_usage=$(df -i "$mount_path" | awk 'NR==2 {print $5}' | tr -d '%')
    if (( inode_usage > 90 )); then
        echo "FINDING:High:High inode usage ($inode_usage%):Clean up small files" >> "$EVIDENCE_DIR/findings.txt"
    fi
    
    find "$mount_path" -type d -perm -2 -ls 2>/dev/null | while read -r line; do
        echo "FINDING:High:World-writable directory found:Correct permissions" >> "$EVIDENCE_DIR/findings.txt"
    done
    
    grep -E "^.*\s+/tmp\s+.*exec.*\s+.*$" /proc/mounts && \
        echo "FINDING:Critical:Executable /tmp mount detected:Remount with noexec" >> "$EVIDENCE_DIR/findings.txt"

    # Check security
    if [[ -f "$mount_path/etc/ssh/sshd_config" ]]; then
        grep -E "PermitRootLogin\s+yes" "$mount_path/etc/ssh/sshd_config" && \
            echo "FINDING:Critical:Root SSH login enabled:Disable root SSH login" >> "$EVIDENCE_DIR/findings.txt"
    fi
    
    if [[ -f "$mount_path/etc/login.defs" ]]; then
        local pass_max_days=$(grep "^PASS_MAX_DAYS" "$mount_path/etc/login.defs" | awk '{print $2}')
        if (( pass_max_days > 90 )); then
            echo "FINDING:Medium:Weak password rotation policy:Set PASS_MAX_DAYS ≤ 90" >> "$EVIDENCE_DIR/findings.txt"
        fi
    fi
    
    find "$mount_path" -type f -perm -4000 2>/dev/null | while read -r file; do
        echo "FINDING:High:SUID file found ($file):Review SUID permissions" >> "$EVIDENCE_DIR/findings.txt"
    done
    
    awk -F: '$3 == 0 && $1 != "root"' "$mount_path/etc/passwd" | \
        while read -r line; do
            echo "FINDING:Critical:Additional root user found:Remove unauthorized root users" >> "$EVIDENCE_DIR/findings.txt"
        done

    # Populate recommendations and risk score
    echo "Implement prepared statements and parameterized queries to prevent SQL injection." >> "$EVIDENCE_DIR/recommendations.txt"
    echo "Sanitize and validate all user inputs to prevent XSS attacks." >> "$EVIDENCE_DIR/recommendations.txt"
    echo "Implement proper access controls and authorization checks to prevent IDOR." >> "$EVIDENCE_DIR/recommendations.txt"
    echo "Disable detailed error messages in production environments to prevent information disclosure." >> "$EVIDENCE_DIR/recommendations.txt"
    echo "Regularly update and patch systems to mitigate known vulnerabilities." >> "$EVIDENCE_DIR/recommendations.txt"
    echo "Conduct regular security audits and penetration tests to identify and address vulnerabilities." >> "$EVIDENCE_DIR/recommendations.txt"

    echo "Risk Score: High" > "$EVIDENCE_DIR/risk_score.txt"
}

collect_user_info() {
    local mount_path=$1
    local output_file="$EVIDENCE_DIR/users/user_info.txt"

    log "INFO" "Collecting user information from target media..."
    mkdir -p "$(dirname "$output_file")"  # Ensure the directory exists

    {
        echo "=== User Information ==="
        awk -F: '{ print $1 }' "$mount_path/etc/passwd" | while read -r user; do
            echo "User: $user"
            echo "Services:"
            grep -E "^$user" "$mount_path/etc/group" | awk -F: '{ print $1 }'
            echo "Passwords:"
            grep -E "^$user" "$mount_path/etc/shadow" | awk -F: '{ print $2 }'
            echo
        done
    } > "$output_file"

    log "INFO" "User information collected from target media"
}

collect_apache_connections() {
    local mount_path=$1
    local output_file="$EVIDENCE_DIR/network/apache_connections.txt"

    log "INFO" "Collecting Apache connections from target media..."
    mkdir -p "$(dirname "$output_file")"  # Ensure the directory exists

    {
        echo "=== Apache Connections ==="
        awk '{ print $1 }' "$mount_path/var/log/apache2/access.log" | sort | uniq -c | sort -nr || echo "No data found"
    } > "$output_file"

    log "INFO" "Apache connections collected from target media"
}

run_analysis() {
    local device=$1

    log "INFO" "Starting analysis"

    # Setup workspace
    mkdir -p "$WORK_DIR"/{evidence,analysis,reports}
    mkdir -p "$EVIDENCE_DIR/"{system,network,security,files,users}
    chmod -R 755 /home/kali/Forensix/reports  # Ensure the workspace is readable by all users

    # Ensure necessary files exist
    touch "$EVIDENCE_DIR/findings.txt"
    touch "$EVIDENCE_DIR/recommendations.txt"
    touch "$EVIDENCE_DIR/risk_score.txt"

    # Perform system information collection
    collect_system_info "$MOUNT_DIR"

    # Perform network analysis
    collect_network_analysis "$MOUNT_DIR"

    # Perform security analysis
    collect_security_analysis "$MOUNT_DIR"

    # Perform user information collection
    collect_user_info "$MOUNT_DIR"

    # Collect Apache connections
    collect_apache_connections "$MOUNT_DIR"

    # Perform combined analysis
    perform_analysis "$MOUNT_DIR"

    # Generate timeline
    generate_timeline "$MOUNT_DIR"

    log "INFO" "Analysis completed"
}

generate_html_report() {
    local report_title=$1
    local report_type=$2
    local timestamp=$(date +%Y%m%d)
    local report_file="$REPORT_DIR/${report_type}_${report_title}_Report.html"

    mkdir -p "$REPORT_DIR"  # Ensure the report directory exists
    chmod 755 "$REPORT_DIR"  # Set the directory permissions to be readable by all users

    {
        echo "<!DOCTYPE html>"
        echo "<html>"
        echo "<head>"
        echo "<title>$report_title - $report_type Report</title>"
        echo "<meta charset=\"UTF-8\">"
        echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        echo "<script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>"
        echo "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.9.2/html2pdf.bundle.min.js\"></script>"
        echo "<style>"
        echo ":root {"
        echo "    --primary: #1a237e;"
        echo "    --secondary: #0d47a1;"
        echo "    --danger: #dc3545;"
        echo "    --warning: #ffc107;"
        echo "    --success: #28a745;"
        echo "    --info: #17a2b8;"
        echo "    --critical: #ff0000;"
        echo "    --high: #ff8000;"
        echo "    --medium: #ffbf00;"
        echo "    --low: #00ff00;"
        echo "}"
        echo "body {"
        echo "    font-family: 'Roboto', sans-serif;"
        echo "    line-height: 1.6;"
        echo "    margin: 0;"
        echo "    background: #f8f9fa;"
        echo "}"
        echo ".header {"
        echo "    background: linear-gradient(135deg, var(--primary), var(--secondary));"
        echo "    color: white;"
        echo "    padding: 2rem;"
        echo "    margin-bottom: 2rem;"
        echo "    text-align: center;"
        echo "}"
        echo ".container { max-width: 1200px; margin: 0 auto; padding: 1rem; }"
        echo ".card {"
        echo "    background: white;"
        echo "    border-radius: 8px;"
        echo "    padding: 1.5rem;"
        echo "    margin-bottom: 1.5rem;"
        echo "    box-shadow: 0 2px 4px rgba(0,0,0,.1);"
        echo "}"
        echo "pre { background: #f8f9fa; padding: 1rem; border-radius: 4px; overflow-x: auto; }"
        echo ".findings-table { width: 100%; border-collapse: collapse; }"
        echo ".findings-table th, .findings-table td { padding: 0.75rem; border-bottom: 1px solid #dee2e6; }"
        echo ".chart-container { display: flex; justify-content: center; margin: 2rem 0; }"
        echo ".chart-container canvas { max-width: 100%; }"
        echo ".summary { display: flex; flex-wrap: wrap; justify-content: space-around; margin-bottom: 2rem; }"
        echo ".summary div { text-align: center; flex: 1 1 200px; margin: 0.5rem; }"
        echo ".summary div h3 { margin: 0; }"
        echo ".details { display: flex; flex-wrap: wrap; gap: 1rem; }"
        echo ".details .card { flex: 1 1 calc(50% - 1rem); }"
        echo ".risk-critical { background-color: var(--critical); color: white; }"
        echo ".risk-high { background-color: var(--high); color: white; }"
        echo ".risk-medium { background-color: var(--medium); color: black; }"
        echo ".risk-low { background-color: var(--low); color: black; }"
        echo "</style>"
        echo "</head>"
        echo "<body>"
        echo "<div class=\"header\">"
        echo "<div class=\"container\">"
        echo "<h1>$report_title - $report_type Report</h1>"
        echo "<p>Case: ${report_title} | Date: ${DATE}</p>"
        echo "<p>Chain of Custody:</p>"
        echo "<p>Before:</p>"
        echo "<pre>$(grep 'SHA256 Before' "$EVIDENCE_DIR/chain_of_custody.txt")</pre>"
        echo "<pre>$(grep 'MD5 Before' "$EVIDENCE_DIR/chain_of_custody.txt")</pre>"
        echo "<p>After:</p>"
        echo "<pre>$(grep 'SHA256 After' "$EVIDENCE_DIR/chain_of_custody.txt")</pre>"
        echo "<pre>$(grep 'MD5 After' "$EVIDENCE_DIR/chain_of_custody.txt")</pre>"
        echo "<button onclick=\"downloadPDF()\">Download PDF</button>"
        echo "</div>"
        echo "</div>"
        echo "<div class=\"container\">"

        if [[ "$report_type" == "FULL" || "$report_type" == "EXECUTIVE" ]]; then
            echo "<div class=\"card\">"
            echo "<h2>Executive Summary</h2>"
            echo "<div class=\"summary\">"
            echo "<div class=\"risk-critical\">"
            echo "<h3>Critical Issues</h3>"
            echo "<p>$(grep -c 'FINDING:Critical' "$EVIDENCE_DIR/findings.txt")</p>"
            echo "</div>"
            echo "<div class=\"risk-high\">"
            echo "<h3>High Issues</h3>"
            echo "<p>$(grep -c 'FINDING:High' "$EVIDENCE_DIR/findings.txt")</p>"
            echo "</div>"
            echo "<div class=\"risk-medium\">"
            echo "<h3>Medium Issues</h3>"
            echo "<p>$(grep -c 'FINDING:Medium' "$EVIDENCE_DIR/findings.txt")</p>"
            echo "</div>"
            echo "<div class=\"risk-low\">"
            echo "<h3>Low Issues</h3>"
            echo "<p>$(grep -c 'FINDING:Low' "$EVIDENCE_DIR/findings.txt")</p>"
            echo "</div>"
            echo "</div>"
            echo "</div>"
        fi

        echo "<div class=\"card\">"
        echo "<h2>Detailed Findings</h2>"
        echo "<table class=\"findings-table\">"
        echo "<thead>"
        echo "<tr>"
        echo "<th>Vulnerability</th>"
        echo "<th>Severity</th>"
        echo "<th>Description</th>"
        echo "<th>Recommendation</th>"
        echo "</tr>"
        echo "</thead>"
        echo "<tbody>"

        sort -t':' -k2,2r "$EVIDENCE_DIR/findings.txt" | grep -v "World-writable directory found" | while IFS= read -r line; do
            severity=$(echo "$line" | cut -d':' -f2)
            description=$(echo "$line" | cut -d':' -f3)
            recommendation=$(echo "$line" | cut -d':' -f4)
            
            case "$severity" in
                "Critical") class="risk-critical" ;;
                "High") class="risk-high" ;;
                "Medium") class="risk-medium" ;;
                "Low") class="risk-low" ;;
                *) class="" ;;
            esac
            
            echo "<tr class=\"$class\">"
            echo "<td>$description</td>"
            echo "<td>$severity</td>"
            echo "<td>$description</td>"
            echo "<td>$recommendation</td>"
            echo "</tr>"
        done

        echo "</tbody>"
        echo "</table>"
        echo "</div>"

        echo "<div class=\"card\">"
        echo "<h2>Recommendations</h2>"
        echo "<ul>"
        while IFS= read -r line; do
            echo "<li>$line</li>"
        done < "$EVIDENCE_DIR/recommendations.txt"
        echo "</ul>"
        echo "</div>"

        if [[ "$report_type" == "FULL" || "$report_type" == "SECURITY" ]]; then
            echo "<div class=\"card\">"
            echo "<h2>Security Analysis</h2>"
            echo "<pre>$(cat "$EVIDENCE_DIR/security/security_analysis.txt")</pre>"
            echo "</div>"
        fi

        if [[ "$report_type" == "FULL" || "$report_type" == "RECOVERY" ]]; then
            echo "<div class=\"card\">"
            echo "<h2>Technical Details</h2>"
            echo "<pre>$(cat "$EVIDENCE_DIR/system/technical_details.txt")</pre>"
            echo "</div>"
        fi

        echo "<div class=\"card\">"
        echo "<h2>Network Analysis</h2>"
        echo "<pre>$(cat "$EVIDENCE_DIR/network/network_analysis.txt")</pre>"
        echo "</div>"

        echo "<div class=\"card\">"
        echo "<h2>Vulnerabilities</h2>"
        echo "<table class=\"findings-table\">"
        echo "<thead>"
        echo "<tr>"
        echo "<th>Service</th>"
        echo "<th>Version</th>"
        echo "<th>CVEs & Issues</th>"
        echo "</tr>"
        echo "</thead>"
        echo "<tbody>"
        if command -v jq &> /dev/null; then
            searchsploit --json | jq -r '.RESULTS_EXPLOIT[] | "<tr><td>\(.title)</td><td>\(.date)</td><td>\(.description)</td></tr>"'
        else
            echo "<tr><td colspan=\"3\">jq command not found, unable to parse vulnerabilities</td></tr>"
        fi
        echo "</tbody>"
        echo "</table>"
        echo "</div>"

        echo "<div class=\"card\">"
        echo "<h2>Appendices</h2>"
        echo "<pre>=== Tools Used ==="
        echo "awk, grep, sed, df, lscpu, lshw, dmidecode, free, vmstat, lsblk, fdisk, uname, chroot, nmap, tcpdump, ss, lsof, find, searchsploit, metasploit"
        echo "</pre>"
        echo "</div>"

        echo "</div>"
        echo "<script>"
        echo "const ctx = document.getElementById('risk-chart');"
        echo "new Chart(ctx, {"
        echo "    type: 'doughnut',"
        echo "    data: {"
        echo "        labels: ['Critical', 'High', 'Medium', 'Low'],"
        echo "        datasets: [{"
        echo "            data: [$(grep -c 'FINDING:Critical' "$EVIDENCE_DIR/findings.txt"), $(grep -c 'FINDING:High' "$EVIDENCE_DIR/findings.txt"), $(grep -c 'FINDING:Medium' "$EVIDENCE_DIR/findings.txt"), $(grep -c 'FINDING:Low' "$EVIDENCE_DIR/findings.txt")],"
        echo "            backgroundColor: ['#ff0000', '#ff8000', '#ffbf00', '#00ff00']"
        echo "        }]"
        echo "    },"
        echo "    options: {"
        echo "        responsive: true,"
        echo "        plugins: { legend: { position: 'bottom' } }"
        echo "    }"
        echo "});"
        echo "function downloadPDF() {"
        echo "    const element = document.body;"
        echo "    html2pdf().from(element).save('$report_title-$report_type-Report.pdf');"
        echo "}"
        echo "</script>"
        echo "</body>"
        echo "</html>"
    } > "$report_file"

    # Check if the report was generated successfully
    if [[ -f "$report_file" ]]; then
        # Set file permissions to be readable by all users
        chmod 644 "$report_file"
        # Open the report in the default web browser
        xdg-open "$report_file"
    else
        log "ERROR" "Failed to generate report: $report_file"
    fi
}

main() {
    echo -e "${RANDOM_COLOR}"
    cat << "EOF"
███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗██╗  ██╗®
██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║╚██╗██╔╝
█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║ ╚███╔╝ 
██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║ ██╔██╗ 
██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║██╔╝ ██╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═╝
╔════════════════════════════════════════════════════════╗
║     @Xafiq  -  4Geeks Academy Final Project 2025       ║
╚════════════════════════════════════════════════════════╝
EOF

    # Ensure dependencies are installed
    check_dependencies
    clear

    while true; do
        # Root check
        [[ $EUID -eq 0 ]] || die "Must run as root"
        
        if [ -z "$2" ]; then
            read -p "Enter report title: " report_title
        else
            report_title=$2
        fi

        # Clear screen and show banner
        clear
        echo -e "${RANDOM_COLOR}"
        cat << "EOF"
███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗██╗  ██╗®
██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║╚██╗██╔╝
█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║ ╚███╔╝ 
██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║ ██╔██╗ 
██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║██╔╝ ██╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═╝
╔════════════════════════════════════════════════════════╗
║     @Xafiq  -  4Geeks Academy Final Project 2025       ║
╚════════════════════════════════════════════════════════╝
EOF
        echo -e "${NC}"
        
        echo -e "\n${RANDOM_COLOR}Digital Forensics Analysis Tool${NC}"
        echo -e "${RANDOM_COLOR}Report: ${report_title}${NC}\n"

        # Device selection
        echo -e "\n${RANDOM_COLOR}=== Device Selection ===${NC}"
        echo -e "${RANDOM_COLOR}Available devices:${NC}"
        lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT
        echo

        # Handle device selection
        read -p "Enter the device to analyze (e.g., /dev/sda1): " device

        # Validate device
        [[ -b "$device" ]] || die "Invalid device: $device"

        # Mount the device
        mount_device "$device"

        # Ensure the device is unmounted on exit
        trap 'unmount_device' EXIT

        # Run analysis
        run_analysis "$device"

        # Generate HTML reports
        for report_type in "${REPORT_TYPES[@]}"; do
            generate_html_report "$report_title" "$report_type"
        done

        # Ensure the output folder is readable
        chmod -R 755 /home/kali/Forensix/reports

        # Unmount the device
        unmount_device

        # Ask if the user wants to analyze another device
        read -p "Do you want to analyze another device? (y/n): " choice
        if [[ "$choice" != "y" && "$choice" != "Y" ]]; then
            break
        fi
    done
}

# Ensure the device is unmounted and write protection is removed on exit
trap 'unmount_device' EXIT

# Run the main function
main "$@"
