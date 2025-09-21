#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e #x  #add x for debugging

# Error trap to capture failures
error_exit() {
    local exit_code=$?
    local line_number=$1
    log "ERROR: Command failed at line $line_number with exit code $exit_code"
    log "ERROR: Last command that failed: ${BASH_COMMAND}"
    exit $exit_code
}

# Set up error trap
trap 'error_exit $LINENO' ERR

# Check if running as root, if not re-execute with sudo
check_root_privileges() {
    if [ "$EUID" -ne 0 ]; then
        # Check if running from pipe (curl | bash)
        if [ ! -t 0 ] || [[ "$0" == "bash" ]] || [[ "$0" == "/bin/bash" ]] || [[ "$0" == "/usr/bin/bash" ]]; then
            echo "ERROR: This script requires root privileges."
            echo "Please run with sudo:"
            echo "  curl -s https://pown.sh | sudo bash -s -- $*"
            exit 1
        else
            echo "Script requires root privileges. Re-executing with sudo..."  # cant use log yet
            exec sudo "$0" "$@"
        fi
    fi
}

# Check root privileges first
check_root_privileges "$@"

# Load environment variables
[ -f .env ] && export $(grep -v '^#' .env | xargs)

# Configuration variables
readonly LOGFILE="/etc/pown.sh.setup.log"
readonly SSSD_CONF="/etc/sssd/sssd.conf"
readonly SSH_CONF="/etc/ssh/sshd_config"
readonly PAM_SSHD="/etc/pam.d/sshd"
readonly PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"

# Function to get packages for package manager
get_packages() {
    local pm=$1
    case $pm in
        apt)
            echo "ldap-utils openssh-client openssh-server sssd sssd-ldap sudo libnss-sss libpam-sss ca-certificates vim net-tools iputils-ping dnsutils"
            ;;
        yum)
            echo "openssh-clients openssh-server sssd sssd-ldap sudo openldap-clients ca-certificates vim net-tools iputils authselect authconfig bind-utils"
            ;;
        pacman)
            echo "openssh sssd openldap sudo ca-certificates vim net-tools iputils pam pambase bind"
            ;;
        dnf)
            echo "openssh-clients openssh-server sssd sssd-ldap sudo openldap-clients ca-certificates vim net-tools iputils authselect authconfig bind-utils"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOGFILE
}

# Function to generate LDAP_BASE from domain
generate_ldap_base_from_domain() {
    local domain=$1
    # Convert domain to LDAP DN format (example.com -> dc=example,dc=com)
    echo "$domain" | sed 's/\./,dc=/g' | sed 's/^/dc=/'
}

# Function to ensure DNS tools are available
ensure_dns_tools() {
    if command -v dig >/dev/null 2>&1 || command -v nslookup >/dev/null 2>&1; then
        return 0
    fi
    
    log "DNS tools not found. Installing..."
    local package_manager=$(detect_package_manager)
    
    case $package_manager in
        apt)
            sudo apt-get update && sudo apt-get install -y dnsutils
            ;;
        yum)
            sudo yum install -y bind-utils
            ;;
        dnf)
            sudo dnf install -y bind-utils
            ;;
        pacman)
            sudo pacman -S --noconfirm bind
            ;;
        *)
            log "Warning: Could not install DNS tools for package manager: $package_manager"
            return 1
            ;;
    esac
}

# Function to perform SRV record lookup with fallbacks
lookup_srv_records() {
    local service=$1
    local domain=$2
    local srv_query="${service}.${domain}"
    
    if command -v dig >/dev/null 2>&1; then
        dig +short "$srv_query" SRV 2>/dev/null
    elif command -v nslookup >/dev/null 2>&1; then
        nslookup -type=SRV "$srv_query" 2>/dev/null | grep -E '^[^;].*SRV' | awk '{print $5, $6, $7, $8}' | sed 's/\.$//'
    else
        log "Warning: No DNS tools available for SRV lookup"
        return 1
    fi
}

# Function to test if a host/port combination is reachable
test_ldap_port() {
    local host=$1
    local port=$2
    local timeout=3
    
    # Use nc (netcat) or timeout+bash to test connectivity
    if command -v nc >/dev/null 2>&1; then
        nc -z -w "$timeout" "$host" "$port" >/dev/null 2>&1
    elif command -v timeout >/dev/null 2>&1; then
        timeout "$timeout" bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
    else
        # Fallback: try to connect with bash
        bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
    fi
}

# Function to extract CA certificate from LDAP server
extract_ca_certificate() {
    local ldap_uri=$1
    local host port
    
    # Parse the LDAP URI to extract host and port
    if [[ "$ldap_uri" =~ ^ldaps?://([^:]+):?([0-9]+)?$ ]]; then
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        
        # Default ports if not specified
        if [ -z "$port" ]; then
            if [[ "$ldap_uri" =~ ^ldaps:// ]]; then
                port=636
            else
                port=389
            fi
        fi
    else
        log "Warning: Could not parse LDAP URI: $ldap_uri"
        return 1
    fi
    
    # Only try to extract certificate for LDAPS connections
    if [[ "$ldap_uri" =~ ^ldaps:// ]]; then
        log "Attempting to extract CA certificate from $host:$port..."
        
        # Check if openssl is available
        if ! command -v openssl >/dev/null 2>&1; then
            log "Warning: openssl not available, cannot extract certificate automatically"
            return 1
        fi
        
        # Extract the certificate
        local cert_content
        cert_content=$(echo | timeout 10 openssl s_client -connect "$host:$port" -showcerts 2>/dev/null | \
                      sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | \
                      head -n -0)  # Get all certificates, not just the first one
        
        if [ -n "$cert_content" ]; then
            # Get the last certificate (usually the CA certificate)
            local ca_cert
            ca_cert=$(echo "$cert_content" | awk '/-----BEGIN CERTIFICATE-----/{cert=""} {cert=cert $0 "\n"} /-----END CERTIFICATE-----/{print cert}' | tail -1)
            
            if [ -n "$ca_cert" ]; then
                log "Successfully extracted CA certificate from server"
                echo "$ca_cert"
                return 0
            fi
        fi
        
        log "Warning: Could not extract certificate from $host:$port"
        return 1
    else
        log "LDAP connection (non-TLS), no certificate extraction needed"
        return 1
    fi
}

# Function to discover LDAP servers - separates host discovery from port testing
discover_ldap_server() {
    local domain=$1
    local discovered_hosts=()
    local ldap_uri=""
    
    log "Discovering LDAP server for domain: $domain"
    
    # Ensure DNS tools are available
    ensure_dns_tools
    
    # Step 1: Collect all potential LDAP hosts from SRV records
    log "Checking DNS SRV records..."
    
    # Try LDAPS SRV records (port 636)
    local srv_records=$(lookup_srv_records "_ldaps._tcp" "$domain")
    if [ -n "$srv_records" ]; then
        while IFS= read -r srv_record; do
            if [ -n "$srv_record" ]; then
                local priority=$(echo "$srv_record" | awk '{print $1}')
                local weight=$(echo "$srv_record" | awk '{print $2}')
                local port=$(echo "$srv_record" | awk '{print $3}')
                local target=$(echo "$srv_record" | awk '{print $4}' | sed 's/\.$//')
                discovered_hosts+=("$target:$port:ldaps")
                log "Found LDAPS SRV record: $target:$port"
            fi
        done <<< "$srv_records"
    fi
    
    # Try LDAP SRV records (port 389)
    srv_records=$(lookup_srv_records "_ldap._tcp" "$domain")
    if [ -n "$srv_records" ]; then
        while IFS= read -r srv_record; do
            if [ -n "$srv_record" ]; then
                local priority=$(echo "$srv_record" | awk '{print $1}')
                local weight=$(echo "$srv_record" | awk '{print $2}')
                local port=$(echo "$srv_record" | awk '{print $3}')
                local target=$(echo "$srv_record" | awk '{print $4}' | sed 's/\.$//')
                discovered_hosts+=("$target:$port:ldap")
                log "Found LDAP SRV record: $target:$port"
            fi
        done <<< "$srv_records"
    fi
    
    # Step 2: Add common hostname patterns to test
    log "Adding common hostname patterns..."
    local common_hostnames=("ldap" "ad" "dc" "directory" "ds" "openldap")
    for hostname in "${common_hostnames[@]}"; do
        if nslookup "$hostname.$domain" >/dev/null 2>&1; then
            discovered_hosts+=("$hostname.$domain:636:ldaps")
            discovered_hosts+=("$hostname.$domain:389:ldap")
            log "Found hostname: $hostname.$domain"
        fi
    done
    
    # Step 3: Add localhost as final fallback
    log "Adding localhost as fallback..."
    local system_hostname=$(hostname -f 2>/dev/null || hostname)
    discovered_hosts+=("localhost:636:ldaps")
    discovered_hosts+=("localhost:389:ldap")
    discovered_hosts+=("127.0.0.1:636:ldaps")
    discovered_hosts+=("127.0.0.1:389:ldap")
    
    # Step 4: Test connectivity to discovered hosts
    log "Testing connectivity to discovered hosts..."
    for host_entry in "${discovered_hosts[@]}"; do
        IFS=':' read -r host port protocol <<< "$host_entry"
        log "Testing $protocol://$host:$port..."
        
        if test_ldap_port "$host" "$port"; then
            # If we found localhost, use the system hostname for the URI
            if [[ "$host" == "localhost" || "$host" == "127.0.0.1" ]]; then
                ldap_uri="$protocol://$system_hostname:$port"
                log "Found local LDAP server, using system hostname: $ldap_uri"
            else
                ldap_uri="$protocol://$host:$port"
                log "Successfully connected to: $ldap_uri"
            fi
            echo "$ldap_uri"
            return 0
        else
            log "Failed to connect to: $protocol://$host:$port"
        fi
    done
    
    # No working LDAP server found
    log "Could not auto-discover LDAP server for domain: $domain"
    echo ""
    return 1
}

# Function to prompt for environment variables  
prompt_for_env_vars() {
    local provided_domain="$1"
    
    # Use provided domain or prompt for one
    if [ -n "$provided_domain" ]; then
        domain="$provided_domain"
        log "Using domain from command line: $domain"
    else
        # Get domain from user
        local hostname=$(hostname -f 2>/dev/null || hostname)
        log "Detected hostname: $hostname"
        local default_domain=""
        if [[ "$hostname" == *.* ]]; then
            default_domain=${hostname#*.}
        fi
        
        if [ -n "$default_domain" ]; then
            read -p "Domain name [$default_domain]: " domain
            domain=${domain:-$default_domain}
        else
            read -p "Domain name (e.g., example.com): " domain
        fi
        
        # Validate that domain is not empty
        if [ -z "$domain" ]; then
            log "Error: Domain name is required. Exiting."
            exit 1
        fi
    fi
    
    # Auto-discover LDAP server
    LDAP_URI=$(discover_ldap_server "$domain") || true
    
    if [ -z "$LDAP_URI" ]; then
        echo
        echo "⚠️  ALERT: Could not auto-discover LDAP server for domain: $domain"
        echo "   - No DNS SRV records found (_ldaps._tcp.$domain or _ldap._tcp.$domain)"
        echo "   - No common LDAP hostnames found (ldap.$domain, ad.$domain, etc.)"
        echo
        echo "Please provide the LDAP server information manually."
        echo
        read -p "LDAP Server URI (e.g., ldaps://ldap.example.com:636): " LDAP_URI
        
        # Validate that LDAP_URI is not empty
        while [ -z "$LDAP_URI" ]; do
            echo "Error: LDAP Server URI is required."
            read -p "LDAP Server URI (e.g., ldaps://ldap.example.com:636): " LDAP_URI
        done
    else
        echo "✅ Auto-discovered LDAP server: $LDAP_URI"
        read -p "Use this server? (Y/n): " use_discovered
        if [[ "$use_discovered" =~ ^[Nn]$ ]]; then
            read -p "Please enter LDAP Server URI manually: " LDAP_URI
            
            # Validate manual entry
            while [ -z "$LDAP_URI" ]; do
                echo "Error: LDAP Server URI is required."
                read -p "LDAP Server URI (e.g., ldaps://ldap.example.com:636): " LDAP_URI
            done
        fi
    fi
    
    # Generate LDAP_BASE from domain
    local default_ldap_base=$(generate_ldap_base_from_domain "$domain")
    read -p "LDAP Base DN [$default_ldap_base]: " LDAP_BASE
    LDAP_BASE=${LDAP_BASE:-$default_ldap_base}
    
    read -p "LDAP Admin DN (e.g., cn=admin,$LDAP_BASE): " LDAP_ADMIN_DN
    
    # Set CA certificate path to our standard location
    CA_CERT="/certificates/ca-cert.pem"
    
    # Try to automatically extract CA certificate from LDAP server
    log "Attempting to extract CA certificate from LDAP server..."
    EXTRACTED_CERT=$(extract_ca_certificate "$LDAP_URI")
    
    if [ -n "$EXTRACTED_CERT" ]; then
        log "✅ Successfully extracted CA certificate from server!"
        log "Certificate preview:"
        echo "$EXTRACTED_CERT" | head -3
        echo "... [certificate content] ..."
        echo "$EXTRACTED_CERT" | tail -3
        echo
        read -p "Use this extracted certificate? (Y/n): " use_extracted
        
        if [[ ! "$use_extracted" =~ ^[Nn]$ ]]; then
            CA_CERT_CONTENT="$EXTRACTED_CERT"
            log "Using extracted CA certificate"
        else
            log "User chose to provide CA certificate manually"
            log "Please provide the CA certificate content (paste the entire certificate):"
            log "Press Ctrl+D when finished:"
            CA_CERT_CONTENT=$(cat)
        fi
    else
        log "⚠️  Could not automatically extract CA certificate"
        log "You can extract it manually with: openssl s_client -connect ${LDAP_URI#*://} -showcerts </dev/null"
        log "Please provide the CA certificate content (paste the entire certificate):"
        log "Press Ctrl+D when finished:"
        CA_CERT_CONTENT=$(cat)
    fi
    
    # Export the variables for use in the current session
    export LDAP_URI LDAP_BASE LDAP_ADMIN_DN CA_CERT CA_CERT_CONTENT
}

# Function to display configuration and confirm with user
confirm_configuration() {
    echo
    echo "========================================"
    echo "LDAP Configuration Summary:"
    echo "========================================"
    echo "LDAP URI:        $LDAP_URI"
    echo "LDAP Base DN:    $LDAP_BASE"
    echo "LDAP Admin DN:   $LDAP_ADMIN_DN"
    echo "CA Certificate:  $CA_CERT"
    echo "CA Cert Content: $(echo "$CA_CERT_CONTENT" | head -1)..."
    echo "========================================"
    echo
    
    read -p "Do you want to proceed with this configuration? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log "Configuration cancelled by user."
        exit 0
    fi
    
    # Save configuration to .env file
    save_env_file
}

# Function to save environment variables to .env file
save_env_file() {
    log "Saving configuration to .env file..."
    cat > .env <<EOF
# LDAP Configuration
LDAP_URI=$LDAP_URI
LDAP_BASE=$LDAP_BASE
LDAP_ADMIN_DN=$LDAP_ADMIN_DN

# CA Certificate Content (multi-line)
CA_CERT_CONTENT="$CA_CERT_CONTENT"
EOF
    
    log ".env file created successfully."
}

# Function to detect package manager
detect_package_manager() {
    local package_managers=("apt-get:apt" "dnf:dnf" "yum:yum" "pacman:pacman")
    
    for pm in "${package_managers[@]}"; do
        IFS=':' read -r cmd name <<< "$pm"
        if command -v "$cmd" >/dev/null 2>&1; then
            echo "$name"
            return 0
        fi
    done
    
    log "Error: Unsupported package manager"
    exit 1
}

# Function to detect OS and version
detect_os_version() {
    if [ -f /etc/arch-release ]; then
        echo "arch-linux"
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID-$VERSION_ID"
    else
        echo "unknown"
    fi
}

# Function to install packages based on package manager
install_packages() {
    local package_manager=$1
    local packages=$(get_packages "$package_manager")
    log "Installing packages with $package_manager..."
    
    case $package_manager in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            sudo apt-get update
            sudo apt-get install -y $packages
            sudo rm -rf /var/lib/apt/lists/*
            unset DEBIAN_FRONTEND
            ;;
        yum)
            sudo yum install -y $packages
            ;;
        dnf)
           sudo dnf install -y $packages
           ;;
        pacman)
            setup_pacman_keyring
            sudo pacman -Syy --noconfirm
            printf 'y\n' | sudo pacman -S --needed base-devel
            for package in $packages; do
                sudo pacman -S --noconfirm --needed "$package"
            done
            sudo pacman -Sc --noconfirm
            ;;
    esac
}

setup_pacman_keyring() {
    log "Setting up pacman keyring..."
    sudo mkdir -p /etc/pacman.d/gnupg
    sudo chmod 700 /etc/pacman.d/gnupg
    sudo pacman-key --init
    sudo pacman-key --populate archlinux
}

# Function to set up SSH
setup_ssh() {
    log "Setting up SSH..."
    sudo mkdir -p /var/run/sshd
    
    # Configure SSH
    configure_ssh_authentication
    generate_ssh_keys
    
    # Start and enable SSH service
    local service_name="ssh"
    [[ "$PACKAGE_MANAGER" =~ ^(yum|pacman|dnf)$ ]] && service_name="sshd"
    
    sudo systemctl enable "$service_name"
    sudo systemctl restart "$service_name"
}

configure_ssh_authentication() {
    # Define SSH configuration settings
    local ssh_settings=(
        "PasswordAuthentication yes"
        "PermitRootLogin yes"
        "PubkeyAuthentication yes"
        "UsePAM yes"
        "KbdInteractiveAuthentication yes"
        "Port 22"
        "Protocol 2"
    )

    # Apply each configuration setting
    for setting in "${ssh_settings[@]}"; do
        local key=$(echo "$setting" | cut -d' ' -f1)
        local value=$(echo "$setting" | cut -d' ' -f2-)
        
        if sudo grep -q "^$key" "$SSH_CONF"; then
            sudo sed -i "s/^$key .*/$key $value/" "$SSH_CONF"
        else
            echo "$key $value" | sudo tee -a "$SSH_CONF" > /dev/null
        fi
    done
}


generate_ssh_keys() {
    log "Generating SSH keys if not present..."
    local key_types=("rsa" "ecdsa" "ed25519")
    
    for type in "${key_types[@]}"; do
        local key_file="/etc/ssh/ssh_host_${type}_key"
        if [ ! -f "$key_file" ]; then
            log "Generating $type SSH key..."
            sudo ssh-keygen -t "$type" -f "$key_file" -N ""
        fi
    done
}

# Function to set up LDAP client
setup_ldap_client() {
    log "Setting up LDAP client..."
    sudo mkdir -p /etc/ldap
    
    sudo tee /etc/ldap/ldap.conf <<EOL
BASE    $LDAP_BASE
URI     $LDAP_URI
BINDDN  $LDAP_ADMIN_DN
TLS_REQCERT never
EOL
}

# Function to set up SSSD
setup_sssd() {
    log "Setting up SSSD..."
    create_sssd_config
    configure_nss
    
    if [ "$PACKAGE_MANAGER" = "pacman" ]; then
        configure_arch_pam
    elif [ "$PACKAGE_MANAGER" = "yum" ] || [ "$PACKAGE_MANAGER" = "dnf" ]; then
        configure_sssd_authselect
    fi
    
    sudo systemctl enable sssd
    sudo systemctl restart sssd
}

create_sssd_config() {
    sudo tee "$SSSD_CONF" <<EOL
[sssd]
domains = LDAP
config_file_version = 2
services = nss, pam, ssh

[domain/LDAP]
debug_level = 9
id_provider = ldap
auth_provider = ldap
ldap_uri = ${LDAP_URI}
ldap_enforce_password_policy = false
ldap_search_base = ${LDAP_BASE}

ldap_connection_expire_timeout = 30
ldap_connection_expire_offset = 0
ldap_account_expire_policy = ad
ldap_network_timeout = 30
ldap_opt_timeout = 30
ldap_timeout = 30

ldap_tls_cacert = ${CA_CERT}
ldap_tls_reqcert = never
ldap_id_use_start_tls = false
ldap_schema = rfc2307

cache_credentials = true
enumerate = true

ldap_user_object_class = posixAccount
ldap_user_name = uid
ldap_user_home_directory = homeDirectory
ldap_user_shell = loginShell
ldap_user_gecos = gecos
ldap_user_shadow_last_change = shadowLastChange

[pam]
pam_response_filter = ENV
pam_verbosity = 3
pam_id_timeout = 30
pam_pwd_response_prompt = Password: 
pam_pwd_response_timeout = 30

EOL

    sudo chmod 600 "$SSSD_CONF"
}

configure_nss() {
    sudo tee /etc/nsswitch.conf <<EOL
passwd: files sss
shadow: files sss
group:  files sss
hosts: files dns myhostname
EOL
}

configure_arch_pam() {
    echo "Configuring PAM for Arch Linux..."
    
    # Configure PAM for SSSD
    sudo tee /etc/pam.d/system-auth <<EOL
#%PAM-1.0
auth     sufficient pam_sss.so forward_pass
auth     required  pam_unix.so try_first_pass nullok
auth     optional  pam_permit.so

account  sufficient pam_sss.so
account  required  pam_unix.so
account  optional  pam_permit.so

password sufficient pam_sss.so use_authtok
password required  pam_unix.so try_first_pass nullok sha512 shadow
password optional  pam_permit.so

session  required  pam_limits.so
session  required  pam_unix.so
session  optional  pam_sss.so
session  required  pam_mkhomedir.so skel=/etc/skel umask=0077
EOL

    # Configure PAM for SSHD
    sudo tee /etc/pam.d/sshd <<EOL
#%PAM-1.0
auth     include  system-auth
account  include  system-auth
password include  system-auth
session  include  system-auth
EOL
}


configure_sssd_authselect() {
    sudo authselect select sssd --force
}

# Function to set up TLS
setup_tls() {
    log "Setting up TLS..."

    sudo mkdir -p /certificates

    echo "$CA_CERT_CONTENT" | sudo tee /certificates/ca-cert.pem > /dev/null
    sudo chmod 644 /certificates/ca-cert.pem

    update_ca_certificates
}


update_ca_certificates() {
    log "Updating CA certificates..."
    case $PACKAGE_MANAGER in
        apt)    sudo update-ca-certificates ;;
        yum)    sudo update-ca-trust extract ;;
        pacman) sudo update-ca-trust ;;
    esac
}

configure_pam_mkhomedir() {
    echo "Configuring PAM for SSHD to enable pam_mkhomedir..."
    PAM_FILE="/etc/pam.d/sshd"

    if ! sudo grep -q "pam_mkhomedir.so" "$PAM_FILE"; then
        echo "Adding pam_mkhomedir.so configuration to $PAM_FILE..."
        echo "session required pam_mkhomedir.so skel=/etc/skel umask=0077" | sudo tee -a "$PAM_FILE"
    else
        echo "pam_mkhomedir.so is already configured in $PAM_FILE. Skipping."
    fi
}

configure_sudo_access() {
    log "Granting sudo access to LDAP group..."
    echo '%#9999 ALL=(ALL:ALL) ALL' | sudo tee /etc/sudoers.d/proxmox-sudo
    sudo chmod 440 /etc/sudoers.d/proxmox-sudo
}

# Main execution
main() {
    log "Starting system setup..."
    
    # Get domain from command line argument if provided
    local provided_domain="$1"
    
    # Check for .env file and prompt if missing
    if [ ! -f .env ]; then
        prompt_for_env_vars "$provided_domain"
        confirm_configuration
    else
        log "Loading environment variables from .env file..."
    fi
    
    # Detect system configuration
    PACKAGE_MANAGER=$(detect_package_manager)
    OS_VERSION=$(detect_os_version)
    log "Detected package manager: $PACKAGE_MANAGER"
    log "Detected OS version: $OS_VERSION"
    
    # Install necessary packages
    install_packages "$PACKAGE_MANAGER"
    
    # Set up services
    setup_ssh
    setup_ldap_client
    setup_sssd
    setup_tls
    configure_pam_mkhomedir
    configure_sudo_access
    
    # Additional setup for Arch Linux
    if [ "$PACKAGE_MANAGER" = "pacman" ]; then
        sudo systemctl enable --now sssd
        sudo systemctl enable --now sshd
        sudo sss_cache -E
        sudo rm -rf /var/lib/sss/db/*
        sudo systemctl restart sssd
    fi
    
    log "Setup completed successfully."
}

# Execute main function with command line arguments
main "$@"