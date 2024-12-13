#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

export DEBIAN_FRONTEND=noninteractive

# Trap errors and display a message
trap 'echo "An error occurred during the execution of the script. Exiting..."; exit 1' ERR

echo "Starting LDAP SSO and SSH configuration..."

# Load environment variables
CONFIG_FILE="./ldap_config.env"
if [[ -f $CONFIG_FILE ]]; then
    echo "Loading configuration from $CONFIG_FILE..."
    source $CONFIG_FILE
else
    echo "Configuration file $CONFIG_FILE not found. Using default environment variables."
fi

# Validate required variables
if [[ -z "$LDAP_URI" || -z "$LDAP_BASE_DN" || -z "$LDAP_ADMIN_DN" || -z "$LDAP_ADMIN_PASSWORD" ]]; then
    echo "One or more required LDAP variables are missing. Please check your configuration."
    exit 1
fi

# Function to determine BASE_DN based on the domain
function get_base_dn() {
    echo "$LDAP_BASE_DN"
}

# Function to detect package manager
function detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    else
        echo "Unsupported package manager. Exiting."
        exit 1
    fi
}

# Install necessary packages for apt
function install_packages_apt() {
    echo "Copying ca-cert.pem to /etc/ssl/certs..."

if [[ ! -d /etc/ssl/certs ]]; then
    mkdir -p /etc/ssl/certs
fi

if [[ -f ./ca-cert.pem ]]; then
    cp ./ca-cert.pem /etc/ssl/certs/
    chmod 644 /etc/ssl/certs/ca-cert.pem
    echo "ca-cert.pem successfully copied to /etc/ssl/certs/"
else
    echo "Error: ca-cert.pem not found in the current directory. Exiting..."
    exit 1
fi

    echo "Installing necessary packages using apt..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y libnss-ldapd libpam-ldap ldap-utils nscd openssh-server
}

# Install necessary packages for yum
function install_packages_yum() {
    echo "Installing necessary packages using yum..."
    yum install -y nss-pam-ldapd nscd openldap-clients openssh-server
}

# Install necessary packages for pacman
function install_packages_pacman() {
    echo "Installing necessary packages using pacman..."
    pacman -Sy --noconfirm nss-pam-ldapd openldap nscd openssh
}

# Configure LDAP settings for APT-based systems
function configure_ldap_apt() {
    echo "Configuring LDAP settings for APT-based system..."
    BASE_DN=$(get_base_dn)
    BIND_DN="$LDAP_ADMIN_DN"
    BIND_PASSWORD="$LDAP_ADMIN_PASSWORD"

    echo "Setting up debconf selections for LDAP..."
    cat <<EOF | debconf-set-selections
libnss-ldapd libnss-ldapd/binddn string $BIND_DN
libnss-ldapd libnss-ldapd/bindpw password $BIND_PASSWORD
libnss-ldapd libnss-ldapd/rootbinddn string $BIND_DN
libnss-ldapd libnss-ldapd/dbrootlogin boolean true
libnss-ldapd libnss-ldapd/override boolean true
libnss-ldapd libnss-ldapd/ldap_version select 3
libnss-ldapd libnss-ldapd/dblogin boolean false
libpam-ldapd libpam-ldapd/binddn string $BIND_DN
libpam-ldapd libpam-ldapd/bindpw password $BIND_PASSWORD
libpam-ldapd libpam-ldapd/base string $BASE_DN
libpam-ldapd libpam-ldapd/ldap_version select 3
libpam-ldapd shared/ldapns/ldap-server string $LDAP_URI
libpam-ldapd libpam-ldapd/dbrootlogin boolean true
libpam-ldapd libpam-ldapd/rootbinddn string $BIND_DN
libpam-ldapd libpam-ldapd/override boolean true
libpam-ldapd libpam-ldapd/dblogin boolean false
EOF

LDAP_CONF="/etc/ldap/ldap.conf"
if [[ ! -d "/etc/ldap" ]]; then
    mkdir -p /etc/ldap
fi

    # Explicitly write to /etc/ldap/ldap.conf
    echo "Updating /etc/ldap/ldap.conf..."
    cat <<EOL > /etc/ldap/ldap.conf
BASE $LDAP_BASE_DN
URI $LDAP_URI
BINDDN $LDAP_ADMIN_DN
TLS_CACERT /etc/ssl/certs/ca-cert.pem
TLS_REQCERT allow
EOL

    # Reconfigure libnss-ldapd and libpam-ldapd
    dpkg-reconfigure -f noninteractive libnss-ldapd
    dpkg-reconfigure -f noninteractive libpam-ldapd
}

# SSH configuration for apt, yum, and pacman
function configure_ssh() {
    echo "Configuring SSH..."
    SSHD_CONFIG="/etc/ssh/sshd_config"

    # Common SSHD configuration

    if ! grep -q "^Port 22" "$SSHD_CONFIG"; then
        echo "Port 22" >> "$SSHD_CONFIG"
    fi

    if ! grep -q "^UsePAM yes" "$SSHD_CONFIG"; then
        echo "UsePAM yes" >> "$SSHD_CONFIG"
    fi

    if ! grep -q "^PasswordAuthentication yes" "$SSHD_CONFIG"; then
        echo "PasswordAuthentication yes" >> "$SSHD_CONFIG"
    fi

    if ! grep -q "^ChallengeResponseAuthentication yes" "$SSHD_CONFIG"; then
        echo "ChallengeResponseAuthentication yes" >> "$SSHD_CONFIG"
    fi

    # Set root password for testing
    echo "root:password" | chpasswd

    # Start SSHD manually in foreground (for containers)
    echo "Starting SSHD..."
    /usr/sbin/sshd -D &
}

# Configure NSS and PAM
function configure_nss_pam() {
    echo "Configuring NSS..."
    # sed -i '/^passwd:/ s/$/ sss/' /etc/nsswitch.conf
    # sed -i '/^group:/ s/$/ sss/' /etc/nsswitch.conf
    # sed -i '/^shadow:/ s/$/ sss/' /etc/nsswitch.conf

    echo "Configuring PAM..."
    if [ "$(detect_package_manager)" == "apt" ]; then
        pam-auth-update --enable mkhomedir
    elif [ "$(detect_package_manager)" == "yum" ]; then
        authconfig --enablemkhomedir --update
    elif [ "$(detect_package_manager)" == "pacman" ]; then
        echo "session required        pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session
    fi
}

# Install and configure SSSD
function configure_sssd() {
    echo "Installing and configuring SSSD..."

    # Install SSSD and related packages
    if [ "$(detect_package_manager)" == "apt" ]; then
        apt-get update
        apt-get install -y sssd sssd-tools libpam-sss libnss-sss
    elif [ "$(detect_package_manager)" == "yum" ]; then
        yum install -y sssd sssd-tools libpam-sss libnss-sss
    elif [ "$(detect_package_manager)" == "pacman" ]; then
        pacman -Sy --noconfirm sssd sssd-tools libpam-sss libnss-sss
    else
        echo "Unsupported package manager for SSSD installation. Exiting..."
        exit 1
    fi

    # Create SSSD configuration file
    echo "Creating /etc/sssd/sssd.conf..."
    cat <<EOF > /etc/sssd/sssd.conf
[sssd]
services = nss, pam
config_file_version = 2
domains = LDAP

[domain/LDAP]
debug_level = 9
id_provider = ldap
auth_provider = ldap
ldap_uri = $LDAP_URI
ldap_search_base = $LDAP_BASE_DN
ldap_default_bind_dn = $LDAP_ADMIN_DN
ldap_default_authtok = $LDAP_ADMIN_PASSWORD
ldap_tls_cacert = '/etc/ssl/certs/ca-cert.pem'
ldap_tls_reqcert = never
# User search configuration
ldap_user_search_base = dc=mieweb,dc=com
ldap_user_object_class = posixAccount
ldap_user_name = uid

# ID mapping

ldap_user_uid_number = uidNumber
ldap_user_gid_number = gidNumber
# ldap_id_use_start_tls = true
cache_credentials = true
enumerate = true
EOF

    # Set proper permissions for sssd.conf
    chmod 600 /etc/sssd/sssd.conf
    chown root:root /etc/sssd/sssd.conf

    # Update NSS configuration
    echo "Updating /etc/nsswitch.conf for SSSD..."
    # sed -i '/^passwd:/ s/$/ sss/' /etc/nsswitch.conf
    # sed -i '/^group:/ s/$/ sss/' /etc/nsswitch.conf
    # sed -i '/^shadow:/ s/$/ sss/' /etc/nsswitch.conf

    # Configure PAM to use SSSD
    echo "Configuring PAM for SSSD..."
    echo "auth required pam_sss.so" >> /etc/pam.d/common-auth
    echo "account required pam_sss.so" >> /etc/pam.d/common-account

    # Enable and start SSSD service
    echo "Enabling and starting SSSD service..."
    # systemctl enable sssd
    # systemctl start sssd

    echo "SSSD configuration complete."
}

# Main script execution
PACKAGE_MANAGER=$(detect_package_manager)
echo "Detected package manager: $PACKAGE_MANAGER"

echo "Installing packages..."
if [ "$PACKAGE_MANAGER" == "apt" ]; then
    install_packages_apt
    configure_ldap_apt
elif [ "$PACKAGE_MANAGER" == "yum" ]; then
    install_packages_yum
    configure_ldap_yum
elif [ "$PACKAGE_MANAGER" == "pacman" ]; then
    install_packages_pacman
    configure_ldap_pacman
fi

configure_nss_pam
configure_ssh
configure_sssd

echo "LDAP SSO and SSH configuration is complete."
