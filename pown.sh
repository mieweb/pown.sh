#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Trap errors and display a message
trap 'echo "An error occurred during the execution of the script. Exiting..."; exit 1' ERR

echo "Starting LDAP SSO configuration..."

# Function to determine BASE_DN based on the domain
function get_base_dn() {
    domain=$(hostname -d)
    IFS='.' read -ra ADDR <<< "$domain"
    for i in "${ADDR[@]}"; do
        BASE_DN+="dc=$i,"
    done
    BASE_DN=${BASE_DN::-1}
    echo $BASE_DN
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

# Install necessary packages based on the package manager
function install_packages() {
    PACKAGE_MANAGER=$(detect_package_manager)
    echo "Detected package manager: $PACKAGE_MANAGER"

    if [ "$PACKAGE_MANAGER" == "apt" ]; then
        echo "Installing necessary packages using apt..."
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y libnss-ldap libpam-ldap ldap-utils nscd
    elif [ "$PACKAGE_MANAGER" == "yum" ]; then
        echo "Installing necessary packages using yum..."
        yum install -y nss-pam-ldapd nscd openldap-clients
    elif [ "$PACKAGE_MANAGER" == "pacman" ]; then
        echo "Installing necessary packages using pacman..."
        pacman -Sy --noconfirm nss-pam-ldapd openldap nscd
    fi
}

# Configure LDAP settings for APT-based systems
function configure_ldap_apt() {
    echo "Configuring LDAP settings for APT-based system..."
    BASE_DN=$(get_base_dn)
    LDAP_URI="ldap://ldap"
    BIND_DN="cn=admin,$BASE_DN"

    # Use LDAP admin password from environment variable
    if [ -z "$LDAP_ADMIN_PASSWORD" ]; then
        echo "LDAP_ADMIN_PASSWORD environment variable is not set. Exiting..."
        exit 1
    fi
    BIND_PASSWORD=$LDAP_ADMIN_PASSWORD

    echo "Setting up debconf selections for LDAP..."
    cat <<EOF | debconf-set-selections
libnss-ldap libnss-ldap/binddn string $BIND_DN
libnss-ldap libnss-ldap/bindpw password $BIND_PASSWORD
libnss-ldap libnss-ldap/rootbinddn string $BIND_DN
libnss-ldap libnss-ldap/dbrootlogin boolean true
libnss-ldap libnss-ldap/override boolean true
libnss-ldap libnss-ldap/ldap_version select 3
libnss-ldap libnss-ldap/dblogin boolean false
libpam-ldap libpam-ldap/binddn string $BIND_DN
libpam-ldap libpam-ldap/bindpw password $BIND_PASSWORD
libpam-ldap libpam-ldap/base string $BASE_DN
libpam-ldap libpam-ldap/ldap_version select 3
libpam-ldap shared/ldapns/ldap-server string $LDAP_URI
libpam-ldap libpam-ldap/dbrootlogin boolean true
libpam-ldap libpam-ldap/rootbinddn string $BIND_DN
libpam-ldap libpam-ldap/override boolean true
libpam-ldap libpam-ldap/dblogin boolean false
EOF

    dpkg-reconfigure -f noninteractive libnss-ldap
    dpkg-reconfigure -f noninteractive libpam-ldap
}

# Configure LDAP settings for YUM-based systems
function configure_ldap_yum() {
    echo "Configuring LDAP settings for YUM-based system..."
    BASE_DN=$(get_base_dn)
    LDAP_URI="ldap://ldap"

    # Use LDAP admin password from environment variable
    if [ -z "$LDAP_ADMIN_PASSWORD" ]; then
        echo "LDAP_ADMIN_PASSWORD environment variable is not set. Exiting..."
        exit 1
    fi
    BIND_PASSWORD=$LDAP_ADMIN_PASSWORD

    echo "Creating /etc/nslcd.conf..."
    echo "URI $LDAP_URI
BASE $BASE_DN
BINDDN cn=admin,$BASE_DN
BINDPW $BIND_PASSWORD
" > /etc/nslcd.conf

    authconfig --enableldap --enableldapauth --ldapserver=$LDAP_URI --ldapbasedn=$BASE_DN --enablemkhomedir --update
}

# Configure LDAP settings for Pacman-based systems
function configure_ldap_pacman() {
    echo "Configuring LDAP settings for Pacman-based system..."
    BASE_DN=$(get_base_dn)
    LDAP_URI="ldap://ldap"
    BIND_DN="cn=admin,$BASE_DN"

    # Use LDAP admin password from environment variable
    if [ -z "$LDAP_ADMIN_PASSWORD" ]; then
        echo "LDAP_ADMIN_PASSWORD environment variable is not set. Exiting..."
        exit 1
    fi
    BIND_PASSWORD=$LDAP_ADMIN_PASSWORD

    echo "Creating /etc/nslcd.conf..."
    echo "uri $LDAP_URI
base $BASE_DN
binddn $BIND_DN
bindpw $BIND_PASSWORD
" > /etc/nslcd.conf

    systemctl enable nslcd
    systemctl start nslcd
}

# Configure NSS and PAM
function configure_nss_pam() {
    echo "Configuring NSS..."
    sed -i '/^passwd:/ s/$/ ldap/' /etc/nsswitch.conf
    sed -i '/^group:/ s/$/ ldap/' /etc/nsswitch.conf
    sed -i '/^shadow:/ s/$/ ldap/' /etc/nsswitch.conf

    echo "Configuring PAM..."
    if [ "$(detect_package_manager)" == "apt" ]; then
        pam-auth-update --enable mkhomedir
    elif [ "$(detect_package_manager)" == "yum" ]; then
        authconfig --enablemkhomedir --update
    elif [ "$(detect_package_manager)" == "pacman" ]; then
        echo "session required        pam_mkhomedir.so skel=/etc/skel umask=0077" >> /etc/pam.d/common-session
    fi
}

# Restart necessary services
function restart_services() {
    echo "Restarting services..."
    systemctl restart nscd
}

# Main script execution
echo "Installing packages..."
install_packages

if [ "$(detect_package_manager)" == "apt" ]; then
    configure_ldap_apt
elif [ "$(detect_package_manager)" == "yum" ]; then
    configure_ldap_yum
elif [ "$(detect_package_manager)" == "pacman" ]; then
    configure_ldap_pacman
fi

configure_nss_pam
restart_services

echo "LDAP SSO configuration is complete."
