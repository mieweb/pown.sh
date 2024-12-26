#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Function to detect package manager
detect_package_manager() {
    # echo "Detecting package manager..."
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    else
        echo "Unsupported package manager. Exiting."
        exit 1
    fi
}

echo "Starting script..."
# Detect the package manager
PACKAGE_MANAGER=$(detect_package_manager)
echo "Detected package manager: $PACKAGE_MANAGER"

# Environment variables
echo "Setting environment variables..."
export LDAP_BASE="dc=mieweb,dc=com"
export LDAP_DOMAIN="mieweb.com"
export LDAP_ORG="MIE"
export LDAP_ADMIN_DN="cn=admin,dc=mieweb,dc=com"
export LDAP_ADMIN_PW="secret"
export SSH_PORT=2222
export LDAP_CERT_SUBJ="/C=US/ST=IN/L=City/O=MIE/CN=localhost"
export LDAP_URI="ldap://8.tcp.ngrok.io:14738"
echo "Environment variables set."

# Common configurations
setup_ssh() {
    echo "Setting up SSH..."
    mkdir -p /var/run/sshd
    cat >> /etc/ssh/sshd_config <<EOL
Port 22
PermitRootLogin yes
PasswordAuthentication yes
UsePAM yes
EOL
    echo "SSH config written."
    generate_ssh_keys
}

generate_ssh_keys() {
    echo "Generating SSH keys if not already present..."
    if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
        echo "Generating RSA SSH key..."
        ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ""
    fi
    if [ ! -f /etc/ssh/ssh_host_ecdsa_key ]; then
        echo "Generating ECDSA SSH key..."
        ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key -N ""
    fi
    if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
        echo "Generating ED25519 SSH key..."
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    fi
}

setup_ldap_client() {
    echo "Setting up LDAP client..."
    mkdir -p /etc/ldap
    cat > /etc/ldap/ldap.conf <<EOL
BASE    $LDAP_BASE
URI     $LDAP_URI
BINDDN  $LDAP_ADMIN_DN
TLS_REQCERT allow
EOL
    echo "LDAP client config written."
}

setup_sssd() {
    echo "Setting up SSSD..."
    cat > /etc/sssd/sssd.conf <<EOL
[sssd]
config_file_version = 2
services = nss, pam
domains = LDAP

[domain/LDAP]
debug_level = 9
id_provider = ldap
auth_provider = ldap
ldap_uri = $LDAP_URI
ldap_search_base = $LDAP_BASE
ldap_default_bind_dn = $LDAP_ADMIN_DN
ldap_default_authtok = $LDAP_ADMIN_PW
ldap_tls_reqcert = never
cache_credentials = true
enumerate = true
ldap_id_use_start_tls = false
ldap_tls_cacert = /etc/ssl/certs/ca-cert.pem

ldap_user_object_class = posixAccount
ldap_group_object_class = posixGroup
ldap_user_home_directory = homeDirectory
ldap_user_shell = loginShell
ldap_user_uid = uid
ldap_user_name = uid
ignore_missing_attributes = True
EOL
    chmod 600 /etc/sssd/sssd.conf
      # Add Red Hat specific authentication configuration
    authselect select sssd --force
    authselect enable-feature with-mkhomedir

    # Ensure SSSD service is enabled
    systemctl enable sssd
    systemctl restart sssd
    echo "SSSD config written and permissions set."
}

setup_tls() {
    echo "Setting up TLS..."
    cat > /etc/ssl/certs/ca-cert.pem <<EOL
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIUU3nQZQO3admOWHDJieY4pttUg18wDQYJKoZIhvcNAQEL
BQAwSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAklOMQ0wCwYDVQQHDARDaXR5MQww
CgYDVQQKDANNSUUxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNDEyMTMxNzI1Mjda
Fw0yNTEyMTMxNzI1MjdaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJJTjENMAsG
A1UEBwwEQ2l0eTEMMAoGA1UECgwDTUlFMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCJ3zO0lYgLxB3szVyuG040HULW
b7GvSBQSywIQPaOIG0BuvXDAG65JEGGcXJ030cH5BrVDmFPLBlyicKWkI4RLUvh1
4ehOsDK0cyCq9BVSqyWEAsGeXhWzqD2fCjL3lEQTxKYMQyqVM3YKhZJvVKh3Ueuj
c0mwd/dm/Vjg8S98S3ggcDu8SIU7OjRvPXrJRSS9tdbh57s0MEo54lk2XsoP1HOy
R7TpaP5ehK3FNR4NLs4HbnkdXq0z0aR/KGBFAmelEJ/4O5IcRQphKUeyBkE++hJV
UWtljLrHBNETU+qw+0FQ9+kIGtdZEiZlQvAM+5w5b55AB0X1aw1StKLr8bLLAgMB
AAGjUzBRMB0GA1UdDgQWBBTpvplsCYIQC5Q2ZXaATld5xUGkGDAfBgNVHSMEGDAW
gBTpvplsCYIQC5Q2ZXaATld5xUGkGDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQAY7aiyo9vORylL1DiH3NtJg9EuQFXXxmc1ge2IwMQRqnQPkKCC
Po+76BB/Kd57a8Bw4GaeGFuYqn696SpaJTS5WjPOfCyIbxPhxBDMMT7SArjHzwpU
22oKAxBMD6QjqzBmkw1IqrQndkn6Mee6cy+3uDNZ1+1za1ATFsqE0VgqbWYBzNJM
2Hpv8dXgNDA1qqfguHQOOgMGP8ZgJr0twAiiSldu02wavEeeski8zyDGjajUOfQf
aTqQ66+qTwptRDJkT0aVHAPC0kjREVF3ATxWPVOitOFfDuQzBcP5FCOXkuhr/jM6
QrZlGFvioZ0gXjJvJ57k5f6fNfVK91VKfORh
-----END CERTIFICATE-----
EOL
    chmod 644 /etc/ssl/certs/ca-cert.pem
    echo "TLS certificate written."

    # Update CA certificates based on the package manager
    echo "Updating CA certificates..."
    if [ "$PACKAGE_MANAGER" = "apt" ]; then
        update-ca-certificates
    elif [ "$PACKAGE_MANAGER" = "yum" ]; then
        update-ca-trust extract
    elif [ "$PACKAGE_MANAGER" = "pacman" ]; then
        update-ca-trust
    fi
    echo "CA certificates updated."
}

install_packages_apt() {
    echo "Installing packages with apt..."
    apt-get update && apt-get install -y \
        ldap-utils \
        openssh-client \
        openssh-server \
        sssd \
        sssd-ldap \
        sudo \
        libnss-ldap \
        libpam-ldap \
        ca-certificates \
        vim \
        net-tools \
        iputils-ping && \
        rm -rf /var/lib/apt/lists/*
    echo "Packages installed."
}

install_packages_yum() {
    echo "Installing packages with yum..."
    yum install -y \
        openssh-clients \
        openssh-server \
        sssd \
        sssd-ldap \
        sudo \
        openldap-clients \
        ca-certificates \
        vim \
        net-tools \
        iputils \
        authselect
    echo "Packages installed."
}

install_packages_dnf() {
    echo "Installing packages with dnf..."
    dnf install -y \
        openssh-clients \
        openssh-server \
        sssd \
        sssd-ldap \
        sudo \
        nss-pam-ldapd \
        openldap-clients \
        ca-certificates \
        vim \
        net-tools \
        iputils
    echo "Packages installed."
}


install_packages_pacman() {
    echo "Installing packages with pacman..."
    pacman -Sy --noconfirm \
        openssh \
        sssd \
        openldap \
        sudo \
        nsswitch \
        ca-certificates \
        vim \
        net-tools \
        iputils
    echo "Packages installed."
}

# Install the necessary packages
echo "Installing necessary packages..."
echo $PACKAGE_MANAGER
if [ "$PACKAGE_MANAGER" = "apt" ]; then
    install_packages_apt
elif [ "$PACKAGE_MANAGER" = "yum" ]; then
    install_packages_yum
elif [ "$PACKAGE_MANAGER" = "pacman" ]; then
    install_packages_pacman
elif [ "$PACKAGE_MANAGER" = "dnf" ]; then
    install_packages_dnf
else
    echo $PACKAGE_MANAGER
    echo "No valid package manager found. Exiting."
    exit 1
fi

# Run the setup functions
setup_ssh
setup_ldap_client
setup_sssd
setup_tls

echo "Setup completed successfully."
