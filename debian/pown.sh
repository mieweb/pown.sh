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
    echo "SSSD config written and permissions set."
}

setup_tls() {
    echo "Setting up TLS..."
    cat > /etc/ssl/certs/ca-cert.pem <<EOL
-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIUAs4rFmNqOrUpw/uaKIwBZvhdbsYwDQYJKoZIhvcNAQEL
BQAwSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAklOMQ0wCwYDVQQHDARDaXR5MQww
CgYDVQQKDANNSUUxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNDEyMTMxNjE4NTZa
Fw0yNTEyMTMxNjE4NTZaMEsxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJJTjENMAsG
A1UEBwwEQ2l0eTEMMAoGA1UECgwDTUlFMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4Jd3uC3VmkINGdZXW9dA+2SRw
HsUE5J1xfuorSjWgOnMEpiaf/VXGomzrlMujV8AJbjtKVMhlbOXR7IoMv9izIQvn
euV0o0MY98TO3KgJEyJojBsgN7Bg9SFJwOYtFKzJ4mfc01RGWYYHHWzoZ+EP3qYj
kUfgwfaKx3E2S9X8Bh71EmRtffMZtfEHNX0TLoYp2pTj3NNYanAYzx1uOqwpVBhS
BXti5RQVxhV+Mb7k+AG08tGLPXN+zI6YhGr4nCYUugk84AmXuC758U2UXs+VDgCK
9WoWafw3ofFLzZxXBK20MzguKL4+sLZvZWU6oxSieM/HnjpaCp+2SjsGyftlAgMB
AAGjUzBRMB0GA1UdDgQWBBRjiJcuy+WoIPHqy9vPXGX+xTa64DAfBgNVHSMEGDAW
gBRjiJcuy+WoIPHqy9vPXGX+xTa64DAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQBdBgWSH+kU3Gs9a0UXgRVoMUkGfoGO08E0QT1q5Tx2rU1nFJHe
AlUO2ztHGS9y3k1HQTLC0l9Ci50vK5TNgHlaaStULXA/V6aMiyLmkBqglZJ2YCn+
ZouHGciplX4MMUG5JLFHs6TSZXVGQciONaBPZAa1+QIwUaCE+YdQTgBEtNUnzIpF
Y8QJ8sUJCfG0irkWiJIpmokXOEPYpcUavpWE91CaWH/CeB2K9j58fthQNHteWneZ
Pr9SgzPMt/Bf0406CdA877ut/gR6LOq+ov2A05IYsyslwXp+ifONSkb4jxPamxX4
TfqJTV4brT8QO9iudS77B1a8r6jrXjzhhfq5
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
        iputils
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
