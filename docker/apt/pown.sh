#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Function to detect package manager
detect_package_manager() {
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

# Detect the package manager
PACKAGE_MANAGER=$(detect_package_manager)

# Environment variables
export LDAP_BASE="dc=mieweb,dc=com"
export LDAP_DOMAIN="mieweb.com"
export LDAP_ORG="MIE"
export LDAP_ADMIN_DN="cn=admin,dc=mieweb,dc=com"
export LDAP_ADMIN_PW="secret"
export SSH_PORT=2222
export LDAP_CERT_SUBJ="/C=US/ST=IN/L=City/O=MIE/CN=localhost"
export LDAP_URI="ldap://172.17.0.2:389"

# Common configurations
setup_ssh() {
    mkdir -p /var/run/sshd
    cat >> /etc/ssh/sshd_config <<EOL
Port 22
PermitRootLogin yes
PasswordAuthentication yes
UsePAM yes
EOL
}

setup_ldap_client() {
    cat > /etc/ldap/ldap.conf <<EOL
BASE    $LDAP_BASE
URI     $LDAP_URI
BINDDN  $LDAP_ADMIN_DN
TLS_REQCERT allow
EOL
}

setup_sssd() {
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
ldap_id_use_start_tls = true
ldap_tls_cacert = /etc/ssl/certs/ca-cert.pem
EOL
    chmod 600 /etc/sssd/sssd.conf
}

setup_tls() {
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
    update-ca-certificates
}

install_packages_apt() {
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
}

install_packages_yum() {
    yum install -y \
        openldap-clients \
        openssh \
        openssh-server \
        openssh-client \
        sssd \
        sssd-ldap \
        sudo \
        nss-pam-ldapd \
        ca-certificates \
        vim \
        net-tools \
        iputils && \
        yum clean all
}

install_packages_pacman() {
    pacman -Syu --noconfirm \
        openldap \
        openssh \
        sssd \
        sudo \
        nss-pam-ldapd \
        ca-certificates \
        vim \
        net-tools \
        iputils && \
        pacman -Scc --noconfirm
}

if [ "$PACKAGE_MANAGER" = "apt" ]; then
    install_packages_apt
    setup_ssh
    setup_ldap_client
    setup_sssd
    setup_tls
    service sssd start

elif [ "$PACKAGE_MANAGER" = "yum" ]; then
    install_packages_yum
    setup_ssh
    setup_ldap_client
    setup_sssd
    setup_tls
    systemctl enable sssd
    systemctl start sssd

elif [ "$PACKAGE_MANAGER" = "pacman" ]; then
    install_packages_pacman
    setup_ssh
    setup_ldap_client
    setup_sssd
    setup_tls
    systemctl enable sssd
    systemctl start sssd
fi

# Keep the container running for debugging
echo "Setup completed. Run 'service ssh start' to start SSH service."
tail -f /dev/null
