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

echo "Starting script..."
# Detect the package manager
PACKAGE_MANAGER=$(detect_package_manager)
OS_VERSION=$(detect_os_version)
echo "Detected package manager: $PACKAGE_MANAGER"
echo "Detected OS version: $OS_VERSION"

# Common configurations
setup_ssh() {
    echo "Setting up SSH..."
    sudo mkdir -p /var/run/sshd

    # Check if PasswordAuthentication is set to 'no' and replace it with 'yes'
    if sudo grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
        echo "Updating PasswordAuthentication to 'yes' in sshd_config..."
        sudo sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    else
        echo "Adding PasswordAuthentication yes to sshd_config..."
        echo "PasswordAuthentication yes" | sudo tee -a /etc/ssh/sshd_config
    fi

    sudo tee -a /etc/ssh/sshd_config <<EOL
Port 22
PermitRootLogin yes
UsePAM yes
EOL
    echo "SSH config written."
    if [ "$PACKAGE_MANAGER" = "yum" ]; then
        sudo systemctl enable sshd
        sudo systemctl restart sshd
    elif [ "$PACKAGE_MANAGER" = "apt" ]; then
        sudo systemctl enable ssh
        sudo systemctl restart ssh
    elif [ "$PACKAGE_MANAGER" = "pacman" ]; then
        sudo systemctl enable sshd
        sudo systemctl restart sshd
    fi

    generate_ssh_keys
}

generate_ssh_keys() {
    echo "Generating SSH keys if not already present..."
    if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
        echo "Generating RSA SSH key..."
        sudo ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ""
    fi
    if [ ! -f /etc/ssh/ssh_host_ecdsa_key ]; then
        echo "Generating ECDSA SSH key..."
        sudo ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key -N ""
    fi
    if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
        echo "Generating ED25519 SSH key..."
        sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    fi
}

setup_ldap_client() {
    echo "Setting up LDAP client..."
    sudo mkdir -p /etc/ldap
    sudo tee /etc/ldap/ldap.conf <<EOL
BASE    $LDAP_BASE
URI     $LDAP_URI
BINDDN  $LDAP_ADMIN_DN
TLS_REQCERT allow
EOL
    echo "LDAP client config written."
}

setup_sssd() {
    echo "Setting up SSSD..."
    sudo tee /etc/sssd/sssd.conf <<EOL
[sssd]
config_file_version = 2
services = nss, pam, ssh
domains = LDAP

[domain/LDAP]
debug_level = 9
access_provider = ldap
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
ldap_uri = $LDAP_URI
ldap_search_base = $LDAP_BASE
ldap_default_bind_dn = $LDAP_ADMIN_DN
ldap_default_authtok = $LDAP_ADMIN_PW
ldap_tls_reqcert = never
cache_credentials = true
enumerate = true
ldap_id_use_start_tls = false
ldap_tls_cacert = $CA_CERT

ldap_user_object_class = posixAccount
ldap_group_object_class = posixGroup
ldap_user_home_directory = homeDirectory
ldap_user_shell = loginShell
ldap_user_uid = uid
ldap_user_name = uid
ignore_missing_attributes = True
ldap_access_order = filter
ldap_access_filter = (objectClass=posixAccount)
ldap_user_ssh_public_key = sshPublicKey
ldap_auth_disable_tls_never_use_in_production = true
ldap_group_name = cn
EOL
    sudo chmod 600 /etc/sssd/sssd.conf

        # Configure NSS for SSSD
    sudo tee /etc/nsswitch.conf <<EOL
passwd: files sss
shadow: files sss
group:  files sss
hosts: files dns myhostname
EOL

    if [ "$PACKAGE_MANAGER" = "pacman" ]; then
        configure_arch_pam
    fi


       if [ "$PACKAGE_MANAGER" = "yum" ]; then
        if [[ "$OS_VERSION" == "amzn-2023" ]]; then
            echo "Amazon Linux 2023 detected"
            sudo authselect select sssd --force
            sudo authselect enable-feature with-mkhomedir
            
        fi
    fi

    sudo systemctl enable sssd
    sudo systemctl restart sssd
    echo "SSSD config written and permissions set."
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

setup_tls() {
    echo "Setting up TLS..."

    echo "$CA_CERT_CONTENT" | sudo tee /etc/ssl/certs/ca-cert.pem > /dev/null
    sudo chmod 644 /etc/ssl/certs/ca-cert.pem
    echo "TLS certificate written."

    echo "Updating CA certificates..."
    if [ "$PACKAGE_MANAGER" = "apt" ]; then
        sudo update-ca-certificates
    elif [ "$PACKAGE_MANAGER" = "yum" ]; then
        sudo update-ca-trust extract
    elif [ "$PACKAGE_MANAGER" = "pacman" ]; then
        sudo update-ca-trust
    fi
    echo "CA certificates updated."
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

install_packages_apt() {
    echo "Installing packages with apt..."
    export DEBIAN_FRONTEND=noninteractive
    sudo apt-get update && sudo apt-get install -y \
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
        sudo rm -rf /var/lib/apt/lists/*
    unset DEBIAN_FRONTEND
}

install_packages_yum() {
    echo "Installing packages with yum..."
    sudo yum install -y \
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
        authselect \
        authconfig
}

install_packages_pacman() {
    echo "Installing packages with pacman..."
    
    # Initialize keyring
    sudo mkdir -p /etc/pacman.d/gnupg
    sudo chmod 700 /etc/pacman.d/gnupg
    
    # Initialize and populate keyring
    sudo pacman-key --init
    sudo pacman-key --populate archlinux
    
    # Force sync package databases
    sudo pacman -Syy --noconfirm
    
    # Install base-devel which includes necessary build tools
    echo "Installing base-devel..."
    printf 'y\n' | sudo pacman -S --needed base-devel
    
    echo "Installing required packages..."
    # Install required packages one by one to handle any potential issues
    packages=(
        "openssh"
        "sssd"
        "openldap"
        "sudo"
        "ca-certificates"
        "vim"
        "net-tools"
        "iputils"
        "pam"
        "pambase"
    )
    
    for package in "${packages[@]}"; do
        echo "Installing $package..."
        if ! sudo pacman -S --noconfirm --needed "$package"; then
            echo "Failed to install $package"
            exit 1
        fi
    done
    
    # Clean package cache
    sudo pacman -Sc --noconfirm
    echo "Packages installed successfully."
}

echo "Installing necessary packages..."
if [ "$PACKAGE_MANAGER" = "apt" ]; then
    install_packages_apt
elif [ "$PACKAGE_MANAGER" = "yum" ]; then
    install_packages_yum
elif [ "$PACKAGE_MANAGER" = "pacman" ]; then
    install_packages_pacman
else
    echo "Unsupported package manager. Exiting."
    exit 1
fi

setup_ssh
setup_ldap_client
setup_sssd
setup_tls
configure_pam_mkhomedir

if [ "$PACKAGE_MANAGER" = "pacman" ]; then
    # Enable and start necessary services
    sudo systemctl enable --now sssd
    sudo systemctl enable --now sshd
    
    # Ensure NSS modules are working
    sudo sss_cache -E
    
    # Clear SSSD cache
    sudo rm -rf /var/lib/sss/db/*
    sudo systemctl restart sssd
fi

echo "Setup completed successfully."