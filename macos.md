# macOS LDAP Authentication

macOS provides comprehensive built-in LDAP authentication through its native Directory Services framework. This document explains how `pown.sh` leverages these native capabilities.

## macOS Directory Services

macOS handles LDAP authentication through its **Directory Services** framework - a unified system for managing network directory services including LDAP, Active Directory, and Open Directory.

### Core Components

- **Directory Services Framework**: Handles all directory service operations
- **dsconfigldap**: Command-line tool for LDAP server configuration  
- **dscl**: Directory Services command-line interface for queries and management
- **Directory Utility.app**: GUI for directory service configuration
- **Security Framework**: Certificate and keychain management

### Built-in Tools (No Installation Required)

macOS includes all necessary tools:
- **LDAP**: `dsconfigldap`, `dscl` 
- **DNS**: `dig`, `nslookup`, `host`
- **SSL/TLS**: `openssl` (LibreSSL), `security`
- **SSH**: `ssh`, `sshd`, `ssh-keygen`

## How LDAP Authentication Works

When a user logs in, macOS:
1. **Queries configured LDAP directories** via Directory Services
2. **Validates credentials** against LDAP server
3. **Creates local session** with LDAP user attributes
4. **Manages certificates** through system Keychain
5. **Provides single sign-on** across macOS services

## Configuration Commands

### LDAP Server Setup
```bash
# Configure LDAP server
sudo dsconfigldap -v -a 'ldap.example.com' -n '/LDAPv3/ldap.example.com'

# Enable SSL/TLS for LDAPS
sudo dsconfigldap -v -a 'ldap.example.com' -n '/LDAPv3/ldap.example.com' -c

# Set search base DN
sudo dscl localhost -create "/LDAPv3/ldap.example.com" "SearchBase" "dc=example,dc=com"
```

### Certificate Management

```bash
# Add LDAP server certificate to system keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert.pem

# Verify certificate installation
security find-certificate -c "ldap.example.com" /Library/Keychains/System.keychain
```

## Management and Verification

### Command Line Operations

```bash
# List all configured LDAP directories
dscl localhost -list /LDAPv3

# View LDAP server configuration
dscl localhost -read '/LDAPv3/ldap.example.com'

# Search for users in LDAP directory
dscl '/LDAPv3/ldap.example.com' -list /Users

# Test user authentication
dscl '/LDAPv3/ldap.example.com' -read '/Users/username'
```

### GUI Management

**Directory Utility.app** provides a user-friendly interface:
- Location: `/Applications/Utilities/Directory Utility.app`
- Requires administrator authentication
- Supports LDAPv3, Active Directory, and Open Directory
- Real-time configuration validation

## Key Features

### Native Integration
- **Zero external dependencies** - all tools built into macOS
- **System-wide authentication** - works across all macOS services
- **Automatic certificate management** via Keychain
- **Single sign-on support** for network resources
- **Seamless user experience** - transparent to end users

### Security Model
- **Keychain integration** for secure credential storage
- **TLS certificate validation** through Security framework
- **Privilege separation** - directory operations require admin rights
- **Audit logging** through macOS logging system

## Script Implementation

The `pown.sh` script automatically:
1. **Detects macOS** and uses native tools (no package installation)
2. **Configures LDAP servers** using `dsconfigldap`
3. **Manages certificates** through system Keychain
4. **Validates connectivity** and provides clear status messages
5. **Integrates with SSH** for remote authentication

### Function: `setup_macos_ldap()`

This function handles the complete LDAP setup:
- Parses LDAP URI and extracts connection details
- Configures Directory Services using `dsconfigldap`
- Sets search base DN with `dscl`
- Adds SSL certificates to system Keychain
- Provides fallback to GUI configuration if needed

## Resources

- **Directory Utility.app**: Built-in GUI for LDAP configuration
- **Man pages**: `man dsconfigldap`, `man dscl`, `man security`
- **Apple Documentation**: [Directory Utility User Guide](https://support.apple.com/guide/directory-utility/welcome/mac)

---

*macOS LDAP authentication provides enterprise-grade directory services with zero external dependencies, leveraging Apple's native Directory Services framework for secure, seamless network authentication.*