# LDAP Client Automation

This project automates LDAP client setup across various Linux distributions (Debian, Amazon Linux, Rocky Linux etc.) and includes AWS infrastructure testing via Terraform.

## Features

* **Interactive Setup**: Automatically prompts for LDAP configuration if no `.env` file exists
* **Smart Domain Detection**: Auto-generates LDAP Base DN from system hostname  
* **Intelligent TLS Detection**: Automatically detects and configures optimal TLS settings
  - Tests LDAPS (port 636) with system CA validation
  - Tests StartTLS (port 389) support
  - Falls back to plain LDAP if TLS unavailable
  - Auto-retrieves certificates only when needed
* **Cross-distro Support**: Works with `apt`, `yum`, `dnf`, and `pacman` package managers, plus native macOS support
* **Secure SSH Configuration**: Sets up SSH with secure defaults and PAM integration
* **SSSD Integration**: Complete SSSD setup for LDAP authentication (Linux) or native Directory Services (macOS)
* **Smart Certificate Handling**: 
  - Uses system CA certificates when valid
  - Auto-retrieves custom certificates when needed
  - No manual certificate pasting required
* **Undo Capability**: Safely remove LDAP configuration and restore original system settings
* **Global CDN Distribution**: Available via Cloudflare Workers for fast worldwide access

## Quick Start

### Interactive Setup

```bash
# Download and run directly (requires sudo for system configuration)
curl -s https://pown.sh | sudo bash
```

### Non-Interactive with Domain

```bash
# Pass domain as command line argument (skips domain prompt)
curl -s https://pown.sh | sudo bash -s -- example.com
```

### Undo Configuration

```bash
# Remove LDAP configuration and restore original settings
curl -s https://pown.sh | sudo bash -s -- --undo

# Or if you have the script locally
sudo ./pown.sh --undo
```


## Interactive Configuration

When you run the script **without a `.env` file**, it will:

1. **Auto-detect your domain** from hostname (e.g., `server.example.com` → `dc=example,dc=com`)
2. **Auto-discover LDAP server** using DNS SRV records and common hostnames
3. **Intelligent TLS detection**:
   - Tests LDAPS (port 636) with system CA certificates
   - Tests StartTLS support on port 389
   - Validates certificate trust automatically
   - Falls back to plain LDAP if TLS unavailable (with security warnings)
4. **Display TLS configuration summary**:
   - Certificate type (CA-signed, self-signed, or none)
   - Security level and recommendations
   - Auto-retrieved certificates when needed
5. **Prompt for LDAP settings**:
   - LDAP Server URI (auto-discovered or manual)
   - LDAP Base DN (with smart default)
   - Admin Distinguished Name
6. **Show configuration summary** and ask for confirmation
7. **Create `.env` file** automatically for future runs

## TLS Detection & Security

The script automatically detects and configures the most secure TLS option available:

### Detection Priority (Best to Worst)
1. **LDAPS with Valid CA Certificate** (Port 636)
   - Most secure option
   - Uses existing system CA certificates
   - No manual certificate installation needed
   
2. **LDAPS with Custom Certificate** (Port 636)
   - Secure with custom/self-signed certs
   - Certificate automatically retrieved from server
   - Installed to system trust store
   
3. **StartTLS** (Port 389)
   - TLS negotiated on plain LDAP port
   - Uses system CA certificates
   - Good fallback option
   
4. **Plain LDAP** (Port 389)
   - **Not recommended** - credentials sent in clear text
   - Security warnings displayed
   - Only use in trusted networks

### Example Output
```
[2024-01-20 10:30:15] Testing LDAP server TLS capabilities...
[2024-01-20 10:30:16] ✓ LDAPS connection successful on port 636
[2024-01-20 10:30:16] ✓ Server certificate validated with system CA store
[2024-01-20 10:30:16] Using LDAPS with existing system certificates
[2024-01-20 10:30:16] TLS configuration: ENABLED
```

### Manual `.env` Configuration

If you prefer to create the configuration file manually:

```env
LDAP_BASE=dc=example,dc=com
LDAP_URI=ldaps://your-ldap-host:636
LDAP_ADMIN_DN=cn=admin,dc=example,dc=com
```

Note: TLS detection and certificate handling is now automatic. No need to manually specify CA certificates.

## Global Distribution

The script is distributed globally via Cloudflare Workers for optimal performance:

- **URL**: `https://pown.sh`
- **Source**: See `worker.js` for the complete implementation

## Distribution Architecture

### Cloudflare Worker (`worker.js`)

The script is served globally through a Cloudflare Worker that:

- **Fetches** the latest script from the source repository
- **Caches** at Cloudflare's edge locations worldwide (10-second TTL)
- **Appends metadata** including commit hash, timestamp, and source URL
- **Handles errors** gracefully with 502 responses

**Deployment**: The worker is deployed at `https://pown.sh`

**Management**: [Cloudflare Dashboard](https://dash.cloudflare.com/10825d9d1d920e844ccd0326c66dfc45/workers/services/view/pownsh/production/metrics)

### Development Workflow

1. **Make changes** to `pown.sh` in this repository
2. **Deploy changes** - updates are automatically available via worker
3. **Test locally** with `./pown.sh` or via `https://pown.sh`
4. **Monitor metrics** in Cloudflare dashboard

## AWS Infrastructure Testing

To validate this setup on real infrastructure:

```bash
./test.sh
```

This script will:

* Launch test EC2 instances using Terraform
* Run the LDAP setup using `pown.sh`
* Validate SSH and LDAP-based login
* Automatically clean up all resources

## Compatibility

- **Shell**: Compatible with Bash 3.2+ (including macOS default)
- **OS Support**: Debian/Ubuntu, RHEL/CentOS/Rocky, Arch Linux, Amazon Linux
- **Package Managers**: apt, yum, dnf, pacman
- **Architecture**: x86_64, arm64

