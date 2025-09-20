# LDAP Client Automation

This project automates LDAP client setup across various Linux distributions (Debian, Amazon Linux, Rocky Linux etc.) and includes AWS infrastructure testing via Terraform.

## Features

* **Interactive Setup**: Automatically prompts for LDAP configuration if no `.env` file exists
* **Smart Domain Detection**: Auto-generates LDAP Base DN from system hostname  
* **Cross-distro Support**: Works with `apt`, `yum`, `dnf`, and `pacman` package managers
* **Secure SSH Configuration**: Sets up SSH with secure defaults and PAM integration
* **SSSD Integration**: Complete SSSD setup for LDAP authentication
* **TLS Certificate Handling**: Automated CA certificate installation and trust setup
* **Global CDN Distribution**: Available via Cloudflare Workers for fast worldwide access

## Quick Start

### Option 1: Direct Download (Recommended)

```bash
# Download and run directly via Cloudflare CDN (fastest)
curl -s https://pownsh.mieweb.workers.dev | bash

# Or download from GitHub
curl -s https://raw.githubusercontent.com/mieweb/pown.sh/main/pown.sh | bash
```

### Option 2: Local Download

```bash
curl -O https://raw.githubusercontent.com/mieweb/pown.sh/main/pown.sh | bash
```


## Interactive Configuration

When you run the script **without a `.env` file**, it will:

1. **Auto-detect your domain** from hostname (e.g., `server.example.com` → `dc=example,dc=com`)
2. **Prompt for LDAP settings**:
   - LDAP Server URI
   - LDAP Base DN (with smart default)
   - Admin Distinguished Name
   - CA Certificate path and content
3. **Show configuration summary** and ask for confirmation
4. **Create `.env` file** automatically for future runs

### Manual `.env` Configuration

If you prefer to create the configuration file manually:

```env
LDAP_BASE=dc=example,dc=com
LDAP_URI=ldap://your-ldap-host:389
LDAP_ADMIN_DN=cn=admin,dc=example,dc=com
CA_CERT=/etc/ssl/certs/ca-cert.pem
CA_CERT_CONTENT="-----BEGIN CERTIFICATE-----
...your certificate content...
-----END CERTIFICATE-----"
```

## Cloudflare Worker Distribution

The script is distributed globally via Cloudflare Workers for optimal performance:

- **URL**: `https://pown.sh`
- **Source**: See `worker.js` for the complete implementation

## Distribution Architecture

### Cloudflare Worker (`worker.js`)

The script is served globally through a Cloudflare Worker that:

- **Fetches** the latest script from GitHub's main branch
- **Caches** at Cloudflare's edge locations worldwide (10-second TTL)
- **Appends metadata** including commit hash, timestamp, and source URL
- **Handles errors** gracefully with 502 responses for GitHub issues

**Deployment**: The worker is deployed at `https://pownsh.bh.workers.dev/`

**Management**: [Cloudflare Dashboard](https://dash.cloudflare.com/10825d9d1d920e844ccd0326c66dfc45/workers/services/view/pownsh/production/metrics)

### Development Workflow

1. **Make changes** to `pown.sh` in this repository
2. **Commit to main branch** - changes are automatically available via worker
3. **Test locally** with `./pown.sh` or via worker URL
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

