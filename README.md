# LDAP Client Automation

This project automates LDAP client setup across various Linux distributions (Debian, Amazon Linux, Rocky Linux etc.) and includes AWS infrastructure testing via Terraform.

## Features

* Automated LDAP client configuration via `pown.sh`
* SSH setup with secure defaults
* SSSD setup and LDAP authentication support
* TLS certificate handling
* Cross-distro support: `apt`, `yum`, `pacman`
* AWS-based infrastructure testing

## Run in Any Container

You can run this script in **any Linux container** to configure it as an LDAP client:

```bash
curl -O https://raw.githubusercontent.com/anishapant21/pown.sh/main/pown.sh
chmod +x pown.sh
./pown.sh
```

### Required `.env` File

Before running the script, make sure to create a `.env` file in the container (same directory as `pown.sh`) with the following contents:

```env
LDAP_BASE=dc=example,dc=com
LDAP_URI=ldap://your-ldap-host
CA_CERT=/path/to/ca.pem
CA_CERT_CONTENT="-----BEGIN CERTIFICATE-----..."
```

> This `.env` file is required **both** for container execution and AWS-based testing.

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

