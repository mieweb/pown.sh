#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

echo "Running Terraform tests..."

# Navigate to the tests folder
cd "$(dirname "$0")"

# Initialize Terraform
terraform init

# Validate Terraform configuration
terraform validate

# Plan Terraform changes
terraform plan -out=tfplan

# Apply Terraform changes
terraform apply -auto-approve tfplan

# Test outputs
debian_ip=$(terraform output -raw debian_public_ip)
amazon_ip=$(terraform output -raw amazon_linux_public_ip)

if [ -z "$debian_ip" ] || [ -z "$amazon_ip" ]; then
    echo "Test failed: Public IP outputs are empty"
    terraform destroy -auto-approve
    exit 1
else
    echo "Test passed: Debian IP ($debian_ip), Amazon Linux IP ($amazon_ip)"
fi

# Clean up resources
terraform destroy -auto-approve

echo "Terraform tests completed successfully."
