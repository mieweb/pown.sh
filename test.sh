#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define the list of Docker images to test
DISTROS=(
    "debian:stable"
    "debian:testing"
    "debian:unstable"
    "ubuntu:20.04"
    "ubuntu:22.04"
    "rockylinux:8"
    "rockylinux:9"
    "balenalib/raspberrypi3-debian:stretch"
    "balenalib/raspberrypi3-debian:buster"
    "archlinux:latest"
)

# Path to the pown.sh script
SCRIPT_PATH=$(realpath pown.sh)

# Function to run the script in a Docker container
function run_test() {
    local distro=$1
    echo "Testing on $distro..."
    case "$distro" in
        *debian*|*ubuntu*)
            docker run --rm -v "$SCRIPT_PATH":/pown.sh -h ldap --privileged "$distro" /bin/bash -c "
                chmod +x /pown.sh && /pown.sh"
            ;;
        *rockylinux*)
            docker run --rm -v "$SCRIPT_PATH":/pown.sh -h ldap --privileged "$distro" /bin/bash -c "
                chmod +x /pown.sh && /pown.sh"
            ;;
        *balenalib/raspberrypi3-debian*)
            docker run --rm --platform linux/arm/v7 -v "$SCRIPT_PATH":/pown.sh -h ldap --privileged "$distro" /bin/bash -c "
                chmod +x /pown.sh && /pown.sh"
            ;;
        *archlinux*)
            docker run --rm -v "$SCRIPT_PATH":/pown.sh -h ldap --privileged "$distro" /bin/bash -c "
                chmod +x /pown.sh && /pown.sh"
            ;;
        *)
            echo "Unsupported distribution: $distro"
            exit 1
            ;;
    esac
}

# Run tests for all defined distributions
for DISTRO in "${DISTROS[@]}"; do
    run_test "$DISTRO"
done
