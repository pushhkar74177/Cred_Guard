#!/usr/bin/env bash
# Install the build + runtime dependencies for the CredGuard demo on
# Debian/Ubuntu/Kali. Run once, as root.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y \
	clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev \
	gcc make pkg-config iproute2 curl python3
echo
echo "Dependencies installed. Check your kernel has BTF:"
ls -l /sys/kernel/btf/vmlinux && echo "BTF present - good."
