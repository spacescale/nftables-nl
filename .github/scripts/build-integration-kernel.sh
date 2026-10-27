#!/usr/bin/env bash
# Runs on the GitHub runner, not inside the test VM.
set -euo pipefail

version=${1:?usage: build-integration-kernel.sh VERSION OUTPUT_DIRECTORY}
output_directory=${2:?provide an output directory}
[[ "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]
mkdir -p "$output_directory"
output_directory=$(cd "$output_directory" && pwd)

build_directory=$(mktemp -d)
trap 'rm -rf "$build_directory"' EXIT
cd "$build_directory"

archive="linux-$version.tar.xz"
base_url="https://cdn.kernel.org/pub/linux/kernel/v${version%%.*}.x"
curl --fail --silent --show-error --location --retry 3 \
  "$base_url/$archive" -o "$archive"
curl --fail --silent --show-error --location --retry 3 \
  "$base_url/sha256sums.asc" -o sha256sums.asc

# Verify the archive against the checksum manifest fetched over HTTPS.
awk -v archive="$archive" '$2 == archive { print }' sha256sums.asc > checksum
test -s checksum
sha256sum --check checksum

tar -xf "$archive"
cd "linux-$version"
make x86_64_defconfig

# Build VM boot support and nftables into the image. This avoids requiring
# separately installed guest modules, which must match the selected kernel.
for option in \
  PCI VIRTIO VIRTIO_PCI VIRTIO_CONSOLE \
  NET_9P NET_9P_VIRTIO 9P_FS 9P_FS_POSIX_ACL \
  DEVTMPFS DEVTMPFS_MOUNT TMPFS TMPFS_POSIX_ACL PROC_FS SYSFS \
  BINFMT_ELF BINFMT_SCRIPT UNIX INET IPV6 \
  NAMESPACES NET_NS NETFILTER NETFILTER_NETLINK NF_TABLES NF_TABLES_INET
do
  scripts/config --enable "$option"
done
scripts/config --disable MODULES --disable WERROR \
  --disable DEBUG_INFO --disable DEBUG_INFO_BTF \
  --disable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT --enable DEBUG_INFO_NONE
make olddefconfig

# Fail before compiling if a dependency silently disabled an essential feature.
for option in \
  VIRTIO_PCI VIRTIO_CONSOLE NET_9P_VIRTIO 9P_FS \
  BINFMT_ELF BINFMT_SCRIPT NET_NS INET IPV6 \
  NETFILTER_NETLINK NF_TABLES NF_TABLES_INET
do
  if ! grep -qx "CONFIG_${option}=y" .config; then
    echo "Required built-in kernel feature missing: CONFIG_$option" >&2
    exit 1
  fi
done

make -j"$(nproc)" bzImage
cp arch/x86/boot/bzImage "$output_directory/bzImage"
cp .config "$output_directory/kernel.config"
make -s kernelrelease > "$output_directory/kernel-release"
