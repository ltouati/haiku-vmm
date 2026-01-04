#!/bin/bash
set -e

# Configuration
KERNEL_VERSION="6.6.14"
UBUNTU_RELEASE="jammy" # 22.04 LTS (Stable)
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
WORKDIR="$(pwd)/vm_build"
IMAGE_SIZE="2G"
ROOT_PASSWORD="root"

# Dependencies (Debian/Ubuntu)
DEPENDENCIES="build-essential libncurses-dev bison flex libssl-dev libelf-dev debootstrap qemu-utils bc"

echo "=== Ubuntu Kernel & RootFS Creator ==="
echo "Workdir: ${WORKDIR}"

mkdir -p "${WORKDIR}"

check_deps() {
    echo "Checking dependencies..."
    MISSING=""
    for dep in $DEPENDENCIES; do
        if ! dpkg -s $dep >/dev/null 2>&1; then
             MISSING="$MISSING $dep"
        fi
    done
    
    if [ ! -z "$MISSING" ]; then
        echo "Missing dependencies: $MISSING"
        read -p "Install them now? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo apt-get update && sudo apt-get install -y $MISSING
        else
            echo "Please install dependencies manually."
            exit 1
        fi
    fi
}

build_kernel() {
    echo "=== Building Kernel ${KERNEL_VERSION} ==="
    cd "${WORKDIR}"
    
    if [ ! -f "linux-${KERNEL_VERSION}.tar.xz" ]; then
        echo "Downloading kernel..."
        wget "${KERNEL_URL}"
    fi
    
    if [ ! -d "linux-${KERNEL_VERSION}" ]; then
        echo "Extracting..."
        tar xf "linux-${KERNEL_VERSION}.tar.xz"
    fi
    
    cd "linux-${KERNEL_VERSION}"
    
    echo "Configuring kernel..."
    make defconfig

    # --- Minimalization: Strip Unnecessary Drivers ---
    # Disable PCI (VMM uses MMIO) - Only needed if user runs pci=off
    # But usually harmless to keep. If user requested minimal, we disable it.
    ./scripts/config --disable CONFIG_PCI
    
    # Disable Multimedia/Sound
    ./scripts/config --disable CONFIG_SOUND
    ./scripts/config --disable CONFIG_MEDIA_SUPPORT
    
    # Disable Graphics/DRM (Headless VMM)
    ./scripts/config --disable CONFIG_AGP
    ./scripts/config --disable CONFIG_DRM
    
    # Disable USB
    ./scripts/config --disable CONFIG_USB_SUPPORT
    ./scripts/config --disable CONFIG_USB
    
    # Disable Wireless/Bluetooth
    ./scripts/config --disable CONFIG_WIRELESS
    ./scripts/config --disable CONFIG_WLAN
    ./scripts/config --disable CONFIG_BT
    
    # Disable unnecessary Network Drivers (Keep only VirtIO)
    ./scripts/config --disable CONFIG_NET_VENDOR_AMAZON
    ./scripts/config --disable CONFIG_NET_VENDOR_AMD
    ./scripts/config --disable CONFIG_NET_VENDOR_BROADCOM
    ./scripts/config --disable CONFIG_NET_VENDOR_INTEL
    ./scripts/config --disable CONFIG_NET_VENDOR_REALTEK
    # (And so on... generic vendor disabling helps)
    ./scripts/config --disable CONFIG_ETHERNET
    
    # Disable Input Devices (Mouse/Joystick/Tablet - Keep Keyboard/Evdev?)
    ./scripts/config --disable CONFIG_INPUT_MOUSE
    ./scripts/config --disable CONFIG_INPUT_JOYSTICK
    ./scripts/config --disable CONFIG_INPUT_TABLET
    ./scripts/config --disable CONFIG_INPUT_TOUCHSCREEN
    
    # --- End Minimalization ---
    
    # Enable VirtIO and MMIO
    ./scripts/config --enable CONFIG_VIRTIO
    ./scripts/config --enable CONFIG_VIRTIO_MENU
    ./scripts/config --enable CONFIG_VIRTIO_MMIO
    ./scripts/config --enable CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES
    ./scripts/config --enable CONFIG_VIRTIO_BLK
    ./scripts/config --enable CONFIG_VIRTIO_NET
    ./scripts/config --enable CONFIG_VIRTIO_CONSOLE
    
    # Enable Serial Console (for booting)
    ./scripts/config --enable CONFIG_SERIAL_8250
    ./scripts/config --enable CONFIG_SERIAL_8250_CONSOLE
    ./scripts/config --enable CONFIG_SERIAL_OF_PLATFORM
    
    # General Support - Kernel 6.6
    ./scripts/config --enable CONFIG_EXT4_FS
    ./scripts/config --enable CONFIG_BINFMT_ELF
    ./scripts/config --enable CONFIG_64BIT
    ./scripts/config --enable CONFIG_TMPFS
    ./scripts/config --enable CONFIG_DEVTMPFS
    ./scripts/config --enable CONFIG_DEVTMPFS_MOUNT

    # Systemd Requirements (Critical)
    ./scripts/config --enable CONFIG_CGROUPS
    ./scripts/config --enable CONFIG_CGROUP_FREEZER
    ./scripts/config --enable CONFIG_CGROUP_PIDS
    ./scripts/config --enable CONFIG_CGROUP_DEVICE
    ./scripts/config --enable CONFIG_CGROUP_CPUACCT
    ./scripts/config --enable CONFIG_MEMCG
    ./scripts/config --enable CONFIG_PROC_PID_CPUSET
    ./scripts/config --enable CONFIG_CPUSETS
    ./scripts/config --enable CONFIG_AUTOFS4_FS
    ./scripts/config --enable CONFIG_AUTOFS_FS
    ./scripts/config --enable CONFIG_FHANDLE
    ./scripts/config --enable CONFIG_SIGNALFD
    ./scripts/config --enable CONFIG_TIMERFD
    ./scripts/config --enable CONFIG_EPOLL
    ./scripts/config --enable CONFIG_IPV6

    # KVM/Paravirt Support (Performance & Timing)
    ./scripts/config --enable CONFIG_HYPERVISOR_GUEST
    ./scripts/config --enable CONFIG_KVM_GUEST
    ./scripts/config --enable CONFIG_PARAVIRT
    ./scripts/config --enable CONFIG_PARAVIRT_SPINLOCKS

    # Debugging
    ./scripts/config --enable CONFIG_IKCONFIG
    ./scripts/config --enable CONFIG_IKCONFIG_PROC

    # Optimize size slightly (optional)
    ./scripts/config --disable CONFIG_DEBUG_INFO
    
    echo "Compiling vmlinux (This will take time)..."
    make -j8 vmlinux
    
    cp vmlinux ../vmlinux-${KERNEL_VERSION}
    echo "Kernel built: ${WORKDIR}/vmlinux-${KERNEL_VERSION}"
}

create_rootfs() {
    echo "=== Creating Ubuntu ${UBUNTU_RELEASE} RootFS ==="
    cd "${WORKDIR}"
    
    IMAGE_NAME="ubuntu-${UBUNTU_RELEASE}.ext4"
    MOUNT_DIR="mnt"
    
    # Create raw image
    truncate -s "${IMAGE_SIZE}" "${IMAGE_NAME}"
    mkfs.ext4 -F "${IMAGE_NAME}"
    
    mkdir -p "${MOUNT_DIR}"
    
    echo "Mounting image (requires sudo)..."
    sudo mount -o loop "${IMAGE_NAME}" "${MOUNT_DIR}"
    
    echo "Bootstrapping Ubuntu..."
    # --variant=minbase for smallest size
    sudo debootstrap --arch=amd64 "${UBUNTU_RELEASE}" "${MOUNT_DIR}" http://archive.ubuntu.com/ubuntu/
    
    echo "Configuring RootFS..."
    
    # Fstab
    echo "/dev/vda / ext4 defaults 0 1" | sudo tee "${MOUNT_DIR}/etc/fstab"
    
    # Netplan
    sudo mkdir -p "${MOUNT_DIR}/etc/netplan"
    cat <<EOF | sudo tee "${MOUNT_DIR}/etc/netplan/01-netcfg.yaml"
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
EOF
    
    # Set Root Password
    echo "Setting root password to '${ROOT_PASSWORD}'"
    echo "root:${ROOT_PASSWORD}" | sudo chroot "${MOUNT_DIR}" chpasswd
    
    # Enable Serial Getty manually
    # Note: On Jammy/Noble, systemd generator usually works.
    # We force it just in case.
    if [ -f "${MOUNT_DIR}/lib/systemd/system/serial-getty@.service" ]; then
         sudo chroot "${MOUNT_DIR}" systemctl enable serial-getty@ttyS0.service
    fi
    
    echo "Unmounting..."
    sudo umount "${MOUNT_DIR}"
    
    echo "RootFS created: ${WORKDIR}/${IMAGE_NAME}"
}

# Main Menu
PS3='Please enter your choice: '
options=("Build Kernel Only" "Create RootFS Only" "Build Both" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Build Kernel Only")
            check_deps
            build_kernel
            break
            ;;
        "Create RootFS Only")
            check_deps
            create_rootfs
            break
            ;;
        "Build Both")
            check_deps
            build_kernel
            create_rootfs
            break
            ;;
        "Quit")
            break
            ;;
        *) echo "invalid option $REPLY";;
    esac
done

echo "Done."
