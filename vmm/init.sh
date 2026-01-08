#!/bin/busybox sh

# Setup busybox applets
/bin/busybox --install -s /bin

# Mount essential filesystems
# Enable sysrq
echo 1 > /proc/sys/kernel/sysrq

# Create mountpoint for real root
mkdir -p /sysroot
mkdir -p /dev
mkdir -p /proc
mkdir -p /sys

# Mount essential filesystems
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys

# Wait for /dev/vda to appear (VirtIO Block)
echo "Waiting for /dev/vda..."
for i in $(seq 1 10); do
    if [ -b /dev/vda ]; then
        echo "/dev/vda found."
        break
    fi
    sleep 0.1
    mdev -s # Trigger mdev scan if needed
done

# Mount the root device
echo "Mounting /dev/vda to /sysroot..."
mount /dev/vda /sysroot


# Start a background diagnostic that dumps stacks every 30 seconds
(
  while true; do
    sleep 30
    echo "=== AUTO STACK DUMP (30s interval) ===" > /dev/console
    echo t > /proc/sysrq-trigger
  done
) &

echo ""
echo "=== INITRD SHELL ==="
echo "You are now in a busybox shell with Ubuntu rootfs mounted at /sysroot"
echo ""
echo "Background stack dump running every 30 seconds"
echo ""
echo "To start systemd manually, run:"
echo "  chroot /sysroot /lib/systemd/systemd"
echo ""
echo "Or for a shell in the chroot:"
echo "  chroot /sysroot /bin/bash"
echo ""

# Drop to shell with explicit console I/O
exec setsid sh -c 'exec /bin/busybox sh </dev/console >/dev/console 2>&1'
