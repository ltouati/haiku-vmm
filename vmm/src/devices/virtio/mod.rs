// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements virtio devices, queues, and transport mechanisms.
#![allow(dead_code)]

use crate::devices::pic::Pic;
use futures::channel::oneshot;
use serde::Deserialize;
use serde::Serialize;
use std::cmp;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};
use virtio_bindings::virtio_config::{VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_VERSION_1};
use virtio_bindings::virtio_ids;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use virtio_device::VirtioConfig;
use virtio_queue::Queue;

const DEVICE_RESET: u32 = 0x0;

const INTERRUPT_STATUS_USED_RING: u32 = 0x1;
const INTERRUPT_STATUS_CONFIG_CHANGED: u32 = 0x2;

const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;
pub mod virtio_blk;
pub mod virtio_console;
pub mod virtio_mmio_device;
pub mod virtio_rng;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u32)]
pub enum DeviceType {
    Net = virtio_ids::VIRTIO_ID_NET,
    Block = virtio_ids::VIRTIO_ID_BLOCK,
    Console = virtio_ids::VIRTIO_ID_CONSOLE,
    Rng = virtio_ids::VIRTIO_ID_RNG,
    Balloon = virtio_ids::VIRTIO_ID_BALLOON,
    Scsi = virtio_ids::VIRTIO_ID_SCSI,
    #[serde(rename = "9p")]
    P9 = virtio_ids::VIRTIO_ID_9P,
    Gpu = virtio_ids::VIRTIO_ID_GPU,
    Input = virtio_ids::VIRTIO_ID_INPUT,
    Vsock = virtio_ids::VIRTIO_ID_VSOCK,
    Iommu = virtio_ids::VIRTIO_ID_IOMMU,
    Sound = virtio_ids::VIRTIO_ID_SOUND,
    Fs = virtio_ids::VIRTIO_ID_FS,
    Pmem = virtio_ids::VIRTIO_ID_PMEM,
    #[serde(rename = "mac80211-hwsim")]
    Mac80211HwSim = virtio_ids::VIRTIO_ID_MAC80211_HWSIM,
    VideoEncoder = virtio_ids::VIRTIO_ID_VIDEO_ENCODER,
    VideoDecoder = virtio_ids::VIRTIO_ID_VIDEO_DECODER,
    Scmi = virtio_ids::VIRTIO_ID_SCMI,
}

impl DeviceType {
    /// Returns the minimum number of queues that a device of the corresponding type must support.
    ///
    /// Note that this does not mean a driver must activate these queues, only that they must be
    /// implemented by a spec-compliant device.
    pub fn min_queues(&self) -> usize {
        match self {
            DeviceType::Net => 3,           // rx, tx (TODO: b/314353246: ctrl is optional)
            DeviceType::Block => 1,         // request queue
            DeviceType::Console => 2,       // receiveq, transmitq
            DeviceType::Rng => 1,           // request queue
            DeviceType::Balloon => 2,       // inflateq, deflateq
            DeviceType::Scsi => 3,          // controlq, eventq, request queue
            DeviceType::P9 => 1,            // request queue
            DeviceType::Gpu => 2,           // controlq, cursorq
            DeviceType::Input => 2,         // eventq, statusq
            DeviceType::Vsock => 3,         // rx, tx, event
            DeviceType::Iommu => 2,         // requestq, eventq
            DeviceType::Sound => 4,         // controlq, eventq, txq, rxq
            DeviceType::Fs => 2,            // hiprio, request queue
            DeviceType::Pmem => 1,          // request queue
            DeviceType::Mac80211HwSim => 2, // tx, rx
            DeviceType::VideoEncoder => 2,  // cmdq, eventq
            DeviceType::VideoDecoder => 2,  // cmdq, eventq
            DeviceType::Scmi => 2,          // cmdq, eventq
        }
    }
}

/// Prints a string representation of the given virtio device type.
impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            DeviceType::Net => write!(f, "net"),
            DeviceType::Block => write!(f, "block"),
            DeviceType::Console => write!(f, "console"),
            DeviceType::Rng => write!(f, "rng"),
            DeviceType::Balloon => write!(f, "balloon"),
            DeviceType::Scsi => write!(f, "scsi"),
            DeviceType::P9 => write!(f, "9p"),
            DeviceType::Input => write!(f, "input"),
            DeviceType::Gpu => write!(f, "gpu"),
            DeviceType::Vsock => write!(f, "vsock"),
            DeviceType::Iommu => write!(f, "iommu"),
            DeviceType::Sound => write!(f, "sound"),
            DeviceType::Fs => write!(f, "fs"),
            DeviceType::Pmem => write!(f, "pmem"),
            DeviceType::VideoDecoder => write!(f, "video-decoder"),
            DeviceType::VideoEncoder => write!(f, "video-encoder"),
            DeviceType::Mac80211HwSim => write!(f, "mac80211-hwsim"),
            DeviceType::Scmi => write!(f, "scmi"),
        }
    }
}

/// Copy virtio device configuration data from a subslice of `src` to a subslice of `dst`.
/// Unlike std::slice::copy_from_slice(), this function copies as much as possible within
/// the common subset of the two slices, truncating the requested range instead of
/// panicking if the slices do not match in size.
///
/// `dst_offset` and `src_offset` specify the starting indexes of the `dst` and `src`
/// slices, respectively; if either index is out of bounds, this function is a no-op
/// rather than panicking.  This makes it safe to call with arbitrary user-controlled
/// inputs.
pub fn copy_config(dst: &mut [u8], dst_offset: u64, src: &[u8], src_offset: u64) {
    if let Ok(dst_offset) = usize::try_from(dst_offset)
        && let Ok(src_offset) = usize::try_from(src_offset)
        && let Some(dst_slice) = dst.get_mut(dst_offset..)
        && let Some(src_slice) = src.get(src_offset..)
    {
        let len = cmp::min(dst_slice.len(), src_slice.len());
        let dst_subslice = &mut dst_slice[0..len];
        let src_subslice = &src_slice[0..len];
        dst_subslice.copy_from_slice(src_subslice);
    }
}

/// Returns the set of reserved base features common to all virtio devices.
pub fn base_features() -> u64 {
    1 << VIRTIO_F_VERSION_1 | 1 << VIRTIO_RING_F_EVENT_IDX | 1 << VIRTIO_F_ACCESS_PLATFORM
}

/// Type of virtio transport.
///
/// The virtio protocol can be transported by several means, which affects a few things for device
/// creation - for instance, the seccomp policy we need to use when jailing the device.
pub enum VirtioDeviceType {
    /// A regular (in-VMM) virtio device.
    Regular,
    /// Socket-backed vhost-user device.
    VhostUser,
}

impl VirtioDeviceType {
    /// Returns the seccomp policy file that we will want to load for device `base`, depending on
    /// the virtio transport type.
    pub fn seccomp_policy_file(&self, base: &str) -> String {
        match self {
            VirtioDeviceType::Regular => format!("{base}_device"),
            VirtioDeviceType::VhostUser => format!("{base}_device_vhost_user"),
        }
    }
}

/// Creates a oneshot channel, returning the rx end and adding the tx end to the
/// provided `Vec`. Useful for creating oneshots that signal a virtqueue future
/// to stop processing and exit.
pub(crate) fn create_stop_oneshot(tx_vec: &mut Vec<oneshot::Sender<()>>) -> oneshot::Receiver<()> {
    let (stop_tx, stop_rx) = futures::channel::oneshot::channel();
    tx_vec.push(stop_tx);
    stop_rx
}

/// When we request to stop the worker, this represents the terminal state
/// for the thread (if it exists).
pub(crate) enum StoppedWorker<Q> {
    /// Worker stopped successfully & returned its queues.
    WithQueues(Box<Q>),

    /// Worker wasn't running when the stop was requested.
    AlreadyStopped,

    /// Worker was running but did not successfully return its queues. Something
    /// has gone wrong (and will be in the error log). In the case of a device
    /// reset this is fine since the next activation will replace the queues.
    MissingQueues,
}
pub fn default_signal_interrupt(
    config: &mut VirtioConfig<Queue>,
    pic: Option<&Arc<Mutex<Pic>>>,
    irq_line: u8,
) {
    config
        .interrupt_status
        .store(1, std::sync::atomic::Ordering::SeqCst);

    // Route through PIC (Pulse)
    if let Some(pic) = &pic {
        let mut p = pic.lock().unwrap();
        p.set_irq(irq_line, true);
        p.set_irq(irq_line, false);
    }
}
