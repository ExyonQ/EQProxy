//! POSIX ACL access entries for the admin Unix socket (ADR-0023).
//!
//! A Unix socket is a file: `connect(2)` requires write permission on it, and
//! the classic mode bits give the owner, one group and "everyone else" a
//! single answer each. A POSIX ACL adds **named users** (and named groups) to
//! that decision without widening the group, and the kernel enforces it at
//! `connect` — before this process sees a peer at all.
//!
//! There is no `acl_set_file` here: that is a C library, and this workspace
//! forbids `unsafe` and links no libacl (the image is a static musl binary on
//! Wolfi, ADR-0016). Linux stores the same ACL as the extended attribute
//! `system.posix_acl_access`; `acl_set_file` ultimately writes exactly this
//! blob, whose layout is kernel UAPI (`include/uapi/linux/posix_acl_xattr.h`):
//!
//! ```text
//! header: version:u32 = 2 (little endian)
//! entry : tag:u16, perm:u16, id:u32      (one per entry)
//! ```
//!
//! Tag order is fixed by the kernel (owner, named users sorted by id, group,
//! mask, other) and a named entry requires a mask. This module builds the
//! canonical blob for one shape only — owner `rw`, each named uid `rw`, the
//! file's group `rw`, mask `rw`, other none — which is the shape of a `0660`
//! admin socket plus named users. The file mode's group class *is* the mask,
//! so `0660` and a `rw` mask agree instead of fighting.

use std::io;
use std::path::Path;

/// Extended attribute the Linux kernel maps to the POSIX access ACL.
pub const ACCESS_XATTR: &str = "system.posix_acl_access";

/// `POSIX_ACL_XATTR_VERSION` (kernel UAPI).
pub const XATTR_VERSION: u32 = 0x0002;

const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;

const ACL_READ: u16 = 0x04;
const ACL_WRITE: u16 = 0x02;

/// `ACL_UNDEFINED_ID`: the entries that carry no uid.
const UNDEFINED_ID: u32 = u32::MAX;

/// Encodes the access ACL of a `0660` socket that also admits `uids` as named
/// users with `rw`. Duplicates are removed and the order is the kernel's
/// (ascending id), so the same list always yields the same bytes.
#[must_use]
pub fn access_blob(uids: &[u32]) -> Vec<u8> {
    let mut named: Vec<u32> = uids.to_vec();
    named.sort_unstable();
    named.dedup();

    let mut blob = Vec::with_capacity(4 + 8 * (4 + named.len()));
    blob.extend_from_slice(&XATTR_VERSION.to_le_bytes());
    let mut entry = |tag: u16, perm: u16, id: u32| {
        blob.extend_from_slice(&tag.to_le_bytes());
        blob.extend_from_slice(&perm.to_le_bytes());
        blob.extend_from_slice(&id.to_le_bytes());
    };
    entry(ACL_USER_OBJ, ACL_READ | ACL_WRITE, UNDEFINED_ID);
    for uid in named {
        entry(ACL_USER, ACL_READ | ACL_WRITE, uid);
    }
    entry(ACL_GROUP_OBJ, ACL_READ | ACL_WRITE, UNDEFINED_ID);
    entry(ACL_MASK, ACL_READ | ACL_WRITE, UNDEFINED_ID);
    entry(ACL_OTHER, 0, UNDEFINED_ID);
    blob
}

/// Installs (or clears, when `uids` is empty) the access ACL of `path`.
///
/// Fail-closed: an unsupported filesystem, a kernel that rejects the blob or
/// a missing permission is an `Err`, never a silent "the mode still works".
#[cfg(target_os = "linux")]
pub fn set_access(path: &Path, uids: &[u32]) -> io::Result<()> {
    if uids.is_empty() {
        // No stale named user may survive a reload that empties the list.
        return match xattr::remove(path, ACCESS_XATTR) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
    }
    xattr::set(path, ACCESS_XATTR, &access_blob(uids))
}

/// A Unix socket cannot carry a Linux ACL on this platform; the configuration
/// validator rejects the field before a plane is ever bound. An empty list is
/// the normal case and has nothing to clear, so it is a no-op here.
#[cfg(not(target_os = "linux"))]
pub fn set_access(_path: &Path, uids: &[u32]) -> io::Result<()> {
    if uids.is_empty() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "POSIX ACLs on the admin socket are implemented on Linux only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(blob: &[u8]) -> Vec<(u16, u16, u32)> {
        let version = u32::from_le_bytes(blob[0..4].try_into().expect("version"));
        assert_eq!(version, XATTR_VERSION);
        blob[4..]
            .chunks_exact(8)
            .map(|chunk| {
                (
                    u16::from_le_bytes(chunk[0..2].try_into().expect("tag")),
                    u16::from_le_bytes(chunk[2..4].try_into().expect("perm")),
                    u32::from_le_bytes(chunk[4..8].try_into().expect("id")),
                )
            })
            .collect()
    }

    #[test]
    fn the_blob_is_the_kernel_layout_for_owner_group_mask_other() {
        let blob = access_blob(&[]);
        assert_eq!(
            blob.len(),
            4 + 8 * 4,
            "no named user, four base entries (owner, group, mask, other)"
        );
        assert_eq!(
            entries(&blob),
            vec![
                (ACL_USER_OBJ, ACL_READ | ACL_WRITE, UNDEFINED_ID),
                (ACL_GROUP_OBJ, ACL_READ | ACL_WRITE, UNDEFINED_ID),
                (ACL_MASK, ACL_READ | ACL_WRITE, UNDEFINED_ID),
                (ACL_OTHER, 0, UNDEFINED_ID),
            ]
        );
    }

    #[test]
    fn named_users_are_sorted_and_deduplicated_between_owner_and_group() {
        let blob = access_blob(&[1002, 1001, 1002]);
        assert_eq!(
            entries(&blob),
            vec![
                (ACL_USER_OBJ, ACL_READ | ACL_WRITE, UNDEFINED_ID),
                (ACL_USER, ACL_READ | ACL_WRITE, 1001),
                (ACL_USER, ACL_READ | ACL_WRITE, 1002),
                (ACL_GROUP_OBJ, ACL_READ | ACL_WRITE, UNDEFINED_ID),
                (ACL_MASK, ACL_READ | ACL_WRITE, UNDEFINED_ID),
                (ACL_OTHER, 0, UNDEFINED_ID),
            ]
        );
        assert_eq!(blob.len(), 4 + 8 * 6);
    }

    #[test]
    fn a_full_validated_list_stays_under_a_kilobyte_and_round_trips_every_uid() {
        // The configuration caps the list at 64 uids (validate.rs).
        let uids: Vec<u32> = (0..64).map(|index| 60_000 + index).collect();
        let blob = access_blob(&uids);
        assert!(blob.len() <= 1024, "{}", blob.len());
        let named: Vec<u32> = entries(&blob)
            .into_iter()
            .filter(|(tag, _, _)| *tag == ACL_USER)
            .map(|(_, _, id)| id)
            .collect();
        assert_eq!(named, uids);
    }
}
