/// Metadata blocks in SquashFS are 8192 bytes in size.
pub const SQUASHFS_METADATA_SIZE: u32 = 8192;

/// Extract the offset within a block from a squashfs inode number
///
/// Squashfs inodes consist of a compressed block number and an
/// uncompressed offset within that block. This function extracts the offset.
pub fn squashfs_inode_offset(inode: u64) -> u32 {
    (inode & 0xffff) as u32
}
