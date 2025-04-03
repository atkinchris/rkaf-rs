use backhand::SuperBlock;
use backhand::{
    BackhandError, FilesystemCompressor, compression::CompressionAction, compression::Compressor,
    compression::DefaultCompressor, kind::Kind,
};

use crate::rc4::RC4;

#[derive(Copy, Clone)]
pub struct CustomCompressor {
    key: [u8; 16],
}

impl CustomCompressor {
    // Compressors need a static lifetime, so we need to leak the box
    pub fn new_static(key: [u8; 16]) -> &'static Self {
        let compressor = Box::new(Self { key });
        Box::leak(compressor)
    }
}

// Special decompress that only has support for the Rust version of gzip: zune-inflate for
// decompression.
impl CompressionAction for CustomCompressor {
    fn decompress(
        &self,
        bytes: &[u8],
        out: &mut Vec<u8>,
        _: Compressor,
    ) -> Result<(), BackhandError> {
        // Clone the bytes to a buffer
        let mut buffer = bytes.to_vec();

        // Decrypt the bytes using RC4
        let mut rc4 = RC4::new(&self.key);
        rc4.process(&mut buffer);

        // Decompress the bytes using Gzip
        DefaultCompressor.decompress(&buffer, out, Compressor::Gzip)?;
        Ok(())
    }

    // Just pass to default compressor
    fn compress(
        &self,
        bytes: &[u8],
        fc: FilesystemCompressor,
        block_size: u32,
    ) -> Result<Vec<u8>, BackhandError> {
        DefaultCompressor.compress(bytes, fc, block_size)
    }

    // pass the default options
    fn compression_options(
        &self,
        _superblock: &mut SuperBlock,
        _kind: &Kind,
        _fs_compressor: FilesystemCompressor,
    ) -> Result<Vec<u8>, BackhandError> {
        DefaultCompressor.compression_options(_superblock, _kind, _fs_compressor)
    }
}
