use backhand::SuperBlock;
use backhand::{
    BackhandError, FilesystemCompressor, compression::CompressionAction, compression::Compressor,
    compression::DefaultCompressor, kind::Kind,
};

#[derive(Copy, Clone)]
pub struct CustomCompressor {
    pub _key: [u8; 16],
}

impl CustomCompressor {
    // Compressors need a static lifetime, so we need to leak the box
    pub fn new_static(key: [u8; 16]) -> &'static Self {
        let compressor = Box::new(Self { _key: key });
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
        DefaultCompressor.decompress(bytes, out, Compressor::Gzip)?;
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
