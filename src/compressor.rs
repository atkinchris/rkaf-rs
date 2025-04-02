use backhand::SuperBlock;
use backhand::{
    BackhandError, FilesystemCompressor, compression::CompressionAction, compression::Compressor,
    compression::DefaultCompressor, kind::Kind,
};

#[derive(Copy, Clone)]
pub struct CustomCompressor;

// Special decompress that only has support for the Rust version of gzip: zune-inflate for
// decompression.
impl CompressionAction for CustomCompressor {
    fn decompress(
        &self,
        bytes: &[u8],
        out: &mut Vec<u8>,
        compressor: Compressor,
    ) -> Result<(), BackhandError> {
        unimplemented!();
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
