use binrw::{BinRead, BinResult};
use bitflags::bitflags;
use chrono::DateTime;
use clap::Parser;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::Path;
use std::process;

mod rc4;
use rc4::RC4;

#[binrw::parser(reader, endian)]
fn as_datetime() -> BinResult<String> {
    // Read the 4-byte timestamp
    let timestamp = <u32>::read_options(reader, endian, ())?;
    // Convert to a human-readable format
    let datetime = DateTime::from_timestamp(timestamp as i64, 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid timestamp"))?;
    Ok(datetime.to_rfc3339())
}

#[binrw::parser(reader, endian)]
fn as_optional() -> BinResult<Option<u64>> {
    // Read the 4-byte value
    let value = <u64>::read_options(reader, endian, ())?;
    // If the value is 0, return None
    if value == 0xFFFFFFFFFFFFFFFF {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

bitflags! {
  #[derive(Debug)]
  pub struct SuperBlockFlags: u16 {
      // 0x0001 Inodes are stored uncompressed.
      const inodes_uncompressed = 0x0001;
      // 0x0002 Data blocks are stored uncompressed.
      const data_uncompressed = 0x0002;
      // 0x0004 Unused, should always be unset.
      const unused = 0x0004;
      // 0x0008 Fragments are stored uncompressed.
      const fragments_uncompressed = 0x0008;
      // 0x0010 Fragments are not used.
      const fragments_not_used = 0x0010;
      // 0x0020 Fragments are always generated.
      const fragments_always_generated = 0x0020;
      // 0x0040 Data has been deduplicated.
      const data_deduplicated = 0x0040;
      // 0x0080 NFS export table exists.
      const nfs_export_table_exists = 0x0080;
      // 0x0100 Xattrs are stored uncompressed.
      const xattrs_uncompressed = 0x0100;
      // 0x0200 There are no Xattrs in the archive.
      const no_xattrs = 0x0200;
      // 0x0400 Compressor options are present.
      const compressor_options_present = 0x0400;
      // 0x0800 The ID table is uncompressed.
      const id_table_uncompressed = 0x0800;
  }
}

impl SuperBlockFlags {
    #[binrw::parser(reader, endian)]
    fn parse() -> BinResult<SuperBlockFlags> {
        let flags = <u16>::read_options(reader, endian, ())?;
        Ok(SuperBlockFlags::from_bits_truncate(flags))
    }
}

#[derive(Debug, BinRead)]
#[brw(little, magic = b"hsqs")]
// SquashFS only practically supports one version of the header (4.0).
#[br(assert(version_major == 4 && version_minor == 0))]
// The Log2 of the block size must be equal to the block log.
#[br(assert((block_size as f32).log(2.0).round() as u16 == block_log))]
// Block size must be a power of two between 4096 (4k) and 1048576 (1 MiB).
#[brw(assert(block_size.is_power_of_two() && block_size >= 4096 && block_size <= 1048576))]
struct SuperBlock {
    inode_count: u32,
    #[br(parse_with = as_datetime)]
    mod_time: String,
    block_size: u32,
    frag_count: u32,
    compressor: u16,
    block_log: u16,
    #[br(parse_with = SuperBlockFlags::parse)]
    flags: SuperBlockFlags,
    id_count: u16,
    version_major: u16,
    version_minor: u16,
    root_inode: u64,
    bytes_used: u64,
    id_table_start: u64,
    #[br(parse_with = as_optional)]
    xattr_id_table_start: Option<u64>,
    inode_table_start: u64,
    directory_table_start: u64,
    #[br(parse_with = as_optional)]
    fragment_table_start: Option<u64>,
    #[br(parse_with = as_optional)]
    export_table_start: Option<u64>,
}

/// Convert a hex string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, &'static str> {
    let hex = hex.replace(" ", "");
    if hex.len() % 2 != 0 {
        return Err("Hex string must have an even number of characters");
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;

    while i < hex.len() {
        let high = u8::from_str_radix(&hex[i..i + 1], 16).map_err(|_| "Invalid hex character")?;
        let low =
            u8::from_str_radix(&hex[i + 1..i + 2], 16).map_err(|_| "Invalid hex character")?;
        bytes.push((high << 4) | low);
        i += 2;
    }

    Ok(bytes)
}

#[derive(Parser)]
#[command(name = "SquashFS Header Decryptor")]
#[command(about = "Decrypts and validates SquashFS headers")]
struct Cli {
    input_file: String,
    output_file: String,
    #[arg(long)]
    key: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let input_file = &cli.input_file;
    let output_file = &cli.output_file;
    let key_str = &cli.key;

    // Convert key from hex string to bytes
    let key = match hex_to_bytes(key_str) {
        Ok(k) => k,
        Err(e) => {
            println!("Error parsing key: {}", e);
            process::exit(1);
        }
    };

    println!("Using key: {}", key_str);

    // Check if input file exists
    if !Path::new(input_file).exists() {
        println!("Error: Input file '{}' not found", input_file);
        process::exit(1);
    }

    // Read input file
    let mut file = fs::File::open(input_file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Decrypt the file
    let mut rc4 = RC4::new(&key);
    rc4.process(&mut buffer);

    let mut buffer_cursor = Cursor::new(buffer);

    let super_block = match SuperBlock::read(&mut buffer_cursor) {
        Ok(block) => block,
        Err(e) => {
            println!("Error during decryption: {}", e);
            process::exit(1);
        }
    };

    println!("Header decryption completed successfully");
    println!("{:#?}", super_block);

    Ok(())
}
