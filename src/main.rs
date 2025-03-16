use binrw::{BinRead, BinResult};
use chrono::DateTime;
use clap::Parser;
use std::fs;
use std::io::{self, Cursor, Read, Write};
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

#[derive(Debug, BinRead)]
#[brw(little, magic = b"hsqs")]
struct SuperBlock {
    inode_count: u32,
    #[br(parse_with = as_datetime)]
    mod_time: String,
    block_size: u32,
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

/// Parse and validate SquashFS header
fn validate_squashfs_header(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Check for SquashFS magic ("hsqs" or "sqsh")
    let magic = &data[0..4];
    if magic == b"hsqs" || magic == b"sqsh" {
        println!(
            "Found valid SquashFS signature: {:?}",
            std::str::from_utf8(magic).unwrap_or("Invalid UTF-8")
        );

        // Print additional header info if we have enough data
        if data.len() >= 28 {
            let block_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
            let version_major = u16::from_le_bytes([data[28], data[29]]);
            let version_minor = u16::from_le_bytes([data[30], data[31]]);

            println!("SquashFS version: {}.{}", version_major, version_minor);
            println!("Block size: {} bytes", block_size);
        }

        return true;
    }

    false
}

/// Decrypt and save header
fn decrypt_header(input_file: &str, output_file: &str, key: &[u8]) -> io::Result<SuperBlock> {
    // Read input file
    let mut file = fs::File::open(input_file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Decrypt header
    let mut header_data = buffer[..96].to_vec();
    let mut rc4 = RC4::new(key);
    rc4.process(&mut header_data);

    // Validate
    if !validate_squashfs_header(&header_data) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Decrypted data is not a valid SquashFS header",
        ));
    }

    let mut header_cursor = Cursor::new(&header_data);
    let super_block = match SuperBlock::read(&mut header_cursor) {
        Ok(block) => block,
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse SuperBlock: {}", e),
            ));
        }
    };

    // Save header
    let mut output = fs::File::create(output_file)?;
    output.write_all(&header_data)?;

    println!(
        "Successfully decrypted and saved SquashFS header to {}",
        output_file
    );
    Ok(super_block)
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

fn main() {
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

    // Decrypt header
    match decrypt_header(input_file, output_file, &key) {
        Ok(super_block) => {
            println!("Header decryption completed successfully");
            println!("{:#?}", super_block);
        }
        Err(e) => {
            println!("Error during decryption: {}", e);
            process::exit(1);
        }
    }
}
