use backhand::FilesystemReader;
use backhand::kind::Kind;
use clap::Parser;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use std::process;
use tracing_subscriber::prelude::*;

mod rc4;

use rc4::RC4;

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
#[command(name = "SquashFS Decryptor")]
#[command(about = "Decrypts SquashFS files using RC4")]
struct Cli {
    input_file: String,
    #[arg(long)]
    key: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let input_file = &cli.input_file;
    let key_str = &cli.key;

    // Convert key from hex string to bytes
    let key = match hex_to_bytes(key_str) {
        Ok(k) => k,
        Err(e) => {
            println!("Error parsing key: {}", e);
            process::exit(1);
        }
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();

    println!("Using key: {}", key_str);

    // Check if input file exists
    if !Path::new(input_file).exists() {
        println!("Error: Input file '{}' not found", input_file);
        process::exit(1);
    }

    // Open the input file
    let mut file = File::open(input_file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Decrypt the header data using RC4
    let mut rc4 = RC4::new(&key);
    rc4.process(&mut buffer[..96]);

    // Create a cursor to read the decrypted data
    // This is necessary because the BinRead trait requires a reader
    let cursor = Cursor::new(&buffer);

    let kind = Kind::from_target("le_v4_0")?;
    let filesystem = FilesystemReader::from_reader_with_offset_and_kind(cursor, 0, kind)?;

    filesystem.files().for_each(|file| {
        println!("File: {}", file.fullpath.display());
    });

    Ok(())
}
