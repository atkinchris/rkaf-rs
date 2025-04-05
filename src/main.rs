use backhand::kind::Kind;
use backhand::{BufReadSeek, FilesystemReader, FilesystemWriter, Squashfs};
use clap::Parser;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use std::process;

mod compressor;
mod rc4;

use compressor::CustomCompressor;
use rc4::RC4;

/// Convert a hex string to bytes
fn hex_to_bytes(hex: &str) -> Result<[u8; 16], &'static str> {
    let hex = hex.replace(" ", "");

    // Check if the hex string has 32 characters
    if hex.len() != 32 {
        return Err("Hex string must be 32 characters long");
    }

    let mut bytes = [0u8; 16];
    let mut i = 0;

    while i < hex.len() {
        let high = u8::from_str_radix(&hex[i..i + 1], 16).map_err(|_| "Invalid hex character")?;
        let low =
            u8::from_str_radix(&hex[i + 1..i + 2], 16).map_err(|_| "Invalid hex character")?;
        bytes[i / 2] = (high << 4) | low;
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

    // Decrypt the header data using RC4, as this won't be compressed
    let mut rc4 = RC4::new(&key);
    rc4.process(&mut buffer[..96]);

    // Create a cursor for the superblock
    let cursor = Cursor::new(buffer.clone());
    let mut reader: Box<dyn BufReadSeek> = Box::new(cursor);
    let superblock = match Squashfs::superblock_and_compression_options(
        &mut reader,
        &Kind::from_target("le_v4_0")?,
    )? {
        (superblock, _) => superblock,
    };

    // Find and decrypt the fragment table size, ready for decryption and decompression
    // TODO: Check if the fragment table is present & how many blocks it has
    // This implementation assumes that the fragment table is present and has 1 block
    let fragment_table_lookup_ptr = superblock.frag_table as usize;
    let mut rc4 = RC4::new(&key);
    rc4.process(&mut buffer[fragment_table_lookup_ptr..fragment_table_lookup_ptr + 8]);
    let fragment_table_ptr = usize::from_le_bytes(
        buffer[fragment_table_lookup_ptr..fragment_table_lookup_ptr + 8].try_into()?,
    );
    // Decrypt the u16 size of the start of the fragment table, without reseting the RC4 state
    rc4.process(&mut buffer[fragment_table_ptr..fragment_table_ptr + 2]);

    // Find and decrypt the lookup table size, ready for decryption and decompression
    let export_table_lookup_ptr = superblock.export_table as usize;
    let mut rc4 = RC4::new(&key);
    rc4.process(&mut buffer[export_table_lookup_ptr..export_table_lookup_ptr + 8]);
    let export_table_ptr = usize::from_le_bytes(
        buffer[export_table_lookup_ptr..export_table_lookup_ptr + 8].try_into()?,
    );
    // Decrypt the u16 size of the export table, without reseting the RC4 state
    rc4.process(&mut buffer[export_table_ptr..export_table_ptr + 2]);

    // Find and decrypt the ID table size, ready for decryption and decompression
    let id_table_lookup_ptr = superblock.id_table as usize;
    let mut rc4 = RC4::new(&key);
    rc4.process(&mut buffer[id_table_lookup_ptr..id_table_lookup_ptr + 8]);

    // Create the custom compressor with the key.
    // This needs to be a static reference, so we use the new_static function.
    let compressor = CustomCompressor::new_static(key);
    let kind = Kind::new(compressor);
    let cursor = Cursor::new(buffer);
    let filesystem_reader = FilesystemReader::from_reader_with_offset_and_kind(cursor, 0, kind)?;

    filesystem_reader.files().for_each(|file| {
        println!("File: {}", file.fullpath.display());
    });

    // Create a writer
    let mut filesystem_writer = FilesystemWriter::from_fs_reader(&filesystem_reader)?;

    // Write the filesystem to a new file
    // This will create a new SquashFS file with the decrypted data
    let mut output = File::create("decrypted.squashfs")?;
    filesystem_writer.write(&mut output)?;

    Ok(())
}
