use binrw::BinRead;
use clap::Parser;
use std::fs::File;

const HEADER_MODEL_LEN: usize = 0x22;
const HEADER_ID_LEN: usize = 0x1E;
const HEADER_MANUFACTURER_LEN: usize = 0x38;

#[derive(Debug, BinRead)]
#[brw(little, magic = b"RKAF")]
struct UpdateHeader {
    length: u32,
    model: [u8; HEADER_MODEL_LEN],
    _id: [u8; HEADER_ID_LEN],
    manufacturer: [u8; HEADER_MANUFACTURER_LEN],
    _unknown: u32,
    _version: u32,
    number_of_parts: u32,
}

#[derive(Parser)]
struct Args {
    /// Input file
    #[arg(short, long)]
    input: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut file = File::open(args.input).expect("Could not open file ({}) for reading");
    let filesize = file.metadata()?.len();

    let header = UpdateHeader::read(&mut file).expect("Could not parse header from file");

    let expected_filesize = header.length as u64 + 4; // 4 bytes for CRC
    if expected_filesize != filesize {
        eprintln!(
            "File length defined in header ({}) does not match actual file length ({})",
            header.length, filesize
        );
        return Err("File length mismatch".into());
    }

    let model = String::from_utf8(header.model.to_vec()).expect("Model should be valid utf8");
    let manufacturer =
        String::from_utf8(header.manufacturer.to_vec()).expect("Manufacturer should be valid utf8");

    println!("Filesize: {}", filesize);
    println!("Model: {}", model);
    println!("Manufacturer: {}", manufacturer);
    println!("Number of parts: {}", header.number_of_parts);

    Ok(())
}
