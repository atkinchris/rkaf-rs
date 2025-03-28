use binrw::BinRead;
use clap::Parser;
use std::fs::File;

const HEADER_MODEL_LEN: usize = 0x22; // 34
const HEADER_ID_LEN: usize = 0x1E; // 30
const HEADER_MANUFACTURER_LEN: usize = 0x38; // 56
const MAX_NAME_LEN: usize = 0x20; // 32
const MAX_FULL_PATH_LEN: usize = 0x3C; // 60

#[derive(Debug, BinRead)]
struct UpdatePart {
    name: [u8; MAX_NAME_LEN],
    full_path: [u8; MAX_FULL_PATH_LEN],
}

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
    #[br(count = number_of_parts)]
    parts: Vec<UpdatePart>,
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

    for part in header.parts.iter() {
        println!("Name: {:?}", part.name);
        println!("Full path: {:?}", part.full_path);
    }

    Ok(())
}
