use binrw::BinRead;
use std::fs::File;

const MAX_MODEL_LEN: usize = 0x22;

#[derive(Debug, BinRead)]
#[brw(little, magic = b"RKAF")]
struct UpdateHeader {
    length: u32,
    model: [u8; MAX_MODEL_LEN],
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "embedded-update.img";
    let mut file = File::open(file_path)?;
    let filesize = file.metadata()?.len();

    println!("Filesize: {}", filesize);

    let header = UpdateHeader::read(&mut file).expect("Could not parse header from file");

    let expected_filesize = header.length as u64 + 4; // 4 bytes for CRC
    if expected_filesize != filesize {
        eprintln!(
            "File length defined in header ({}) does not match actual file length ({})",
            header.length, filesize
        );
        return Err("File length mismatch".into());
    }

    println!(
        "Model: {}",
        String::from_utf8(header.model.to_vec()).expect("Model should be valid utf8")
    );

    Ok(())
}
