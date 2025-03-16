use binrw::BinRead;
use std::fs::File;

const MAX_MODEL_LEN: usize = 0x22;

#[derive(Debug, BinRead)]
#[brw(big, magic = b"RKAF")]
struct UpdateHeader {
    length: u32,
    model: [u8; MAX_MODEL_LEN],
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_path = "embedded-update.img";

    let mut fp = File::open(file_path)?;

    let rkaf = UpdateHeader::read(&mut fp)?;

    println!("Filesize: {}", rkaf.length);
    println!(
        "Model: {}",
        String::from_utf8(rkaf.model.to_vec()).expect("Model should be valid utf8")
    );

    Ok(())
}
