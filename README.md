# rkaf-rs

A Rust tool for parsing Rockchip RKAF update image files. This utility can read and display information about Rockchip firmware update packages.

## Installation

Clone the repository and build using Cargo:

```bash
git clone https://github.com/atkinchris/rkaf-rs.git
cd rkaf-rs
cargo build --release
```

The compiled binary will be available at `target/release/rkaf-rs`.

## Usage

```bash
# Display information about an update file
rkaf-rs -i path/to/update.img
```

### Options

- `-i, --input <FILE>`: Path to the RKAF update image file to analyze

## References

- <https://github.com/neo-technologies/rockchip-mkbootimg/blob/master/rkafp.h>
- <https://github.com/suyulin/apftool-rs/blob/main/src/lib.rs>
