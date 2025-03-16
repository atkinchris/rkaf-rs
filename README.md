# squashfs-rc4

A tool for working with [RC4](https://en.wikipedia.org/wiki/RC4) encrypted SquashFS images.

## Installation

Clone the repository and build using [Cargo](https://crates.io):

```bash
git clone https://github.com/atkinchris/squashfs-rc4.git
cd squashfs-rc4
cargo build --release
```

The compiled binary will be available at `target/release/squashfs-rc4`.

## Usage

```sh
# To list the files in a SquashFS image
squashfs-rc4 squashfs.img --key "37058547775720062483765742771373"
```

### Options

- `--key`: 16-byte key used to decrypt the SquashFS image. The key must be in hex format.
