##############################################
# Payload to boot.dat - originally by CTCaer #
##############################################

import argparse
import struct
import hashlib
from pathlib import Path

"""
typedef struct boot_dat_hdr
{
	unsigned char ident[0x10];
	unsigned char sha2_s2[0x20];
	unsigned int s2_dst;
	unsigned int s2_size;
	unsigned int s2_enc;
	unsigned char pad[0x10];
	unsigned int s3_size;
	unsigned char pad2[0x90];
	unsigned char sha2_hdr[0x20];
} boot_dat_hdr_t;
"""


def get_sha256(data):
    sha256 = hashlib.new("sha256")
    sha256.update(data)
    return sha256.digest()


def main():
    parser = argparse.ArgumentParser(description="Converts payload to custom boot.dat")
    parser.add_argument("payload_fn", help="input filename of the payload to convert")
    parser.add_argument(
        "boot_fn",
        nargs="?",
        default="boot.dat",
        help="output filename of the resulting boot.dat",
    )
    args = parser.parse_args()

    stage2 = Path(args.payload_fn).read_bytes()

    # Re-create the header.
    header = b""

    # Magic ID.
    header += b"\x43\x54\x43\x61\x65\x72\x20\x42\x4F\x4F\x54\x00"

    # Version 2.5.
    header += b"\x56\x32\x2E\x35"

    # Set sha256 hash of stage2 payload.
    header += get_sha256(stage2)

    # Set stage2 payload destination to 0x40010000.
    header += b"\x00\x00\x01\x40"

    # Stage2 payload size.
    header += struct.pack("I", len(stage2))

    # Disable Stage2 encryption.
    header += struct.pack("I", 0)

    # Add padding. Stage3 size is 0.
    header += b"\x00" * 0xA4

    # Add header's sha256 hash.
    header += get_sha256(header)

    # Write header and the plaintext custom payload.
    with Path(args.boot_fn).open("wb") as boot:
        boot.write(header)
        boot.write(stage2)


if __name__ == "__main__":
    main()
