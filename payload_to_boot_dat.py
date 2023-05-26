import argparse
import struct
import hashlib
from pathlib import Path


def get_sha256_bytes(data):
    return hashlib.sha256(data).digest()


def create_header(payload_bytes):
    magic_id = b"CTCaer BOOT\x00"  # Magic ID
    version = b"V2.5"  # Version 2.5
    payload_hash = get_sha256_bytes(payload_bytes)  # SHA256 hash of stage2 payload
    payload_destination = 0x40010000  # Set stage2 payload destination to 0x40010000
    payload_size = len(payload_bytes)  # Stage2 payload size
    encryption = 0  # Disable Stage2 encryption
    padding = b"\x00" * 0xA4  # Add padding (Stage3 size is 0)

    # Pack the header fields into a byte string
    header = (
        magic_id
        + version
        + payload_hash
        + struct.pack("I", payload_destination)
        + struct.pack("I", payload_size)
        + struct.pack("I", encryption)
        + padding
    )

    # Add header's SHA256 hash
    header += get_sha256_bytes(header)

    return header


def main():
    parser = argparse.ArgumentParser(
        description="Converts Switch payload to custom boot.dat"
    )
    parser.add_argument(
        "payload_path", help="input file path of the payload to convert"
    )
    parser.add_argument(
        "bootdat_path",
        nargs="?",
        default="boot.dat",
        help="output file path of the resulting boot.dat",
    )
    args = parser.parse_args()

    payload_bytes = Path(args.payload_path).read_bytes()
    header = create_header(payload_bytes)

    # Prepend header to payload and write boot.dat
    Path(args.bootdat_path).write_bytes(header + payload_bytes)


if __name__ == "__main__":
    main()
