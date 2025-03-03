#!/usr/bin/env python3

import argparse
import os


def is_valid_file(parser: argparse.ArgumentParser, file_path: str) -> str:
    if not os.path.exists(file_path):
        parser.error(f"The file {file_path} does not exist!")
    return file_path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--signature-file-path",
        required=True,
        metavar="FILE",
        help="signature file to read/write",
    )
    parser.add_argument(
        "--hex-to-file",
        help="convert hex to binary file",
        action="store_true",
    )
    parser.add_argument(
        "--hex",
        help="signature hex to convert to binary",
    )
    args = parser.parse_args()
    if args.hex_to_file and args.hex is None:
        parser.error(f"signature hex needs to be supplied")
    elif args.hex and not args.hex_to_file:
        parser.error(
            f"signature hex is only read when --hex-to-file is chosen")
    elif not args.hex_to_file:
        is_valid_file(parser=parser, file_path=args.signature_file_path)
    return args


if __name__ == "__main__":
    args = parse_arguments()

    if not args.hex_to_file:
        with open(args.signature_file_path, "rb") as signature_file_descriptor:
            print(signature_file_descriptor.read().hex())
    else:
        with open(args.signature_file_path, "wb") as signature_file_descriptor:
            print(f"[*] Writing binary to {args.signature_file_path}...")
            signature_hex = args.hex
            if signature_hex.startswith("0x"):
                signature_hex = signature_hex[2:]
            signature_file_descriptor.write(bytes.fromhex(signature_hex))
            print(
                f"[+] Successfully wrote binary to {args.signature_file_path}!")
