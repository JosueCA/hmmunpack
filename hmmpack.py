"""Script to create HMMSys Packed objects from a directory.

This is the reverse operation of hmmunpack.py.

The format is:

    +=============================================+
    |               HMM Packfile                  |
    +=============================================+
    | Format header (40 bytes)                    |
    +---------------------------------------------+
    | File directory (n-bytes * no_files)         |
    | (1, 1, max(255), max(255), 4, 4) * no_files |
    +---------------------------------------------+
    | Padding (no_files * 4-bytes)                |
    +---------------------------------------------+
    | Files (n-bytes * no_files * file_length)    |
    +---------------------------------------------+

Header format:
    char {16}    - Header ("HMMSYS PackFile" + (byte)10)
    uint32 {4}   - Unknown (26)
    byte {12}    - null
    uint32 {4}   - Number Of Files
    uint32 {4}   - Directory Length [+40 archive header]

Directory entry format:
    byte {1}     - Filename Length
    byte {1}     - Previous Filename Reuse Length
    char {X}     - Filename Part (length = filenameLength - previousFilenameReuseLength)
    uint32 {4}   - File Offset
    uint32 {4}   - File Length

"""

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final, List, Tuple

sig: Final[bytes] = b"HMMSYS PackFile\x0a"
header_length: Final[int] = 40
byte_order: Final[str] = "little"


class ArgError(Exception):
    """Provide feedback to the caller if there is a problem with the
    arguments supplied to the script.
    """


class ProcessError(Exception):
    """To raise when there are issues processing the pack file."""


@dataclass
class FileEntry:
    """File object for storing metadata about files to pack."""

    filepath: Path  # Full path to the file on disk
    pakname: str  # Name as it will appear in the pak (with backslashes)
    offset: int = 0
    length: int = 0
    fname_len: int = 0
    reuse_len: int = 0
    fname_part: str = ""  # The part of the filename to write (after reuse)

    def __repr__(self) -> str:
        return f"({self.pakname}: offset={self.offset}, length={self.length}, reuse={self.reuse_len})"


def collect_files(input_dir: Path) -> List[FileEntry]:
    """Collect all files from the input directory recursively.

    Returns a sorted list of FileEntry objects, sorted by pakname
    (Windows-style path with backslashes) to match the original pak order.
    """
    files = []
    input_dir = input_dir.resolve()

    for filepath in input_dir.rglob("*"):
        if filepath.is_file():
            # Get relative path and convert to Windows-style backslashes
            relpath = filepath.relative_to(input_dir)
            pakname = str(relpath).replace("/", "\\")

            entry = FileEntry(
                filepath=filepath,
                pakname=pakname,
                length=filepath.stat().st_size
            )
            files.append(entry)

    # Sort by pakname (Windows-style path) to match original pak order
    files.sort(key=lambda e: e.pakname)

    return files


def calculate_filename_compression(files: List[FileEntry]) -> None:
    """Calculate filename compression (reuse length) for each file.

    The HMMSYS format compresses filenames by reusing the prefix from
    the previous filename.
    """
    last_name = ""

    for entry in files:
        # Find common prefix length with previous filename
        reuse_len = 0
        min_len = min(len(last_name), len(entry.pakname))

        for i in range(min_len):
            if last_name[i] == entry.pakname[i]:
                reuse_len += 1
            else:
                break

        # Limit reuse to 255 bytes (1 byte field)
        reuse_len = min(reuse_len, 255)

        entry.reuse_len = reuse_len
        entry.fname_len = len(entry.pakname)
        entry.fname_part = entry.pakname[reuse_len:]

        last_name = entry.pakname


def calculate_directory_size(files: List[FileEntry]) -> int:
    """Calculate the total size of the directory section."""
    size = 0
    for entry in files:
        # 1 byte fname_len + 1 byte reuse_len + fname_part + 4 bytes offset + 4 bytes length
        size += 1 + 1 + len(entry.fname_part) + 4 + 4
    return size


def calculate_offsets(files: List[FileEntry], dir_size: int, no_files: int) -> None:
    """Calculate file offsets within the pak file."""
    # First file starts after: header (40) + directory + padding (no_files * 4)
    padding_size = no_files * 4
    current_offset = header_length + dir_size + padding_size

    for entry in files:
        entry.offset = current_offset
        current_offset += entry.length


def build_header(no_files: int, dir_length: int) -> bytes:
    """Build the 40-byte header."""
    header = bytearray(40)

    # Signature (16 bytes)
    header[0:16] = sig

    # Unknown constant (4 bytes) - always 0x1a (26)
    header[16:20] = (26).to_bytes(4, byteorder=byte_order)

    # Null bytes (12 bytes) - already zero

    # Number of files (4 bytes)
    header[32:36] = no_files.to_bytes(4, byteorder=byte_order)

    # Directory length (4 bytes)
    header[36:40] = dir_length.to_bytes(4, byteorder=byte_order)

    return bytes(header)


def build_directory(files: List[FileEntry]) -> bytes:
    """Build the directory section."""
    directory = bytearray()

    for entry in files:
        # Filename length (1 byte)
        directory.append(entry.fname_len)

        # Reuse length (1 byte)
        directory.append(entry.reuse_len)

        # Filename part (variable length)
        directory.extend(entry.fname_part.encode("utf-8"))

        # File offset (4 bytes)
        directory.extend(entry.offset.to_bytes(4, byteorder=byte_order))

        # File length (4 bytes)
        directory.extend(entry.length.to_bytes(4, byteorder=byte_order))

    return bytes(directory)


def build_padding(no_files: int) -> bytes:
    """Build the padding section.

    The original format uses repeating pattern: 153, 121, 150, 50
    But it seems this is just padding and can be any values.
    We'll use the original pattern for compatibility.
    """
    pattern = bytes([153, 121, 150, 50])
    padding = bytearray()

    for i in range(no_files):
        padding.append(pattern[i % 4])
        padding.append(pattern[(i + 1) % 4])
        padding.append(pattern[(i + 2) % 4])
        padding.append(pattern[(i + 3) % 4])

    return bytes(padding)


def pack(input_dir: Path, output_file: Path) -> None:
    """Pack a directory into a HMM packfile."""

    print(f"Collecting files from: {input_dir}", file=sys.stderr)
    files = collect_files(input_dir)

    if not files:
        raise ProcessError(f"No files found in directory: {input_dir}")

    no_files = len(files)
    print(f"Found {no_files} files", file=sys.stderr)

    # Calculate filename compression
    calculate_filename_compression(files)

    # Calculate directory size
    dir_size = calculate_directory_size(files)
    print(f"Directory size: {dir_size} bytes", file=sys.stderr)

    # Calculate file offsets
    calculate_offsets(files, dir_size, no_files)

    # Build components
    header = build_header(no_files, dir_size)
    directory = build_directory(files)
    padding = build_padding(no_files)

    # Write the pak file
    print(f"Writing pak file: {output_file}", file=sys.stderr)

    total_size = 0
    with open(output_file, "wb") as pak:
        # Write header
        pak.write(header)
        total_size += len(header)

        # Write directory
        pak.write(directory)
        total_size += len(directory)

        # Write padding
        pak.write(padding)
        total_size += len(padding)

        # Write file data
        for i, entry in enumerate(files):
            with open(entry.filepath, "rb") as f:
                data = f.read()

            if len(data) != entry.length:
                print(f"Warning: File size mismatch for {entry.pakname}", file=sys.stderr)

            pak.write(data)
            total_size += len(data)

            if (i + 1) % 100 == 0:
                print(f"  Packed {i + 1}/{no_files} files...", file=sys.stderr)

    print(f"Pack complete!", file=sys.stderr)
    print(f"  Total files: {no_files}", file=sys.stderr)
    print(f"  Total size: {total_size} bytes ({total_size / 1024:.1f} KB)", file=sys.stderr)
    print(f"  Output: {output_file.absolute()}", file=sys.stderr)


def validate_dir_arg(path: str) -> Path:
    """Validates the directory argument supplied to the script."""
    p = Path(path)
    if not p.exists():
        raise ArgError(f"Supplied path does not exist: {path}")
    if not p.is_dir():
        raise ArgError(f"Supplied path is not a directory: {path}")
    return p


def args() -> Tuple[Path, Path]:
    """Process the script's arguments."""
    parser = argparse.ArgumentParser(
        prog="HMM Packfile Creator",
        description="Creates HMM packfile archives from a directory",
        epilog="Reverse operation of hmmunpack.py",
    )
    parser.add_argument(
        "directory",
        metavar="DIRECTORY",
        type=str,
        nargs=1,
        help="a path to a directory to pack",
    )
    parser.add_argument(
        "output",
        metavar="OUTPUT",
        type=str,
        nargs="?",
        default=None,
        help="output pak file name (default: <directory>.pak)",
    )
    parsed = parser.parse_args()

    input_dir = validate_dir_arg(parsed.directory[0])

    if parsed.output:
        output_file = Path(parsed.output)
    else:
        output_file = Path(f"{input_dir.name}.pak")

    return input_dir, output_file


def main() -> None:
    """Primary entry point for this script."""
    try:
        input_dir, output_file = args()
    except ArgError as err:
        return sys.exit(f"{err}")

    try:
        pack(input_dir, output_file)
    except ProcessError as err:
        return sys.exit(f"Error: {err}")


if __name__ == "__main__":
    main()
