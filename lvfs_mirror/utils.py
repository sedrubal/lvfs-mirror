"""Utils for lvfs_mirror."""

import hashlib
import logging
import shutil
import sys
from gzip import GzipFile
from pathlib import Path

LOGGER = logging.getLogger()


def get_gzip_mtime(file_path: Path) -> int | None:
    """:return: The mtime stored in a gzip file or None if it can't be parsed."""
    with GzipFile(file_path, mode="r") as file:
        file.read(1)
        return file.mtime


def get_metadata_mtime(file_path: Path) -> int:
    """Determine the modification time of a zip file."""
    if file_path.suffix == ".gz":
        gzip_mtime = get_gzip_mtime(file_path=file_path)
        if gzip_mtime:
            return gzip_mtime

    return int(file_path.stat().st_mtime)


def local_file_exists_and_up_to_date(
    expected_checksums: dict[str, str],
    expected_size: int | None,
    file_path: Path,
) -> bool:
    """:Return: True, if the local firmware file exists and is valid."""
    if not file_path.exists():
        return False

    file_stat = file_path.stat()
    if expected_size and file_stat.st_size != expected_size:
        LOGGER.warning(
            "Local file %s is invalid. Size is %i bytes, expected %i bytes.",
            file_path,
            file_stat.st_size,
            expected_size,
        )
        return False

    for checksum_type, expected_checksum_value in expected_checksums.items():
        with file_path.open("rb") as file:
            checksum_value = (
                hashlib.file_digest(file, checksum_type).hexdigest().lower()
            )
        if expected_checksum_value != checksum_value:
            LOGGER.warning(
                "Local file %s is invalid. Checksum %s miss-match: expected %s got %s.",
                file_path,
                checksum_type,
                expected_checksum_value,
                checksum_value,
            )
            return False

    return True


def human_file_size(file_size: int | float) -> str:
    """
    :param file_size: The file size that should be formatted.
    :return: File size in human readable.
    """
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(file_size) < 1024.0:
            return f"{file_size:3.1f}{unit}B"
        file_size /= 1024.0
    return f"{file_size:.1f}YiB"


class TerminalLineUpdater:
    """Tool to write and refresh a text line on terminals."""

    def update(self, text: str, on_non_terminals: bool = False):
        """Print new text to the terminal."""
        terminal_width = shutil.get_terminal_size((-1, -1)).columns
        if sys.stderr.isatty() and terminal_width != -1:
            if len(text) > terminal_width:
                text = f"…{text[-terminal_width + 1:]}"
            print(f"\33[2K\r{text}", end="", flush=True, file=sys.stderr)
        elif on_non_terminals:
            print(text, file=sys.stderr)

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        if sys.stderr.isatty():
            print(file=sys.stderr)
