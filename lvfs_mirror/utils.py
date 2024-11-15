"""Utils for lvfs_mirror."""

import hashlib
import logging
import re
import fnmatch
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


def filter_component_id(component_id: str, filter_patterns: list[re.Pattern]) -> bool:
    """:Return: True if one of the patterns matches the `component_id`."""
    if not filter_patterns:
        return True

    for id_re in filter_patterns:
        if id_re.match(component_id):
            LOGGER.debug(
                "Component ID pattern %s matches component ID %s",
                id_re.pattern,
                component_id,
            )
            return True

    LOGGER.debug("Skipping component ID %s (no pattern matches ID)", component_id)
    return False


def filter_vendor_id(version: str, compare: str, filter_vendor_ids: list[str]) -> bool:
    """:Return: True if one of the vendor ids in `filter_vendor_ids` matches the condition."""
    if not filter_vendor_ids:
        return True

    if compare == "eq":
        for vendor_id in filter_vendor_ids:
            if version == vendor_id:
                LOGGER.debug("Vendor ID %s is part of the filter list.", version)
                return True

        LOGGER.debug("Vendor ID %s not in filter list.", version)
    elif compare in ("regex", "glob"):
        if compare == "regex":
            pattern = re.compile(version)
        else:
            pattern = re.compile(fnmatch.translate(version), re.IGNORECASE)

        for vendor_id in filter_vendor_ids:
            if pattern.match(vendor_id):
                LOGGER.debug(
                    "Vendor ID %s from filter list matches pattern %s.",
                    vendor_id,
                    version,
                )
                return True

        LOGGER.debug(
            "Vendor ID pattern %s doesn't match any of the vendor IDs in filter list.",
            version,
        )
    elif compare == "ne":
        # can be ignored
        return True
    elif compare in ("lt", "le", "gt", "ge"):
        LOGGER.warning(
            "Compare function %s (against version %s) not implemented (but also not expected).",
            compare,
            version,
        )
        return True
    else:
        LOGGER.warning(
            "Unknown compare method %s (against version %s).", compare, version
        )
        return True

    return False
