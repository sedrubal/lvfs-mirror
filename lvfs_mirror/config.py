"""Tools to read and parse configuration."""

import fnmatch
import logging
import re
from configparser import ConfigParser
from dataclasses import dataclass
from pathlib import Path

LOGGER = logging.getLogger()


@dataclass
class Remote:
    """A LVFS remote."""

    name: str
    title: str
    metadata_uri: str


@dataclass
class Config:
    """The configuration."""

    #: Path to directory, where firmware and metadata will be stored.
    mirror_root: Path

    #: URL under which MirrorRoot can be reached from other clients.
    root_url: str

    #: Parsed remote configurations.
    #: The syntax and directory structure of fwupd itself can be used here.
    remotes: list[Remote]

    #: Download only firmware which matches the these ID patterns.
    filter_ids: list[re.Pattern]

    #: Download only firmware which applies for one of the vendors in this list.
    filter_vendor_ids: list[str]

    #: Limit the amount of old firmware versions that is downloaded per firmware ID.
    #: Does not delete old firmware files.
    keep_versions: int | None


MAIN_SECTION = "mirror"
REMOTE_SECTION = "fwupd Remote"


def parse_config(main_config_file: Path) -> Config:
    """Parse config files."""

    main_cfg = ConfigParser()
    main_cfg.read(main_config_file)
    main_section = main_cfg[MAIN_SECTION]
    filter_ids: list[re.Pattern] = [
        re.compile(fnmatch.translate(entry.strip()), re.IGNORECASE)
        for entry in main_section.get("FilterIds", fallback="").strip().split(",")
        if entry.strip()
    ]
    filter_vendor_ids: list[str] = [
        entry.strip().upper()
        for entry in main_section.get("FilterVendorIds", fallback="").strip().split(",")
        if entry.strip()
    ]
    mirror_root = Path(main_section.get("MirrorRoot", fallback="/srv/lvfs_mirror/"))
    root_url = main_section.get("RootUrl", fallback="http://localhost:8000/")
    keep_versions_str = main_section.get("KeepVersions", fallback="1")
    if keep_versions_str == "all":
        keep_versions: int | None = None
    else:
        keep_versions = int(keep_versions_str)
    remotes_dir = Path(main_section.get("RemotesDir", fallback="/etc/fwupd/remotes.d/"))

    if not remotes_dir.is_absolute():
        remotes_dir = main_config_file.parent / remotes_dir

    cfg = Config(
        filter_ids=filter_ids,
        filter_vendor_ids=filter_vendor_ids,
        mirror_root=mirror_root,
        root_url=root_url,
        keep_versions=keep_versions,
        remotes=[],
    )

    for file in remotes_dir.iterdir():
        if not file.is_file() or not file.suffix == ".conf":
            continue

        remote_cfg = ConfigParser()
        remote_cfg.read(file)

        if REMOTE_SECTION not in remote_cfg:
            LOGGER.info("No remote found in %s. Ignoring file.", file)

            continue
        remote_cfg_sec = remote_cfg[REMOTE_SECTION]

        if not remote_cfg_sec.getboolean("Enabled", fallback=True):
            LOGGER.info("Remote in %s is not enabled. Ignoring file.", file)

            continue

        if "MetadataURI" not in remote_cfg_sec:
            LOGGER.warning("MetadataURI is missing in %s. Ignoring remote.", file)

            continue
        metadata_uri = remote_cfg_sec["MetadataURI"]

        if not metadata_uri.startswith("https://") and not metadata_uri.startswith(
            "http://"
        ):
            LOGGER.warning(
                "MetadataURI %s in %s is not a HTTPS/HTTP URI. Ignoring remote.",
                metadata_uri,
                file,
            )

            continue

        remote = Remote(
            name=file.stem,
            title=remote_cfg_sec.get("Title", file.stem),
            metadata_uri=metadata_uri,
        )
        cfg.remotes.append(remote)

    return cfg
