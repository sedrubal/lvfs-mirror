"""Mirror LVFS repositories for fwupd."""

import argparse
import fnmatch
import gzip
import hashlib
import logging
import os
import re
import sys
import typing
from configparser import ConfigParser
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from xml.etree import ElementTree

import urllib3
from packaging.version import InvalidVersion, Version

from .utils import (
    TerminalLineUpdater,
    get_metadata_mtime,
    human_file_size,
    local_file_exists_and_up_to_date,
)

LOGGER = logging.getLogger()


DOWNLOAD_CHUNK_SIZE = 1024 * 1024


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

    #: Download only firmware which match the these ID patterns.
    filter_ids: list[re.Pattern]

    #: Limit the amount of old firmware versions that is downloaded per firmware ID.
    #: Does not delete old firmware files.
    keep_versions: int | None


class LVFSMirror:
    """(Command line) tool to mirror LVFS repositories."""

    def __init__(
        self,
        filter_ids: list[re.Pattern],
        remotes: list[Remote],
        mirror_root: Path,
        root_url: str,
        force: bool = False,
        keep_versions: int | None = 1,
    ):
        self.filter_ids = filter_ids
        self.remotes = remotes
        self.mirror_root = mirror_root
        self.session = urllib3.PoolManager()
        self.force = force
        self.keep_versions = keep_versions
        self.root_url = root_url

        # counters
        self._processed_components = 0
        self._skipped_components = 0
        self._downloaded_files = 0
        self._downloaded_size = 0
        self._processed_repos = 0

    def run(self):
        """Run the tool: Update metadata and firmware files ones."""
        self._downloaded_files = 0
        self._downloaded_size = 0
        self._processed_repos = 0

        for remote in self.remotes:
            self.update_remote(remote)
            self._processed_repos += 1

        LOGGER.info(
            "Processed %i repos, downloaded %i files (%s)",
            self._processed_repos,
            self._downloaded_files,
            human_file_size(self._downloaded_size),
        )

    def update_remote(self, remote: Remote):
        """Update the mirrored repository of a remote."""
        self._processed_components = 0
        self._skipped_components = 0

        root = self.mirror_root / remote.name
        root.mkdir(parents=True, exist_ok=True)
        (root / "downloads").mkdir(parents=True, exist_ok=True)
        try:
            metadata, src_mtime = self.get_metadata(remote)
        except urllib3.exceptions.HTTPError as exc:
            LOGGER.error("Failed to update remote %s: %s", remote.name, exc)
            return

        self.process_metadata(
            metadata, remote=remote, output_root=root, src_mtime=src_mtime
        )

        LOGGER.info(
            "Processed %i components (skipped %i)",
            self._processed_components,
            self._skipped_components,
        )

    def get_metadata(
        self, remote: Remote
    ) -> tuple[
        typing.Union[urllib3.BaseHTTPResponse, gzip.GzipFile], typing.Union[int, None]
    ]:
        """
        Start a request to download and extract the metadata on the fly.

        :Return: A file like object.
        """
        # For debugging this can be used in combination with http.server:
        # remote.metadata_uri = "http://localhost:8000/firmware.xml.gz"
        resp = self.session.request("GET", remote.metadata_uri, preload_content=False)
        data: typing.Union[urllib3.BaseHTTPResponse, gzip.GzipFile]
        mtime: int | None = None
        try:
            date_str: str | None = resp.headers.get("Last-Modified")
            if date_str:
                mtime = int(parsedate_to_datetime(date_str).timestamp())
        except ValueError:
            mtime = None

        if remote.metadata_uri.endswith(".gz"):
            # extract data
            data = gzip.GzipFile(fileobj=resp)
            # read mtime
            data.read(1)
            data.rewind()
            mtime = data.mtime
        else:
            data = resp

        return data, mtime

    def process_metadata(
        self,
        metadata: typing.Union[urllib3.BaseHTTPResponse, gzip.GzipFile, typing.IO],
        remote: Remote,
        output_root: Path,
        src_mtime: int | None,
    ):
        """Process the metadata of a repo and download the corresponding firmware files."""
        output_file: typing.Union[gzip.GzipFile, typing.IO, None] = None
        output_file_name = (
            output_root / remote.metadata_uri[remote.metadata_uri.rindex("/") + 1 :]
        )
        tmp_file = output_file_name.parent / f".{output_file_name.name}.part"

        # check if we need to update the output file
        if (
            not self.force
            and src_mtime
            and output_file_name.is_file()
            and (dst_mtime := get_metadata_mtime(output_file_name) >= src_mtime)
        ):
            LOGGER.info("Local metadata file for remote %s is up to date.", remote.name)
            LOGGER.debug(
                "Target file %s newer than source file (%i <= %i)",
                output_file_name,
                src_mtime,
                dst_mtime,
            )
            if output_file_name.suffix == ".gz":
                metadata = gzip.GzipFile(fileobj=output_file_name.open("rb"), mode="rb")
            else:
                metadata = output_file_name.open("rb")
        else:
            if remote.metadata_uri.endswith(".gz"):
                # compress output
                output_file = gzip.GzipFile(
                    filename=tmp_file, mode="wb", mtime=src_mtime
                )
            else:
                output_file = tmp_file.open("wb")

        try:
            if output_file:
                # write header
                output_file.write(
                    b'<?xml version="1.0" encoding="utf-8"?>'
                    b'<components origin="lvfs" version="0.9">'
                )

            # process components
            for _event, element in ElementTree.iterparse(metadata):
                if element.tag == "component":
                    self.process_component(element, output_root)
                    self._processed_components += 1

                    if output_file:
                        output_file.write(
                            ElementTree.tostring(
                                element, encoding="utf8", method="html"
                            )
                        )

            if output_file:
                # write trailer
                output_file.write(b"</components>")
        finally:
            if output_file:
                output_file.close()

        if output_file:
            tmp_file.rename(output_file_name)
            LOGGER.info(
                "Successfully updated and processed repo %s (file %s)",
                remote.name,
                output_file_name,
            )
        else:
            LOGGER.info(
                "Successfully processed repo %s (file %s)",
                remote.name,
                output_file_name,
            )

    def process_component(
        self, component: ElementTree.Element, output_root: Path
    ) -> None:
        """Process and update a component which is part of the repo metadata."""
        component_id_element = component.find("id")
        if component_id_element is None or not component_id_element.text:
            LOGGER.warning("Component %s has no ID. Ignoring.", component)
            return
        component_id = component_id_element.text

        if self.filter_ids:
            for id_re in self.filter_ids:
                if id_re.match(component_id):
                    LOGGER.debug(
                        "Pattern %s matches component ID %s",
                        id_re.pattern,
                        component_id,
                    )
                    break
            else:
                LOGGER.debug(
                    "Skipping component ID %s (no pattern matches ID)", component_id
                )
                self._skipped_components += 1
                return

        releases_element = component.find("releases")
        if releases_element is None:
            LOGGER.warning("No <releases> found in component %s", component_id)
            return

        release_elements = releases_element.findall("release")

        if not release_elements:
            LOGGER.warning("No <release> found in component %s", component_id)
            return

        if self.keep_versions:
            elements_with_sort_key: list[
                tuple[Version | None, list[str], ElementTree.Element]
            ] = []
            use_fallback = False
            for release in release_elements:
                version_str = release.attrib.get("version")
                if not version_str:
                    LOGGER.warning(
                        "Component %s has release with invalid version %s",
                        component_id,
                        version_str,
                    )
                    continue
                version: Version | None = None
                try:
                    version = Version(version_str)
                except InvalidVersion as exc:
                    LOGGER.warning(
                        (
                            "Component %s has release with invalid version %s (%s). "
                            "Version sort might not be accurate."
                        ),
                        component_id,
                        version_str,
                        exc,
                    )
                    use_fallback = True
                version_fallback: list[str] = version_str.split(".")
                elements_with_sort_key.append((version, version_fallback, release))

            elements_with_sort_key.sort(
                reverse=True,
                key=lambda entry: entry[1] if use_fallback else entry[0],  # type: ignore
            )

            num_all_versions = len(release_elements)
            release_elements = []
            versions: list[str] = []
            for version, version_fallback, release_element in elements_with_sort_key[
                : self.keep_versions
            ]:
                release_elements.append(release_element)
                versions.append(".".join(version_fallback))

            if num_all_versions < len(elements_with_sort_key):
                LOGGER.debug(
                    "Keeping only %i of %i most recent versions of %s: %s",
                    len(elements_with_sort_key),
                    num_all_versions,
                    component_id,
                    ", ".join(versions),
                )

        for release in release_elements:
            location = release.find("location")
            if location is None:
                LOGGER.warning(
                    "No <location> found in <release> %s of component %s",
                    release,
                    component_id,
                )
                continue
            release_url_str = location.text
            if not release_url_str:
                LOGGER.warning(
                    "<location> found in <release> %s of component %s has no URL",
                    release,
                    component_id,
                )
                continue
            release_url = urllib3.util.url.parse_url(release_url_str)
            if release_url.scheme not in ("https", "http"):
                LOGGER.warning(
                    "<location> found in <release> %s of component %s has invalid URL %s",
                    release,
                    component_id,
                    release_url_str,
                )
                continue

            if release_url.path:
                output_file = output_root / "downloads" / Path(release_url.path).name
            else:
                output_file = output_root / "downloads" / component_id

            checksums: dict[str, str] = {}
            for checksum in release.findall("checksum"):
                if checksum.attrib.get("target") == "container":
                    checksum_type = checksum.attrib.get("type")
                    checksum_value = checksum.text
                    if not checksum_value or not checksum_type:
                        LOGGER.warning(
                            "Invalid checksum %s in <release> %s of component %s",
                            checksum,
                            release,
                            component_id,
                        )
                        continue
                    checksums[checksum_type.lower()] = checksum_value.lower()

            LOGGER.debug(
                "Found following checksums for %s: %s",
                release_url_str,
                ", ".join(checksums.keys()),
            )

            size: int | None = None
            for size_element in release.findall("size"):
                if size_element.attrib.get("type") == "download" and size_element.text:
                    size = int(size_element.text)

            new_release_path = self.download_and_verify_file(
                url=release_url_str,
                expected_checksums=checksums,
                expected_size=size,
                output_file=output_file,
            )

            if new_release_path:
                path = new_release_path.relative_to(self.mirror_root)
                new_release_url = f"{self.root_url.rstrip('/')}/{path}"
                location.text = new_release_url
            # elif self.prune_metadata:
            # -> remove from metadata

    def download_and_verify_file(
        self,
        url: str,
        expected_checksums: dict[str, str],
        expected_size: int | None,
        output_file: Path,
    ) -> Path | None:
        """Download & verify firmware files."""
        tmp_file = output_file.parent / f".{output_file.name}.part"

        size = 0
        checksums = {}
        for checksum_type in expected_checksums.keys():
            if checksum_type not in hashlib.algorithms_available:
                LOGGER.warning("Unsupported checksum %s.", checksum_type)
                continue
            checksums[checksum_type] = hashlib.new(checksum_type)

        if not self.force and local_file_exists_and_up_to_date(
            expected_checksums=expected_checksums,
            expected_size=expected_size,
            file_path=output_file,
        ):
            LOGGER.debug("File %s is up to date and valid.", output_file)
            return output_file

        resp = self.session.request("GET", url, preload_content=False)

        with TerminalLineUpdater() as printer:
            printer.update(
                f"Downloading {output_file}: {human_file_size(size)}",
                on_non_terminals=True,
            )

            with tmp_file.open("wb") as file:
                while chunk := resp.read(DOWNLOAD_CHUNK_SIZE):
                    printer.update(
                        f"Downloading {output_file}: {human_file_size(size)}"
                    )
                    file.write(chunk)
                    for checksum_algo in checksums.values():
                        checksum_algo.update(chunk)
                    size += len(chunk)

            self._downloaded_files += 1
            self._downloaded_size += size
            printer.update(f"Downloaded {output_file}: {human_file_size(size)}")

            if expected_size and size != expected_size:
                LOGGER.warning(
                    "Failed to download %s. Received %i bytes, expected %i bytes.",
                    url,
                    size,
                    expected_size,
                )
                os.unlink(tmp_file)
                return None

            for checksum_type, checksum_value in checksums.items():
                expected_checksum_value = expected_checksums[checksum_type]
                if checksum_value.hexdigest().lower() != expected_checksum_value:
                    LOGGER.warning(
                        "Failed to download %s. Checksum %s miss-match: expected %s got %s.",
                        url,
                        checksum_type,
                        expected_checksum_value,
                        checksum_value.hexdigest(),
                    )
                    os.unlink(tmp_file)
                    return None

            tmp_file.rename(output_file)
            printer.update(
                f"Downloaded and verified {output_file}", on_non_terminals=True
            )

        return output_file


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(__name__)
    parser.add_argument(
        "-c",
        "--config",
        default="/etc/lvfs_mirror/mirror.conf",
        type=Path,
        help="The path to the main config file (default %(default)s).",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Force overwriting output (even if it seems to be up to date).",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug output.",
    )

    return parser.parse_args()


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


def main():
    """Run the mirror."""
    args = parse_args()
    handler = logging.StreamHandler(sys.stderr)
    LOGGER.addHandler(handler)
    if args.debug:
        LOGGER.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
    else:
        LOGGER.setLevel(logging.INFO)
        handler.setLevel(logging.INFO)

    cfg = parse_config(args.config)
    mirror = LVFSMirror(
        filter_ids=cfg.filter_ids,
        remotes=cfg.remotes,
        mirror_root=cfg.mirror_root,
        root_url=cfg.root_url,
        force=args.force,
        keep_versions=cfg.keep_versions,
    )

    try:
        mirror.run()
    except KeyboardInterrupt:
        print("\33[2K\rAbort", file=sys.stderr)


if __name__ == "__main__":
    main()
