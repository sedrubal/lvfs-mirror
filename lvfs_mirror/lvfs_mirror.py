"""
Mirror LVFS repositories for fwupd.

This tools works with lvfs metadata files.
The specification can be found here:
https://lvfs.readthedocs.io/en/latest/metainfo.html
"""

import argparse
import gzip
import hashlib
import logging
import os
import re
import sys
import typing
from email.utils import parsedate_to_datetime
from pathlib import Path
from xml.etree import ElementTree
import socket

import urllib3
from packaging.version import InvalidVersion, Version

from .config import Config, Remote, parse_config
from .utils import (
    TerminalLineUpdater,
    filter_component_id,
    filter_vendor_id,
    get_metadata_mtime,
    human_file_size,
    local_file_exists_and_up_to_date,
)

LOGGER = logging.getLogger()


DOWNLOAD_CHUNK_SIZE = 1024


class LVFSMirror:
    """(Command line) tool to mirror LVFS repositories."""

    def __init__(
        self,
        filter_ids: list[re.Pattern],
        filter_vendor_ids: list[str],
        remotes: list[Remote],
        mirror_root: Path,
        root_url: str,
        force: bool = False,
        keep_versions: int | None = 1,
    ):
        self.filter_ids = filter_ids
        self.filter_vendor_ids = filter_vendor_ids
        self.remotes = remotes
        self.mirror_root = mirror_root
        self.session = urllib3.PoolManager(
            headers=urllib3.util.make_headers(
                keep_alive=True, user_agent="lvfs-mirror"
            ),
            socket_options=urllib3.connection.HTTPConnection.default_socket_options
            + [
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
            ],
        )
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

        if not filter_component_id(component_id, self.filter_ids):
            self._skipped_components += 1
            return

        requires_element = component.find("requires")
        if requires_element is None:
            LOGGER.warning(
                "Component %s has no <requires> block. Ignoring.", component_id
            )
            return
        for condition_element in requires_element:
            if condition_element.tag == "firmware":
                if not condition_element.text:
                    # This is a requirement on another installed firmware.
                    # We can't use this condition on the mirror as we don't know,
                    # which firmware is installed on the client.
                    continue

                if condition_element.text.strip() != "vendor-id":
                    LOGGER.debug(
                        "Unsupported requirement condition %s.",
                        ElementTree.tostring(condition_element).decode("utf8"),
                    )
                    continue

                condition_compare = condition_element.attrib.get("compare")
                condition_version = condition_element.attrib.get("version")

                if not condition_compare or not condition_version:
                    LOGGER.warning(
                        "Missing compare and/or version attribute for <firmware>vendor-id</firmare> requirement."
                    )
                    continue
                elif filter_vendor_id(
                    condition_version.upper(),
                    condition_compare.lower(),
                    self.filter_vendor_ids,
                ):
                    continue
                else:
                    self._skipped_components += 1
                    return
            elif (
                condition_element.tag == "id"
                and condition_element.text
                and condition_element.text.strip() == "org.freedesktop.fwupd"
            ):
                # download firmware for all versions of fwupd
                continue
            elif condition_element.tag == "hardware":
                # Filtering by computer hardware (ID?) is not yet supported.
                # I don't know how I can get a list of computer hardware IDs of devices on my computer.
                continue
            elif condition_element.tag == "client":
                # This is used if this update requires user interaction.
                # We don't filter by this condition.
                continue
            else:
                LOGGER.warning(
                    "Unknown requires condition: %s",
                    ElementTree.tostring(condition_element).decode("utf8"),
                )
                continue

        releases_element = component.find("releases")
        if releases_element is None:
            LOGGER.warning("No <releases> found in component %s", component_id)
            return

        release_elements = releases_element.findall("release")

        if not release_elements:
            LOGGER.warning("No <release> found in component %s", component_id)
            return

        release_elements = self.exclude_old_versions(release_elements, component_id)

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

    def exclude_old_versions(
        self, release_elements: list[ElementTree.Element], component_id: str
    ) -> list[ElementTree.Element]:
        """
        If keep_versions is set, this will exclude old release versions.

        It filters a list of release elements from metadata XML.
        """

        if not self.keep_versions or len(release_elements) <= self.keep_versions:
            return release_elements

        EntryT = tuple[
            Version | None,
            int | None,
            int | None,
            list[str] | None,
            ElementTree.Element,
        ]
        elements_with_sort_key: list[EntryT] = []

        version_usable = True
        timestamp_usable = True
        id_usable = True
        version_fallback_usable = True

        for release in release_elements:
            version: Version | None = None
            timestamp: int | None = None
            release_id: int | None = None
            version_fallback: list[str] | None = None

            version_str = release.attrib.get("version")
            timestamp_str = release.attrib.get("timestamp")
            id_str = release.attrib.get("id")

            if version_str:
                version_fallback = version_str.split(".")

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
                    version_usable = False
            else:
                LOGGER.warning(
                    "Component %s has release with invalid version %s",
                    component_id,
                    version_str,
                )
                version_usable = False
                version_fallback_usable = False

            try:
                timestamp = int(timestamp_str or "")
            except ValueError as err:
                LOGGER.warning(
                    "Component %s has release with invalid timestamp %s (%s)",
                    component_id,
                    timestamp_str,
                    err,
                )
                timestamp_usable = False

            try:
                release_id = int(id_str or "")
            except ValueError as err:
                LOGGER.warning(
                    "Component %s has release with invalid id %s (%s)",
                    component_id,
                    id_str,
                    err,
                )
                id_usable = False

            elements_with_sort_key.append(
                (version, timestamp, release_id, version_fallback, release)
            )

        if version_usable:
            sort_idx = 0
        elif timestamp_usable:
            sort_idx = 1
        elif id_usable:
            sort_idx = 2
        elif version_fallback_usable:
            sort_idx = 3
        else:
            LOGGER.warning(
                "Did not find a useable sort criteria for the release versions of component %s. Will download all versions.",
                component_id,
            )
            return release_elements

        if sort_idx > 0:
            LOGGER.warning(
                "Can't reliably sort release versions of component %s by their version. Latest version might not be available.",
                component_id,
            )

        elements_with_sort_key.sort(
            reverse=True,
            key=lambda entry: typing.cast(Version | int | list[str], entry[sort_idx]),
        )

        num_all_versions = len(release_elements)
        release_elements = []
        versions: list[str] = []
        for (
            version,
            _timestamp,
            _release_id,
            version_fallback,
            release_element,
        ) in elements_with_sort_key[: self.keep_versions]:
            release_elements.append(release_element)
            versions.append(".".join(version_fallback) if version_fallback else "???")

        if num_all_versions < len(elements_with_sort_key):
            LOGGER.debug(
                "Keeping only %i of %i most recent versions of %s: %s",
                len(elements_with_sort_key),
                num_all_versions,
                component_id,
                ", ".join(versions),
            )

        return release_elements

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
        checksums_str = ", ".join(checksums.keys())

        if not self.force and local_file_exists_and_up_to_date(
            expected_checksums=expected_checksums,
            expected_size=expected_size,
            file_path=output_file,
        ):
            LOGGER.debug(
                "File %s is up to date and valid (checksums %s match).",
                output_file,
                checksums_str,
            )
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
                f"Downloaded and verified {output_file} with checksums {checksums_str}",
                on_non_terminals=True,
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

    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug output.",
    )
    verbosity_group.add_argument(
        "-q",
        "--quiet",
        "--silent",
        action="store_true",
        help="Mute output (print only warnings and errors).",
    )

    return parser.parse_args()


def main() -> None:
    """Run the mirror."""
    args = parse_args()
    handler = logging.StreamHandler(sys.stderr)
    LOGGER.addHandler(handler)
    if args.debug:
        LOGGER.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
    elif args.quiet:
        LOGGER.setLevel(logging.WARNING)
        handler.setLevel(logging.WARNING)
    else:
        LOGGER.setLevel(logging.INFO)
        handler.setLevel(logging.INFO)

    cfg: Config = parse_config(args.config)
    mirror = LVFSMirror(
        filter_ids=cfg.filter_ids,
        filter_vendor_ids=cfg.filter_vendor_ids,
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
