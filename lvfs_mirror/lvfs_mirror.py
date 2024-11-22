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
import socket
import sys
import typing
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

import urllib3
import xattr  # pylint: disable=import-error
from packaging.version import InvalidVersion, Version

from .config import Config, Remote, parse_config
from .jcat import get_jcat_item, jcat_sign_file, jcat_verify_file
from .utils import (
    TerminalLineUpdater,
    filter_component_id,
    filter_vendor_id,
    human_file_size,
    local_file_exists_and_up_to_date,
)

LOGGER = logging.getLogger()


DOWNLOAD_CHUNK_SIZE = 1024

#: A helper type.
VersionEntryT = tuple[
    Version | None,
    int | None,
    int | None,
    list[str] | None,
    ElementTree.Element,
]


@dataclass
class FirmwareBlob:
    """A description of a firmware blob."""

    url: str
    expected_checksums: dict[str, str]
    expected_size: int | None
    output_path: Path

    def __post_init__(self):
        for checksum_algo in tuple(self.expected_checksums.keys()):
            if checksum_algo not in hashlib.algorithms_available:
                LOGGER.warning(
                    "Unsupported checksum algorithm %s. Ignoring.", checksum_algo
                )
                self.expected_checksums.pop(checksum_algo)

    def verify_firmware(self, use_xattrs: bool = True) -> bool:
        """
        Verify a local firmware blob

        :return: True, if it exists and is valid.
        """
        if local_file_exists_and_up_to_date(
            expected_checksums=self.expected_checksums,
            expected_size=self.expected_size,
            file_path=self.output_path,
            use_xattrs=use_xattrs,
        ):
            LOGGER.debug(
                "Firmware file %s is up to date and valid (checksums %s match).",
                self.output_path,
                ", ".join(sorted(self.expected_checksums.keys())),
            )
            return True

        return False


class LVFSMirror:
    """(Command line) tool to mirror LVFS repositories."""

    def __init__(self, cfg: Config, force: bool = False):
        self.cfg = cfg
        self.force = force

        self.session = urllib3.PoolManager(
            headers=urllib3.util.make_headers(
                keep_alive=True, user_agent="lvfs-mirror"
            ),
            socket_options=urllib3.connection.HTTPConnection.default_socket_options
            + [
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
            ],
        )

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

        for remote in self.cfg.remotes:
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

        root = self.cfg.mirror_root / remote.name
        # create output directories
        root.mkdir(parents=True, exist_ok=True)
        firmware_root = root / "downloads"
        firmware_root.mkdir(parents=True, exist_ok=True)
        tmp_root = root / ".tmp"
        tmp_root.mkdir(parents=True, exist_ok=True)
        tmp_root_in = tmp_root / "in"
        tmp_root_in.mkdir(parents=True, exist_ok=True)
        tmp_root_out = tmp_root / "out"
        tmp_root_out.mkdir(parents=True, exist_ok=True)

        firmware_url_base = f"{self.cfg.root_url.rstrip('/')}/{remote.name}/downloads/"

        remote_url_base = remote.metadata_uri[: remote.metadata_uri.rindex("/")]
        metadata_name_original = remote.metadata_uri[
            remote.metadata_uri.rindex("/") + 1 :
        ]
        jcat_url = f"{remote.metadata_uri}.jcat"
        jcat_file_name = f"{metadata_name_original}.jcat"

        jcat_input_path = tmp_root_in / jcat_file_name
        jcat_output_path = tmp_root_out / jcat_file_name
        jcat_mirror_path = root / jcat_file_name

        keyring_dir = tmp_root / "keyring"

        # download jcat file
        try:
            self.download_file(jcat_url, jcat_input_path)
        except urllib3.exceptions.HTTPError as exc:
            LOGGER.error("Failed to update remote %s: %s", remote.name, exc)
            return

        # extract items
        try:
            metadata_name = get_jcat_item(jcat_input_path)
        except ValueError as err:
            LOGGER.error("Skipping remote %s: %s", remote.name, err)
            return

        metadata_mirror_path_default = root / metadata_name_original
        metadata_mirror_path = root / metadata_name
        metadata_input_path = tmp_root_in / metadata_name
        metadata_output_path = tmp_root_out / metadata_name

        if metadata_input_path.is_file() and jcat_verify_file(
            jcat_input_path, self.cfg.public_keys_dir, keyring_dir
        ):
            LOGGER.info("Metadata %s is already downloaded and valid.", jcat_input_path)
        else:
            try:
                self.download_file(
                    f"{remote_url_base}/{metadata_name}", metadata_input_path
                )
            except urllib3.exceptions.HTTPError as exc:
                LOGGER.error("Failed to update remote %s: %s", remote.name, exc)
                return

            if jcat_verify_file(jcat_input_path, self.cfg.public_keys_dir, keyring_dir):
                # metadata is valid
                LOGGER.info(
                    "Successfully downloaded and verified metadata %s.",
                    metadata_input_path,
                )
            else:
                LOGGER.error(
                    (
                        "Metadata %s downloaded but verification with jcat %s failed."
                        " Skipping remote %s"
                    ),
                    metadata_input_path,
                    jcat_input_path,
                    remote.name,
                )
                return

        # process metadata
        repo_firmware_blobs = list(
            self.process_metadata(
                metadata_input_path=metadata_input_path,
                metadata_output_path=metadata_output_path,
                firmware_blob_dir=firmware_root,
                firmware_url_base=firmware_url_base,
            )
        )

        LOGGER.info(
            "Processed %i components (skipped %i)",
            self._processed_components,
            self._skipped_components,
        )

        total_repo_size = sum(
            fw.expected_size for fw in repo_firmware_blobs if fw.expected_size
        )
        LOGGER.info(
            "Repo will cache %i firmware blobs (%s)",
            len(repo_firmware_blobs),
            human_file_size(total_repo_size),
        )

        if not self.force:
            LOGGER.info("Validating existing firmware blobs...")
            # Validate local files and remove valid firmware blobs from list of blobs
            # that we need to downloaded.
            repo_firmware_blobs = [
                fw for fw in repo_firmware_blobs if not fw.verify_firmware()
            ]

        download_size = sum(
            fw.expected_size for fw in repo_firmware_blobs if fw.expected_size
        )
        amount_fw_blobs_str = str(len(repo_firmware_blobs))
        LOGGER.info(
            "Will download %s firmware blobs (%s)...",
            amount_fw_blobs_str,
            human_file_size(download_size),
        )

        # download & verify firmware blobs
        for idx, firmware_blob in enumerate(repo_firmware_blobs, start=1):
            counter = f"[{idx:>{len(amount_fw_blobs_str)}}/{amount_fw_blobs_str}]"
            self.download_and_verify_firmware(firmware_blob, tmp_root, counter)

        # sign new metadata
        jcat_sign_file(
            data_file_path=metadata_output_path,
            jcat_file_path=jcat_output_path,
            pkcs7_cert_file_path=self.cfg.pkcs7_signing_cert,
            pkcs7_private_key_file_path=self.cfg.pkcs7_signing_key,
            gpg_signing_key_id=self.cfg.gpg_signing_key_id,
            alias=metadata_name_original,
        )

        # "publish" jcat and modified metadata file
        jcat_output_path.rename(jcat_mirror_path)
        metadata_output_path.rename(metadata_mirror_path)
        metadata_mirror_path_default.unlink(missing_ok=True)
        metadata_mirror_path_default.symlink_to(metadata_name)

    def download_file(self, url: str, output_file: Path) -> None:
        """Download a file."""
        resp = self.session.request("GET", url, preload_content=False)
        size = 0

        with TerminalLineUpdater() as printer:
            printer.update(
                f"Downloading {output_file}",
                on_non_terminals=True,
            )

            with output_file.open("wb") as file:
                while chunk := resp.read(DOWNLOAD_CHUNK_SIZE):
                    printer.update(
                        f"Downloading {output_file}: {human_file_size(size)}"
                    )
                    file.write(chunk)
                    size += len(chunk)

            printer.update(
                f"Downloaded {output_file}: {human_file_size(size)}",
                on_non_terminals=True,
            )

    def process_metadata(
        self,
        metadata_input_path: Path,
        metadata_output_path: Path,
        firmware_blob_dir: Path,
        firmware_url_base: str,
    ) -> typing.Generator[FirmwareBlob, None, None]:
        """
        Process the metadata of a repo.

        Write an updated version of the firmware and extract firmware blobs
        that need to be downloaded.
        """

        input_file: gzip.GzipFile | typing.IO
        src_mtime: int | None = None
        if metadata_input_path.suffix == ".gz":
            # extract output
            input_file = gzip.GzipFile(filename=metadata_input_path, mode="rb")
            # get gzip mtime
            input_file.read(1)
            src_mtime = input_file.mtime
            input_file.rewind()
        else:
            input_file = metadata_input_path.open("rb")

        output_file: gzip.GzipFile | typing.IO
        if metadata_output_path.suffix == ".gz":
            # compress output
            output_file = gzip.GzipFile(
                filename=metadata_output_path, mode="wb", mtime=src_mtime
            )
        else:
            output_file = metadata_output_path.open("wb")

        try:
            # write header
            output_file.write(
                b'<?xml version="1.0" encoding="utf-8"?>'
                b'<components origin="lvfs" version="0.9">'
            )

            # process components
            for _event, element in ElementTree.iterparse(input_file):
                if element.tag == "component":
                    yield from self.process_component(
                        element,
                        firmware_blob_dir,
                        firmware_url_base,
                    )
                    self._processed_components += 1

                    output_file.write(
                        ElementTree.tostring(element, encoding="utf8", method="html")
                    )

            # write trailer
            output_file.write(b"</components>")
        finally:
            input_file.close()
            output_file.close()

    def process_component(
        self,
        component: ElementTree.Element,
        firmware_blob_dir: Path,
        firmware_url_base: str,
    ) -> typing.Generator[FirmwareBlob, None, None]:
        """
        Process and update a component which is part of the repo metadata.

        Extract and yield info of firmware blobs that need to be downloaded.
        """
        component_id_element = component.find("id")
        if component_id_element is None or not component_id_element.text:
            LOGGER.warning("Component %s has no ID. Ignoring.", component)
            return
        component_id = component_id_element.text

        if not filter_component_id(component_id, self.cfg.filter_ids):
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
                        "Missing compare and/or version attribute for <firmware>vendor-id</firmware> requirement."
                    )
                    continue
                elif filter_vendor_id(
                    condition_version.upper(),
                    condition_compare.lower(),
                    self.cfg.filter_vendor_ids,
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
                # I don't know how I can get a list of computer hardware IDs
                # of devices on my computer.
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

            firmware_blob_name = (
                Path(release_url.path).name if release_url.path else component_id
            )

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

            output_path = firmware_blob_dir / firmware_blob_name
            yield FirmwareBlob(
                url=release_url_str,
                expected_checksums=checksums,
                expected_size=size,
                output_path=output_path,
            )

            new_release_url = f"{firmware_url_base.rstrip('/')}/{firmware_blob_name}"
            location.text = new_release_url

    def exclude_old_versions(
        self, release_elements: list[ElementTree.Element], component_id: str
    ) -> list[ElementTree.Element]:
        """
        If keep_versions is set, this will exclude old release versions.

        It filters a list of release elements from metadata XML.
        """

        keep_versions = self.cfg.keep_versions
        if not keep_versions or len(release_elements) <= keep_versions:
            return release_elements

        elements_with_sort_key: list[VersionEntryT] = []

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
                (
                    "Did not find a useable sort criteria for the release versions of component %s."
                    " Will download all versions."
                ),
                component_id,
            )
            return release_elements

        if sort_idx > 0:
            LOGGER.warning(
                (
                    "Can't reliably sort release versions of component %s by their version."
                    " Latest version might not be available."
                ),
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
        ) in elements_with_sort_key[: self.cfg.keep_versions]:
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

    def download_and_verify_firmware(
        self, firmware_blob: FirmwareBlob, tmp_dir: Path, counter: str
    ) -> None:
        """Download & verify firmware files."""
        checksums = {}
        for checksum_type in firmware_blob.expected_checksums.keys():
            checksums[checksum_type] = hashlib.new(checksum_type)

        resp = self.session.request("GET", firmware_blob.url, preload_content=False)
        size = 0

        tmp_file = tmp_dir / firmware_blob.output_path.name

        with TerminalLineUpdater() as printer:
            printer.update(
                f"{counter} Downloading {firmware_blob.output_path}",
                on_non_terminals=True,
            )

            with tmp_file.open("wb") as file:
                while chunk := resp.read(DOWNLOAD_CHUNK_SIZE):
                    printer.update(
                        f"{counter} Downloading {firmware_blob.output_path}: {human_file_size(size)}"
                    )
                    file.write(chunk)
                    for checksum_algo in checksums.values():
                        checksum_algo.update(chunk)
                    size += len(chunk)

            self._downloaded_files += 1
            self._downloaded_size += size
            printer.update(
                f"{counter} Downloaded {firmware_blob.output_path}: {human_file_size(size)}"
            )

            if firmware_blob.expected_size and size != firmware_blob.expected_size:
                LOGGER.warning(
                    "%s Failed to download %s. Received %i bytes, expected %i bytes.",
                    counter,
                    firmware_blob.url,
                    size,
                    firmware_blob.expected_size,
                )
                os.unlink(tmp_file)
                return

            for checksum_type, checksum_value in checksums.items():
                expected_checksum_value = firmware_blob.expected_checksums[
                    checksum_type
                ]
                actual_checksum_digest = checksum_value.hexdigest().lower()
                if actual_checksum_digest == expected_checksum_value:
                    try:
                        xattr.set(
                            tmp_file,
                            f"user.checksum.{checksum_type}".encode("utf-8"),
                            actual_checksum_digest.encode("utf-8"),
                        )
                    except OSError as err:
                        LOGGER.warning(
                            "Could not set file xattrs to %s: %s", tmp_file, err
                        )
                else:
                    LOGGER.warning(
                        "%s Failed to download %s. Checksum %s miss-match: expected %s got %s.",
                        counter,
                        firmware_blob.url,
                        checksum_type,
                        expected_checksum_value,
                        actual_checksum_digest,
                    )
                    os.unlink(tmp_file)
                    return

            tmp_file.rename(firmware_blob.output_path)
            checksums_str = ", ".join(sorted(checksums.keys()))
            printer.update(
                f"{counter} Downloaded and verified {firmware_blob.output_path} with checksums {checksums_str}",
                on_non_terminals=True,
            )


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(__name__)
    parser.add_argument(
        "-c",
        "--config",
        default="/etc/lvfs-mirror/mirror.conf",
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
        cfg=cfg,
        force=args.force,
    )

    try:
        mirror.run()
    except KeyboardInterrupt:
        print("\33[2K\rAbort", file=sys.stderr)


if __name__ == "__main__":
    main()
