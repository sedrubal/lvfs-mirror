"""Minimal re-implementation of lib-jcat."""

import gzip
import json
import logging
import subprocess
import typing
from pathlib import Path

LOGGER = logging.getLogger()

JCAT_MAGIC_END = b"IHATECDN"


def get_jcat_items(jcat_file_path: Path) -> typing.Generator[str, None, None]:
    """Get the JcatItem IDs from a jcat file."""
    with jcat_file_path.open(mode="rb") as jcat_file:
        jcat_compressed_data = jcat_file.read()

    # There is trailing garbage at the end of jcat files.
    # Normal gzip ignores it but python gzip throws and exception because it thinks
    # that a new gzip member (file) starts at that position
    # but the garbage is not a valid gzip member header.
    # We strip that garbage before we give it to gzip.
    if jcat_compressed_data[-len(JCAT_MAGIC_END) :] == JCAT_MAGIC_END:
        jcat_compressed_data = jcat_compressed_data[: -len(JCAT_MAGIC_END)]

    jcat_data = gzip.decompress(jcat_compressed_data)
    jcat = json.loads(jcat_data)
    for item in jcat.get("Items", []):
        yield item["Id"]


def get_jcat_item(jcat_file_path: Path) -> str:
    """Assume that only one item is in the jcat file and return it."""
    jcat_items: list[str] = list(get_jcat_items(jcat_file_path=jcat_file_path))
    if len(jcat_items) == 1:
        jcat_item = jcat_items[0]
        if "/" in jcat_item:
            raise ValueError(f"Refusing unsecure jcat_item with name {jcat_item}")
        return jcat_item
    else:
        raise ValueError(
            f"Jcat file unexpectedly contained multiple items: {', '.join(jcat_items)}."
        )


def jcat_verify_file(jcat_file_path: Path, public_keys_dir: Path) -> bool:
    """:return: True, if a jcat file validated successfully."""
    try:
        subprocess.check_call(
            [
                "jcat-tool",
                "verify",
                f"--public-keys={public_keys_dir}",
                jcat_file_path.name,
            ],
            # jcat-tool will search for the files to verify relative to the current directory.
            cwd=jcat_file_path.parent,
        )
    except subprocess.CalledProcessError as err:
        if err.returncode == 1:
            LOGGER.error(
                "Failed to verify jcat file %s.",
                jcat_file_path,
            )
            return False

    return True


def jcat_sign_file(
    data_file_path: Path,
    jcat_file_path: Path,
    pkcs7_cert_file_path: Path,
    pkcs7_private_key_file_path: Path,
    # gpg_private_key: Path,
) -> None:
    """
    Sign `data_file_path` and write signature jcat into `jcat_file_path`.

    Creates:
    - sha1
    - sha256
    - pkcs7 signature

    Not (yet) supported: gpg signature.
    """
    assert jcat_file_path.parent == data_file_path.parent
    cwd = data_file_path.parent
    pkcs7_cert_file_path = pkcs7_cert_file_path.absolute()
    pkcs7_private_key_file_path = pkcs7_private_key_file_path.absolute()

    LOGGER.debug("Signing using PKCS7 key...")
    subprocess.check_call(
        [
            "jcat-tool",
            "sign",
            jcat_file_path.name,
            data_file_path.name,
            pkcs7_cert_file_path,
            pkcs7_private_key_file_path,
        ],
        cwd=cwd,
    )
    # LOGGER.debug("Signing using gpg key...")
    # subprocess.check_call(
    #     [
    #         "jcat-tool",
    #         "import",
    #         jcat_file_path.name,
    #         data_file_path.name,
    #         gpg_signature_file_path,
    #     ],
    #     cwd=cwd,
    # )
    for checksum_algo in ("sha1", "sha256"):
        LOGGER.debug("Creating %s checksum...", checksum_algo)
        subprocess.check_call(
            [
                "jcat-tool",
                "self-sign",
                jcat_file_path.name,
                data_file_path.name,
                f"--kind={checksum_algo}",
            ],
            cwd=cwd,
        )
