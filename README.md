# LVFS Mirror

Tool to mirror Linux Vendor Firmware Service (LVFS) repositories,
that are used for [fwupd](https://fwupd.org/).

## Configuration

The configuration is by default stored under `/etc/lvfs-mirror/mirror.conf`
or any path you give with `--config` / `-c`.
An example configuration file can be found in `mirror.conf`.

The configuration of remotes is the same as for fwupd.

Details about signing and verifying can be found [here](https://github.com/hughsie/libjcat/).

## Installation

### Dependencies

This tool requires the tool `jcat-tool` available in the `PATH`.

### Production

[![Publish Python Package](https://github.com/sedrubal/lvfs-mirror/actions/workflows/python-publish.yml/badge.svg)](https://pypi.org/project/lvfs-mirror/)

Install from [pypi]() using:

```bash
pipx install lvfs-mirror
```

### Development

Clone the repo and install it using:

```bash
poetry install
```

Contributions are very welcome.

## License

© 2024 Sebastian Endres
[MIT License](LICENSE.txt)
