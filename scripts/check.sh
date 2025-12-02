#!/bin/bash

set -eu

cd "$(dirname "$0")/.."

PKG="lvfs_mirror"
echo "--> Running isort"
uv run isort "${PKG}"
echo "--> Running ruff"
uv run ruff format
uv run ruff check
# echo "--> Running tox"
# set +e  # I don't understand how to temporarily get tox to exit with 0
# uv run tox
# set -e
echo "--> Running pylint"
uv run pylint --exit-zero --jobs 0 "${PKG}"
echo "--> Running mypy"
set +e  # mypy has no flag to exit with 0
uv run mypy "${PKG}"
set -e

if [[ "$*" == *"--all"* ]]; then
    echo "--> Running pyre"
    set +e  # pyre has no flag to exit with 0
    uv run pyre check
    set -e
else
    echo
    echo "!!!"
    echo "!!! Skipping less important tasks. Run with --all to run all. !!!"
    echo "!!!"
    echo
fi

# Run the scripts
echo "--> Executing the tool entry points"
CMDS=(
    lvfs-mirror
)
for cmd in "${CMDS[@]}"; do
    uv run "${cmd}" --version
done
