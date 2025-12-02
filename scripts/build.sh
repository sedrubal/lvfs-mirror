#!/bin/bash

set -euxo pipefail

cd "$(dirname "$0")/.."

uv build

# strip non-deterministic things
strip-nondeterminism ./dist/*
for f in ./dist/*.tar.gz; do
    tmp=$(mktemp -d)

    tar -xzf "${f}" --directory="${tmp}"

    root=$(basename "${f/.tar.gz/}")

    rm "${f}"

    tar \
        --sort=name \
        --owner=root:0 \
        --group=root:0 \
        --mtime='UTC 2019-01-01' \
        -czf "${f}" \
        --directory="${tmp}" \
        "${root}"

    rm -rf "$tmp"
done

set +u
if [ "$1" == "--publish" ]; then
    set -u
    # see uv config in pyproject.toml
    uv publish --username=__token__
fi
