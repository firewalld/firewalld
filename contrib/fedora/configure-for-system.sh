#!/usr/bin/bash

set -ex

BASE_DIR="$(cd "$(dirname "$BASH_SOURCE")"; git rev-parse --show-toplevel)"

cd "$BASE_DIR"

git clean -fdx
./autogen.sh
./configure --enable-sysconfig --enable-rpmmacros PYTHON="/usr/bin/python3"
make -j 8
