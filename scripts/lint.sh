#! /bin/bash

set -x

./venv/bin/pylint .
./venv/bin/ruff check .
