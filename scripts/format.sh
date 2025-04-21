#! /bin/bash

set -x

./venv/bin/ruff check --fix --unsafe-fixes --preview .
./venv/bin/ruff format --preview .
