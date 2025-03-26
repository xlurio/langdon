from __future__ import annotations

import pathlib
from argparse import Namespace

import tomli_w

from langdon.output import OutputColor


class InitNamespace(Namespace):
    filefox_profile: pathlib.Path
    directory: pathlib.Path | None


def initialize(args: InitNamespace) -> None:
    cleaned_directory = args.directory.absolute() or pathlib.Path(".").absolute()
    database_path = str(cleaned_directory / "langdon.db")
    web_directories_artifacts = str(cleaned_directory / "web_directories")
    firefox_profile = str(args.filefox_profile.absolute())
    toml_path = cleaned_directory / "pyproject.toml"

    toml_config = {
        "tool.langdon": {
            "database": database_path,
            "web_directories_artifacts": web_directories_artifacts,
            "firefox_profile": firefox_profile,
        }
    }

    with open(toml_path, "w") as f:
        tomli_w.dump(toml_config, f)

    print(
        f"{OutputColor.GREEN}Project initialized in directory {cleaned_directory}{OutputColor.RESET}"
    )
