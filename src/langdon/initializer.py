from __future__ import annotations

import pathlib
from argparse import Namespace

import tomli_w

from langdon.exceptions import LangdonException
from langdon.output import OutputColor

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0"
)


class InitNamespace(Namespace):
    filefox_profile: pathlib.Path
    resolvers_file: pathlib.Path
    dns_wordlist: pathlib.Path
    content_wordlist: pathlib.Path
    directory: pathlib.Path | None


def initialize(args: InitNamespace) -> None:
    cleaned_directory = args.directory.absolute() or pathlib.Path(".").absolute()
    database_path = str(cleaned_directory / "langdon.db")
    web_directories_artifacts = str(cleaned_directory / "web_directories")
    web_directory_screenshots = str(cleaned_directory / "web_screenshots")
    downloaded_apks_dir = str(cleaned_directory / "downloaded_apks")
    firefox_profile = str(args.filefox_profile.absolute())
    toml_path = cleaned_directory / "pyproject.toml"
    resolvers_file = str(args.resolvers_file.absolute())
    dns_wordlist = str(args.dns_wordlist.absolute())
    content_wordlist = str(args.content_wordlist.absolute())

    toml_config = {
        "tool.langdon": {
            "database": database_path,
            "web_directories_artifacts": web_directories_artifacts,
            "web_directory_screenshots": web_directory_screenshots,
            "firefox_profile": firefox_profile,
            "log_file": str(cleaned_directory / "langdon.log"),
            "downloaded_apks_dir": downloaded_apks_dir,
            "resolvers_file": resolvers_file,
            "dns_wordlist": dns_wordlist,
            "content_wordlist": content_wordlist,
            "user_agent": DEFAULT_USER_AGENT,
        }
    }

    if toml_path.exists():
        raise LangdonException(
            f"There already is a pyproject.toml file in '{cleaned_directory}'"
        )

    with open(toml_path, "w") as f:
        tomli_w.dump(toml_config, f)

    print(
        f"{OutputColor.GREEN}Project initialized in directory {cleaned_directory}{OutputColor.RESET}"
    )
