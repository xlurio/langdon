from __future__ import annotations

import pathlib
from argparse import Namespace

import tomli_w

from langdon.output import OutputColor

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0"
)


class InitNamespace(Namespace):
    content_wordlist: pathlib.Path
    directory: pathlib.Path | None
    dns_wordlist: pathlib.Path
    resolvers_file: pathlib.Path


def initialize(args: InitNamespace) -> None:
    cleaned_directory = (
        args.directory.absolute() if args.directory else pathlib.Path(".").absolute()
    )
    toml_path = cleaned_directory / "pyproject.toml"

    if toml_path.exists():
        print(
            f"{OutputColor.RED}There already is a pyproject.toml file in "
            f"'{cleaned_directory}'{OutputColor.RESET}"
        )
        exit(1)

    # Ensure necessary directories exist

    database_path = cleaned_directory / "langdon.db"

    web_directory_screenshots = cleaned_directory / "web_screenshots"
    web_directory_screenshots.mkdir(parents=True, exist_ok=True)

    downloaded_apks_dir = cleaned_directory / "downloaded_apks"
    downloaded_apks_dir.mkdir(parents=True, exist_ok=True)

    resolvers_file = args.resolvers_file.absolute()
    dns_wordlist = args.dns_wordlist.absolute()
    content_wordlist = args.content_wordlist.absolute()
    cache_file = cleaned_directory / ".langdon.cache.json"

    toml_config = {
        "tool": {
            "langdon": {
                "cache_file": str(cache_file),
                "database": str(database_path),
                "web_directory_screenshots": str(web_directory_screenshots),
                "log_file": str(cleaned_directory / "langdon.log"),
                "downloaded_apks_dir": str(downloaded_apks_dir),
                "resolvers_file": str(resolvers_file),
                "dns_wordlist": str(dns_wordlist),
                "content_wordlist": str(content_wordlist),
                "user_agent": DEFAULT_USER_AGENT,
            }
        }
    }

    with open(toml_path, "wb") as f:
        tomli_w.dump(toml_config, f)

    print(
        f"{OutputColor.GREEN}Project initialized in directory {cleaned_directory}{OutputColor.RESET}"
    )
