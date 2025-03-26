import argparse
import pathlib
import sys
from collections.abc import Callable, Iterator
from typing import Literal


class LangdonNamespace(argparse.Namespace):
    loglevel: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    openvpn: pathlib.Path | None
    module: Literal["init", "importcsv"]


def _make_global_arguments_parser(
    main_parser: argparse.ArgumentParser,
) -> argparse.ArgumentParser:
    main_parser.add_argument(
        "--loglevel",
        "-l",
        default="CRITICAL",
        help="Set the logging level. Options are DEBUG, INFO, WARNING, ERROR and "
        "CRITICAL. Default is CRITICAL",
    )
    main_parser.add_argument(
        "--openvpn",
        "-o",
        type=pathlib.Path,
        help="OpenVPN client configuration file for VPN tunneling during execution. "
        "Recommended in case you don't have a VPN already enabled",
    )

    return main_parser


def _make_init_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    init_parser = subparsers.add_parser(
        "init", help="Initialize Langdon reconnaissance project directory"
    )
    init_parser.add_argument(
        "filefox_profile",
        type=pathlib.Path,
        help="Path to the Firefox profile to be used for content discovery",
    )
    init_parser.add_argument(
        "--directory",
        "-d",
        type=pathlib.Path,
        help="Select a directory to store the reconnaissance results. "
        "Default is the current directory",
    )


def _make_importcsv_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    importcsv_parser = subparsers.add_parser(
        "importcsv", help="Import target known assets from a CSV file"
    )
    importcsv_parser.add_argument(
        "csv_file",
        type=pathlib.Path,
        help="path to the CSV with the data to import. The file should have at least "
        "the columns name, asset_type and max_severity, with the name of the columns "
        'on the first line. asset_type accepts the value "URL", "WILDCARD", '
        '"APPLE_STORE_APP_ID", "GOOGLE_PLAY_APP_ID". max_severity accepts “low”, '
        "“medium”, “high” and “critical.",
    )


ModuleParserFactory = Callable[
    [argparse._SubParsersAction[argparse.ArgumentParser]], None
]


def _iter_module_parser_factories() -> Iterator[ModuleParserFactory]:
    yield _make_init_parser
    yield _make_importcsv_parser


def parse_args() -> LangdonNamespace:
    main_parser = argparse.ArgumentParser(
        prog="Langdon", description="Tool for target applications reconnaissance"
    )
    main_parser_w_args = _make_global_arguments_parser(main_parser)
    main_subparsers = main_parser_w_args.add_subparsers(dest="module")

    for module_parser_factory in _iter_module_parser_factories():
        module_parser_factory(main_subparsers)

    return main_parser.parse_args(sys.argv[1:])
