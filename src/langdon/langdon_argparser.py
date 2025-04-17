from __future__ import annotations

import argparse
import functools
import json
import pathlib
import sys
import typing
from collections.abc import Callable
from typing import TYPE_CHECKING

from langdon.langdon_t import CrudModuleT

if TYPE_CHECKING:
    from collections.abc import Iterator
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
        "-O",
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
        "--resolvers_file",
        "-r",
        type=pathlib.Path,
        required=True,
        help="Required. Path to the resolvers list file to be used for DNS discovery",
    )
    init_parser.add_argument(
        "--dns_wordlist",
        "-dw",
        type=pathlib.Path,
        required=True,
        help="Required. Path to the wordlist file to be used for DNS discovery",
    )
    init_parser.add_argument(
        "--content_wordlist",
        "-cw",
        type=pathlib.Path,
        required=True,
        help="Required. Path to the wordlist file to be used for content discovery",
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


def _make_run_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    run_parser = subparsers.add_parser(
        "run", help="Run Langdon reconnaissance on the known assets"
    )
    run_parser.add_argument(
        "--nodownloadandroidapps",
        action=argparse.BooleanOptionalAction,
        help="Skip downloading Android apps",
    )
    run_parser.add_argument(
        "--noprocessknowndomains",
        action=argparse.BooleanOptionalAction,
        help="Skip processing known domains",
    )
    run_parser.add_argument(
        "--noprocessknownips",
        action=argparse.BooleanOptionalAction,
        help="Skip processing known IPs",
    )
    run_parser.add_argument(
        "--nodiscoverdomainsfromknownonespassively",
        action=argparse.BooleanOptionalAction,
        help="Skip discovering domains from known ones passively",
    )
    run_parser.add_argument(
        "--nodiscovercontentpassively",
        action=argparse.BooleanOptionalAction,
        help="Skip discovering content passively",
    )


def _make_graph_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    graph_parser = subparsers.add_parser(
        "graph", help="Generate a graph of the known assets"
    )
    graph_parser.add_argument(
        "--output",
        "-o",
        type=pathlib.Path,
        default=pathlib.Path("langdon-graph.png"),
        help="Path to the output file. Default is langdon-graph.png",
    )


def _make_crud_parser_factory(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    model: CrudModuleT,
):
    crud_parser = subparsers.add_parser(
        model, help=f"CRUD operations for {model} table"
    )

    abc_writing_parser = argparse.ArgumentParser(add_help=False)
    abc_writing_parser.add_argument(
        "--data",
        type=json.loads,
        help="Data to create the object. The data should be a JSON string.",
    )
    abc_detail_parser = argparse.ArgumentParser(add_help=False)
    abc_detail_parser.add_argument(
        "--id",
        type=int,
        help="ID of the object to act. The ID should be an integer.",
    )

    crud_subparsers = crud_parser.add_subparsers(dest="operation")
    crud_subparsers.add_parser(
        "create", help=f"Create a new {model} object", parents=[abc_writing_parser]
    )
    crud_subparsers.add_parser(
        "update",
        help=f"Update an existing {model} object",
        parents=[abc_writing_parser, abc_detail_parser],
    )
    crud_subparsers.add_parser(
        "delete", help=f"Delete an existing {model} object", parents=[abc_detail_parser]
    )
    list_parser = crud_subparsers.add_parser("list", help=f"List all {model} objects")
    list_parser.add_argument(
        "--filter",
        "-F",
        type=json.loads,
        help="Filter to apply to the list. The filter should be a JSON string.",
    )
    list_parser.add_argument(
        "--limit",
        "-L",
        type=int,
        help="Limit the number of objects to return. The limit should be an integer.",
    )
    crud_subparsers.add_parser(
        "retrieve", help=f"Get details of a {model} object", parents=[abc_detail_parser]
    )


def _make_takescreenshot_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    takescreenshot_parser = subparsers.add_parser(
        "takescreenshot", help="Take a screenshot of a URL"
    )
    takescreenshot_parser.add_argument(
        "url",
        type=str,
        help="URL to take a screenshot of. The URL should be a string.",
    )


ModuleParserFactory = Callable[
    ["argparse._SubParsersAction[argparse.ArgumentParser]"], None
]


def _iter_module_parser_factories() -> Iterator[ModuleParserFactory]:
    yield _make_init_parser
    yield _make_importcsv_parser
    yield _make_run_parser
    yield _make_graph_parser
    yield _make_takescreenshot_parser

    for model_module in typing.get_args(CrudModuleT):
        yield functools.partial(_make_crud_parser_factory, model=model_module)


def parse_args() -> LangdonNamespace:
    main_parser = argparse.ArgumentParser(
        prog="Langdon", description="Tool for target applications reconnaissance"
    )
    main_parser_w_args = _make_global_arguments_parser(main_parser)
    main_subparsers = main_parser_w_args.add_subparsers(dest="module")

    for module_parser_factory in _iter_module_parser_factories():
        module_parser_factory(main_subparsers)

    return main_parser.parse_args(sys.argv[1:])
