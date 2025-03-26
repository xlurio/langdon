import argparse
import sys


class LangdonNamespace(argparse.Namespace):
    loglevel: str
    openvpn: str | None
    module: str


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
        help="Path to the Firefox profile to be used for content discovery",
    )
    init_parser.add_argument(
        "--directory",
        "-d",
        help="Select a directory to store the reconnaissance results. "
        "Default is the current directory",
    )


def parse_args() -> LangdonNamespace:
    main_parser = argparse.ArgumentParser(
        prog="Langdon", description="Tool for target applications reconnaissance"
    )
    main_parser_w_args = _make_global_arguments_parser(main_parser)
    main_subparsers = main_parser_w_args.add_subparsers(dest="module")
    _make_init_parser(main_subparsers)

    return main_parser.parse_args(sys.argv[1:])
