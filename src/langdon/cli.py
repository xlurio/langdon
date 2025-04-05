from __future__ import annotations

import logging
import pathlib
import sys
import typing

from langdon import (
    assetimporter,
    crud_executor,
    graph_generator,
    initializer,
    langdon_logging,
    recon_executor,
)
from langdon import langdon_argparser as argparser
from langdon.langdon_logging import logger
from langdon.langdon_manager import LangdonManager
from langdon.langdon_t import CrudModuleT
from langdon.output import OutputColor


def run():
    parsed_args = argparser.parse_args()
    is_initializing = parsed_args.module == "init"

    if not (is_initializing or pathlib.Path("pyproject.toml").exists()):
        print(
            f"{OutputColor.RED}Error: Langdon project not initialized. Run "
            f"'langdon init' to initialize the project{OutputColor.RESET}"
        )
        sys.exit(1)

    logger.setLevel(parsed_args.loglevel or "CRITICAL")

    if is_initializing:
        return initializer.initialize(parsed_args)

    with LangdonManager() as manager:
        log_file_handler = logging.FileHandler(
            manager.config["log_file"] + f".{parsed_args.module}"
        )
        logger.addHandler(log_file_handler)
        log_file_handler.setLevel(logging.NOTSET)
        log_file_handler.setFormatter(langdon_logging.log_formatter)

        return {
            "importcsv": lambda: assetimporter.import_from_csv(
                parsed_args, manager=manager
            ),
            "run": lambda: recon_executor.run_recon(parsed_args, manager=manager),
            "graph": lambda: graph_generator.generate_graph(
                parsed_args, manager=manager
            ),
            **{
                model_module: lambda: crud_executor.execute_crud_operation(
                    parsed_args, manager=manager
                )
                for model_module in typing.get_args(CrudModuleT)
            },
        }[parsed_args.module]()


if __name__ == "__main__":
    run()
