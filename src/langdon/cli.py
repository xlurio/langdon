from __future__ import annotations

import logging
import pathlib
import sys

from langdon import (
    assetimporter,
    graph_generator,
    initializer,
    langdon_logging,
    recon_executor,
)
from langdon import langdon_argparser as argparser
from langdon.langdon_logging import logger
from langdon.langdon_manager import LangdonManager
from langdon import event_listener
from langdon.output import OutputColor
from langdon import task_queue


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

    with (
        task_queue.task_queue_context(),
        event_listener.event_listener_context(),
        LangdonManager() as manager,
    ):
        log_file_handler = logging.FileHandler(manager.config["log_file"])
        log_file_handler.setLevel(logging.NOTSET)
        log_file_handler.setFormatter(langdon_logging.log_formatter)

        logger.addHandler(log_file_handler)
        return {
            "importcsv": lambda: assetimporter.import_from_csv(
                parsed_args, manager=manager
            ),
            "run": lambda: recon_executor.run_recon(parsed_args, manager=manager),
            "graph": lambda: graph_generator.generate_graph(
                parsed_args, manager=manager
            ),
        }[parsed_args.module]()


if __name__ == "__main__":
    run()
