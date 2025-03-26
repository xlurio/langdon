import pathlib
import sys

from langdon import assetimporter, initializer
from langdon import langdon_argparser as argparser
from langdon.langdon_logging import logger
from langdon.langdon_manager import LangdonManager
from langdon.output import OutputColor


def main():
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
        return {
            "importcsv": assetimporter.import_from_csv(parsed_args, manager=manager),
        }[parsed_args.module]


if __name__ == "__main__":
    main()
