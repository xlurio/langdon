import pathlib
from langdon import initializer
from langdon import langdon_argparser as argparser
import sys

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

    if is_initializing:
        return initializer.initialize(parsed_args)


if __name__ == "__main__":
    main()
