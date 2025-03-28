from __future__ import annotations

import argparse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from langdon.langdon_manager import LangdonManager


class GraphGeneratorNamespace(argparse.Namespace):
    output: Path


def generate_graph(parsed_args: GraphGeneratorNamespace, *manager: LangdonManager) -> None:
    """
    Generate a graph of the known assets using the Graphviz library.
    """
    raise NotImplementedError("TODO")
