from langdon.events import WebDirectoryResponseDiscovered
from langdon.langdon_manager import LangdonManager


def handle_event(
    event: WebDirectoryResponseDiscovered, *, manager: LangdonManager
) -> None:
    raise NotImplementedError("TODO: Implement this")
