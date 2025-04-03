from __future__ import annotations

from collections.abc import Mapping
import random
import time
from typing import TYPE_CHECKING

from langdon.abc import DataFileManagerABC

if TYPE_CHECKING:
    from langdon.langdon_manager import LangdonManager

MIN_TIME_BETWEEN_REQUESTS = 5
MAX_TIME_BETWEEN_REQUESTS = 10


class CacheFileManager(DataFileManagerABC[Mapping[str, float]]):
    FILE_CONFIG_KEY = "cache_file"

    def get_default_file_initial_value(self) -> Mapping[str, float]:
        return {}


def _get_cache(key: str, *, manager: CacheFileManager) -> Mapping[str, float]:
    return manager.read_data_file()[key]


def _set_cache(key: str, value: float, *, manager: CacheFileManager) -> None:
    cache = manager.read_data_file()
    cache[key] = value
    manager.write_data_file(cache)


def wait_for_slot(queue: str, *, manager: LangdonManager) -> None:
    cache_manager = CacheFileManager(manager=manager)

    if queue not in cache_manager.read_data_file():
        return _set_cache(queue, time.time(), manager=cache_manager)

    expected_time_between_requests = random.randint(
        MIN_TIME_BETWEEN_REQUESTS, MAX_TIME_BETWEEN_REQUESTS
    )

    while (
        time.time() - _get_cache(queue, manager=cache_manager)
        < expected_time_between_requests
    ):
        time.sleep(0.1)

    _set_cache(queue, time.time(), manager=cache_manager)
