from __future__ import annotations

import random
import time
from collections.abc import Mapping
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


def _get_cache(key: str, *, manager: LangdonManager) -> Mapping[str, float]:
    with CacheFileManager(manager=manager) as cache_manager:
        return cache_manager.read_data_file()[key]


def _set_cache(key: str, value: float, *, manager: LangdonManager) -> None:
    with CacheFileManager(manager=manager) as cache_manager:
        cache = cache_manager.read_data_file()
        cache[key] = value
        cache_manager.write_data_file(cache)


def wait_for_slot(queue: str, *, manager: LangdonManager) -> None:
    expected_time_between_requests = random.randint(
        MIN_TIME_BETWEEN_REQUESTS, MAX_TIME_BETWEEN_REQUESTS
    )

    try:
        while (
            time.time() - _get_cache(queue, manager=manager)
            < expected_time_between_requests
        ):
            time.sleep(0.1)

        _set_cache(queue, time.time(), manager=manager)

    except KeyError:
        return _set_cache(queue, time.time(), manager=manager)
