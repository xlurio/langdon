from __future__ import annotations

import json
import pathlib
import random
import time
from typing import TYPE_CHECKING

from langdon.langdon_logging import logger

if TYPE_CHECKING:
    from langdon.langdon_manager import LangdonManager

MIN_TIME_BETWEEN_REQUESTS = 5
MAX_TIME_BETWEEN_REQUESTS = 10


def _read_cache_data(*, manager: LangdonManager) -> dict[str, float]:
    try:
        cache_file = manager.config["cache_file"]
        return json.loads(pathlib.Path(cache_file).read_text())
    
    except FileNotFoundError:
        logger.debug("No cache file found")
        return {}


def _write_cache_data(data: dict[str, float], *, manager: LangdonManager) -> None:
    cache_file = manager.config["cache_file"]
    pathlib.Path(cache_file).write_text(json.dumps(data))


def _get_cache(key, *, manager: LangdonManager) -> dict[str, float]:
    return _read_cache_data(manager=manager)[key]


def _set_cache(key, value, *, manager: LangdonManager) -> None:
    cache = _read_cache_data(manager=manager)
    cache[key] = value
    _write_cache_data(cache, manager=manager)


def wait_for_slot(queue: str, *, manager: LangdonManager) -> None:
    if queue not in _read_cache_data(manager=manager):
        return _set_cache(queue, time.time(), manager=manager)

    expected_time_between_requests = random.randint(
        MIN_TIME_BETWEEN_REQUESTS, MAX_TIME_BETWEEN_REQUESTS
    )

    while time.time() - _get_cache(queue, manager=manager) < expected_time_between_requests:
        time.sleep(0.1)

    _set_cache(queue, time.time(), manager=manager)
