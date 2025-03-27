import random
import time

_cache = {}
MIN_TIME_BETWEEN_REQUESTS = 5
MAX_TIME_BETWEEN_REQUESTS = 10


def wait_for_slot(queue: str):
    if queue not in _cache:
        _cache[queue] = time.time()
        return

    expected_time_between_requests = random.randint(
        MIN_TIME_BETWEEN_REQUESTS, MAX_TIME_BETWEEN_REQUESTS
    )

    while time.time() - _cache[queue] < expected_time_between_requests:
        time.sleep(0.1)

    _cache[queue] = time.time()
