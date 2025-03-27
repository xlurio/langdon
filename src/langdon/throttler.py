import time

_cache = {}
TIME_BETWEEN_REQUESTS = 5


def wait_for_slot(queue: str):
    if queue not in _cache:
        _cache[queue] = time.time()
        return

    while time.time() - _cache[queue] < TIME_BETWEEN_REQUESTS:
        time.sleep(0.1)

    _cache[queue] = time.time()
