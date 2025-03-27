import time

_cache = {}


def wait_for_slot(queue: str):
    if queue not in _cache:
        _cache[queue] = time.time()
        return

    while time.time() - _cache[queue] < 1:
        time.sleep(0.1)

    _cache[queue] = time.time()
