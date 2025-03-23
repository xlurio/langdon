import time


_cache = {}
TIME_BETWEEN_REQUESTS = 5
TIME_BETWEEN_CHECKS = 1


def wait_for_slot(queue_name: str) -> None:
    if queue_name not in _cache:
        _cache[queue_name] = time.time()
    else:
        while time.time() - _cache[queue_name] < TIME_BETWEEN_REQUESTS:
            time.sleep(TIME_BETWEEN_CHECKS)
        _cache[queue_name] = time.time()
