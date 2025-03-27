import logging

log_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

_handler = logging.StreamHandler()
_handler.setLevel(logging.NOTSET)
_handler.setFormatter(log_formatter)


logger = logging.getLogger("langdon")
logger.setLevel(logging.CRITICAL)
logger.addHandler(_handler)
