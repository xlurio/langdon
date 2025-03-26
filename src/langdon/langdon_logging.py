import logging

_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

_handler = logging.StreamHandler()
_handler.setLevel(logging.DEBUG)
_handler.setFormatter(_formatter)


logger = logging.getLogger("langdon")
logger.setLevel(logging.CRITICAL)
logger.addHandler(_handler)
