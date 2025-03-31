import logging
import sys
from types import TracebackType

log_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

_handler = logging.StreamHandler()
_handler.setLevel(logging.NOTSET)
_handler.setFormatter(log_formatter)

logger = logging.getLogger("langdon")
logger.setLevel(logging.CRITICAL)
logger.addHandler(_handler)


def new_excepthook(
    exc_type: type[Exception], exc_value: Exception, traceback: TracebackType
):
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, traceback))


sys.excepthook = new_excepthook
