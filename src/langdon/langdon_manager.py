from __future__ import annotations

import sys
from typing import TYPE_CHECKING, TypeVar

from langdon_core.langdon_logging import logger
from langdon_core.langdon_manager import LangdonManager as LangdonCoreManager

from langdon.exceptions import LangdonException
from langdon.output import OutputColor

if TYPE_CHECKING:
    from collections.abc import Mapping
    from types import TracebackType

    from langdon.events import Event


T = TypeVar("T", bound="Event")
_events_mapping: Mapping[str, type[T]] = {}


def register_event(event_cls: type[T]) -> type[T]:
    _events_mapping[event_cls.__name__] = event_cls

    return event_cls


class LangdonManager(LangdonCoreManager):
    def get_event_by_name(self, name: str) -> type[Event]:
        """Utility to avoid circular imports."""
        return _events_mapping[name]

    def __exit__(
        self,
        exc_type: type[Exception] | None,
        exc_value: Exception | None,
        traceback: TracebackType,
    ) -> None:
        self.__session.rollback()
        self.__session.close()

        if exc_type is not None:
            self._handle_exception(exc_type, exc_value, traceback)

    def _handle_exception(
        self,
        exc_type: type[Exception],
        exc_value: Exception,
        traceback: TracebackType,
    ) -> None:
        if exc_type == LangdonException:
            logger.debug("Error while running Langdon", exc_info=True)
            print(f"{OutputColor.RED}Error: {exc_value!s}{OutputColor.RESET}")
            sys.exit(1)

        elif exc_type is KeyboardInterrupt:
            print("Exiting...")
            sys.exit(0)

        logger.debug("Unhandled exception while running Langdon", exc_info=True)
        raise exc_value.with_traceback(traceback)
