from __future__ import annotations

import contextlib
import sys
import tomllib
from typing import TYPE_CHECKING, TypeVar

import sqlalchemy
from sqlalchemy import orm

from langdon.exceptions import LangdonException
from langdon.langdon_logging import logger
from langdon.models import SqlAlchemyModel
from langdon.output import OutputColor

if TYPE_CHECKING:
    from collections.abc import Mapping
    from types import TracebackType

    from langdon.events import Event
    from langdon.langdon_t import ConfigurationKeyT


T = TypeVar("T", bound="Event")
_events_mapping: Mapping[str, type[T]] = {}


def register_event(event_cls: type[T]) -> type[T]:
    _events_mapping[event_cls.__name__] = event_cls

    return event_cls


class LangdonManager(contextlib.AbstractContextManager):
    def __init__(self) -> None:
        with open("pyproject.toml", "rb") as pyproject_file:
            self.__config = tomllib.load(pyproject_file)["tool"]["langdon"]

        db_path = self.__config["database"]
        self.__engine = sqlalchemy.create_engine(
            f"sqlite:///{db_path}",
        )

    def __enter__(self) -> LangdonManager:
        SqlAlchemyModel.metadata.create_all(self.__engine, checkfirst=True)
        self.__session = orm.Session(self.__engine)

        return self

    def get_event_by_name(self, name: str) -> type[Event]:
        """Utility to avoid circular imports."""
        return _events_mapping[name]

    @property
    def session(self) -> orm.Session:
        return self.__session

    @property
    def config(self) -> dict[ConfigurationKeyT, str]:
        return self.__config

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
