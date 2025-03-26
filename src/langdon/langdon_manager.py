from __future__ import annotations

import contextlib
import sys
import tomllib
from typing import TYPE_CHECKING, TypeVar

import sqlalchemy
from sqlalchemy import orm

from langdon.exceptions import LangdonException
from langdon.models import SqlAlchemyModel
from langdon.output import OutputColor

if TYPE_CHECKING:
    from types import TracebackType

    from langdon.events import Event


_events_mapping = {}


T = TypeVar("T", bound="Event")


def register_event(event_cls: type[T]) -> type[T]:
    _events_mapping[event_cls.__name__] = event_cls


class LangdonManager(contextlib.AbstractContextManager):
    def __init__(self) -> None:
        self.__config = tomllib.load("pyproject.toml")
        self.__engine = sqlalchemy.create_engine(
            self.__config["tool.langdon"]["database"]
        )

    def __enter__(self):
        SqlAlchemyModel.metadata.create_all(self.__engine, checkfirst=True)
        self.__session = orm.Session()

    @property
    def session(self) -> orm.Session:
        return self.__session

    @property
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

        if exc_type is None:
            return

        if exc_type == LangdonException:
            print(f"{OutputColor.RED}Error: {exc_value!s}{OutputColor.RESET}")
            sys.exit(1)

        raise exc_value.with_traceback(traceback)
