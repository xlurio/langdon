from __future__ import annotations

import concurrent.futures as CF
import contextlib
import os
import sys
import threading
import tomllib
from typing import TYPE_CHECKING, TypeVar

import sqlalchemy
from sqlalchemy import orm

from langdon.exceptions import AlreadyInChildThread, LangdonException
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
        self.__thread_executor = None

    def __enter__(self) -> LangdonManager:
        SqlAlchemyModel.metadata.create_all(self.__engine, checkfirst=True)
        self.__session = orm.Session(self.__engine)

        if threading.current_thread() == threading.main_thread():
            self.__thread_executor = CF.ThreadPoolExecutor(os.cpu_count() or 1)

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

    @property
    def thread_executor(self) -> CF.ThreadPoolExecutor:
        if self.__thread_executor is None:
            raise AlreadyInChildThread(
                "Creating a thread in a child thread is not allowed."
            )

        return self.__thread_executor

    def __exit__(
        self,
        exc_type: type[Exception] | None,
        exc_value: Exception | None,
        traceback: TracebackType,
    ) -> None:
        self.__session.rollback()
        self.__session.close()

        if self.__thread_executor:
            self.__thread_executor.shutdown(wait=True)

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

        elif exc_type == KeyboardInterrupt:
            print(f"Exiting...")
            sys.exit(0)

        raise exc_value.with_traceback(traceback)
