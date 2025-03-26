from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING
from sqlalchemy import orm
import tomllib
import sqlalchemy

from langdon.models import SqlAlchemyModel

if TYPE_CHECKING:
    from types import TracebackType


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

    def __exit__(
        self, exc_type: type[Exception], exc_value: Exception, traceback: TracebackType
    ) -> None:
        self.__session.rollback()
        self.__session.close()
