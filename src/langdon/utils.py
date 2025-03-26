from collections.abc import Mapping
from typing import Any

from sqlalchemy import sql

from langdon.langdon_manager import LangdonManager
from langdon.models import SqlAlchemyModel


def create_if_not_exist(
    model: type[SqlAlchemyModel],
    defaults: Mapping[str, Any] | None = None,
    *,
    manager: LangdonManager,
    **kwargs,
) -> bool:
    """Check if an instance of the given model exists with the given kwargs.
    If it doesn't, create a new instance with the given kwargs and the default values.
    Return True if a new instance was created, False otherwise
    """

    session = manager.session
    cleaned_defaults = defaults or {}
    query = sql.select(model)

    for key, value in kwargs.items():
        query = query.where(getattr(model, key) == value)

    if session.execute(query).scalar_one_or_none() is not None:
        return False

    session.add(model(**cleaned_defaults, **kwargs))
    session.commit()

    return True
