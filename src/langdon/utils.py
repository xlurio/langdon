from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import sql

if TYPE_CHECKING:
    from collections.abc import Mapping

    from langdon.langdon_manager import LangdonManager
    from langdon.models import IpAddressVersionT, SqlAlchemyModel


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


def detect_ip_version(ip_address: str) -> IpAddressVersionT:
    if ":" in ip_address:
        return "ipv6"
    return "ipv4"
