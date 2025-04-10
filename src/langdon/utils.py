from __future__ import annotations

import hashlib
import pathlib
from typing import IO, TYPE_CHECKING, Any

import pydantic
from sqlalchemy import sql

from langdon.langdon_logging import logger

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


class CreateBulkIfNotExistInput(pydantic.BaseModel):
    defaults: dict[str, Any] | None = None
    kwargs: dict[str, Any]


def bulk_create_if_not_exist(
    model: type[SqlAlchemyModel],
    dataset: list[CreateBulkIfNotExistInput],
    *,
    manager: LangdonManager,
) -> None:
    """Check if an instance of the given model exists with the given kwargs.
    If it doesn't, create a new instance with the given kwargs and the default values.
    """
    CHUNK_SIZE = 64

    for i in range(0, len(dataset), CHUNK_SIZE):
        chunk = dataset[i : i + CHUNK_SIZE]
        or_conditions = _build_or_conditions(model, chunk)
        existing_items = _fetch_existing_items(manager, model, or_conditions)
        new_items = _prepare_new_items(chunk, existing_items, model)

        if new_items:
            manager.session.add_all(new_items)
            manager.session.commit()
            logger.debug("Created %d new %s items", len(new_items), model.__name__)


def _build_or_conditions(
    model: type[SqlAlchemyModel], data: list[CreateBulkIfNotExistInput]
) -> list:
    or_conditions = []
    for item in data:
        and_conditions = [
            getattr(model, key) == value for key, value in item.kwargs.items()
        ]
        or_conditions.append(sql.and_(*and_conditions))
    return or_conditions


def _fetch_existing_items(
    manager: LangdonManager,
    model: type[SqlAlchemyModel],
    or_conditions: list[sql.ClauseElement],
) -> set[tuple[tuple[str, Any], ...]]:
    existing_items_query = sql.select(model).where(sql.or_(*or_conditions))
    existing_items: set[tuple[tuple[str, Any], ...]] = set()

    for item in manager.session.execute(existing_items_query).scalars():
        existing_item_as_list = [
            (key, value)
            for key, value in vars(item).items()
            if key != "_sa_instance_state"
        ]
        existing_items.add(tuple(existing_item_as_list))

    return existing_items


def _prepare_new_items(
    data: list[CreateBulkIfNotExistInput],
    existing_items: set,
    model: type[SqlAlchemyModel],
) -> list:
    return [
        model(
            **(item.defaults or {}),
            **item.kwargs,
        )
        for item in data
        if tuple(item.kwargs.items()) not in existing_items
    ]


def detect_ip_version(ip_address: str) -> IpAddressVersionT:
    if ":" in ip_address:
        return "ipv6"
    return "ipv4"


def langdon_tempfile(reference: str, mode: str = "w+", suffix: str = "") -> IO:
    """Create a temporary file with a specific reference and mode."""
    filename = hashlib.md5(reference.encode()).hexdigest()
    return pathlib.Path("/tmp").joinpath(f"{filename}{suffix}").open(mode=mode)
