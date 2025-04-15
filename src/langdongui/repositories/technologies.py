from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, sql

from langdon import models as langdon_models

if TYPE_CHECKING:
    from sqlalchemy.engine import ScalarResult
    from sqlalchemy.orm import Session


def count(*, session: Session) -> int:
    technologies_query = sql.select(func.count(langdon_models.Technology.id))
    technologies_count = session.execute(technologies_query).scalar_one()
    return technologies_count


def count_promissing_technologies(*, session: Session) -> int:
    technologies_query = sql.select(func.count(langdon_models.Technology.id)).where(
        langdon_models.Technology.version != None
    )
    technologies_count = session.execute(technologies_query).scalar_one()
    return technologies_count


def list_promissing_technologies(
    *, session: Session, offset: int | None = None, limit: int | None = None
) -> ScalarResult[langdon_models.Technology]:
    technologies_query = sql.select(langdon_models.Technology).where(
        langdon_models.Technology.version != None
    )

    if offset:
        technologies_query = technologies_query.offset(offset)
    if limit:
        technologies_query = technologies_query.limit(limit)

    return session.scalars(technologies_query)
