from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, sql

from langdon import models as langdon_models

if TYPE_CHECKING:
    from sqlalchemy.engine import ScalarResult
    from sqlalchemy.orm import Session

__all__ = ("count", "list_promissing_web_directories")


PROMISSING_DIRECTORY_NAME_KEYWORDS = ("admin", "api", "ftp", "cpanel", "dashboard")


def count(*, session: Session) -> int:
    web_directories_query = sql.select(func.count(langdon_models.WebDirectory.id))
    web_directories_count = session.execute(web_directories_query).scalar_one()
    return web_directories_count


def count_promissing_web_directories(*, session: Session) -> int:
    or_clauses = [
        langdon_models.WebDirectory.path.contains(interesting_keyword)
        for interesting_keyword in PROMISSING_DIRECTORY_NAME_KEYWORDS
    ]
    web_directories_query = sql.select(
        func.count(langdon_models.WebDirectory.id)
    ).where(sql.or_(*or_clauses))
    web_directories_count = session.execute(web_directories_query).scalar_one()
    return web_directories_count


def list_promissing_web_directories(
    *, session: Session, offset: int | None = None, limit: int | None = None
) -> ScalarResult[langdon_models.WebDirectory]:
    or_clauses = [
        langdon_models.WebDirectory.path.contains(interesting_keyword)
        for interesting_keyword in PROMISSING_DIRECTORY_NAME_KEYWORDS
    ]
    web_directories_query = (
        sql.select(langdon_models.WebDirectory)
        .join(langdon_models.WebDirectory.domain)
        .join(langdon_models.WebDirectory.ip_address)
        .where(sql.or_(*or_clauses))
    )

    if offset:
        web_directories_query.offset(offset)
    if limit:
        web_directories_query.limit(limit)

    return session.scalars(web_directories_query)
