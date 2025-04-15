from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, sql

from langdon import models as langdon_models

if TYPE_CHECKING:
    from sqlalchemy.engine import ScalarResult
    from sqlalchemy.orm import Session


def count(*, session: Session) -> int:
    vulnerabilities_query = sql.select(func.count(langdon_models.Vulnerability.id))
    vulnerabilities_count = session.execute(vulnerabilities_query).scalar_one()
    return vulnerabilities_count


def list_all(
    *, session: Session, offset: int | None = None, limit: int | None = None
) -> ScalarResult[langdon_models.Vulnerability]:
    vulnerabilities_query = sql.select(langdon_models.Vulnerability)

    if offset:
        vulnerabilities_query = vulnerabilities_query.offset(offset)
    if limit:
        vulnerabilities_query = vulnerabilities_query.limit(limit)

    return session.scalars(vulnerabilities_query)
