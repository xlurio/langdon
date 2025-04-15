from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, orm, sql

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


def get_by_id(*, session: Session) -> langdon_models.Technology:
    technologies_query = (
        sql.select(langdon_models.Technology)
        .where(langdon_models.Technology.id == langdon_models.Technology.id)
        .options(orm.joinedload(langdon_models.Technology.port_relationships), orm.subqueryload(langdon_models.Technology.web_directory_relationships))
        .join(langdon_models.PortTechRel.port)
        .join(langdon_models.UsedPort.ip_address)
        .join(langdon_models.WebDirTechRel.directory)
        .join(langdon_models.WebDirectory.domain, outerjoin=True)
        .join(langdon_models.WebDirectory.ip_address, outerjoin=True)
    )
    return session.execute(technologies_query).scalar_one()


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
