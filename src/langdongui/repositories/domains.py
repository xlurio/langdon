from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, sql

from langdon import models as langdon_models

if TYPE_CHECKING:
    from sqlalchemy.engine import ScalarResult
    from sqlalchemy.orm import Session


__all__ = ("count", "list_promissing_domains")


PROMISSING_DOMAIN_NAME_KEYWORDS = ("admin", "api", "ftp", "cpanel", "dashboard")


def count(*, session: Session) -> int:
    domains_query = sql.select(func.count(langdon_models.Domain.id))
    domains_count = session.execute(domains_query).scalar_one()
    return domains_count


def count_promissing_domains(*, session: Session) -> int:
    or_clauses = [
        langdon_models.Domain.name.contains(interesting_keyword)
        for interesting_keyword in PROMISSING_DOMAIN_NAME_KEYWORDS
    ]
    domains_query = sql.select(func.count(langdon_models.Domain.id)).where(
        sql.or_(*or_clauses)
    )
    domains_count = session.execute(domains_query).scalar_one()
    return domains_count


def list_promissing_domains(
    *, session: Session, offset: int | None = None, limit: int | None = None
) -> ScalarResult[langdon_models.Domain]:
    ports_query = sql.select(langdon_models.UsedPort.ip_address_id)
    ip_rel_query = sql.select(langdon_models.IpDomainRel.domain_id).where(
        langdon_models.IpDomainRel.ip_id.in_(ports_query)
    )
    or_clauses = [
        langdon_models.Domain.name.contains(interesting_keyword)
        for interesting_keyword in PROMISSING_DOMAIN_NAME_KEYWORDS
    ]
    domains_query = (
        sql.select(langdon_models.Domain)
        .where(sql.or_(*or_clauses))
        .where(langdon_models.Domain.id.in_(ip_rel_query))
    )

    if offset:
        domains_query = domains_query.offset(offset)
    if limit:
        domains_query = domains_query.limit(limit)

    return session.scalars(domains_query)
