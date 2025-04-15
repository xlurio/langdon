from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, sql

from langdon import models as langdon_models

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def count(*, session: Session) -> int:
    http_headers_query = sql.select(func.count(langdon_models.HttpHeader.id))
    http_headers_count = session.execute(http_headers_query).scalar_one()
    return http_headers_count
