from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, sql

from langdon import models as langdon_models

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def count(*, session: Session) -> int:
    http_cookies_query = sql.select(func.count(langdon_models.HttpCookie.id))
    http_cookies_count = session.execute(http_cookies_query).scalar_one()
    return http_cookies_count
