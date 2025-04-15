from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, sql

from langdon import models as langdon_models

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def count(*, session: Session) -> int:
    android_apps_query = sql.select(func.count(langdon_models.AndroidApp.id))
    android_apps_count = session.execute(android_apps_query).scalar_one()
    return android_apps_count
