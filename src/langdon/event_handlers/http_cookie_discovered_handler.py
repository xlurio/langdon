from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon.langdon_logging import logger
from langdon.models import DirCookieRel, HttpCookie
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from langdon.events import HttpCookieDiscovered
    from langdon.langdon_manager import LangdonManager


def handle_event(event: HttpCookieDiscovered, *, manager: LangdonManager) -> None:
    was_already_known = create_if_not_exist(
        HttpCookie,
        name=event.name,
        manager=manager,
    )

    if not was_already_known:
        logger.info("Discovered HTTP cookie %s", event.name)

    cookie_query = sql.select(HttpCookie).where(HttpCookie.name == event.name)
    cookie = manager.session.execute(cookie_query).scalar_one()

    was_already_related = create_if_not_exist(
        DirCookieRel,
        directory_id=event.web_directory.id,
        cookie_id=cookie.id,
        manager=manager,
    )

    if not was_already_related:
        logger.info(
            "Discovered relation between web directory %s and HTTP header %s",
            event.web_directory.path,
            event.name,
        )
