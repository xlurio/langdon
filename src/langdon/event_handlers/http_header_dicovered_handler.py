from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon.langdon_logging import logger
from langdon.models import DirHeaderRel, HttpHeader
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from langdon.events import HttpHeaderDiscovered
    from langdon.langdon_manager import LangdonManager


def handle_event(event: HttpHeaderDiscovered, *, manager: LangdonManager) -> None:
    was_already_known = create_if_not_exist(
        HttpHeader,
        name=event.name,
        manager=manager,
    )

    if not was_already_known:
        logger.info("Discovered HTTP header %s", event.name)

    header_query = sql.select(HttpHeader).where(HttpHeader.name == event.name)
    header = manager.session.execute(header_query).scalar_one()

    was_already_related = create_if_not_exist(
        DirHeaderRel,
        directory_id=event.web_directory.id,
        header_id=header.id,
        manager=manager,
    )

    if not was_already_related:
        logger.info(
            "Discovered relation between web directory %s and HTTP header %s",
            event.web_directory.path,
            event.name,
        )
