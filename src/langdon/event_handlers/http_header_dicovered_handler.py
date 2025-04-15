from __future__ import annotations

from typing import TYPE_CHECKING

from langdon_core.langdon_logging import logger
from langdon_core.models import DirHeaderRel, HttpHeader, WebDirectory
from sqlalchemy import sql

from langdon import utils

if TYPE_CHECKING:
    from langdon.events import HttpHeaderDiscovered
    from langdon.langdon_manager import LangdonManager


def handle_event(event: HttpHeaderDiscovered, *, manager: LangdonManager) -> None:
    was_already_known = utils.create_if_not_exist(
        HttpHeader,
        name=event.name,
        manager=manager,
    )

    if not was_already_known:
        logger.info("Discovered HTTP header %s", event.name)

    header_query = sql.select(HttpHeader).where(HttpHeader.name == event.name)
    header = manager.session.execute(header_query).scalar_one()

    was_already_related = utils.create_if_not_exist(
        DirHeaderRel,
        directory_id=event.web_directory_id,
        header_id=header.id,
        manager=manager,
    )

    web_directory_query = sql.select(WebDirectory).where(
        WebDirectory.id == event.web_directory_id
    )
    web_directory = manager.session.execute(web_directory_query).scalar_one()

    if not was_already_related:
        logger.info(
            "Discovered relation between web directory %s and HTTP header %s",
            web_directory.path,
            event.name,
        )
