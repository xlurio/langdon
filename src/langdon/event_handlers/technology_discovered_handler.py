from __future__ import annotations

import json
from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon import event_listener
from langdon.command_executor import (
    CommandData,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
)
from langdon.langdon_logging import logger
from langdon.models import (
    PortTechRel,
    Technology,
    UsedPort,
    WebDirectory,
    WebDirTechRel,
)
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from langdon.events import TechnologyDiscovered
    from langdon.langdon_manager import LangdonManager


def _enumerate_vulnerabilities(
    technology: Technology, *, manager: LangdonManager
) -> None:
    if technology.version is None:
        return

    with (
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="searchsploit",
                args=f"{technology.name} {technology.version} --www --json",
            ),
            manager=manager,
        ) as output,
    ):
        output_parsed = json.loads(output)

        for entry in output_parsed["RESULTS_EXPLOIT"]:
            event_listener.send_event_message(
                manager.get_event_by_name("VulnerabilityDiscovered")(
                    name=entry["Title"], source=entry["URL"], technology=technology
                ),
                manager=manager,
            )


def handle_event(event: TechnologyDiscovered, *, manager: LangdonManager) -> None:
    _handle_technology_creation(event, manager)
    technology = _fetch_technology(event, manager)

    if event.directory_id is not None:
        _handle_directory_relation(event, technology, manager)

    if event.port_id is not None:
        _handle_port_relation(event, technology, manager)

    _enumerate_vulnerabilities(technology, manager=manager)


def _handle_technology_creation(
    event: TechnologyDiscovered, manager: LangdonManager
) -> bool:
    already_existed = create_if_not_exist(
        Technology,
        name=event.name,
        version=event.version,
        manager=manager,
    )

    if not already_existed:
        logger.info(
            "Technology discovered: %s%s", event.name, f" {event.version}" or ""
        )
    return already_existed


def _fetch_technology(
    event: TechnologyDiscovered, manager: LangdonManager
) -> Technology:
    session = manager.session
    query = (
        sql.select(Technology)
        .where(Technology.name == event.name)
        .where(Technology.version == event.version)
    )
    return session.execute(query).scalar_one()


def _handle_directory_relation(
    event: TechnologyDiscovered, technology: Technology, manager: LangdonManager
) -> None:
    was_dir_rel_already_known = create_if_not_exist(
        WebDirTechRel,
        directory_id=event.directory_id,
        technology_id=technology.id,
        manager=manager,
    )

    directory_query = sql.select(WebDirectory).where(
        WebDirectory.id == event.directory_id
    )
    directory = manager.session.execute(directory_query).scalar_one()

    if not was_dir_rel_already_known:
        logger.info(
            "Discovered relation between directory %s and technology %s",
            directory.path,
            technology.name,
        )


def _handle_port_relation(
    event: TechnologyDiscovered, technology: Technology, manager: LangdonManager
) -> None:
    was_port_rel_already_known = create_if_not_exist(
        PortTechRel,
        port_id=event.port_id,
        technology_id=technology.id,
        manager=manager,
    )

    port_query = sql.select(UsedPort).where(UsedPort.id == event.port_id)
    port_obj = manager.session.execute(port_query).scalar_one()

    if not was_port_rel_already_known:
        logger.info(
            "Discovered relation between port %s and technology %s",
            port_obj.port,
            technology.name,
        )
