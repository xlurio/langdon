from __future__ import annotations

import json
from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon import message_broker
from langdon.command_executor import CommandData, shell_command_execution_context
from langdon.events import VulnerabilityDiscovered
from langdon.models import (
    PortTechRel,
    Technology,
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

    with shell_command_execution_context(
        CommandData(
            command="searchsploit",
            args=f"{technology.name} {technology.version} --www --json",
        ),
        manager=manager,
    ) as output:
        output_parsed = json.loads(output)

        for entry in output_parsed["RESULTS_EXPLOIT"]:
            message_broker.dispatch_event(
                VulnerabilityDiscovered(
                    name=entry["Title"], source=entry["URL"], technology=technology
                )
            )


def handle_event(event: TechnologyDiscovered, *, manager: LangdonManager) -> None:
    already_existed = create_if_not_exist(
        Technology,
        name=event.name,
        version=event.version,
        manager=manager,
    )

    session = manager.session
    query = (
        sql.select(Technology)
        .where(Technology.name == event.name)
        .where(Technology.version == event.version)
    )
    technology = session.execute(query).scalar_one()

    if event.directory is not None:
        create_if_not_exist(
            WebDirTechRel,
            directory_id=event.directory.id,
            technology_id=technology.id,
            manager=manager,
        )

    if event.port is not None:
        create_if_not_exist(
            PortTechRel,
            port_id=event.port.id,
            technology_id=technology.id,
            manager=manager,
        )

    if not already_existed:
        _enumerate_vulnerabilities(technology, manager=manager)
