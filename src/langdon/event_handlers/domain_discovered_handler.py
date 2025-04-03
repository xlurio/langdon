from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon import event_listener
from langdon.command_executor import (
    CommandData,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
    suppress_timeout_expired_error,
)
from langdon.langdon_logging import logger
from langdon.models import Domain
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from langdon.events import DomainDiscovered
    from langdon.langdon_manager import LangdonManager


def _resolve_domain(domain: Domain, *, manager: LangdonManager) -> Domain:
    with (
        suppress_timeout_expired_error(),
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(command="host", args=domain.name), manager=manager, timeout=3600
        ) as result,
    ):
        for line in result.splitlines():
            if "has address" in line:
                ip_address = line.split()[-1]
                event_listener.send_event_message(
                    manager.get_event_by_name("IpAddressDiscovered")(
                        address=ip_address, domain_id=domain.id
                    ),
                    manager=manager,
                )


def handle_event(event: DomainDiscovered, *, manager: LangdonManager) -> None:
    was_already_known = create_if_not_exist(
        Domain,
        name=event.name,
        manager=manager,
    )

    if not was_already_known:
        logger.info("Domain discovered: %s", event.name)

    session = manager.session
    query = sql.select(Domain).filter(Domain.name == event.name)
    domain = session.execute(query).scalar_one()

    _resolve_domain(domain, manager=manager)
