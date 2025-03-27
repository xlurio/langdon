from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon import message_broker, throttler
from langdon.command_executor import CommandData, shell_command_execution_context
from langdon.events import IpAddressDiscovered
from langdon.models import Domain
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from langdon.events import DomainDiscovered
    from langdon.langdon_manager import LangdonManager


def _resolve_domain(domain: Domain, *, manager: LangdonManager) -> Domain:
    throttler.wait_for_slot(f"throttle_{domain.name}")

    with shell_command_execution_context(
        CommandData(command="host", args=domain.name), manager=manager
    ) as result:
        for line in result.splitlines():
            if "has address" in line:
                ip_address = line.split()[-1]
                message_broker.dispatch_event(
                    IpAddressDiscovered(address=ip_address, domain=domain),
                    manager=manager,
                )


def handle_event(event: DomainDiscovered, *, manager: LangdonManager) -> None:
    if not create_if_not_exist(
        Domain,
        name=event.name,
        manager=manager,
    ):
        return

    session = manager.session
    query = sql.select(Domain).filter(Domain.name == event.name)
    domain = session.execute(query).scalar_one()

    _resolve_domain(domain, manager=manager)
