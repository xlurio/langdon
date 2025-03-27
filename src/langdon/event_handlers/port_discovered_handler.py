from __future__ import annotations  # noqa: I001

from typing import TYPE_CHECKING

from langdon import message_broker
from langdon.command_executor import (
    CommandData,
    FunctionData,
    function_execution_context,
    shell_command_execution_context,
)
from langdon.content_enumerators import google
from langdon.events import WebDirectoryDiscovered
from langdon.models import Domain, IpDomainRel, PortIpRel, UsedPort
from langdon.utils import create_if_not_exist
from sqlalchemy import sql

if TYPE_CHECKING:
    from langdon.events import PortDiscovered
    from langdon.langdon_manager import LangdonManager


HTTP_PORTS = (80, 443)


def _enumerate_web_directories_for_domain(
    domain: Domain, *, manager: LangdonManager
) -> None:
    with shell_command_execution_context(
        CommandData(
            command="gau",
            args=f"--blacklist png,jpg,gif,ttf,woff --fp --json {domain.name}",
        ),
        manager=manager,
    ) as output:
        for url in output.splitlines():
            cleaned_path = url.replace(domain.name, "", 1).strip()

            message_broker.dispatch_event(
                WebDirectoryDiscovered(
                    path=cleaned_path, domain=domain, manager=manager
                )
            )

    with function_execution_context(
        FunctionData(
            function=google.enumerate_directories,
            args=[domain.name],
            kwargs={"manager": manager},
        )
    ) as output:
        raise NotImplementedError("TODO")


def _process_http_port(event: PortDiscovered, *, manager: LangdonManager) -> None:
    domain_ids_subquery = (
        sql.select(IpDomainRel.domain_id)
        .where(IpDomainRel.ip_id == event.ip_address.id)
        .subquery()
    )
    query = sql.select(Domain).where(Domain.id.in_(domain_ids_subquery))
    domains = manager.session.scalars(query)

    if domains:
        for domain in manager.session.scalars(query):
            message_broker.dispatch_event(
                WebDirectoryDiscovered(path="/", domain=domain, manager=manager)
            )
            _enumerate_web_directories_for_domain(domain, manager=manager)

    else:
        message_broker.dispatch_event(
            WebDirectoryDiscovered(
                path="/", ip_address=event.ip_address, manager=manager
            )
        )


def _process_found_port(event: PortDiscovered, *, manager: LangdonManager) -> None:
    is_http = (event.port in HTTP_PORTS) and (event.transport_layer_protocol == "tcp")

    if is_http:
        _process_http_port(event, manager=manager)


def handle_event(event: PortDiscovered, *, manager: LangdonManager) -> None:
    already_existed = create_if_not_exist(
        UsedPort,
        port=event.port,
        transport_layer_protocol=event.transport_layer_protocol,
        is_filtered=event.is_filtered,
        manager=manager,
    )
    query = (
        sql.select(UsedPort)
        .where(UsedPort.port == event.port)
        .where(UsedPort.transport_layer_protocol == event.transport_layer_protocol)
        .where(UsedPort.is_filtered == event.is_filtered)
    )
    port_obj = manager.session.execute(query).scalar_one()

    create_if_not_exist(
        PortIpRel,
        port_id=port_obj.id,
        ip_address_id=event.ip_address.id,
        manager=manager,
    )

    if not already_existed:
        _process_found_port(event, manager=manager)
