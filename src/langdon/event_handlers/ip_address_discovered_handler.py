from __future__ import annotations

import xml.etree.ElementTree as ET
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon import event_listener, task_queue
from langdon.command_executor import (
    CommandData,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
)
from langdon.exceptions import AlreadyInChildThread
from langdon.langdon_logging import logger
from langdon.langdon_manager import LangdonManager
from langdon.models import Domain, IpAddress, IpAddressId, IpDomainRel
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from langdon.events import IpAddressDiscovered
    from langdon.models import IpAddressVersionT


def _detect_ip_version(ip_address: str) -> IpAddressVersionT:
    if ":" in ip_address:
        return "ipv6"
    return "ipv4"


def _process_nmap_output(
    output: str, *, ip_address: IpAddress, manager: LangdonManager
) -> None:
    root = ET.fromstring(output)
    ports = root.findall(".//port")

    for port in ports:
        state_data = port.find("state")

        if state_data.attrib["state"] == "closed":
            continue

        transport_layer_protocol = port.attrib["protocol"]
        port_number = int(port.attrib["portid"])
        is_filtered = state_data.attrib["state"] == "filtered"

        event_listener.send_event_message(
            manager.get_event_by_name("PortDiscovered")(
                port=port_number,
                transport_layer_protocol=transport_layer_protocol,
                is_filtered=is_filtered,
                ip_address_id=ip_address.id,
            ),
            manager=manager,
        )


def _enumerate_udp_ports(ip_address_id: IpAddressId) -> None:
    with LangdonManager() as manager:
        ip_address_query = sql.select(IpAddress).where(IpAddress.id == ip_address_id)
        ip_address = manager.session.execute(ip_address_query).scalar_one()

        with (
            NamedTemporaryFile("w+b", suffix=".xml") as temp_file,
            suppress_duplicated_recon_process(),
            shell_command_execution_context(
                CommandData(
                    command="nmap",
                    args=f"-Pn -sU -vv -oX '{temp_file.name}' '{ip_address.address}'",
                ),
                manager=manager,
            ),
        ):
            temp_file.seek(0)
            file_content = temp_file.read()
            logger.debug("Nmap XML:\n%s", file_content)
            _process_nmap_output(file_content, ip_address=ip_address, manager=manager)


def _process_ip_address(ip_address: IpAddress, *, manager: LangdonManager) -> None:
    with (
        NamedTemporaryFile("w+b", suffix=".xml") as temp_file,
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="nmap",
                args=f"-Pn -sS -vv -oX '{temp_file.name}' '{ip_address.address}'",
            ),
            manager=manager,
        ),
    ):
        temp_file.seek(0)
        file_content = temp_file.read()
        logger.debug("Nmap XML:\n%s", file_content)
        _process_nmap_output(file_content, ip_address=ip_address, manager=manager)

    try:
        task_queue.submit_task(
            _enumerate_udp_ports,
            ip_address.id,
            manager=manager,
        )
    except AlreadyInChildThread:
        logger.debug("Enumerating UDP ports synchronously. Already in child process.")
        _enumerate_udp_ports(ip_address, manager=manager)


def handle_event(event: IpAddressDiscovered, *, manager: LangdonManager) -> None:
    ip_version = _detect_ip_version(event.address)

    was_already_discovered = create_if_not_exist(
        IpAddress,
        address=event.address,
        defaults={"version": ip_version},
        manager=manager,
    )

    logger.info(
        "IP address discovered: %s", event.address
    ) if not was_already_discovered else None

    query = sql.select(IpAddress).where(IpAddress.address == event.address)
    ip_address = manager.session.execute(query).scalar_one()

    if event.domain_id is not None:
        was_relation_already_known = create_if_not_exist(
            IpDomainRel,
            ip_id=ip_address.id,
            domain_id=event.domain_id,
            manager=manager,
        )
        domain_query = sql.select(Domain).where(Domain.id == event.domain_id)
        domain = manager.session.execute(domain_query).scalar_one()

        logger.info(
            "Discovered relation between IP address %s and domain %s",
            ip_address.address,
            domain.name,
        ) if not was_relation_already_known else None

    _process_ip_address(ip_address, manager=manager)
