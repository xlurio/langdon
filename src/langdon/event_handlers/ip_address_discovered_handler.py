from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon import event_listener, task_queue, utils
from langdon.command_executor import (
    CommandData,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
)
from langdon.langdon_logging import logger
from langdon.langdon_manager import LangdonManager
from langdon.models import Domain, IpAddress, IpAddressId, IpDomainRel

if TYPE_CHECKING:
    from langdon.events import IpAddressDiscovered


def _process_nmap_output(
    output: str, *, ip_address: IpAddress, manager: LangdonManager
) -> None:
    root = ET.fromstring(output)
    ports = root.findall(".//port")

    if not ports:
        return logger.debug("No ports found in Nmap output.")

    for port in ports:
        state_data = port.find("state")
        port_number = int(port.attrib["portid"])

        if state_data.attrib["state"] == "closed":
            logger.debug("Port %d is closed. Skipping.", port_number)
            continue

        transport_layer_protocol = port.attrib["protocol"]
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
            utils.langdon_tempfile(
                f"langdon_nmap_udp_{ip_address.address}", suffix=".xml"
            ) as temp_file,
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
        utils.langdon_tempfile(
            f"langdon_nmap_tcp_{ip_address.address}", suffix=".xml"
        ) as temp_file,
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="nmap",
                args=f"-Pn --max-retries 3 --host-timeout 1h -sS -vv -p- -oX "
                f"'{temp_file.name}' '{ip_address.address}'",
            ),
            manager=manager,
        ),
    ):
        temp_file.seek(0)
        file_content = temp_file.read()
        logger.debug("Nmap XML:\n%s", file_content)
        _process_nmap_output(file_content, ip_address=ip_address, manager=manager)

    task_queue.submit_task(
        _enumerate_udp_ports,
        ip_address.id,
        manager=manager,
    )


def handle_event(event: IpAddressDiscovered, *, manager: LangdonManager) -> None:
    ip_version = utils.detect_ip_version(event.address)

    was_already_discovered = utils.create_if_not_exist(
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
        was_relation_already_known = utils.create_if_not_exist(
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
