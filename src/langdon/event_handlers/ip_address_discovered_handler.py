from __future__ import annotations

import xml.etree.ElementTree as ET
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon import message_broker
from langdon.command_executor import CommandData, shell_command_execution_context
from langdon.events import PortDiscovered
from langdon.models import IpAddress, IpDomainRel
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from langdon.events import IpAddressDiscovered
    from langdon.langdon_manager import LangdonManager
    from langdon.models import IpAddressVersionT


def _detect_ip_version(ip_address: str) -> IpAddressVersionT:
    if ":" in ip_address:
        return "ipv6"
    return "ipv4"


def _process_nmap_output(output: str, *, ip_address: IpAddress) -> None:
    root = ET.fromstring(output)
    ports = root.findall(".//port")

    for port in ports:
        if port.attrib["state"] == "closed":
            continue

        transport_layer_protocol = port.attrib["protocol"]
        port_number = int(port.attrib["portid"])
        is_filtered = port.attrib["state"] == "filtered"

        message_broker.dispatch_event(
            PortDiscovered(
                port=port_number,
                transport_layer_protocol=transport_layer_protocol,
                is_filtered=is_filtered,
                ip_address=ip_address,
            )
        )


def _enumerate_ports(ip_address: IpAddress, *, manager: LangdonManager) -> None:
    with NamedTemporaryFile("w+b", suffix=".xml") as temp_file:
        with shell_command_execution_context(
            CommandData(
                "nmap", f"-Pn -sS -oX '{temp_file.name}' '{ip_address.address}'"
            ),
            manager=manager,
        ) as result:
            temp_file.seek(0)
            _process_nmap_output(temp_file.read(), ip_address=ip_address)


def handle_event(event: IpAddressDiscovered, *, manager: LangdonManager) -> None:
    ip_version = _detect_ip_version(event.address)

    was_already_discovered = create_if_not_exist(
        IpAddress,
        address=event.address,
        defaults={"version": ip_version},
        manager=manager,
    )

    query = sql.select(IpAddress).where(IpAddress.address == event.address)
    ip_address = manager.session.execute(query).scalar_one()

    if event.domain is not None:
        create_if_not_exist(
            IpDomainRel,
            ip_id=ip_address.id,
            domain_id=event.domain.id,
            manager=manager,
        )

    if not was_already_discovered:
        _enumerate_ports(ip_address, manager=manager)
