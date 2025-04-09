from __future__ import annotations

import csv
import re
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, cast

from sqlalchemy import sql

from langdon import event_listener, throttler
from langdon.command_executor import (
    CommandData,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
)
from langdon.langdon_logging import logger
from langdon.models import Domain, IpAddress, IpDomainRel, UsedPort
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from collections.abc import Sequence

    from langdon.events import PortDiscovered
    from langdon.langdon_manager import LangdonManager


HTTP_PORTS = (80, 443)


def _enumerate_web_directories(
    port_obj: UsedPort,
    *,
    domain: Domain | None = None,
    ip_address: IpAddress | None = None,
    manager: LangdonManager,
) -> None:
    cleaned_host_name = domain.name if domain else ip_address.address
    proxy = urllib.parse.urlunparse(
        (
            "socks5",
            f"{manager.config['socks_proxy_host']}:"
            f"{manager.config['socks_proxy_port']}",
            "",
            "",
            "",
            "",
        )
    )

    throttler.wait_for_slot(f"throttle_{cleaned_host_name}", manager=manager)

    with (
        tempfile.NamedTemporaryFile("w+", suffix=".csv") as temp_file,
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="wafw00f",
                args=f"-f csv -o {temp_file.name} -p {proxy} --no-colors "
                f"{'https' if port_obj.port == 443 else 'http'}://{cleaned_host_name}",
            ),
            manager=manager,
        ) as output,
    ):
        temp_file.seek(0)
        logger.debug("Wafw00f CSV: %s", temp_file.read())
        temp_file.seek(0)
        reader = csv.DictReader(temp_file)
        for row in reader:
            if row["firewall"] == "None":
                continue

            event_listener.send_event_message(
                manager.get_event_by_name("TechnologyDiscovered")(
                    name=row["firewall"],
                    version=None,
                    domain_id=domain.id if domain else None,
                    port_id=port_obj.id,
                ),
                manager=manager,
            )

    # TODO discover directories from getJS


def _process_http_port(
    port_obj: UsedPort, ip_address_obj: IpAddress, *, manager: LangdonManager
) -> None:
    def process_domains(domains: Sequence[Domain]):
        for domain in domains:
            event_listener.send_event_message(
                manager.get_event_by_name("WebDirectoryDiscovered")(
                    path="/",
                    domain_id=domain.id,
                    manager=manager,
                    uses_ssl=port_obj.port == 443,
                ),
                manager=manager,
            )
            _enumerate_web_directories(port_obj, domain=domain, manager=manager)

    def process_ip_address():
        event_listener.send_event_message(
            manager.get_event_by_name("WebDirectoryDiscovered")(
                path="/",
                ip_address_id=port_obj.ip_address_id,
                manager=manager,
                uses_ssl=False,
            ),
            manager=manager,
        )
        _enumerate_web_directories(port_obj, ip_address=ip_address_obj, manager=manager)

    domain_ids_subquery = sql.select(IpDomainRel.domain_id).where(
        IpDomainRel.ip_id == port_obj.ip_address_id
    )
    query = sql.select(Domain).where(Domain.id.in_(domain_ids_subquery))
    domains = manager.session.scalars(query).all()

    if domains:
        process_domains(domains)
    elif port_obj.port == 80:
        process_ip_address()
    else:
        logger.error(
            f"No domain found for IP address {ip_address_obj.address}. Unable to enumerate "
            "web content in port 443."
        )


def _process_other_ports(
    port_obj: UsedPort, ip_address_obj: IpAddress, *, manager: LangdonManager
) -> None:
    with (
        tempfile.NamedTemporaryFile() as temp_file,
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="nmap",
                args=f"--host-timeout 1h -oX {temp_file.name} -sC -sU -sV -p "
                f"{port_obj.port} {ip_address_obj.address}",
            ),
            manager=manager,
        ),
    ):
        temp_file.seek(0)
        logger.debug("Nmap XML: %s", temp_file.read())
        temp_file.seek(0)

        root = ET.parse(temp_file.name).getroot()

        if service_data := root.find(".//service"):
            technology = cast("str", service_data.get("product"))
            technology_re = re.compile(r"([^\s]+)[^\d]*(\d+\.\d+)")

            if re_match := technology_re.match(technology):
                name, version = re_match.groups()
            else:
                name = technology
                version = None

            event_listener.send_event_message(
                manager.get_event_by_name("TechnologyDiscovered")(
                    name=name, version=version, port_id=port_obj.id
                ),
                manager=manager,
            )


def _process_found_port(
    port_obj: UsedPort, ip_address_obj: IpAddress, *, manager: LangdonManager
) -> None:
    is_http = (port_obj.port in HTTP_PORTS) and (
        port_obj.transport_layer_protocol == "tcp"
    )

    if is_http:
        return _process_http_port(port_obj, ip_address_obj, manager=manager)

    return _process_other_ports(port_obj, ip_address_obj, manager=manager)


def handle_event(event: PortDiscovered, *, manager: LangdonManager) -> None:
    was_already_known = create_if_not_exist(
        UsedPort,
        port=event.port,
        transport_layer_protocol=event.transport_layer_protocol,
        ip_address_id=event.ip_address_id,
        defaults={"is_filtered": event.is_filtered},
        manager=manager,
    )
    ip_address_query = sql.select(IpAddress).where(IpAddress.id == event.ip_address_id)
    ip_address_obj = manager.session.execute(ip_address_query).scalar_one_or_none()

    logger.info(
        "Port discovered at IP %s: %s", ip_address_obj.address, event.port
    ) if not was_already_known else None

    query = (
        sql.select(UsedPort)
        .where(UsedPort.ip_address_id == event.ip_address_id)
        .where(UsedPort.port == event.port)
        .where(UsedPort.transport_layer_protocol == event.transport_layer_protocol)
    )
    port_obj = manager.session.execute(query).scalar_one()

    if not port_obj.is_filtered:
        _process_found_port(port_obj, ip_address_obj, manager=manager)
    else:
        logger.debug(
            "Port %s on IP %s is filtered. Skipping further processing.",
            event.port,
            ip_address_obj.address,
        )
