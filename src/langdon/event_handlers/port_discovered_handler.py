from __future__ import annotations

import csv
import re
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING, cast

from sqlalchemy import sql

from langdon import message_broker, throttler
from langdon.command_executor import (
    CommandData,
    FunctionData,
    function_execution_context,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
)
from langdon.content_enumerators import google
from langdon.langdon_logging import logger
from langdon.models import Domain, IpAddress, IpDomainRel, UsedPort
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from langdon.events import PortDiscovered
    from langdon.langdon_manager import LangdonManager


HTTP_PORTS = (80, 443)


def _dispatch_web_directory_discovered(
    event: PortDiscovered,
    urls: list[str],
    domain_name: Domain | None,
    ip_address: IpAddress | None,
    *,
    manager: LangdonManager,
) -> None:
    for url in urls:
        url_parsed = urllib.parse.urlparse(url)

        if not url_parsed.netloc:
            return

        domain_name = url_parsed.netloc.split(":")[0]

        message_broker.dispatch_event(
            manager.get_event_by_name("DomainDiscovered")(name=domain_name),
            manager=manager,
        )
        new_domain_query = sql.select(Domain).filter(Domain.name == domain_name)
        new_domain = manager.session.execute(new_domain_query).scalar_one_or_none()

        cleaned_path = url_parsed.path
        message_broker.dispatch_event(
            manager.get_event_by_name("WebDirectoryDiscovered")(
                path=cleaned_path,
                domain=new_domain,
                ip_address=ip_address,
                uses_ssl=event.port == 443,
            ),
            manager=manager,
        )


def _enumerate_web_directories(
    event: PortDiscovered,
    *,
    domain: Domain | None = None,
    ip_address: IpAddress | None = None,
    manager: LangdonManager,
) -> None:
    cleaned_host_name = domain.name if domain else ip_address.address

    with (
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="gau",
                args="--blacklist png,jpg,gif,ttf,woff --fp "
                f"--proxy socks5://localhost:9050 {cleaned_host_name}",
            ),
            manager=manager,
        ) as output,
    ):
        _dispatch_web_directory_discovered(
            event, output.splitlines(), domain, ip_address, manager=manager
        )

    with (
        suppress_duplicated_recon_process(),
        function_execution_context(
            FunctionData(
                function=google.enumerate_directories,
                args=[cleaned_host_name],
                kwargs={"manager": manager},
            ),
            manager=manager,
        ) as output,
    ):
        _dispatch_web_directory_discovered(
            output, cleaned_host_name, domain, ip_address, manager=manager
        )

    throttler.wait_for_slot(f"throttle_{cleaned_host_name}", manager=manager)

    with (
        tempfile.NamedTemporaryFile("w+", suffix=".csv") as temp_file,
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="wafw00f",
                args=f"-f csv -o {temp_file.name} -p socks5://localhost:9050 --no-colors "
                f"{'https' if event.port == 443 else 'http'}://{cleaned_host_name}",
            ),
            manager=manager,
        ) as output,
    ):
        temp_file.seek(0)
        logger.debug("Wafw00f CSV: %s", temp_file.read())
        temp_file.seek(0)
        reader = csv.DictReader(temp_file)
        for row in reader:
            message_broker.dispatch_event(
                manager.get_event_by_name("TechnologyDiscovered")(
                    name=row["firewall"],
                    version=None,
                    domain=domain,
                    ip_address=ip_address,
                ),
                manager=manager,
            )


def _process_http_port(event: PortDiscovered, *, manager: LangdonManager) -> None:
    def process_domains(domains):
        for domain in domains:
            message_broker.dispatch_event(
                manager.get_event_by_name("WebDirectoryDiscovered")(
                    path="/", domain=domain, manager=manager, uses_ssl=event.port == 443
                ),
                manager=manager,
            )
            _enumerate_web_directories(event, domain=domain, manager=manager)

    def process_ip_address():
        message_broker.dispatch_event(
            manager.get_event_by_name("WebDirectoryDiscovered")(
                path="/", ip_address=event.ip_address, manager=manager, uses_ssl=False
            ),
            manager=manager,
        )
        _enumerate_web_directories(event, ip_address=event.ip_address, manager=manager)

    domain_ids_subquery = sql.select(IpDomainRel.domain_id).where(
        IpDomainRel.ip_id == event.ip_address.id
    )
    query = sql.select(Domain).where(Domain.id.in_(domain_ids_subquery))
    domains = manager.session.scalars(query).all()

    if domains:
        process_domains(domains)
    elif event.port == 80:
        process_ip_address()
    else:
        logger.error(
            f"No domain found for IP address {event.ip_address}. Unable to enumerate "
            "web content in port 443."
        )


def _process_other_ports(
    port_obj: UsedPort, event: PortDiscovered, *, manager: LangdonManager
) -> None:
    with (
        tempfile.NamedTemporaryFile() as temp_file,
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="nmap",
                args=f"--host-timeout 1h -oX {temp_file.name} -sC -sU -sV -p "
                f"{port_obj.port} {event.ip_address}",
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

            message_broker.dispatch_event(
                manager.get_event_by_name("TechnologyDiscovered")(
                    name=name, version=version, port=port_obj
                ),
                manager=manager,
            )


def _process_found_port(
    port_obj: UsedPort, event: PortDiscovered, *, manager: LangdonManager
) -> None:
    is_http = (event.port in HTTP_PORTS) and (event.transport_layer_protocol == "tcp")

    if is_http:
        return _process_http_port(event, manager=manager)

    return _process_other_ports(port_obj, event, manager=manager)


def handle_event(event: PortDiscovered, *, manager: LangdonManager) -> None:
    was_already_known = create_if_not_exist(
        UsedPort,
        port=event.port,
        transport_layer_protocol=event.transport_layer_protocol,
        ip_address_id=event.ip_address.id,
        defaults={"is_filtered": event.is_filtered},
        manager=manager,
    )

    logger.info(
        "Port discovered at IP %s: %s", event.ip_address.address, event.port
    ) if not was_already_known else None

    query = (
        sql.select(UsedPort)
        .where(UsedPort.ip_address_id == event.ip_address.id)
        .where(UsedPort.port == event.port)
        .where(UsedPort.transport_layer_protocol == event.transport_layer_protocol)
    )
    port_obj = manager.session.execute(query).scalar_one()

    if not port_obj.is_filtered:
        _process_found_port(port_obj, event, manager=manager)
    else:
        logger.debug(
            "Port %s on IP %s is filtered. Skipping further processing.",
            event.port,
            event.ip_address.address,
        )
