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
)
from langdon.content_enumerators import google
from langdon.events import (
    DomainDiscovered,
    TechnologyDiscovered,
    WebDirectoryDiscovered,
)
from langdon.langdon_logging import logger
from langdon.models import Domain, IpAddress, IpDomainRel, PortIpRel, UsedPort
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from langdon.events import PortDiscovered
    from langdon.langdon_manager import LangdonManager


HTTP_PORTS = (80, 443)


def _dispatch_web_directory_discovered(
    urls: list[str],
    domain_name: Domain | None,
    ip_address: IpAddress | None,
    *,
    manager: LangdonManager,
) -> None:
    for url in urls:
        url_parsed = urllib.parse.urlparse(url)
        domain_name = url_parsed.netloc.split(":")[0]

        message_broker.dispatch_event(DomainDiscovered(name=domain_name))
        new_domain_query = sql.select(Domain).filter(Domain.name == domain_name)
        new_domain = manager.session.execute(new_domain_query).scalar_one_or_none()

        cleaned_path = url_parsed.path
        message_broker.dispatch_event(
            WebDirectoryDiscovered(
                path=cleaned_path,
                domain=new_domain,
                ip_address=ip_address,
                manager=manager,
            )
        )


def _enumerate_web_directories(
    event: PortDiscovered,
    *,
    domain: Domain | None = None,
    ip_address: IpAddress | None = None,
    manager: LangdonManager,
) -> None:
    cleaned_host_name = domain.name if domain else ip_address.address

    with shell_command_execution_context(
        CommandData(
            command="gau",
            args=f"--blacklist png,jpg,gif,ttf,woff --fp --json {cleaned_host_name}",
        ),
        manager=manager,
    ) as output:
        _dispatch_web_directory_discovered(
            output.splitlines(), cleaned_host_name, domain, ip_address, manager=manager
        )

    with function_execution_context(
        FunctionData(
            function=google.enumerate_directories,
            args=[cleaned_host_name],
            kwargs={"manager": manager},
        ),
        manager=manager,
    ) as output:
        _dispatch_web_directory_discovered(
            output, cleaned_host_name, domain, ip_address, manager=manager
        )

    throttler.wait_for_slot(f"throttle_{cleaned_host_name}")

    with tempfile.NamedTemporaryFile("w+", suffix=".csv") as temp_file, shell_command_execution_context(
        CommandData(
            command="wafw00f",
            args=f"-f csv -o {temp_file} -p socks5://localhost:9050 --no-colors "
            f"{'https' if event.port == 443 else 'http'}://{cleaned_host_name}",
        )
    ) as output:
        temp_file.seek(0)
        reader = csv.DictReader(temp_file)
        for row in reader:
            message_broker.dispatch_event(
                TechnologyDiscovered(
                    name=row["firewall"],
                    version=None,
                    domain=domain,
                    ip_address=ip_address,
                )
            )


def _process_http_port(event: PortDiscovered, *, manager: LangdonManager) -> None:
    def process_domains(domains):
        for domain in domains:
            message_broker.dispatch_event(
                WebDirectoryDiscovered(
                    path="/", domain=domain, manager=manager, uses_ssl=event.port == 443
                )
            )
            _enumerate_web_directories(event, domain=domain, manager=manager)

    def process_ip_address():
        message_broker.dispatch_event(
            WebDirectoryDiscovered(
                path="/", ip_address=event.ip_address, manager=manager, uses_ssl=False
            )
        )
        _enumerate_web_directories(event, ip_address=event.ip_address, manager=manager)

    domain_ids_subquery = (
        sql.select(IpDomainRel.domain_id)
        .where(IpDomainRel.ip_id == event.ip_address.id)
        .subquery()
    )
    query = sql.select(Domain).where(Domain.id.in_(domain_ids_subquery))
    domains = manager.session.scalars(query)

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
    with tempfile.NamedTemporaryFile() as temp_file, shell_command_execution_context(
        CommandData(
            command="nmap",
            args=f"-oX {temp_file.name} -sC -sU -sV -p {port_obj.port} "
            f"{event.ip_address}",
        ),
        manager=manager,
    ) as result:
        root = ET.parse(temp_file.name).getroot()
        technology = cast("str", root.find(".//service").get("product"))
        technology_re = re.compile(r"([^\s]+)[^\d]*(\d+\.\d+)")

        if re_match := technology_re.match(technology):
            name, version = re_match.groups()
        else:
            name = technology
            version = None

        message_broker.dispatch_event(
            TechnologyDiscovered(name=name, version=version, port=port_obj)
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
        is_filtered=event.is_filtered,
        manager=manager,
    )

    logger.info("Port discovered: %s", event.port) if not was_already_known else None

    query = (
        sql.select(UsedPort)
        .where(UsedPort.port == event.port)
        .where(UsedPort.transport_layer_protocol == event.transport_layer_protocol)
        .where(UsedPort.is_filtered == event.is_filtered)
    )
    port_obj = manager.session.execute(query).scalar_one()

    was_relation_already_known = create_if_not_exist(
        PortIpRel,
        port_id=port_obj.id,
        ip_address_id=event.ip_address.id,
        manager=manager,
    )
    logger.info(
        "Discovered relation between port %s and IP address %s",
        port_obj.port,
        event.ip_address.address,
    ) if not was_relation_already_known else None

    if not was_already_known:
        _process_found_port(port_obj, event, manager=manager)
