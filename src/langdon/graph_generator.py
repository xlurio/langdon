from __future__ import annotations

import argparse
import random
import re
import urllib.parse
from typing import TYPE_CHECKING

import graphviz
from sqlalchemy import sql

from langdon.langdon_logging import logger
from langdon.models import (
    DirCookieRel,
    DirHeaderRel,
    Domain,
    HttpCookie,
    HttpHeader,
    IpAddress,
    IpDomainRel,
    PortTechRel,
    Technology,
    UsedPort,
    Vulnerability,
    WebDirectory,
    WebDirTechRel,
)

if TYPE_CHECKING:
    from pathlib import Path

    from langdon.langdon_manager import LangdonManager


class GraphGeneratorNamespace(argparse.Namespace):
    output: Path


def _generate_random_color() -> str:
    return f"{random.random():.3f} 1.000 1.000"


NODE_COLORS = {}


def _get_node_color(node_id: str) -> str:
    if node_id not in NODE_COLORS:
        NODE_COLORS[node_id] = _generate_random_color()
    return NODE_COLORS[node_id]


def generate_graph(
    parsed_args: GraphGeneratorNamespace, *, manager: LangdonManager
) -> None:
    """
    Generate a graph of the known assets using the Graphviz library.
    """
    dot = graphviz.Digraph(
        name="langdon_graph",
        engine="sfdp",
        strict=True,
        graph_attr={"dpi": 70, "overlap": "false", "size": 24, "splines": "true"},
    )

    add_domains(dot, manager)
    add_ip_addresses(dot, manager)
    add_ip_domain_relationships(dot, manager)
    add_web_directories(dot, manager)
    add_http_headers(dot, manager)
    add_dir_header_relationships(dot, manager)
    add_http_cookies(dot, manager)
    add_dir_cookie_relationships(dot, manager)
    add_used_ports(dot, manager)
    add_technologies(dot, manager)
    add_vulnerabilities(dot, manager)
    add_web_dir_tech_relationships(dot, manager)
    add_port_tech_relationships(dot, manager)

    logger.info("Rendering the graph.")
    dot.render(
        parsed_args.output.with_suffix(""),
        format=parsed_args.output.suffix.replace(".", ""),
        cleanup=True,
    )


def _make_web_directory_node_name(directory: WebDirectory) -> str:
    schema = "https" if directory.uses_ssl else "http"
    cleaned_hostname = (
        directory.domain.name if directory.domain else directory.ip_address.address
    )
    cleaned_directory_path = directory.path.lstrip("/")
    parsed_url = urllib.parse.urlunparse(
        (
            schema,
            cleaned_hostname,
            cleaned_directory_path,
            "",
            "",
            "",
        )
    )

    return re.sub(r"[^a-zA-Z0-9]", "_", parsed_url)


def add_domains(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    logger.info("Adding domains to the graph.")
    port_query = sql.select(UsedPort.ip_address_id)
    ip_address_domain_rel_query = sql.select(IpDomainRel.domain_id).where(
        IpDomainRel.id.in_(port_query)
    )

    directories_query = sql.select(WebDirectory.domain_id).where(
        WebDirectory.domain_id != None
    )

    domains_query = sql.select(Domain).where(
        sql.or_(
            Domain.id.in_(ip_address_domain_rel_query), Domain.id.in_(directories_query)
        )
    )
    for domain in manager.session.scalars(domains_query):
        color = _get_node_color(domain.name)
        dot.node(domain.name, shape="box", color=color, fontcolor=color)


def add_ip_addresses(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    logger.info("Adding IP addresses to the graph.")
    port_query = sql.select(UsedPort.ip_address_id)
    ip_address_query = sql.select(IpAddress).where(IpAddress.id.in_(port_query))
    for ip_address in manager.session.scalars(ip_address_query):
        color = _get_node_color(ip_address.address)
        dot.node(
            ip_address.address,
            label=ip_address.address,
            shape="ellipse",
            color=color,
            fontcolor=color,
        )


def add_ip_domain_relationships(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    logger.info("Adding IP-domain relationships to the graph.")
    ip_address_domain_rel_query = (
        sql.select(IpDomainRel).join(IpDomainRel.domain).join(IpDomainRel.ip_address)
    )
    for ip_domain_rel in manager.session.scalars(ip_address_domain_rel_query):
        color = _get_node_color(ip_domain_rel.domain.name)
        dot.edge(
            ip_domain_rel.domain.name, ip_domain_rel.ip_address.address, color=color
        )


def add_web_directories(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    logger.info("Adding web directories to the graph.")
    web_directories_query = (
        sql.select(WebDirectory)
        .join(WebDirectory.domain, isouter=True)
        .join(WebDirectory.ip_address, isouter=True)
    )

    for web_directory in manager.session.scalars(web_directories_query):
        node_name = _make_web_directory_node_name(web_directory)
        dir_color = _get_node_color(node_name)
        dot.node(node_name, shape="note", color=dir_color, fontcolor=dir_color)

        if web_directory.domain:
            domain_color = _get_node_color(web_directory.domain.name)
            dot.edge(web_directory.domain.name, node_name, color=domain_color)
        else:
            ip_color = _get_node_color(web_directory.ip_address.address)
            dot.edge(web_directory.ip_address.address, node_name, color=ip_color)


def add_http_headers(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    logger.info("Adding HTTP headers to the graph.")
    http_headers_query = sql.select(HttpHeader)
    for http_header in manager.session.scalars(http_headers_query):
        dot.node(http_header.name, shape="parallelogram")


def add_dir_header_relationships(
    dot: graphviz.Digraph, manager: LangdonManager
) -> None:
    logger.info("Adding directory-header relationships to the graph.")
    dir_header_rel_query = (
        sql.select(DirHeaderRel)
        .join(DirHeaderRel.directory)
        .join(WebDirectory.domain, isouter=True)
        .join(WebDirectory.ip_address, isouter=True)
        .join(DirHeaderRel.header)
    )
    for dir_header_rel in manager.session.scalars(dir_header_rel_query):
        color = _get_node_color(_make_web_directory_node_name(dir_header_rel.directory))
        dot.edge(
            _make_web_directory_node_name(dir_header_rel.directory),
            dir_header_rel.header.name,
            color=color,
        )


def add_http_cookies(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    logger.info("Adding HTTP cookies to the graph.")
    http_cookies_query = sql.select(HttpCookie)
    for http_cookie in manager.session.scalars(http_cookies_query):
        dot.node(http_cookie.name, shape="trapezium")


def add_dir_cookie_relationships(
    dot: graphviz.Digraph, manager: LangdonManager
) -> None:
    logger.info("Adding directory-cookie relationships to the graph.")
    dir_cookie_rel_query = (
        sql.select(DirCookieRel)
        .join(DirCookieRel.directory)
        .join(WebDirectory.domain, isouter=True)
        .join(WebDirectory.ip_address, isouter=True)
        .join(DirCookieRel.cookie)
    )
    for dir_cookie_rel in manager.session.scalars(dir_cookie_rel_query):
        color = _get_node_color(_make_web_directory_node_name(dir_cookie_rel.directory))
        dot.edge(
            _make_web_directory_node_name(dir_cookie_rel.directory),
            dir_cookie_rel.cookie.name,
            color=color,
        )


def add_used_ports(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    logger.info("Adding used ports to the graph.")
    used_ports_query = (
        sql.select(UsedPort)
        .join(WebDirectory.domain, isouter=True)
        .join(UsedPort.ip_address)
    )
    for used_port in manager.session.scalars(used_ports_query):
        dot.node(
            f"{used_port.port}/{used_port.transport_layer_protocol}", shape="diamond"
        )
        color = _get_node_color(used_port.ip_address.address)
        dot.edge(
            used_port.ip_address.address,
            f"{used_port.port}/{used_port.transport_layer_protocol}",
            color=color,
        )


def add_technologies(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    logger.info("Adding technologies to the graph.")
    techonologies_query = sql.select(Technology)
    for technology in manager.session.scalars(techonologies_query):
        dot.node(f"{technology.name} {technology.version or ''}", shape="octagon")


def add_vulnerabilities(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    logger.info("Adding vulnerabilities to the graph.")
    vulnerabilities_query = sql.select(Vulnerability).join(Vulnerability.technology)
    for vulnerability in manager.session.scalars(vulnerabilities_query):
        dot.node(vulnerability.name, shape="hexagon")
        dot.edge(
            vulnerability.name,
            f"{vulnerability.technology.name} {vulnerability.technology.version or ''}",
        )


def add_web_dir_tech_relationships(
    dot: graphviz.Digraph, manager: LangdonManager
) -> None:
    logger.info("Adding web directory-technology relationships to the graph.")
    web_dir_tech_rel_query = (
        sql.select(WebDirTechRel)
        .join(WebDirTechRel.directory)
        .join(WebDirectory.domain, isouter=True)
        .join(WebDirectory.ip_address, isouter=True)
        .join(WebDirTechRel.technology)
    )
    for web_dir_tech_rel in manager.session.scalars(web_dir_tech_rel_query):
        color = _get_node_color(
            _make_web_directory_node_name(web_dir_tech_rel.directory)
        )
        dot.edge(
            _make_web_directory_node_name(web_dir_tech_rel.directory),
            f"{web_dir_tech_rel.technology.name} {web_dir_tech_rel.technology.version or ''}",
            color=color,
        )


def add_port_tech_relationships(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    logger.info("Adding port-technology relationships to the graph.")
    port_tech_rel_query = (
        sql.select(PortTechRel).join(PortTechRel.port).join(PortTechRel.technology)
    )
    for port_tech_rel in manager.session.scalars(port_tech_rel_query):
        color = _get_node_color(str(port_tech_rel.port.port))
        dot.edge(
            str(port_tech_rel.port.port),
            f"{port_tech_rel.technology.name} {port_tech_rel.technology.version or ''}",
            color=color,
        )
