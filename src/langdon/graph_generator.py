from __future__ import annotations

import argparse
import urllib.parse
from typing import TYPE_CHECKING

import graphviz
from sqlalchemy import sql

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


def generate_graph(
    parsed_args: GraphGeneratorNamespace, *, manager: LangdonManager
) -> None:
    """
    Generate a graph of the known assets using the Graphviz library.
    """
    dot = graphviz.Digraph(name="langdon_graph", strict=True)

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
    return urllib.parse.urlunparse(
        (schema, cleaned_hostname, cleaned_directory_path, "", "", "")
    )


def add_domains(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    domains_query = sql.select(Domain)
    for domain in manager.session.scalars(domains_query):
        dot.node(domain.name, shape="box")


def add_ip_addresses(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    ip_address_query = sql.select(IpAddress)
    for ip_address in manager.session.scalars(ip_address_query):
        dot.node(ip_address.address, label=ip_address.address, shape="ellipse")


def add_ip_domain_relationships(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    ip_address_domain_rel_query = (
        sql.select(IpDomainRel).join(IpDomainRel.domain).join(IpDomainRel.ip_address)
    )
    for ip_domain_rel in manager.session.scalars(ip_address_domain_rel_query):
        dot.edge(ip_domain_rel.ip_address.address, ip_domain_rel.domain.name)


def add_web_directories(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    web_directories_query = (
        sql.select(WebDirectory)
        .join(WebDirectory.domain, isouter=True)
        .join(WebDirectory.ip_address, isouter=True)
    )

    for web_directory in manager.session.scalars(web_directories_query):
        dot.node(_make_web_directory_node_name(web_directory), shape="note")

        if web_directory.domain:
            dot.edge(
                web_directory.domain.name, _make_web_directory_node_name(web_directory)
            )
        else:
            dot.edge(
                web_directory.ip_address.address,
                _make_web_directory_node_name(web_directory),
            )


def add_http_headers(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    http_headers_query = sql.select(HttpHeader)
    for http_header in manager.session.scalars(http_headers_query):
        dot.node(http_header.name, shape="parallelogram")


def add_dir_header_relationships(
    dot: graphviz.Digraph, manager: LangdonManager
) -> None:
    dir_header_rel_query = (
        sql.select(DirHeaderRel)
        .join(DirHeaderRel.directory)
        .join(WebDirectory.domain, isouter=True)
        .join(WebDirectory.ip_address, isouter=True)
        .join(DirHeaderRel.header)
    )
    for dir_header_rel in manager.session.scalars(dir_header_rel_query):
        dot.edge(
            _make_web_directory_node_name(dir_header_rel.directory),
            dir_header_rel.header.name,
        )


def add_http_cookies(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    http_cookies_query = sql.select(HttpCookie)
    for http_cookie in manager.session.scalars(http_cookies_query):
        dot.node(http_cookie.name, shape="trapezium")


def add_dir_cookie_relationships(
    dot: graphviz.Digraph, manager: LangdonManager
) -> None:
    dir_cookie_rel_query = (
        sql.select(DirCookieRel)
        .join(DirCookieRel.directory)
        .join(WebDirectory.domain, isouter=True)
        .join(WebDirectory.ip_address, isouter=True)
        .join(DirCookieRel.cookie)
    )
    for dir_cookie_rel in manager.session.scalars(dir_cookie_rel_query):
        dot.edge(
            _make_web_directory_node_name(dir_cookie_rel.directory),
            dir_cookie_rel.cookie.name,
        )


def add_used_ports(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    used_ports_query = (
        sql.select(UsedPort).join(WebDirectory.domain, isouter=True).join(UsedPort.ip_address)
    )
    for used_port in manager.session.scalars(used_ports_query):
        dot.node(str(used_port.port), shape="diamond")
        dot.edge(str(used_port.port), used_port.ip_address.address)


def add_technologies(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    techonologies_query = sql.select(Technology)
    for technology in manager.session.scalars(techonologies_query):
        dot.node(f"{technology.name} {technology.version or ''}", shape="octagon")


def add_vulnerabilities(dot: graphviz.Digraph, manager: LangdonManager) -> None:
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
    web_dir_tech_rel_query = (
        sql.select(WebDirTechRel)
        .join(WebDirTechRel.directory)
        .join(WebDirectory.domain, isouter=True)
        .join(WebDirectory.ip_address, isouter=True)
        .join(WebDirTechRel.technology)
    )
    for web_dir_tech_rel in manager.session.scalars(web_dir_tech_rel_query):
        dot.edge(
            _make_web_directory_node_name(web_dir_tech_rel.directory),
            f"{web_dir_tech_rel.technology.name} {web_dir_tech_rel.technology.version or ''}",
        )


def add_port_tech_relationships(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    port_tech_rel_query = (
        sql.select(PortTechRel).join(PortTechRel.port).join(PortTechRel.technology)
    )
    for port_tech_rel in manager.session.scalars(port_tech_rel_query):
        dot.edge(
            str(port_tech_rel.port.port),
            f"{port_tech_rel.technology.name} {port_tech_rel.technology.version or ''}",
        )
