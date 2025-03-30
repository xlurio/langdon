from __future__ import annotations

import argparse
from typing import TYPE_CHECKING

import graphviz
from sqlalchemy import sql

from langdon.models import (
    DirHeaderRel,
    Domain,
    HttpCookie,
    HttpHeader,
    IpAddress,
    IpDomainRel,
    PortIpRel,
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
    dot = graphviz.Digraph(name="langdon_graph")

    add_domains(dot, manager)
    add_ip_addresses(dot, manager)
    add_ip_domain_relationships(dot, manager)
    add_web_directories(dot, manager)
    add_http_headers(dot, manager)
    add_dir_header_relationships(dot, manager)
    add_http_cookies(dot, manager)
    add_dir_cookie_relationships(dot, manager)
    add_used_ports(dot, manager)
    add_ip_port_relationships(dot, manager)
    add_technologies(dot, manager)
    add_vulnerabilities(dot, manager)
    add_web_dir_tech_relationships(dot, manager)
    add_port_tech_relationships(dot, manager)

    dot.render(
        parsed_args.output.with_suffix(""),
        format=parsed_args.output.suffix.replace(".", ""),
        cleanup=True,
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
    web_directories_query = sql.select(WebDirectory).join(WebDirectory.domain)
    for web_directory in manager.session.scalars(web_directories_query):
        dot.node(web_directory.path, shape="note")
        dot.edge(web_directory.domain.name, web_directory.path)


def add_http_headers(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    http_headers_query = sql.select(HttpHeader)
    for http_header in manager.session.scalars(http_headers_query):
        dot.node(http_header.name, shape="parallelogram")


def add_dir_header_relationships(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    dir_header_rel_query = (
        sql.select(DirHeaderRel).join(DirHeaderRel.directory).join(DirHeaderRel.header)
    )
    for dir_header_rel in manager.session.scalars(dir_header_rel_query):
        dot.edge(dir_header_rel.directory.path, dir_header_rel.header.name)


def add_http_cookies(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    http_cookies_query = sql.select(HttpCookie)
    for http_cookie in manager.session.scalars(http_cookies_query):
        dot.node(http_cookie.name, shape="trapezium")


def add_dir_cookie_relationships(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    dir_cookie_rel_query = (
        sql.select(DirHeaderRel).join(DirHeaderRel.directory).join(DirHeaderRel.header)
    )
    for dir_cookie_rel in manager.session.scalars(dir_cookie_rel_query):
        dot.edge(dir_cookie_rel.directory.path, dir_cookie_rel.header.name)


def add_used_ports(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    used_ports_query = sql.select(UsedPort).join(WebDirectory.domain)
    for used_port in manager.session.scalars(used_ports_query):
        dot.node(str(used_port.port), shape="diamond")


def add_ip_port_relationships(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    ip_port_rel_query = sql.select(PortIpRel).join(PortIpRel.ip).join(PortIpRel.port)
    for ip_port_rel in manager.session.scalars(ip_port_rel_query):
        dot.edge(str(ip_port_rel.port.port), ip_port_rel.ip.address)


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


def add_web_dir_tech_relationships(dot: graphviz.Digraph, manager: LangdonManager) -> None:
    web_dir_tech_rel_query = (
        sql.select(WebDirTechRel)
        .join(WebDirTechRel.directory)
        .join(WebDirTechRel.technology)
    )
    for web_dir_tech_rel in manager.session.scalars(web_dir_tech_rel_query):
        dot.edge(
            web_dir_tech_rel.directory.path,
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
