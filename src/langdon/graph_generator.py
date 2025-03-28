from __future__ import annotations

import argparse
from typing import TYPE_CHECKING

from graphviz import Digraph

from langdon.models import (
    Domain,
    IpAddress,
    IpDomainRel,
    PortIpRel,
    PortTechRel,
    Technology,
    UsedPort,
    Vulnerability,
    WebDirectory,
    WebDirectoryResponse,
    WebDirectoryResponseScreenshot,
)
from langdon.output import OutputColor

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.orm import Session

    from langdon.langdon_manager import LangdonManager


class GraphGeneratorNamespace(argparse.Namespace):
    output: Path


def generate_graph(
    parsed_args: GraphGeneratorNamespace, *, manager: LangdonManager
) -> None:
    """
    Generate a graph of the known assets using the Graphviz library.
    """
    # Initialize the graph
    graph = Digraph(format="png")
    graph.attr(rankdir="LR")

    # Get database session
    session: Session = manager.session

    # Add nodes and edges for domains and IPs
    for domain in session.query(Domain).all():
        graph.node(f"domain_{domain.id}", domain.name, shape="ellipse")
        for ip_rel in session.query(IpDomainRel).filter_by(domain_id=domain.id).all():
            ip = session.query(IpAddress).filter_by(id=ip_rel.ip_id).first()
            if ip:
                graph.node(f"ip_{ip.id}", ip.address, shape="box")
                graph.edge(f"domain_{domain.id}", f"ip_{ip.id}")

    # Add nodes and edges for web directories and responses
    for web_dir in session.query(WebDirectory).all():
        graph.node(f"webdir_{web_dir.id}", web_dir.path, shape="folder")
        if web_dir.domain_id:
            graph.edge(f"domain_{web_dir.domain_id}", f"webdir_{web_dir.id}")
        for response in (
            session.query(WebDirectoryResponse)
            .filter_by(web_directory_id=web_dir.id)
            .all()
        ):
            graph.node(f"response_{response.id}", response.response_hash, shape="note")
            graph.edge(f"webdir_{web_dir.id}", f"response_{response.id}")
            screenshot = (
                session.query(WebDirectoryResponseScreenshot)
                .filter_by(web_directory_response_id=response.id)
                .first()
            )
            if screenshot:
                graph.node(
                    f"screenshot_{screenshot.id}",
                    str(screenshot.screenshot_path),
                    shape="image",
                )
                graph.edge(f"response_{response.id}", f"screenshot_{screenshot.id}")

    # Add nodes and edges for ports and technologies
    for port in session.query(UsedPort).all():
        graph.node(
            f"port_{port.id}",
            f"Port {port.port}/{port.transport_layer_protocol}",
            shape="hexagon",
        )
        for port_ip_rel in session.query(PortIpRel).filter_by(port_id=port.id).all():
            graph.edge(f"ip_{port_ip_rel.ip_id}", f"port_{port.id}")
        for tech_rel in session.query(PortTechRel).filter_by(port_id=port.id).all():
            tech = (
                session.query(Technology).filter_by(id=tech_rel.technology_id).first()
            )
            if tech:
                graph.node(
                    f"tech_{tech.id}",
                    f"{tech.name} {tech.version or ''}",
                    shape="component",
                )
                graph.edge(f"port_{port.id}", f"tech_{tech.id}")

    # Add nodes and edges for vulnerabilities
    for vuln in session.query(Vulnerability).all():
        graph.node(f"vuln_{vuln.id}", vuln.name, shape="octagon")
        graph.edge(f"tech_{vuln.technology_id}", f"vuln_{vuln.id}")

    # Render the graph to the specified output path
    output_path = str(parsed_args.output)
    graph.render(output_path, cleanup=True)
    print(
        f"{OutputColor.GREEN}Graph generated and saved to {output_path}"
        f"{OutputColor.RESET}"
    )
