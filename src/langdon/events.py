from __future__ import annotations

import abc
from typing import TYPE_CHECKING

import pydantic

from langdon.langdon_manager import register_event

if TYPE_CHECKING:
    from langdon.models import Domain, Technology, UsedPort, WebDirectory


class Event(pydantic.BaseModel, abc.ABC): ...


@register_event
class VulnerabilityDiscovered(Event):
    name: str
    source: str
    technology: Technology


@register_event
class TechnologyDiscovered(Event):
    name: str
    version: str | None
    directory: WebDirectory | None
    port: UsedPort | None


@register_event
class DomainDiscovered(Event):
    name: str


@register_event
class IpAddressDiscovered(Event):
    address: str


@register_event
class WebDirectoryDiscovered(Event):
    path: str
    domain: Domain
