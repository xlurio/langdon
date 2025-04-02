import abc
import re

import pydantic

from langdon.langdon_manager import register_event
from langdon.models import (
    Domain,
    IpAddress,
    Technology,
    TransportLayerProtocolT,
    UsedPort,
    WebDirectory,
)


class Event(pydantic.BaseModel, abc.ABC):
    model_config = {"arbitrary_types_allowed": True}


@register_event
class VulnerabilityDiscovered(Event):
    name: str = pydantic.Field(min_length=1)
    source: str = pydantic.Field(min_length=1)
    technology: Technology


@register_event
class TechnologyDiscovered(Event):
    name: str = pydantic.Field(min_length=1)
    version: str | None = None
    directory: WebDirectory | None = None
    port: UsedPort | None = None


@register_event
class DomainDiscovered(Event):
    name: str

    @pydantic.field_validator("name")
    @classmethod
    def validate_domain_name(cls, value: str):
        domain_regex = r"^(?:[^.\s]*\.)*[^.\s]+$"
        if not re.match(domain_regex, value):
            raise ValueError("Invalid domain name")
        return value


@register_event
class IpAddressDiscovered(Event):
    address: str
    domain: Domain | None = None

    @pydantic.field_validator("address")
    @classmethod
    def validate_ip_address(cls, value: str):
        ipv4_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        ipv6_regex = r"^[0-9A-Fa-f:]+$"

        if not re.match(ipv4_regex, value) and not re.match(ipv6_regex, value):
            raise ValueError("Invalid IP address")

        return value


@register_event
class PortDiscovered(Event):
    port: int = pydantic.Field(gt=0)
    transport_layer_protocol: TransportLayerProtocolT
    is_filtered: bool
    ip_address: IpAddress


@register_event
class WebDirectoryDiscovered(Event):
    path: str = pydantic.Field(min_length=1)
    domain: Domain | None = None
    ip_address: IpAddress | None = None
    uses_ssl: bool


@register_event
class HttpHeaderDiscovered(Event):
    name: str = pydantic.Field(min_length=1)
    web_directory: WebDirectory


@register_event
class HttpCookieDiscovered(Event):
    name: str = pydantic.Field(min_length=1)
    web_directory: WebDirectory
