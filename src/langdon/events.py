import abc
import re

import pydantic
from langdon_core.models import (
    DomainId,
    IpAddressId,
    TechnologyId,
    TransportLayerProtocolT,
    UsedPortId,
    WebDirectoryId,
)

from langdon.langdon_manager import register_event


class Event(pydantic.BaseModel, abc.ABC): ...


@register_event
class VulnerabilityDiscovered(Event):
    name: str = pydantic.Field(min_length=1)
    source: str = pydantic.Field(min_length=1)
    technology_id: TechnologyId


@register_event
class TechnologyDiscovered(Event):
    name: str = pydantic.Field(min_length=1)
    version: str | None = None
    directory_id: WebDirectoryId | None = None
    port_id: UsedPortId | None = None

    @pydantic.field_validator("name")
    @classmethod
    def validate_technology_name(cls, value: str):
        if value == "None":
            raise ValueError("Invalid technology name")

        return value


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
    domain_id: DomainId | None = None

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
    ip_address_id: IpAddressId


@register_event
class WebDirectoryDiscovered(Event):
    path: str = pydantic.Field(min_length=1)
    domain_id: DomainId | None = None
    ip_address_id: IpAddressId | None = None
    uses_ssl: bool


@register_event
class HttpHeaderDiscovered(Event):
    name: str = pydantic.Field(min_length=1)
    web_directory_id: WebDirectoryId


@register_event
class HttpCookieDiscovered(Event):
    name: str = pydantic.Field(min_length=1)
    web_directory_id: WebDirectoryId
