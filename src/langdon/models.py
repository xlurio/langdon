from __future__ import annotations

from typing import TYPE_CHECKING, Literal

import sqlalchemy
from sqlalchemy import orm

if TYPE_CHECKING:
    from pathlib import Path


class SqlAlchemyModel(orm.DeclarativeBase): ...


class ReconProcess(SqlAlchemyModel):
    __tablename__ = "langdon_reconprocesses"
    __table_args__ = (
        sqlalchemy.UniqueConstraint("name", "args", name="_name_args_uc"),
    )

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    name: orm.Mapped[str]
    args: orm.Mapped[str]


class Domain(SqlAlchemyModel):
    __tablename__ = "langdon_domains"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    name: orm.Mapped[str] = orm.mapped_column(unique=True)
    was_known: orm.Mapped[bool]
    web_directories: orm.Mapped[list[WebDirectory]] = orm.relationship(
        back_populates="domain", cascade="all, delete-orphan"
    )


class AndroidApp(SqlAlchemyModel):
    __tablename__ = "langdon_androidapps"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    android_app_id: orm.Mapped[str] = orm.mapped_column(unique=True)


IpAddressVersionT = Literal["ipv4", "ipv6"]


class IpAddress(SqlAlchemyModel):
    __tablename__ = "langdon_ipaddresses"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    address: orm.Mapped[str] = orm.mapped_column(unique=True)
    version: orm.Mapped[IpAddressVersionT]


class IpDomainRel(SqlAlchemyModel):
    __tablename__ = "langdon_ipdomainrels"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    ip_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_ipaddresses.id")
    )
    domain_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_domains.id")
    )


class WebDirectory(SqlAlchemyModel):
    __tablename__ = "langdon_webdirectories"
    __table_args__ = (
        sqlalchemy.UniqueConstraint(
            "path", "domain_id", "ip_ip", name="_path_domain_ip_uc"
        ),
    )

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    path: orm.Mapped[str]
    domain_id: orm.Mapped[int | None] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_domains.id"), nullable=True
    )
    domain: orm.Mapped[Domain | None] = orm.relationship(
        back_populates="web_directories", nullable=True
    )
    ip_id: orm.Mapped[int | None] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_ipaddresses.id"), nullable=True
    )


class WebDirectoryResponse(SqlAlchemyModel):
    __tablename__ = "langdon_webdirectoryresponses"
    __table_args__ = (
        sqlalchemy.UniqueConstraint(
            "web_directory_id", "response_hash", name="_wd_id_hash_uc"
        ),
    )

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    web_directory_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_webdirectories.id")
    )
    response_hash: orm.Mapped[str]
    response_path: orm.Mapped[Path]


class WebDirectoryResponseScreenshot(SqlAlchemyModel):
    __tablename__ = "langdon_webdirectoryresponsescreenshots"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    web_directory_response_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_webdirectoryresponses.id"), unique=True
    )
    screenshot_path: orm.Mapped[Path]


TransportLayerProtocolT = Literal["tcp", "udp"]


class UsedPort(SqlAlchemyModel):
    __tablename__ = "langdon_usedports"
    __table_args__ = (
        sqlalchemy.UniqueConstraint(
            "port",
            "transport_layer_protocol",
            "is_filtered",
            name="_port_tlp_is_filtered_uc",
        ),
    )

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    port: orm.Mapped[int] = orm.mapped_column()
    transport_layer_protocol: orm.Mapped[TransportLayerProtocolT]
    is_filtered: orm.Mapped[bool]


class PortIpRel(SqlAlchemyModel):
    __tablename__ = "langdon_portiprels"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    port_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_usedports.id")
    )
    ip_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_ipaddresses.id")
    )


class Technology(SqlAlchemyModel):
    __tablename__ = "langdon_technologies"
    __table_args__ = (
        sqlalchemy.UniqueConstraint("name", "version", name="_name_version_uc"),
    )

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)

    name: orm.Mapped[str]
    version: orm.Mapped[str | None]


class WebDirTechRel(SqlAlchemyModel):
    __tablename__ = "langdon_webdirtechrels"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    directory_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_webdirectories.id")
    )
    technology_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_technologies.id")
    )


class PortTechRel(SqlAlchemyModel):
    __tablename__ = "langdon_porttechrels"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    port_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_usedports.id")
    )
    technology_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_technologies.id")
    )


class Vulnerability(SqlAlchemyModel):
    __tablename__ = "langdon_vulnerabilities"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    name: orm.Mapped[str] = orm.mapped_column(unique=True)
    source: orm.Mapped[str]
    technology_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_technologies.id")
    )
