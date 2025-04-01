from __future__ import annotations

from typing import Literal

import sqlalchemy
from sqlalchemy import orm


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
    was_known: orm.Mapped[bool] = orm.mapped_column(default=False)
    web_directories: orm.Mapped[list[WebDirectory]] = (
        orm.relationship(  # Fixed type hint
            back_populates="domain", cascade="all, delete-orphan"
        )
    )
    ip_relationships: orm.Mapped[list[IpDomainRel]] = orm.relationship(
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
    domain_relationships: orm.Mapped[list[IpDomainRel]] = orm.relationship(
        back_populates="ip_address", cascade="all, delete-orphan"
    )
    ports: orm.Mapped[list[UsedPort]] = orm.relationship(
        back_populates="ip_address", cascade="all, delete-orphan"
    )


class IpDomainRel(SqlAlchemyModel):
    __tablename__ = "langdon_ipdomainrels"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    ip_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_ipaddresses.id")
    )
    domain_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_domains.id")
    )
    ip_address: orm.Mapped[IpAddress] = orm.relationship(
        back_populates="domain_relationships"
    )
    domain: orm.Mapped[Domain] = orm.relationship(back_populates="ip_relationships")


class WebDirectory(SqlAlchemyModel):
    __tablename__ = "langdon_webdirectories"
    __table_args__ = (
        sqlalchemy.UniqueConstraint(
            "path", "domain_id", "ip_id", "uses_ssl", name="_path_domain_ip_uc"
        ),
    )

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    path: orm.Mapped[str]
    domain_id: orm.Mapped[int | None] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_domains.id"), nullable=True
    )
    domain: orm.Mapped[Domain | None] = orm.relationship(
        back_populates="web_directories"
    )
    ip_id: orm.Mapped[int | None] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_ipaddresses.id"), nullable=True
    )
    uses_ssl: orm.Mapped[bool]
    technologies: orm.Mapped[list[WebDirTechRel]] = orm.relationship(
        back_populates="directory", cascade="all, delete-orphan"
    )
    http_header_relationships: orm.Mapped[list[DirHeaderRel]] = orm.relationship(
        back_populates="directory", cascade="all, delete-orphan"
    )
    http_cookie_relationships: orm.Mapped[list[DirCookieRel]] = orm.relationship(
        back_populates="directory", cascade="all, delete-orphan"
    )
    screenshots: orm.Mapped[list[WebDirectoryScreenshot]] = orm.relationship(
        back_populates="directory", cascade="all, delete-orphan"
    )


class HttpHeader(SqlAlchemyModel):
    __tablename__ = "langdon_httpheaders"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    name: orm.Mapped[str] = orm.mapped_column(unique=True)
    directory_relationships: orm.Mapped[list[DirHeaderRel]] = orm.relationship(
        back_populates="header", cascade="all, delete-orphan"
    )


class DirHeaderRel(SqlAlchemyModel):
    __tablename__ = "langdon_dirheaderrels"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    header_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_httpheaders.id")
    )
    directory_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_webdirectories.id")
    )
    directory: orm.Mapped[WebDirectory] = orm.relationship(
        back_populates="http_header_relationships"
    )
    header: orm.Mapped[HttpHeader] = orm.relationship(
        back_populates="directory_relationships"
    )


class HttpCookie(SqlAlchemyModel):
    __tablename__ = "langdon_httpcookies"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    name: orm.Mapped[str] = orm.mapped_column(unique=True)
    directory_relationships: orm.Mapped[list[DirCookieRel]] = orm.relationship(
        back_populates="cookie", cascade="all, delete-orphan"
    )


class DirCookieRel(SqlAlchemyModel):
    __tablename__ = "langdon_dircookierels"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    cookie_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_httpcookies.id")
    )
    directory_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_webdirectories.id")
    )
    cookie: orm.Mapped[HttpCookie] = orm.relationship(
        back_populates="directory_relationships"
    )
    directory: orm.Mapped[WebDirectory] = orm.relationship(
        back_populates="http_cookie_relationships"
    )


class WebDirectoryScreenshot(SqlAlchemyModel):
    __tablename__ = "langdon_webdirectoryscreenshots"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    screenshot_path: orm.Mapped[str]
    directory_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_webdirectories.id")
    )
    directory: orm.Mapped[WebDirectory] = orm.relationship(back_populates="screenshots")


TransportLayerProtocolT = Literal["tcp", "udp"]


class UsedPort(SqlAlchemyModel):
    __tablename__ = "langdon_usedports"
    __table_args__ = (
        sqlalchemy.UniqueConstraint(
            "port",
            "transport_layer_protocol",
            "ip_address_id",
            name="_port_tlp_is_filtered_uc",
        ),
    )

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    port: orm.Mapped[int] = orm.mapped_column()
    transport_layer_protocol: orm.Mapped[TransportLayerProtocolT]
    is_filtered: orm.Mapped[bool]
    ip_address_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_ipaddresses.id")
    )
    ip_address: orm.Mapped[IpAddress] = orm.relationship(back_populates="ports")
    technology_relationships: orm.Mapped[list[PortTechRel]] = orm.relationship(
        back_populates="port", cascade="all, delete-orphan"
    )


class Technology(SqlAlchemyModel):
    __tablename__ = "langdon_technologies"
    __table_args__ = (
        sqlalchemy.UniqueConstraint("name", "version", name="_name_version_uc"),
    )

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)

    name: orm.Mapped[str]
    version: orm.Mapped[str | None]
    web_directory_relationships: orm.Mapped[list[WebDirTechRel]] = orm.relationship(
        back_populates="technology", cascade="all, delete-orphan"
    )
    port_relationships: orm.Mapped[list[PortTechRel]] = orm.relationship(
        back_populates="technology", cascade="all, delete-orphan"
    )
    vulnerabilities: orm.Mapped[list[Vulnerability]] = orm.relationship(
        back_populates="technology", cascade="all, delete-orphan"
    )


class WebDirTechRel(SqlAlchemyModel):
    __tablename__ = "langdon_webdirtechrels"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    directory_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_webdirectories.id")
    )
    technology_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_technologies.id")
    )
    directory: orm.Mapped[WebDirectory] = orm.relationship(
        back_populates="technologies"
    )
    technology: orm.Mapped[Technology] = orm.relationship(
        back_populates="web_directory_relationships"
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
    port: orm.Mapped[UsedPort] = orm.relationship(
        back_populates="technology_relationships"
    )
    technology: orm.Mapped[Technology] = orm.relationship(
        back_populates="port_relationships"
    )


class Vulnerability(SqlAlchemyModel):
    __tablename__ = "langdon_vulnerabilities"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    name: orm.Mapped[str] = orm.mapped_column(unique=True)
    source: orm.Mapped[str]
    technology_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey("langdon_technologies.id")
    )
    technology: orm.Mapped[Technology] = orm.relationship(
        back_populates="vulnerabilities"
    )
