from typing import Literal
from sqlalchemy import orm
import sqlalchemy


class SqlAlchemyModel(orm.DeclarativeBase): ...


AssetTypeT = Literal["URL", "WILDCARD", "APPLE_STORE_APP_ID", "GOOGLE_PLAY_APP_ID"]
AssetSeverityType = Literal[0, 7, 14, 21] | None
LangdonConfigKeyT = Literal["FIREFOX_PROFILE_PATH"]


class LangdonConfig(SqlAlchemyModel):
    __tablename__ = "langdon_config"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    name: orm.Mapped[LangdonConfigKeyT] = orm.mapped_column(
        sqlalchemy.String(255), unique=True
    )
    value: orm.Mapped[str] = orm.mapped_column(sqlalchemy.String(255))


class Asset(SqlAlchemyModel):
    __tablename__ = "langdon_assets"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    name: orm.Mapped[str] = orm.mapped_column(sqlalchemy.String(255), unique=True)
    asset_type: orm.Mapped[AssetTypeT]
    max_severity: orm.Mapped[AssetSeverityType] = orm.mapped_column(
        sqlalchemy.Integer, nullable=True
    )


class Directory(SqlAlchemyModel):
    __tablename__ = "langdon_directories"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    asset_id: orm.Mapped[int] = orm.mapped_column(
        sqlalchemy.ForeignKey(Asset.id, ondelete="CASCADE")
    )
    url: orm.Mapped[str] = orm.mapped_column(sqlalchemy.String(255), unique=True)
    title: orm.Mapped[str] = orm.mapped_column(sqlalchemy.String(255), nullable=True)
