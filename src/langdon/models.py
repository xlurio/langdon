from sqlalchemy import orm


class SqlAlchemyModel(orm.DeclarativeBase): ...


class Domain(SqlAlchemyModel):
    __tablename__ = "langdon_domains"

    id: orm.Mapped[int] = orm.mapped_column(primary_key=True)
    domain: orm.Mapped[str] = orm.mapped_column()
    was_known: orm.Mapped[bool] = orm.mapped_column()


class AndroidApp(SqlAlchemyModel):
    id: int
    android_app_id: str
