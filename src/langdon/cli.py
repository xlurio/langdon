import argparse
import pathlib
import sys
from sqlalchemy import orm, sql
import pandas as pd

from langdon.enumeration import enumerate_directories_from_assets
from langdon.exceptions import LangdonException
from langdon.models import Asset, Directory, LangdonConfig, SqlAlchemyModel
from langdon import data_access, langdon_log


def set_configuration(key: str, value: str, *, session: orm.Session):
    langdon_log.logger.debug("Setting configuration %s to %s", key, value)
    query = sql.select(LangdonConfig).where(LangdonConfig.name == key)

    if session.execute(query).scalar_one_or_none() is not None:
        session.execute(
            sql.update(LangdonConfig)
            .where(LangdonConfig.name == key)
            .values(value=value)
        )
    else:
        session.add(LangdonConfig(name=key, value=value))

    session.commit()

    print(f"Configuration {key} set to {value}")


def configure(args: argparse.Namespace, *, session: orm.Session):
    langdon_log.logger.debug("Configuring Langdon")

    return {"set": lambda: set_configuration(args.key, args.value, session=session)}[
        args.config_subcommand
    ]()


def enumerate_directories(*, session: orm.Session):
    langdon_log.logger.debug("Enumerating directories")

    domain_assert_types = ("URL", "WILDCARD")
    statement = sql.select(Asset).where(Asset.asset_type.in_(domain_assert_types))
    domain_assets = set(session.scalars(statement))

    for directory in enumerate_directories_from_assets(
        domain_assets, session=session
    ):
        query = sql.select(Directory).where(Directory.url == directory.url).limit(1)

        if session.execute(query).scalar_one_or_none() is not None:
            continue

        session.add(directory)
        session.commit()

    print(f"Enumerated directories for {len(domain_assets)} assets")


def import_assets(file: pathlib.Path, *, session: orm.Session):
    langdon_log.logger.debug("Importing assets from %s", file)

    dataframe = pd.read_csv(file)
    dataframe_with_eligible_assets = dataframe[dataframe["eligible_for_bounty"]]
    dataframe_w_adjusted_col_names = dataframe_with_eligible_assets.rename(
        columns={"identifier": "name"}
    )
    dataframe_w_adjusted_col_names["max_severity"] = (
        dataframe_w_adjusted_col_names["max_severity"]
        .map({"low": 0, "medium": 7, "high": 14, "critical": 21})
        .astype("Int8")
    )

    dataframe_w_adjusted_col_names[
        ["name", "asset_type", "max_severity"]
    ].drop_duplicates(subset=["name"]).to_sql(
        Asset.__tablename__, session.bind, if_exists="append", index=False
    )

    print(f"Imported assets from {file}")


def run():
    SqlAlchemyModel.metadata.create_all(data_access.engine, checkfirst=True)

    with orm.Session(data_access.engine) as session:
        abstract_parser = argparse.ArgumentParser(add_help=False)
        abstract_parser.add_argument(
            "--loglevel",
            "-l",
            type=str,
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="WARNING",
            help="Log level",
        )

        main_parser = argparse.ArgumentParser(
            prog="Langdon", description="Tool for target applications reconnaissance"
        )
        main_subparsers = main_parser.add_subparsers(dest="subcommand")

        config_parser = main_subparsers.add_parser("config")
        config_subparsers = config_parser.add_subparsers(dest="config_subcommand")
        set_parser = config_subparsers.add_parser("set", parents=[abstract_parser])
        set_parser.add_argument("key", type=str, help="Configuration key")
        set_parser.add_argument("value", type=str, help="Configuration value")

        main_subparsers.add_parser("enumpages", parents=[abstract_parser])

        import_assets_parser = main_subparsers.add_parser(
            "import", parents=[abstract_parser]
        )
        import_assets_parser.add_argument(
            "file", type=pathlib.Path, help="Path to the CSV file containing the assets"
        )

        args = main_parser.parse_args(sys.argv[1:])
        langdon_log.logger.setLevel(args.loglevel)

        try:
            {
                "config": lambda: configure(args, session=session),
                "enumpages": lambda: enumerate_directories(session=session),
                "import": lambda: import_assets(args.file, session=session),
            }[args.subcommand]()
        except LangdonException as exception:
            print(exception)
            sys.exit(1)


if __name__ == "__main__":
    run()
