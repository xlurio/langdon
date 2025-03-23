from collections.abc import Iterator

from sqlalchemy.orm import Session
from langdon import langdon_log
from langdon.langdon_t import EnumeratorType
from langdon.enumerators import google
from langdon.models import Asset, Directory


DirectoryType = str


def iter_enumerators() -> Iterator[EnumeratorType]:
    yield google.enumerate_directories


def enumerate_directories_from_assets(
    assets: set[Asset], *, session: Session
) -> Iterator[Directory]:
    directory: Directory

    for enumerate in iter_enumerators():
        for asset in assets:
            langdon_log.logger.info("Enumerating directories for %s", asset.name)
            counter = 0
            for directory in enumerate(asset.name, session=session):
                yield Directory(
                    url=directory.url, asset_id=asset.id, title=directory.title
                )
                counter += 1

                if counter % 50 == 0:
                    langdon_log.logger.info(
                        "Enumerated %d directories for %s", counter, asset.name
                    )
            langdon_log.logger.info(
                "Enumerated %d directories for %s", counter, asset.name
            )
