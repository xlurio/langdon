from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pandas as pd

from langdon.langdon_logging import logger
from langdon.models import AndroidApp, Domain
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from pathlib import Path

    from langdon.langdon_manager import LangdonManager


class ImportCSVNamespace:
    csv_file: Path


def _turn_wildcard_into_domain(wildcard: str) -> str:
    pattern = re.compile(r"(?:(?:^\*\.)|(?:\.\*$))")
    return pattern.sub("", wildcard)


def import_from_csv(args: ImportCSVNamespace, *, manager: LangdonManager) -> None:
    raw_dataframe = pd.read_csv(args.csv_file)
    _process_wildcards(raw_dataframe)
    _import_domains(raw_dataframe, manager)
    _import_apps(raw_dataframe, manager)
    manager.session.commit()


def _process_wildcards(raw_dataframe: pd.DataFrame) -> None:
    raw_dataframe[raw_dataframe["asset_type"] == "WILDCARD"]["identifier"] = (
        raw_dataframe[raw_dataframe["asset_type"] == "WILDCARD"]["identifier"].apply(
            _turn_wildcard_into_domain
        )
    )
    raw_dataframe[raw_dataframe["asset_type"] == "WILDCARD"]["asset_type"] = "URL"


def _import_domains(raw_dataframe: pd.DataFrame, manager: LangdonManager) -> None:
    for domain in raw_dataframe[raw_dataframe["asset_type"] == "URL"]["identifier"]:
        was_already_known = create_if_not_exist(
            Domain,
            defaults={"was_known": False},
            manager=manager,
            name=domain,
        )
        if not was_already_known:
            logger.info("Domain %s successfully imported", domain)


def _import_apps(raw_dataframe: pd.DataFrame, manager: LangdonManager) -> None:
    for app in raw_dataframe[raw_dataframe["asset_type"] == "GOOGLE_PLAY_APP_ID"][
        "identifier"
    ]:
        was_already_known = create_if_not_exist(
            AndroidApp,
            manager=manager,
            android_app_id=app,
        )
        if not was_already_known:
            logger.info("App %s successfully imported", app)
