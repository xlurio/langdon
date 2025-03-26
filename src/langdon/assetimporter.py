from __future__ import annotations

import pathlib
from typing import TYPE_CHECKING
import pandas as pd
import re

from langdon.models import AndroidApp, Domain


if TYPE_CHECKING:
    from langdon.langdon_manager import LangdonManager


class ImportCSVNamespace:
    csv_file: pathlib.Path


def _turn_wildcard_into_domain(wildcard: str) -> str:
    pattern = re.compile(r"(?:(?:^\*\.)|(?:\.\*$))")
    return pattern.sub("", wildcard)


def import_from_csv(args: ImportCSVNamespace, *, manager: LangdonManager) -> None:
    raw_dataframe = pd.read_csv(args.csv_file)
    raw_dataframe[raw_dataframe["asset_type"] == "WILDCARD"]["name"] = raw_dataframe[
        raw_dataframe["asset_type"] == "WILDCARD"
    ]["name"].apply(_turn_wildcard_into_domain)
    raw_dataframe[raw_dataframe["asset_type"] == "WILDCARD"]["asset_type"] = "URL"

    for domain in raw_dataframe[raw_dataframe["asset_type"] == "URL"]["name"]:
        manager.session.add(Domain(domain=domain, was_known=False))

    for app in raw_dataframe[raw_dataframe["asset_type"] == "GOOGLE_PLAY_APP_ID"][
        "name"
    ]:
        manager.session.add(AndroidApp(android_app_id=app))

    manager.session.commit()
