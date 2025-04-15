from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pandas as pd
from langdon_core.langdon_logging import logger
from langdon_core.models import AndroidApp, Domain, IpAddress

from langdon import utils

if TYPE_CHECKING:
    from pathlib import Path

    from langdon.langdon_manager import LangdonManager


class ImportCSVNamespace:
    csv_file: Path


def _ip_to_int(ip: str) -> int:
    parts = map(int, ip.split("."))
    return sum(part << (8 * (3 - i)) for i, part in enumerate(parts))


def _int_to_ip(ip_int: int) -> str:
    return ".".join(str((ip_int >> (8 * i)) & 0xFF) for i in reversed(range(4)))


def _convert_cidr_to_ip_addresses(cidr: str) -> list[str]:
    """ipaddress module is not maintained anymore. So here is a custom implementation
    to convert CIDR to IP addresses"""
    network, prefix_length = cidr.split("/")
    prefix_length = int(prefix_length)
    network_int = _ip_to_int(network)
    host_count = 2 ** (32 - prefix_length)

    return [_int_to_ip(network_int + i) for i in range(1, host_count - 1)]


def _turn_wildcard_into_domain(wildcard: str) -> str:
    pattern = re.compile(r"(?:(?:^\*\.)|(?:\.\*$))")
    return pattern.sub("", wildcard)


def import_from_csv(args: ImportCSVNamespace, *, manager: LangdonManager) -> None:
    raw_dataframe = pd.read_csv(args.csv_file)[["identifier", "asset_type"]]
    _process_wildcards(raw_dataframe)
    _process_cidrs(raw_dataframe)
    _import_domains(raw_dataframe, manager=manager)
    _import_apps(raw_dataframe, manager=manager)
    _import_ip_addresses(raw_dataframe, manager=manager)
    manager.session.commit()


def _process_wildcards(raw_dataframe: pd.DataFrame) -> None:
    raw_dataframe[raw_dataframe["asset_type"] == "WILDCARD"]["identifier"] = (
        raw_dataframe[raw_dataframe["asset_type"] == "WILDCARD"]["identifier"].apply(
            _turn_wildcard_into_domain
        )
    )
    raw_dataframe[raw_dataframe["asset_type"] == "WILDCARD"]["asset_type"] = "URL"


def _process_cidrs(raw_dataframe: pd.DataFrame) -> None:
    """Conver CIDR to IP addresses"""
    discovered_ip_addresses: set[str] = set()

    for index, row in raw_dataframe[raw_dataframe["asset_type"] == "CIDR"].iterrows():
        cidr = row["identifier"]
        discovered_ip_addresses = discovered_ip_addresses.union(
            _convert_cidr_to_ip_addresses(cidr)
        )

    raw_dataframe.drop(
        raw_dataframe[raw_dataframe["asset_type"] == "CIDR"].index, inplace=True
    )
    dataframe_length = len(raw_dataframe)

    for ip_index, ip_address in enumerate(discovered_ip_addresses):
        raw_dataframe.loc[dataframe_length + ip_index] = {
            "identifier": ip_address,
            "asset_type": "IP_ADDRESS",
        }


def _import_domains(raw_dataframe: pd.DataFrame, *, manager: LangdonManager) -> None:
    for domain in raw_dataframe[raw_dataframe["asset_type"] == "URL"]["identifier"]:
        was_already_known = utils.create_if_not_exist(
            Domain,
            defaults={"was_known": True},
            manager=manager,
            name=domain,
        )
        if not was_already_known:
            logger.info("Domain %s successfully imported", domain)


def _import_apps(raw_dataframe: pd.DataFrame, *, manager: LangdonManager) -> None:
    for app in raw_dataframe[raw_dataframe["asset_type"] == "GOOGLE_PLAY_APP_ID"][
        "identifier"
    ]:
        was_already_known = utils.create_if_not_exist(
            AndroidApp,
            manager=manager,
            android_app_id=app,
        )
        if not was_already_known:
            logger.info("App %s successfully imported", app)


def _import_ip_addresses(
    raw_dataframe: pd.DataFrame, *, manager: LangdonManager
) -> None:
    ip_addresses_dataset = []

    for ip_address in raw_dataframe[raw_dataframe["asset_type"] == "IP_ADDRESS"][
        "identifier"
    ]:
        kwargs = {"address": ip_address}
        defaults = {"version": utils.detect_ip_version(ip_address), "was_known": True}
        ip_addresses_dataset.append(
            utils.CreateBulkIfNotExistInput(kwargs=kwargs, defaults=defaults)
        )

    utils.bulk_create_if_not_exist(
        IpAddress,
        ip_addresses_dataset,
        manager=manager,
    )
