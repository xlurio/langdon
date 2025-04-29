from __future__ import annotations

import itertools
import os
import pathlib
import shutil
import time
import urllib.parse

from langdon_core.models import WebDirectory, WebDirectoryId, WebDirectoryScreenshot
from selenium.webdriver.firefox import options, service, webdriver
from sqlalchemy import sql

from langdon import throttler, utils
from langdon.langdon_manager import LangdonManager


def _get_domain_or_ip_name(web_directory: WebDirectory) -> str:
    return (
        web_directory.domain.name
        if web_directory.domain
        else web_directory.ip_address.address
    )


def _make_webdriver(*, manager: LangdonManager) -> webdriver.WebDriver:
    wd_options = options.Options()
    wd_options.add_argument("--headless")

    if firefox_profile := manager.config.get("firefox_profile"):
        wd_options.set_preference("profile", firefox_profile)

    wd_options.set_preference("network.proxy.type", 1)
    wd_options.set_preference("network.proxy.socks", manager.config["socks_proxy_host"])
    wd_options.set_preference(
        "network.proxy.socks_port", manager.config["socks_proxy_port"]
    )
    wd_options.set_preference(
        "general.useragent.override", manager.config["user_agent"]
    )

    wd_service = service.Service(shutil.which("geckodriver"))

    return webdriver.WebDriver(options=wd_options, service=wd_service)


def take_screenshot(
    cleaned_url: str, web_directory: WebDirectory, *, manager: LangdonManager
) -> None:
    domain_name = _get_domain_or_ip_name(web_directory)
    cleaned_directory_path = urllib.parse.urlparse(cleaned_url).path.lstrip("/")
    screenshot_destination_filepath = (
        pathlib.Path(
            os.path.join(
                manager.config["web_directory_screenshots"],
                domain_name,
                cleaned_directory_path,
            )
        )
        / "screenshot.png"
    )
    screenshot_destination_filepath.parent.mkdir(parents=True, exist_ok=True)

    with _make_webdriver(manager=manager) as driver:
        throttler.wait_for_slot(f"throttle_{domain_name}", manager=manager)
        driver.get(cleaned_url)

        time.sleep(15)
        utils.wait_for_slot_in_opened_files()

        screenshot_destination_filepath.write_bytes(
            driver.get_full_page_screenshot_as_png()
        )

    utils.create_if_not_exist(
        WebDirectoryScreenshot,
        directory_id=web_directory.id,
        defaults={"screenshot_path": str(screenshot_destination_filepath)},
        manager=manager,
    )


def _generate_visualization_for_dir_id_chunk(chunk: list[WebDirectoryId]) -> None:
    with LangdonManager() as manager:
        directories_query = (
            sql.select(WebDirectory)
            .join(WebDirectory.domain, isouter=True)
            .join(WebDirectory.ip_address, isouter=True)
            .where(WebDirectory.id.in_(chunk))
        )
        for known_directory in manager.session.scalars(directories_query):
            known_url = urllib.parse.urlunparse((
                "https" if known_directory.uses_ssl else "http",
                _get_domain_or_ip_name(known_directory),
                known_directory.path,
                "",
                "",
                "",
            ))
            take_screenshot(known_url, known_directory, manager=manager)


def generate_visualization(*, manager: LangdonManager) -> None:
    web_directories_query = sql.select(WebDirectory.id)

    CHUNK_SIZE = 8

    for dir_id_chunk in itertools.batched(
        manager.session.scalars(web_directories_query), CHUNK_SIZE
    ):
        _generate_visualization_for_dir_id_chunk(dir_id_chunk)
