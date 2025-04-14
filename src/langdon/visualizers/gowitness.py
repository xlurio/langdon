import glob
import itertools
import os
import pathlib
import urllib.parse

from sqlalchemy import sql

from langdon import throttler, utils
from langdon.command_executor import (
    CommandData,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
)
from langdon.langdon_manager import LangdonManager
from langdon.models import (
    WebDirectory,
    WebDirectoryId,
    WebDirectoryScreenshot,
)


def _get_domain_or_ip_name(web_directory: WebDirectory) -> str:
    return (
        web_directory.domain.name
        if web_directory.domain
        else web_directory.ip_address.address
    )


def take_screenshot(
    cleaned_url: str, web_directory: WebDirectory, *, manager: LangdonManager
) -> None:
    domain_name = _get_domain_or_ip_name(web_directory, manager=manager)
    cleaned_directory_path = urllib.parse.urlparse(cleaned_url).path.lstrip("/")
    gowitness_destination_dir = pathlib.Path(
        os.path.join(
            manager.config["web_directory_screenshots"],
            domain_name,
            cleaned_directory_path,
        )
    )
    gowitness_destination_dir.mkdir(parents=True, exist_ok=True)

    throttler.wait_for_slot(f"throttle_{domain_name}", manager=manager)
    command_data = CommandData(
        command="gowitness",
        args=f"scan single -u {cleaned_url} --screenshot-fullpage -s "
        f"{gowitness_destination_dir!s}",
    )

    with (
        suppress_duplicated_recon_process(),
        shell_command_execution_context(command_data, manager=manager),
    ):
        jpeg_files = glob.glob(os.path.join(f"{gowitness_destination_dir!s}", "*.jpeg"))
        if jpeg_files:
            latest_jpeg = max(jpeg_files, key=os.path.getmtime)
            utils.create_if_not_exist(
                WebDirectoryScreenshot,
                web_directory_response_id=web_directory.id,
                defaults={"screenshot_path": pathlib.Path(latest_jpeg)},
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
            known_url = urllib.parse.urlunparse(
                (
                    "https" if known_directory.uses_ssl else "http",
                    _get_domain_or_ip_name(known_directory),
                    known_directory.path,
                    "",
                    "",
                    "",
                )
            )
            take_screenshot(known_url, known_directory, manager=manager)


def generate_visualization(*, manager: LangdonManager) -> None:
    web_directories_query = sql.select(WebDirectory.id)

    CHUNK_SIZE = 8

    for dir_id_chunk in itertools.batched(
        manager.session.scalars(web_directories_query), CHUNK_SIZE
    ):
        _generate_visualization_for_dir_id_chunk(dir_id_chunk)
