from __future__ import annotations

import csv
import glob
import os
import pathlib
import tempfile
from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon import message_broker, throttler
from langdon.command_executor import (
    CommandData,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
)
from langdon.events import TechnologyDiscovered, WebDirectoryResponseDiscovered
from langdon.langdon_logging import logger
from langdon.models import Domain, WebDirectoryResponse, WebDirectoryResponseScreenshot
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from langdon.langdon_manager import LangdonManager


def _process_new_response(
    event: WebDirectoryResponseDiscovered, *, manager: LangdonManager
) -> None:
    domain_query = sql.select(Domain).where(Domain.id == event.directory.domain_id)
    domain = manager.session.execute(domain_query).scalar_one()
    cleaned_directory_path = event.directory.path.lstrip("/")

    throttler.wait_for_slot(f"throttle_{domain.name}", manager=manager)

    with (
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="webanalyze",
                args=f"-worker 1 -host {'https' if event.directory.uses_ssl else 'http'}://{domain.name}/{cleaned_directory_path} "
                "-output csv",
            ),
            manager=manager,
        ) as output,
        tempfile.NamedTemporaryFile("w+", suffix=".csv") as temp_file,
    ):
        cleaned_output = "\n".join(
            line.strip() for line in output.splitlines() if line.strip()
        )
        temp_file.write(cleaned_output)
        temp_file.flush()
        temp_file.seek(0)

        reader = csv.DictReader(temp_file)

        for row in reader:
            raw_version = str(row["Version"]).strip()
            cleaned_version = raw_version if raw_version else None

            message_broker.dispatch_event(
                TechnologyDiscovered(
                    name=row["App"],
                    version=cleaned_version,
                    directory=event.directory,
                ),
                manager=manager,
            )

    gowitness_destination_dir = os.path.join(
        manager.config["web_directory_screenshots"], domain.name, cleaned_directory_path
    )

    with tempfile.NamedTemporaryFile("w+b", suffix=".html") as file:
        split_response = event.response_path.read_bytes().split(b"\r\n\r\n", 1)

        if len(split_response) < 2:
            return logger.info("Response to directory %s has no body", event.directory.path)

        file.write(event.response_path.read_bytes().split(b"\r\n\r\n", 1)[1])
        with (
            suppress_duplicated_recon_process(),
            shell_command_execution_context(
                CommandData(
                    command="gowitness",
                    args=f"gowitness scan file -f {file.name} --screenshot-fullpage -s "
                    f"{gowitness_destination_dir}",
                ),
                manager=manager,
            ),
        ):
            jpeg_files = glob.glob(os.path.join(gowitness_destination_dir, "*.jpeg"))
            if jpeg_files:
                latest_jpeg = max(jpeg_files, key=os.path.getmtime)
                create_if_not_exist(
                    WebDirectoryResponseScreenshot,
                    web_directory_response_id=event.directory.id,
                    defaults={"screenshot_path": pathlib.Path(latest_jpeg)},
                    manager=manager,
                )


def handle_event(
    event: WebDirectoryResponseDiscovered, *, manager: LangdonManager
) -> None:
    cleaned_path = str(event.response_path.absolute())
    was_already_known = create_if_not_exist(
        WebDirectoryResponse,
        directory_id=event.directory.id,
        response_hash=event.response_hash,
        defaults={"response_path": cleaned_path},
        manager=manager,
    )

    if not was_already_known:
        logger.info("New web directory response discovered: %s", event.directory.path)

    _process_new_response(event, manager=manager)
