import csv
import glob
import os
import pathlib
import tempfile

from sqlalchemy import sql

from langdon import message_broker, throttler
from langdon.command_executor import CommandData, shell_command_execution_context
from langdon.events import TechnologyDiscovered, WebDirectoryResponseDiscovered
from langdon.langdon_manager import LangdonManager
from langdon.models import Domain, WebDirectoryResponse, WebDirectoryResponseScreenshot
from langdon.utils import create_if_not_exist


def _process_new_response(
    event: WebDirectoryResponseDiscovered, *, manager: LangdonManager
) -> None:
    domain_query = sql.select(Domain).where(Domain.id == event.web_directory.domain_id)
    domain = manager.session.execute(domain_query).scalar_one()
    cleaned_directory_path = event.web_directory.path.lstrip("/")

    throttler.wait_for_slot(f"throttle_{domain.name}")

    with shell_command_execution_context(
        CommandData(
            command="webanalyze",
            args=f"-worker 1 -host https://{domain.name}/{cleaned_directory_path} "
            "-output csv",
        )
    ) as output:
        with tempfile.NamedTemporaryFile("w+", suffix=".csv") as temp_file:
            temp_file.write(output)
            temp_file.flush()
            temp_file.seek(0)

            reader = csv.DictReader(temp_file)
            raw_version = str(row["Version"]).strip()
            cleaned_version = raw_version if raw_version else None

            for row in reader:
                message_broker.dispatch_event(
                    TechnologyDiscovered(
                        name=row["App"],
                        version=cleaned_version,
                        directory=event.web_directory,
                    )
                )

    gowitness_destination_dir = os.path.join(
        manager.config["web_directory_screenshots"], domain.name, cleaned_directory_path
    )

    with tempfile.NamedTemporaryFile("w+b", suffix=".html") as file:
        file.write(event.response_path.read_bytes().split(b"\r\n\r\n", 1)[1])
        with shell_command_execution_context(
            CommandData(
                command="gowitness",
                args=f"gowitness scan file -f {file.name} --screenshot-fullpage -s "
                f"{gowitness_destination_dir}",
            )
        ):
            jpeg_files = glob.glob(os.path.join(gowitness_destination_dir, "*.jpeg"))
            if jpeg_files:
                latest_jpeg = max(jpeg_files, key=os.path.getmtime)
                create_if_not_exist(
                    WebDirectoryResponseScreenshot,
                    web_directory_response_id=event.web_directory.id,
                    defaults={"screenshot_path": pathlib.Path(latest_jpeg)},
                    manager=manager,
                )


def handle_event(
    event: WebDirectoryResponseDiscovered, *, manager: LangdonManager
) -> None:
    # TODO add logs
    was_already_known = create_if_not_exist(
        WebDirectoryResponse,
        web_directory_id=event.web_directory.id,
        response_hash=event.response_hash,
        defaults={"response_path": event.response_path},
        manager=manager,
    )

    if not was_already_known:
        _process_new_response(event, manager=manager)
