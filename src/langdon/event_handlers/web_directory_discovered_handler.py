from __future__ import annotations

import csv
import json
import tempfile
import urllib.parse
from typing import TYPE_CHECKING, Any

from langdon_core.langdon_logging import logger
from langdon_core.models import WebDirectory
from sqlalchemy import sql

from langdon import event_listener, throttler, utils
from langdon.command_executor import (
    CommandData,
    FunctionData,
    function_execution_context,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
)
from langdon.visualizers import selenium

if TYPE_CHECKING:
    from langdon.events import WebDirectoryDiscovered
    from langdon.langdon_manager import LangdonManager


def _get_domain_or_ip_name(web_directory: WebDirectory) -> str:
    return (
        web_directory.domain.name
        if web_directory.domain
        else web_directory.ip_address.address
    )


def _process_directory(web_directory: WebDirectory, *, manager: LangdonManager) -> None:
    cleaned_hostname = _get_domain_or_ip_name(web_directory)
    cleaned_directory_path = web_directory.path.lstrip("/")
    cleaned_url = _build_cleaned_url(
        web_directory, cleaned_hostname, cleaned_directory_path
    )

    _analyze_with_whatweb(cleaned_url, web_directory, manager)
    _run_webanalyze(cleaned_url, web_directory, manager=manager)
    with function_execution_context(
        FunctionData(
            function=selenium.take_screenshot,
            args=(cleaned_url, web_directory),
            kwargs={"manager": manager},
        ),
        manager=manager,
    ):
        ...


def _build_cleaned_url(
    web_directory: WebDirectory, cleaned_hostname: str, cleaned_directory_path: str
) -> str:
    schema = "https" if web_directory.uses_ssl else "http"
    return urllib.parse.urlunparse(
        (
            schema,
            cleaned_hostname,
            cleaned_directory_path,
            "",
            "",
            "",
        )
    )


def _analyze_with_whatweb(
    cleaned_url: str, web_directory: WebDirectory, manager: LangdonManager
) -> None:
    domain_name = urllib.parse.urlparse(cleaned_url).netloc
    user_agent = manager.config["user_agent"]
    throttler.wait_for_slot(f"throttle_{domain_name}", manager=manager)
    command_data = CommandData(
        command="whatweb",
        args=f'--user-agent "{user_agent}" --colour never --quiet --max-threads 1 '
        f"--wait 5 --log-json /dev/stdout {cleaned_url}",
    )

    with (
        suppress_duplicated_recon_process(),
        shell_command_execution_context(command_data, manager=manager) as output,
    ):
        for item in json.loads(output):
            _process_uncommon_headers(item, web_directory, manager=manager)
            _process_cookies(item, web_directory, manager=manager)


def _run_webanalyze(
    cleaned_url: str, web_directory: WebDirectory, *, manager: LangdonManager
) -> None:
    domain_name = _get_domain_or_ip_name(web_directory)
    throttler.wait_for_slot(f"throttle_{domain_name}", manager=manager)
    command_data = CommandData(
        command="webanalyze", args=f"-worker 1 -host {cleaned_url} -output csv"
    )

    utils.wait_for_slot_in_opened_files()
    with (
        suppress_duplicated_recon_process(),
        shell_command_execution_context(command_data, manager=manager) as output,
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
            event_listener.send_event_message(
                manager.get_event_by_name("TechnologyDiscovered")(
                    name=row["App"],
                    version=row["Version"].strip() if row["Version"].strip() else None,
                    directory_id=web_directory.id,
                ),
                manager=manager,
            )


def _process_uncommon_headers(
    item: dict[str, Any], web_directory: WebDirectory, *, manager: LangdonManager
) -> None:
    uncommon_headers: str
    if (
        uncommon_headers := item.get("plugins", {})
        .get("UncommonHeaders", {})
        .get("string", [None])[0]
    ):
        if isinstance(uncommon_headers, str):
            for header in uncommon_headers.split(","):
                header = header.strip()
                event_listener.send_event_message(
                    manager.get_event_by_name("HttpHeaderDiscovered")(
                        name=header,
                        web_directory_id=web_directory.id,
                    ),
                    manager=manager,
                )


def _process_cookies(
    item: dict[str, Any], web_directory: WebDirectory, *, manager: LangdonManager
) -> None:
    cookies: str
    if cookies := item.get("plugins", {}).get("Cookies", {}).get("string", []):
        for cookie in cookies:
            cookie = cookie.strip()
            event_listener.send_event_message(
                manager.get_event_by_name("HttpCookieDiscovered")(
                    name=cookie,
                    web_directory_id=web_directory.id,
                ),
                manager=manager,
            )


def handle_event(event: WebDirectoryDiscovered, *, manager: LangdonManager) -> None:
    was_already_known = utils.create_if_not_exist(
        WebDirectory,
        path=event.path,
        domain_id=event.domain_id if event.domain_id else None,
        ip_id=event.ip_address_id if event.ip_address_id else None,
        uses_ssl=event.uses_ssl,
        manager=manager,
    )

    if not was_already_known:
        logger.debug(
            "Web directory discovered: %s",
            event.path,
        )

    session = manager.session
    query = (
        sql.select(WebDirectory)
        .join(WebDirectory.domain, isouter=True)
        .join(WebDirectory.ip_address, isouter=True)
        .where(WebDirectory.path == event.path)
        .where(
            WebDirectory.uses_ssl == event.uses_ssl,
        )
    )

    if event.ip_address_id is not None:
        query = query.where(WebDirectory.ip_id == event.ip_address_id)
    elif event.domain_id is not None:
        query = query.where(WebDirectory.domain_id == event.domain_id)

    web_directory = session.execute(query).scalar_one()

    _process_directory(web_directory, manager=manager)
