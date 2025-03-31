from __future__ import annotations

import hashlib
import json
import pathlib
import urllib.parse
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import sql

from langdon import message_broker, throttler
from langdon.command_executor import (
    CommandData,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
)
from langdon.langdon_logging import logger
from langdon.models import Domain, IpAddress, WebDirectory
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
    from langdon.events import WebDirectoryDiscovered
    from langdon.langdon_manager import LangdonManager


def _clean_hostname(web_directory: WebDirectory, *, manager: LangdonManager) -> str:
    if web_directory.domain_id is not None:
        domain_query = sql.select(Domain.name).filter(
            Domain.id == web_directory.domain_id
        )
        return manager.session.execute(domain_query).scalar_one()
    else:
        ip_query = sql.select(IpAddress.address).filter(
            IpAddress.id == web_directory.ip_id
        )
        return manager.session.execute(ip_query).scalar_one()


def _process_directory(web_directory: WebDirectory, *, manager: LangdonManager) -> None:
    cleaned_hostname = _clean_hostname(web_directory, manager=manager)
    cleaned_directory_path = web_directory.path.lstrip("/")
    artifact_directory = pathlib.Path(
        f"{manager.config['web_directories_artifacts']}/{cleaned_hostname}/"
        f"{cleaned_directory_path}"
    )
    httpx_file_name = f"get_{uuid.uuid4()}.httpx"

    cleaned_url = _build_cleaned_url(
        web_directory, cleaned_hostname, cleaned_directory_path
    )

    _download_httpx_file(
        cleaned_url, artifact_directory, httpx_file_name, web_directory, manager
    )

    _analyze_with_whatweb(cleaned_url, web_directory, manager)


def _build_cleaned_url(
    web_directory: WebDirectory, cleaned_hostname: str, cleaned_directory_path: str
) -> str:
    schema = "https" if web_directory.uses_ssl else "http"
    return urllib.parse.urlunparse(
        (schema, cleaned_hostname, cleaned_directory_path, "", "", "")
    )


def _download_httpx_file(
    cleaned_url: str,
    artifact_directory: pathlib.Path,
    httpx_file_name: str,
    web_directory: WebDirectory,
    manager: LangdonManager,
) -> None:
    throttler.wait_for_slot(f"throttle_{cleaned_url}", manager=manager)
    user_agent = manager.config["user_agent"]
    artifact_directory.mkdir(parents=True, exist_ok=True)

    with (
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="httpx",
                args=f"{cleaned_url} --headers 'User-Agent' '{user_agent}' --download "
                f"{artifact_directory / httpx_file_name!s}",
            ),
            manager=manager,
            ignore_exit_code=True,
        ) as _,
    ):
        md5_hasher = hashlib.md5()
        md5_hasher.update(
            pathlib.Path(artifact_directory / httpx_file_name).read_bytes()
        )
        message_broker.dispatch_event(
            manager.get_event_by_name("WebDirectoryResponseDiscovered")(
                directory=web_directory,
                response_hash=md5_hasher.hexdigest(),
                response_path=artifact_directory / httpx_file_name,
            ),
            manager=manager,
        )


def _analyze_with_whatweb(
    cleaned_url: str, web_directory: WebDirectory, manager: LangdonManager
) -> None:
    user_agent = manager.config["user_agent"]

    throttler.wait_for_slot(f"throttle_{cleaned_url}", manager=manager)

    with (
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="whatweb",
                args=f'--user-agent "{user_agent}" --colour never --quiet --max-threads 1 '
                f"--wait 5 --log-json /dev/stdout {cleaned_url}",
            ),
            manager=manager,
        ) as output,
    ):
        item: dict[str, Any]
        for item in json.loads(output):
            _process_uncommon_headers(item, web_directory, manager=manager)
            _process_cookies(item, web_directory, manager=manager)


def _process_uncommon_headers(
    item: dict[str, Any], web_directory: WebDirectory, *, manager: LangdonManager
) -> None:
    uncommon_headers: str
    if (
        uncommon_headers := item.get("plugins", {})
        .get("UncommonHeaders", {})
        .get("string", {})
    ):
        for header in uncommon_headers.split(","):
            header = header.strip()
            message_broker.dispatch_event(
                manager.get_event_by_name("HttpHeaderDiscovered")(
                    name=header,
                    web_directory=web_directory,
                ),
                manager=manager,
            )


def _process_cookies(
    item: dict[str, Any], web_directory: WebDirectory, *, manager: LangdonManager
) -> None:
    cookies: str
    if cookies := item.get("plugins", {}).get("Cookies", {}).get("string", {}):
        for cookie in cookies.split(","):
            cookie = cookie.strip()
            message_broker.dispatch_event(
                manager.get_event_by_name("HttpCookieDiscovered")(
                    name=cookie,
                    web_directory=web_directory,
                ),
                manager=manager,
            )


def handle_event(event: WebDirectoryDiscovered, *, manager: LangdonManager) -> None:
    was_already_known = create_if_not_exist(
        WebDirectory,
        path=event.path,
        domain_id=event.domain.id if event.domain else None,
        ip_id=event.ip_address.id if event.ip_address else None,
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
        .where(WebDirectory.path == event.path)
        .where(
            WebDirectory.uses_ssl == event.uses_ssl,
        )
    )

    if event.ip_address is not None:
        query = query.where(WebDirectory.ip_id == event.ip_address.id)
    elif event.domain is not None:
        query = query.where(WebDirectory.domain_id == event.domain.id)

    web_directory = session.execute(query).scalar_one()

    _process_directory(web_directory, manager=manager)
