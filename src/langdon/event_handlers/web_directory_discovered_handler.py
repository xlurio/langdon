from __future__ import annotations

import hashlib
import json
import pathlib
import urllib.parse
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import sql

from langdon import message_broker, throttler
from langdon.command_executor import CommandData, shell_command_execution_context
from langdon.events import (
    HttpCookieDiscovered,
    HttpHeaderDiscovered,
    WebDirectoryDiscovered,
    WebDirectoryResponseDiscovered,
)
from langdon.models import Domain, IpAddress, WebDirectory
from langdon.utils import create_if_not_exist

if TYPE_CHECKING:
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

    cleaned_url = _build_cleaned_url(web_directory, cleaned_hostname, cleaned_directory_path)

    _download_httpx_file(cleaned_url, artifact_directory, httpx_file_name, web_directory, manager)

    _analyze_with_whatweb(cleaned_url, web_directory, manager)


def _build_cleaned_url(web_directory: WebDirectory, cleaned_hostname: str, cleaned_directory_path: str) -> str:
    schema = "https" if web_directory.uses_ssl else "http"
    return urllib.parse.urlunparse(
        (schema, cleaned_hostname, cleaned_directory_path, "", "", "")
    )


def _download_httpx_file(cleaned_url: str, artifact_directory: pathlib.Path, httpx_file_name: str, web_directory: WebDirectory, manager: LangdonManager) -> None:
    throttler.wait_for_slot(f"throttle_{cleaned_url}")

    with shell_command_execution_context(
        CommandData(
            command="httpx",
            args=f"{cleaned_url} --download {artifact_directory / httpx_file_name!s}",
        ),
        manager=manager,
    ) as _:
        md5_hasher = hashlib.md5()
        md5_hasher.update(
            pathlib.Path(artifact_directory / httpx_file_name).read_bytes()
        )
        message_broker.dispatch_event(
            WebDirectoryResponseDiscovered(
                directory=web_directory,
                response_hash=md5_hasher.hexdigest(),
                response_path=httpx_file_name,
            )
        )


def _analyze_with_whatweb(cleaned_url: str, web_directory: WebDirectory, manager: LangdonManager) -> None:
    throttler.wait_for_slot(f"throttle_{cleaned_url}")

    user_agent = manager.config["user_agent"]

    with shell_command_execution_context(
        CommandData(
            command="whatweb",
            args=f'--user-agent "{user_agent}" --colour never --quiet --max-threads 1 '
            f"--wait 5 --log-json /dev/stdout {cleaned_url}",
        )
    ) as output:
        item: dict[str, Any]
        for item in json.loads(output):
            _process_uncommon_headers(item, web_directory)
            _process_cookies(item, web_directory)


def _process_uncommon_headers(item: dict[str, Any], web_directory: WebDirectory) -> None:
    uncommon_headers: str
    if (
        uncommon_headers := item.get("plugins", {})
        .get("UncommonHeaders", {})
        .get("string", {})
    ):
        for header in uncommon_headers.split(","):
            header = header.strip()
            message_broker.dispatch_event(
                HttpHeaderDiscovered(
                    name=header,
                    web_directory=web_directory,
                )
            )


def _process_cookies(item: dict[str, Any], web_directory: WebDirectory) -> None:
    cookies: str
    if (
        cookies := item.get("plugins", {}).get("Cookies", {})
        .get("string", {})
    ):
        for cookie in cookies.split(","):
            cookie = cookie.strip()
            message_broker.dispatch_event(
                HttpCookieDiscovered(
                    name=cookie,
                    web_directory=web_directory,
                )
            )


def handle_event(event: WebDirectoryDiscovered, *, manager: LangdonManager) -> None:
    # TODO add logs
    was_already_known = create_if_not_exist(
        WebDirectory,
        path=event.path,
        domain_id=event.domain.id if event.domain else None,
        ip_id=event.ip_address.id if event.ip_address else None,
        manager=manager,
    )

    session = manager.session
    query = sql.select(WebDirectory).filter(WebDirectory.path == event.path)
    web_directory = session.execute(query).scalar_one()

    if not was_already_known:
        _process_directory(web_directory, manager=manager)
