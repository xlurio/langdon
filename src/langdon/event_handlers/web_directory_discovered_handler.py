from __future__ import annotations

import hashlib
import pathlib
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon import message_broker, throttler
from langdon.command_executor import CommandData, shell_command_execution_context
from langdon.events import WebDirectoryDiscovered, WebDirectoryResponseDiscovered
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
        f"{manager.config['web_directories_artifacts']}/{cleaned_hostname}/{cleaned_directory_path}"
    )
    httpx_file_name = f"get_{uuid.uuid4()}.httpx"

    throttler.wait_for_slot(f"throttle_{cleaned_hostname}")

    with shell_command_execution_context(
        CommandData(
            command="httpx",
            args=f"https://{cleaned_hostname}/{cleaned_directory_path} "
            f"--download {artifact_directory / httpx_file_name!s}",
        ),
        manager=manager,
    ) as _:
        md5_hasher = hashlib.md5()
        md5_hasher.update(
            pathlib.Path(artifact_directory / httpx_file_name).read_bytes()
        )
        message_broker.dispatch_event(
            WebDirectoryResponseDiscovered(
                web_directory=web_directory,
                response_hash=md5_hasher.hexdigest(),
                response_path=httpx_file_name,
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
