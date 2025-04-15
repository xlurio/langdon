import itertools
import re
import urllib.parse

import requests
from langdon_core.langdon_logging import logger
from langdon_core.models import Domain, DomainId, WebDirectory
from sqlalchemy import sql

from langdon import event_listener, task_queue, throttler
from langdon.command_executor import (
    CommandData,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
)
from langdon.events import DomainDiscovered, WebDirectoryDiscovered
from langdon.langdon_manager import LangdonManager


def _process_url(url_match: re.Match, *, manager: LangdonManager):
    parsed_url = urllib.parse.urlparse(url_match.group(0))
    found_domain = parsed_url.netloc.split(":")[0]
    uses_ssl = parsed_url.scheme == "https"
    event_listener.handle_event(DomainDiscovered(name=found_domain), manager=manager)
    new_domain_query = sql.select(Domain.id).where(Domain.name == found_domain)
    new_domain_id = manager.session.execute(new_domain_query).scalar_one()

    event_listener.send_event_message(
        WebDirectoryDiscovered(
            path=parsed_url.path,
            domain_id=new_domain_id,
            uses_ssl=uses_ssl,
        ),
        manager=manager,
    )


def _process_path(url_match: re.Match, domain_id: DomainId, *, manager: LangdonManager):
    event_listener.send_event_message(
        WebDirectoryDiscovered(
            path=url_match.group(0), domain_id=domain_id, uses_ssl=True
        ),
        manager=manager,
    )


def _process_discovered_js(
    discovered_js: str,
    url_regex: re.Pattern,
    domain_id: DomainId,
    manager: LangdonManager,
) -> None:
    domain_name_query = sql.select(Domain.name).where(Domain.id == domain_id)
    domain_name = manager.session.execute(domain_name_query).scalar_one()

    throttler.wait_for_slot(f"throttle_{domain_name}", manager=manager)
    proxies = {
        "http": "socks5://localhost:9050",
        "https": "socks5://localhost:9050",
    }
    response = requests.get(discovered_js, proxies=proxies)

    if _should_skip_response(response, discovered_js):
        return

    _process_response_urls(response.text, url_regex, domain_id, manager)


def _should_skip_response(response: requests.Response, discovered_js: str) -> bool:
    if response.status_code >= 300 and response.status_code < 500:
        logger.debug(
            f"Skipping {discovered_js} due to status code {response.status_code}"
        )
        return True
    return False


def _process_response_urls(
    response_text: str,
    url_regex: re.Pattern,
    domain_id: DomainId,
    manager: LangdonManager,
) -> None:
    for url_match in url_regex.finditer(response_text):
        if url_match.group(0).startswith("http"):
            _process_url(url_match, manager=manager)
        else:
            _process_path(url_match, domain_id, manager=manager)


def _discover_urls_from_js(chunk: list[str], domain_id: DomainId) -> None:
    url_regex = re.compile(
        r"(?:http[s]?:/)?(\/)((?:[a-zA-Z\-_\:\.0-9\{\}]+))(\/)*"
        r"((?:[a-zA-Z\-_\:\.0-9\{\}]+))(\/)((?:[a-zA-Z\-_\/\:\.0-9\{\}]+))"
    )

    with LangdonManager() as manager:
        for discovered_js in chunk:
            _process_discovered_js(discovered_js, url_regex, domain_id, manager)


def _discover_from_js_in_chunk(chunk: list[str], domain_id: DomainId) -> None:
    CHUNK_SIZE = 8

    with LangdonManager() as manager:
        user_agent = manager.config["user_agent"]

        for known_url in chunk:
            host_name = urllib.parse.urlparse(known_url).netloc.split(":")[0]
            throttler.wait_for_slot(f"throttle_{host_name}", manager=manager)
            with (
                suppress_duplicated_recon_process(),
                shell_command_execution_context(
                    CommandData(
                        command="getJS",
                        args=f"-complete -header 'User-Agent: {user_agent}' -resolve "
                        f"-url {known_url}",
                    ),
                    manager=manager,
                ) as output,
            ):
                for discovered_js_chunk in itertools.batched(
                    output.splitlines(), CHUNK_SIZE
                ):
                    task_queue.submit_task(
                        _discover_urls_from_js,
                        discovered_js_chunk,
                        domain_id,
                        manager=manager,
                    )


def _discover_from_js_in_domain(domain_id: int, *, manager: LangdonManager) -> None:
    CHUNK_SIZE = 8

    directories_query = (
        sql.select(WebDirectory)
        .join(WebDirectory.domain)
        .where(WebDirectory.domain_id == domain_id)
    )
    known_urls: list[str] = []

    for known_directory in manager.session.scalars(directories_query):
        known_url = urllib.parse.urlunparse((
            "https" if known_directory.uses_ssl else "http",
            known_directory.domain.name,
            known_directory.path,
            "",
            "",
            "",
        ))
        known_urls.append(known_url)

    if not known_urls:
        return logger.debug(f"No known URLs to crawl for domain ID {domain_id}")

    for known_urls_chunk in itertools.batched(known_urls, CHUNK_SIZE):
        task_queue.submit_task(
            _discover_from_js_in_chunk, known_urls_chunk, domain_id, manager=manager
        )


def _discover_from_js_in_domain_chunk(chunk: list[DomainId]) -> None:
    with LangdonManager() as manager:
        for domain_id in chunk:
            _discover_from_js_in_domain(domain_id, manager=manager)


def discover_content(*, manager: LangdonManager) -> None:
    known_domain_ids_query = sql.select(Domain.id)
    known_domain_ids = set(manager.session.scalars(known_domain_ids_query).all())

    known_domain_ids_query = sql.select(Domain.id)
    known_domain_ids = set(manager.session.scalars(known_domain_ids_query).all())

    if not known_domain_ids:
        return logger.info("No known domains to katana crawl")

    CHUNK_SIZE = 8

    for domain_id_chunk in itertools.batched(known_domain_ids, CHUNK_SIZE):
        task_queue.submit_task(
            _discover_from_js_in_domain_chunk, domain_id_chunk, manager=manager
        )
