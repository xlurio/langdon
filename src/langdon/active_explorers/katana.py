import itertools
import urllib.parse

from langdon_core.langdon_logging import logger
from langdon_core.models import Domain, DomainId, WebDirectory
from sqlalchemy import sql

from langdon import event_listener, task_queue
from langdon.command_executor import (
    CommandData,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
)
from langdon.events import DomainDiscovered, WebDirectoryDiscovered
from langdon.langdon_manager import LangdonManager


def _handle_katana_result_chunk(chunk: list[str]) -> None:
    with LangdonManager() as manager:
        for line in chunk:
            if stripped_line := line.strip():
                parsed_urls = urllib.parse.urlparse(stripped_line)
                new_domain_name = parsed_urls.netloc.split(":")[0]
                event_listener.handle_event(
                    DomainDiscovered(name=new_domain_name), manager=manager
                )

                new_domain_query = sql.select(Domain).filter(
                    Domain.name == new_domain_name
                )
                new_domain = manager.session.execute(new_domain_query).scalar_one()

                path = parsed_urls.path
                event_listener.send_event_message(
                    WebDirectoryDiscovered(
                        path=path, domain_id=new_domain.id, uses_ssl=True
                    ),
                    manager=manager,
                )


def _crawl_urls_with_katana(known_urls_separated_by_comma: str) -> None:
    CHUNK_SIZE = 8

    with LangdonManager() as manager:
        user_agent = manager.config["user_agent"]
        proxy = (
            f"{manager.config['socks_proxy_host']}:{manager.config['socks_proxy_port']}"
        )

        with (
            suppress_duplicated_recon_process(),
            shell_command_execution_context(
                CommandData(
                    command="katana",
                    args=f"-list {known_urls_separated_by_comma} -js-crawl "
                    f"-known-files all -proxy {proxy} -headless -delay 5s "
                    "-rate-limit-minute 12 -silent -no-color "
                    f"-headers User-Agent:{user_agent}",
                ),
                manager=manager,
            ) as output,
        ):
            for chunk in itertools.batched(output.splitlines(), CHUNK_SIZE):
                task_queue.submit_task(
                    _handle_katana_result_chunk, chunk, manager=manager
                )


def crawl_domain_with_katana(domain_id: DomainId, *, manager: LangdonManager) -> None:
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

    task_queue.submit_task(
        _crawl_urls_with_katana, ",".join(known_urls), manager=manager
    )


def _crawl_domain_chunk_with_katana(chunk: list[DomainId]) -> None:
    with LangdonManager() as manager:
        for domain_id in chunk:
            crawl_domain_with_katana(domain_id, manager=manager)


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
            _crawl_domain_chunk_with_katana, domain_id_chunk, manager=manager
        )
