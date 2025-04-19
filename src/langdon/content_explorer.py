import argparse
import itertools
import urllib.parse

from langdon_core.langdon_logging import logger
from langdon_core.models import Domain, DomainId, WebDirectory
from sqlalchemy import sql

from langdon import domain_processor, event_listener, task_queue
from langdon.active_explorers import getjs, katana
from langdon.command_executor import (
    CommandData,
    FunctionData,
    function_execution_context,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
)
from langdon.content_enumerators import google
from langdon.langdon_manager import LangdonManager
from langdon.output import OutputColor


class DiscoverContentFromDomainNamespace(argparse.Namespace):
    domain: str


def _build_url(directory: WebDirectory) -> str:
    return urllib.parse.urlunparse(
        (
            "https" if directory.uses_ssl else "http",
            directory.domain.name if directory.domain else directory.ip_address.address,
            directory.path,
            "",
            "",
            "",
        )
    )


def _build_proxy(manager: LangdonManager) -> str:
    return urllib.parse.urlunparse(
        (
            "socks5",
            f"{manager.config['socks_proxy_host']}:{manager.config['socks_proxy_port']}",
            "",
            "",
            "",
            "",
        )
    )


def _get_directories_query(chunk: set[int]):
    return (
        sql.select(WebDirectory)
        .join(WebDirectory.ip_address, isouter=True)
        .join(WebDirectory.domain, isouter=True)
        .where(WebDirectory.id.in_(chunk))
    )


def _get_or_create_domain(
    domain_name: str, directory: WebDirectory, manager: LangdonManager
):
    new_domain_query = sql.select(Domain).filter(Domain.name == domain_name)
    new_domain = manager.session.execute(new_domain_query).scalar_one_or_none()

    if new_domain:
        return new_domain

    return directory.domain


def _process_found_url(
    found_url: str, directory: WebDirectory, manager: LangdonManager
):
    found_url_parsed = urllib.parse.urlparse(found_url)

    if not found_url_parsed.netloc:
        return

    domain_name = found_url_parsed.netloc.split(":")[0]

    event_listener.send_event_message(
        manager.get_event_by_name("DomainDiscovered")(name=domain_name),
        manager=manager,
    )
    new_directory_domain = _get_or_create_domain(domain_name, directory, manager)

    cleaned_path = found_url_parsed.path
    event_listener.send_event_message(
        manager.get_event_by_name("WebDirectoryDiscovered")(
            path=cleaned_path,
            domain_id=new_directory_domain.id if new_directory_domain else None,
            ip_address_id=directory.ip_address.id if directory.ip_address else None,
            uses_ssl=found_url_parsed.scheme == "https",
        ),
        manager=manager,
    )


def _process_gau_output(
    curr_url: str, proxy: str, directory: WebDirectory, manager: LangdonManager
):
    with (
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="gau",
                args="--blacklist png,jpg,gif,ttf,woff --fp "
                f"--proxy {proxy} {curr_url}",
            ),
            manager=manager,
        ) as output,
    ):
        for found_url in output.splitlines():
            _process_found_url(found_url, directory, manager)


def _run_gau_for_chunk(chunk: set[int]) -> None:
    directories_from_chunk_query = _get_directories_query(chunk)

    with LangdonManager() as manager:
        for directory in manager.session.scalars(directories_from_chunk_query):
            curr_url = _build_url(directory)
            proxy = _build_proxy(manager)

            _process_gau_output(curr_url, proxy, directory, manager)


def _process_google_output(
    curr_url: str, directory: WebDirectory, manager: LangdonManager
):
    with (
        suppress_duplicated_recon_process(),
        function_execution_context(
            FunctionData(
                function=google.enumerate_directories_with_google,
                args=[curr_url],
                kwargs={"manager": manager},
            ),
            manager=manager,
        ) as output,
    ):
        for found_url in output:
            _process_found_url(found_url, directory, manager)


def _run_google_for_chunk(chunk: set[int]) -> None:
    directories_from_chunk_query = _get_directories_query(chunk)

    with LangdonManager() as manager:
        for directory in manager.session.scalars(directories_from_chunk_query):
            _process_google_output(
                directory.domain.name
                if directory.domain
                else directory.ip_address.address,
                directory,
                manager,
            )

def run_google_for_known_directory_ids(
    known_directories_ids: set[int], *, manager: LangdonManager
) -> None:
    CHUNK_SIZE = 8

    for chunk in itertools.batched(known_directories_ids, CHUNK_SIZE):
        task_queue.submit_task(_run_google_for_chunk, chunk, manager=manager)


def run_gau_for_known_directory_ids(
    known_directories_ids: set[int], *, manager: LangdonManager
) -> None:
    CHUNK_SIZE = 8

    for chunk in itertools.batched(known_directories_ids, CHUNK_SIZE):
        task_queue.submit_task(_run_gau_for_chunk, chunk, manager=manager)


def _discover_content_passively_from_domain_id(
    domain_id: DomainId, *, manager: LangdonManager
) -> None:
    known_directories_query = sql.select(WebDirectory.id).where(
        WebDirectory.domain_id == domain_id
    )
    known_directories_ids = set(
        manager.session.execute(known_directories_query).scalars().all()
    )

    if not known_directories_ids:
        logger.debug(f"No known directories found.")
        return

    logger.debug(f"Running passive discovery for directories...")
    run_gau_for_known_directory_ids(known_directories_ids, manager=manager)
    run_google_for_known_directory_ids(known_directories_ids, manager=manager)


def _discover_content_actively_from_domain_id(
    domain_id: DomainId, *, manager: LangdonManager
) -> None:
    getjs.discover_from_js_in_domain(domain_id, manager=manager)
    katana.crawl_domain_with_katana(domain_id, manager=manager)

def discover_content_from_domain(
    args: DiscoverContentFromDomainNamespace, *, manager: LangdonManager
) -> None:
    with task_queue.task_queue_context(), event_listener.event_listener_context():
        domain_processor.internal_process_domain(args.domain, manager=manager)

        domain_query = sql.select(Domain.id).where(Domain.name == args.domain)
        domain_id = manager.session.execute(domain_query).scalar_one()

        _discover_content_passively_from_domain_id(domain_id, manager=manager)
        _discover_content_actively_from_domain_id(domain_id, manager=manager)
        task_queue.wait_for_all_tasks_to_finish(manager=manager)
        event_listener.wait_for_all_events_to_be_handled(manager=manager)

    print(f"{OutputColor.GREEN}Domain processed successfully!{OutputColor.RESET}")
