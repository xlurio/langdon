from __future__ import annotations

import itertools
import re
import shlex
import shutil
import subprocess
import tempfile
import urllib.parse
from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon import event_listener, task_queue, utils
from langdon.command_executor import (
    CommandData,
    FunctionData,
    function_execution_context,
    shell_command_execution_context,
    suppress_called_process_error,
    suppress_duplicated_recon_process,
    suppress_timeout_expired_error,
)
from langdon.content_enumerators import google
from langdon.events import DomainDiscovered, IpAddressDiscovered, WebDirectoryDiscovered
from langdon.exceptions import LangdonProgrammingError
from langdon.langdon_logging import logger
from langdon.langdon_manager import LangdonManager
from langdon.models import AndroidApp, Domain, IpAddress, ReconProcess, WebDirectory
from langdon.output import OutputColor

if TYPE_CHECKING:
    from langdon.langdon_argparser import LangdonNamespace


def _download_android_binaries() -> None:
    with LangdonManager() as manager:
        android_bin_dir = manager.config["downloaded_apks_dir"]
        android_apps_query = sql.select(AndroidApp.android_app_id)
        app_ids = set(manager.session.scalars(android_apps_query).all())

        if not app_ids:
            return logger.debug("No Android apps to download")

        for android_app_id in app_ids:
            with (
                suppress_duplicated_recon_process(),
                shell_command_execution_context(
                    CommandData(
                        command="apkeep",
                        args=f"--app {android_app_id} {android_bin_dir}",
                    ),
                    manager=manager,
                ),
            ):
                ...


def _discover_domains_from_known_ones_passively(*, manager: LangdonManager) -> None:
    known_domains_query = sql.select(Domain.name).where(Domain.was_known == True)
    known_domains_names = set(manager.session.scalars(known_domains_query))

    if not known_domains_names:
        return logger.debug("No known domains to passively enumerate from")

    utils.wait_for_slot_in_opened_files()
    with tempfile.NamedTemporaryFile("w+") as temp_file:
        temp_file.write("\n".join(known_domains_names))
        temp_file.seek(0)

        _process_amass_for_domains(known_domains_names, manager=manager)
        task_queue.submit_task(_process_subfinder, temp_file.name, manager=manager)
        task_queue.submit_task(
            _process_assetfinder_for_domains, known_domains_names, manager=manager
        )

        task_queue.wait_for_all_tasks_to_finish(manager=manager)
        event_listener.wait_for_all_events_to_be_handled(manager=manager)


def _run_gau_for_chunk(chunk: set[int]) -> None:
    directories_from_chunk_query = _get_directories_query(chunk)

    with LangdonManager() as manager:
        for directory in manager.session.scalars(directories_from_chunk_query):
            curr_url = _build_url(directory)
            proxy = _build_proxy(manager)

            _process_gau_output(curr_url, proxy, directory, manager)


def _get_directories_query(chunk: set[int]):
    return (
        sql.select(WebDirectory)
        .join(WebDirectory.ip_address, isouter=True)
        .join(WebDirectory.domain, isouter=True)
        .where(WebDirectory.id.in_(chunk))
    )


def _build_url(directory: WebDirectory) -> str:
    return urllib.parse.urlunparse((
        "https" if directory.uses_ssl else "http",
        directory.domain.name if directory.domain else directory.ip_address.address,
        directory.path,
        "",
        "",
        "",
    ))


def _build_proxy(manager: LangdonManager) -> str:
    return urllib.parse.urlunparse((
        "socks5",
        f"{manager.config['socks_proxy_host']}:{manager.config['socks_proxy_port']}",
        "",
        "",
        "",
        "",
    ))


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


def _get_or_create_domain(
    domain_name: str, directory: WebDirectory, manager: LangdonManager
):
    new_domain_query = sql.select(Domain).filter(Domain.name == domain_name)
    new_domain = manager.session.execute(new_domain_query).scalar_one_or_none()

    if new_domain:
        return new_domain

    return directory.domain


def _run_gau_for_known_directory_ids(
    known_directories_ids: set[int], *, manager: LangdonManager
) -> None:
    CHUNK_SIZE = 8

    for chunk in itertools.batched(known_directories_ids, CHUNK_SIZE):
        task_queue.submit_task(_run_gau_for_chunk, chunk, manager=manager)


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


def _run_google_for_known_directory_ids(
    known_directories_ids: set[int], *, manager: LangdonManager
) -> None:
    CHUNK_SIZE = 8

    for chunk in itertools.batched(known_directories_ids, CHUNK_SIZE):
        task_queue.submit_task(_run_google_for_chunk, chunk, manager=manager)


def _discover_content_passively(*, manager: LangdonManager) -> None:
    recon_processes_ran_query = sql.select(ReconProcess.name)
    recon_processes_ran = set(manager.session.scalars(recon_processes_ran_query).all())

    assert "amass" in recon_processes_ran, (
        "Amass should be run before discovering domains actively."
    )
    assert "subfinder" in recon_processes_ran, (
        "Subfinder should be run before discovering domains actively."
    )
    assert "assetfinder" in recon_processes_ran, (
        "Assetfinder should be run before discovering domains actively."
    )

    known_directories_query = sql.select(WebDirectory.id)
    known_directories_ids = set(manager.session.scalars(known_directories_query).all())

    if not known_directories_ids:
        return logger.debug("No known directories to passively enumerate from")

    _run_gau_for_known_directory_ids(known_directories_ids, manager=manager)
    _run_google_for_known_directory_ids(known_directories_ids, manager=manager)
    task_queue.wait_for_all_tasks_to_finish(manager=manager)
    event_listener.wait_for_all_events_to_be_handled(manager=manager)


def _process_amass_for_domains(
    known_domains_names: set[str], *, manager: LangdonManager
) -> None:
    CHUNK_SIZE = 8

    for chunk in itertools.batched(known_domains_names, CHUNK_SIZE):
        task_queue.submit_task(_process_amass_for_chunk, chunk, manager=manager)


def _process_amass_for_chunk(known_domains_names: set[str]) -> None:
    amass_domain_regex = re.compile(r"(?P<domain>(?:[^.\s]*\.)*[^.\s]+) \(FQDN\)")
    amass_ip_address_regex = re.compile(
        r"(?P<ip_address>(?:(?:\d{1,3}\.){3}\d{1,3})|(?:[A-Fa-f0-9:]+)) \(IPAddress\)"
    )
    with LangdonManager() as manager:
        for known_domain_name in known_domains_names:
            with (
                suppress_timeout_expired_error(),
                suppress_called_process_error(),
                suppress_duplicated_recon_process(),
                shell_command_execution_context(
                    CommandData(command="amass", args=f"enum -d {known_domain_name}"),
                    manager=manager,
                    timeout=3600,
                ) as output,
            ):
                for line in output.splitlines():
                    _process_amass_line_for_domains(line, amass_domain_regex, manager)
                    _process_amass_line_for_ips(line, amass_ip_address_regex, manager)


def _process_amass_line_for_domains(
    line: str, regex: re.Pattern, manager: LangdonManager
) -> None:
    domains = regex.findall(line)
    if (not domains) and "FQDN" in line:
        raise LangdonProgrammingError(
            f"A new domain was found but was not retrieved from output:\n{line}"
        )
    for domain_name in domains:
        event_listener.send_event_message(
            DomainDiscovered(name=domain_name), manager=manager
        )


def _process_amass_line_for_ips(
    line: str, regex: re.Pattern, manager: LangdonManager
) -> None:
    ip_addresses = regex.findall(line)
    if (not ip_addresses) and "IPAddress" in line:
        raise LangdonProgrammingError(
            f"A new IP address was found but was not retrieved from output:\n{line}"
        )
    for ip_address in ip_addresses:
        event_listener.send_event_message(
            IpAddressDiscovered(address=ip_address),
            manager=manager,
        )


def _process_subfinder(temp_file_name: str) -> None:
    with (
        LangdonManager() as manager,
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(command="subfinder", args=f"-silent -dL {temp_file_name}"),
            manager=manager,
        ) as output,
    ):
        for domain_name in output.splitlines():
            if domain_name:
                event_listener.send_event_message(
                    DomainDiscovered(name=domain_name), manager=manager
                )


def _process_assetfinder_for_domains(known_domains_names: list[str]) -> None:
    with LangdonManager() as manager:
        for known_domain_name in known_domains_names:
            with (
                suppress_duplicated_recon_process(),
                shell_command_execution_context(
                    CommandData(
                        command="assetfinder", args=f"-subs-only {known_domain_name}"
                    ),
                    manager=manager,
                ) as output,
            ):
                for discovered_domain_name in output.splitlines():
                    if discovered_domain_name:
                        event_listener.send_event_message(
                            DomainDiscovered(name=discovered_domain_name),
                            manager=manager,
                        )


def _discover_domains_with_dnsgen_n_massdns(known_domain_names: list[str]) -> None:
    with LangdonManager() as manager:
        generated_domains = _generate_domains(known_domain_names, manager)
        _resolve_domains(generated_domains, manager)


def _discover_domains_actively(*, manager: LangdonManager) -> None:
    recon_processes_ran_query = sql.select(ReconProcess.name)
    recon_processes_ran = set(manager.session.scalars(recon_processes_ran_query).all())

    assert "gau" in recon_processes_ran, (
        "Gau should be run before discovering domains actively."
    )
    assert "enumerate_directories_with_google" in recon_processes_ran, (
        "Google should be run before discovering domains actively."
    )

    known_domain_names = _get_known_domain_names(manager)

    if not known_domain_names:
        return logger.debug("No known domains to actively enumerate from")

    task_queue.submit_task(
        _discover_domains_with_dnsgen_n_massdns, known_domain_names, manager=manager
    )
    _discover_domains_with_gobuster(known_domain_names, manager)

    task_queue.wait_for_all_tasks_to_finish(manager=manager)
    event_listener.wait_for_all_events_to_be_handled(manager=manager)


def _get_known_domain_names(manager: LangdonManager) -> list[str]:
    known_domains_query = sql.select(Domain.name)
    return set(manager.session.scalars(known_domains_query).all())


def _generate_domains(
    known_domain_names: list[str], manager: LangdonManager
) -> list[str]:
    
    utils.wait_for_slot_in_opened_files()
    with tempfile.NamedTemporaryFile("w+") as temp_file:
        temp_file.write("\n".join(known_domain_names))
        temp_file.seek(0)

        with (
            suppress_duplicated_recon_process(),
            shell_command_execution_context(
                CommandData(command="dnsgen", args=f"{temp_file.name}"),
                manager=manager,
            ) as output,
        ):
            return output.splitlines()


def _resolve_domains(generated_domains: list[str], manager: LangdonManager) -> None:
    resolvers_file = manager.config["resolvers_file"]

    utils.wait_for_slot_in_opened_files()
    with tempfile.NamedTemporaryFile("w+") as temp_file:
        temp_file.write("\n".join(generated_domains))
        temp_file.seek(0)

        with (
            suppress_duplicated_recon_process(),
            shell_command_execution_context(
                CommandData(
                    command="massdns",
                    args=f"--quiet --resolvers {resolvers_file} --output L {temp_file.name}",
                ),
                manager=manager,
            ) as output,
        ):
            for domain_name in output.splitlines():
                if domain_name:
                    event_listener.send_event_message(
                        DomainDiscovered(name=domain_name), manager=manager
                    )


def _discover_domains_with_gobuster(
    known_domain_names: list[str], manager: LangdonManager
) -> None:
    dns_wordlist = manager.config["dns_wordlist"]
    domain_regex = re.compile(r"(?P<domain>(?:[^.\s]*\.)[^.\s]*)")

    for known_domain_name in known_domain_names:
        with (
            suppress_duplicated_recon_process(),
            shell_command_execution_context(
                CommandData(
                    command="gobuster",
                    args=f"dns --domain {known_domain_name} --wordlist {dns_wordlist} "
                    "--quiet --no-color --delay 5s",
                ),
                manager=manager,
            ) as output,
        ):
            for domain_name in output.splitlines():
                if domain_match := domain_regex.match(domain_name):
                    domain_name = domain_match.group("domain")
                    event_listener.send_event_message(
                        DomainDiscovered(name=domain_name), manager=manager
                    )


WEB_FILE_EXTENSIONS = (
    "asp",
    "aspx",
    "bat",
    "c",
    "cfm",
    "cgi",
    "css",
    "com",
    "dll",
    "exe",
    "hta",
    "htm",
    "html",
    "inc",
    "jhtml",
    "js",
    "jsa",
    "json",
    "jsp",
    "log",
    "mdb",
    "nsf",
    "pcap",
    "php",
    "php2",
    "php3",
    "php4",
    "php5",
    "php6",
    "php7",
    "phps",
    "pht",
    "phtml",
    "pl",
    "phar",
    "rb",
    "reg",
    "sh",
    "shtml",
    "sql",
    "swf",
    "txt",
    "xml",
)


def _discover_content_actively(*, manager: LangdonManager) -> None:
    recon_processes_ran_query = sql.select(ReconProcess.name)
    recon_processes_ran = set(manager.session.scalars(recon_processes_ran_query).all())

    assert "dnsgen" in recon_processes_ran, (
        "DNSGen should be run before discovering domains actively."
    )
    assert "massdns" in recon_processes_ran, (
        "MassDNS should be run before discovering domains actively."
    )
    assert "gobuster" in recon_processes_ran, (
        "gobuster should be run before discovering domains actively."
    )

    known_urls_query = sql.select(
        Domain.name + sql.literal("/") + sql.func.ltrim(WebDirectory.path, "/")
    ).join(WebDirectory.domain)
    known_urls = set(manager.session.scalars(known_urls_query))

    if not known_urls:
        return logger.debug("No known URLs to actively enumerate content from")

    known_urls_separated_by_comma = ",".join(known_urls)
    extensions_separated_by_comma = ",".join(WEB_FILE_EXTENSIONS)
    user_agent = manager.config["user_agent"]

    task_queue.submit_task(
        _crawl_with_katana, known_urls_separated_by_comma, manager=manager
    )
    _discover_content_with_gobuster(
        known_urls, extensions_separated_by_comma, user_agent, manager
    )


def _crawl_with_katana(known_urls_separated_by_comma: str) -> None:
    with LangdonManager() as manager:
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
                    "-rate-limit-minute 12 -silent -no-color",
                ),
                manager=manager,
            ) as output,
        ):
            for line in output.splitlines():
                if line:
                    parsed_urls = urllib.parse.urlparse(line)
                    new_domain_name = parsed_urls.netloc.split(":")[0]
                    event_listener.send_event_message(
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


def _discover_content_with_gobuster(
    known_urls: list[str],
    extensions_separated_by_comma: str,
    user_agent: str,
    manager: LangdonManager,
) -> None:
    content_wordlist = manager.config["content_wordlist"]

    for known_url in known_urls:
        parsed_url = urllib.parse.urlparse(known_url)
        known_domain_name = parsed_url.netloc.split(":")[0]
        known_domain_query = sql.select(Domain).filter(Domain.name == known_domain_name)
        known_domain = manager.session.execute(known_domain_query).scalar_one()
        proxy = urllib.parse.urlunparse((
            "socks5",
            f"{manager.config['socks_proxy_host']}:"
            f"{manager.config['socks_proxy_port']}",
            "",
            "",
            "",
            "",
        ))

        with (
            suppress_duplicated_recon_process(),
            shell_command_execution_context(
                CommandData(
                    command="gobuster",
                    args=f"dir --url {known_url} --delay 5s --quiet "
                    f"--wordlist {content_wordlist} "
                    f"--extensions {extensions_separated_by_comma} --hide-length"
                    f"--no-status --retry --timeout 30 --useragent '{user_agent}'"
                    f"--proxy {proxy}",
                ),
                manager=manager,
            ) as output,
        ):
            for discovered_path in output.splitlines():
                if cleaned_path := discovered_path.strip():
                    event_listener.send_event_message(
                        WebDirectoryDiscovered(
                            path=cleaned_path, domain_id=known_domain.id, uses_ssl=True
                        ),
                        manager=manager,
                    )


def _process_known_domains() -> None:
    with LangdonManager() as manager:
        known_domains_query = sql.select(Domain.name).where(Domain.was_known == True)
        known_domain_names = set(manager.session.scalars(known_domains_query).all())

        if not known_domain_names:
            return logger.debug("No known domains to process")

        for domain_name in known_domain_names:
            event_listener.send_event_message(
                DomainDiscovered(name=domain_name), manager=manager
            )


def _process_known_ip_addresses() -> None:
    with LangdonManager() as manager:
        known_ip_addresses_query = sql.select(IpAddress.address).where(
            IpAddress.was_known == True
        )
        known_ip_addresses = set(
            manager.session.scalars(known_ip_addresses_query).all()
        )

        if not known_ip_addresses:
            return logger.debug("No known IP addresses to process")

        for ip_address in manager.session.scalars(known_ip_addresses_query):
            event_listener.send_event_message(
                IpAddressDiscovered(address=ip_address), manager=manager
            )


def run_recon(args: LangdonNamespace, *, manager: LangdonManager) -> None:
    if args.openvpn:
        openvpn_bin_path = shutil.which("openvpn")
        subprocess.Popen([openvpn_bin_path, str(args.openvpn.absolute())], check=True)

    systemctl_bin_path = shutil.which("systemctl")
    systemctl_command_line = shlex.split(f"{systemctl_bin_path} restart tor")
    subprocess.run(systemctl_command_line, check=True)

    webanalyze_bin_path = shutil.which("webanalyze")
    subprocess.run([webanalyze_bin_path, "-update"], check=True)

    with task_queue.task_queue_context(), event_listener.event_listener_context():
        task_queue.submit_task(_download_android_binaries, manager=manager)
        task_queue.submit_task(_process_known_domains, manager=manager)
        task_queue.submit_task(_process_known_ip_addresses, manager=manager)
        _discover_domains_from_known_ones_passively(manager=manager)
        _discover_content_passively(manager=manager)
        _discover_domains_actively(manager=manager)
        _discover_content_actively(manager=manager)

    print(f"{OutputColor.GREEN}Reconnaissance finished{OutputColor.RESET}")
