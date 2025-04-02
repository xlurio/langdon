from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import tempfile
import urllib.parse
from typing import TYPE_CHECKING

from sqlalchemy import sql

from langdon import message_broker
from langdon.command_executor import (
    CommandData,
    shell_command_execution_context,
    suppress_duplicated_recon_process,
    suppress_timeout_expired_error,
)
from langdon.events import DomainDiscovered, IpAddressDiscovered, WebDirectoryDiscovered
from langdon.exceptions import LangdonProgrammingError
from langdon.langdon_manager import LangdonManager
from langdon.models import AndroidApp, Domain, WebDirectory
from langdon.output import OutputColor

if TYPE_CHECKING:
    from langdon.langdon_argparser import LangdonNamespace


def _download_android_binaries(*, manager: LangdonManager) -> None:
    android_bin_dir = manager.config["downloaded_apks_dir"]
    android_apps_query = sql.select(AndroidApp.android_app_id)
    for android_app_id in manager.session.scalars(android_apps_query):
        with (
            suppress_duplicated_recon_process(),
            shell_command_execution_context(
                CommandData(
                    command="apkeep", args=f"--app {android_app_id} {android_bin_dir}"
                ),
                manager=manager,
            ),
        ):
            ...


def _discover_domains_from_known_ones_passively(*, manager: LangdonManager) -> None:
    known_domains_query = sql.select(Domain.name).where(Domain.was_known == True)
    known_domains_names = set(manager.session.scalars(known_domains_query))

    with tempfile.NamedTemporaryFile("w+") as temp_file:
        temp_file.write("\n".join(known_domains_names))
        temp_file.seek(0)

        _process_amass_for_domains(known_domains_names, manager)
        _process_subfinder(temp_file.name, manager)
        _process_assetfinder(known_domains_names, manager)

    manager.wait_for_pending_tasks()


def _process_amass_for_domain(domain: str) -> None:
    amass_domain_regex = re.compile(r"(?P<domain>(?:[^.\s]*\.)*[^.\s]+) \(FQDN\)")
    amass_ip_address_regex = re.compile(
        r"(?P<ip_address>(?:\d{1,3}\.){3}\d{1,3}) \(IPAddress\)"
    )
    with (
        LangdonManager() as manager,
        suppress_timeout_expired_error(),
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(command="amass", args=f"enum -d {domain}"),
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
        message_broker.dispatch_event(
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
        message_broker.dispatch_event(
            IpAddressDiscovered(address=ip_address),
            manager=manager,
        )


def _process_amass_for_domains(domains: set[str], manager: LangdonManager) -> None:
    for domain in domains:
        manager.submit_task(_process_amass_for_domain, domain)


def _process_subfinder(temp_file_name: str, manager: LangdonManager) -> None:
    with (
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(command="subfinder", args=f"-silent -dL {temp_file_name}"),
            manager=manager,
        ) as output,
    ):
        for domain_name in output.splitlines():
            if domain_name:
                message_broker.dispatch_event(
                    DomainDiscovered(name=domain_name), manager=manager
                )


def _process_assetfinder(
    known_domains_names: list[str], manager: LangdonManager
) -> None:
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
            for domain_name in output.splitlines():
                if domain_name:
                    message_broker.dispatch_event(
                        DomainDiscovered(name=domain_name), manager=manager
                    )


def _discover_domains_actively(*, manager: LangdonManager) -> None:
    known_domain_names = _get_known_domain_names(manager)
    generated_domains = _generate_domains(known_domain_names, manager)
    _resolve_domains(generated_domains, manager)
    _discover_domains_with_gobuster(known_domain_names, manager)


def _get_known_domain_names(manager: LangdonManager) -> list[str]:
    known_domains_query = sql.select(Domain.name)
    return set(manager.session.scalars(known_domains_query))


def _generate_domains(
    known_domain_names: list[str], manager: LangdonManager
) -> list[str]:
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
                    message_broker.dispatch_event(
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
                    "--quiet --no-color --delay 5",
                ),
                manager=manager,
            ) as output,
        ):
            for domain_name in output.splitlines():
                if domain_match := domain_regex.match(domain_name):
                    domain_name = domain_match.group("domain")
                    message_broker.dispatch_event(
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
    known_urls_query = sql.select(
        Domain.name + sql.literal("/") + sql.func.ltrim(WebDirectory.path, "/")
    ).join(WebDirectory.domain)
    known_urls = set(manager.session.scalars(known_urls_query))
    known_urls_separated_by_comma = ",".join(known_urls)
    extensions_separated_by_comma = ",".join(WEB_FILE_EXTENSIONS)
    user_agent = manager.config["user_agent"]

    _crawl_with_katana(known_urls_separated_by_comma, manager)
    _discover_content_with_gobuster(
        known_urls, extensions_separated_by_comma, user_agent, manager
    )


def _crawl_with_katana(
    known_urls_separated_by_comma: str, manager: LangdonManager
) -> None:
    with (
        suppress_duplicated_recon_process(),
        shell_command_execution_context(
            CommandData(
                command="katana",
                args=f"-list {known_urls_separated_by_comma} -js-crawl -known-files all "
                "-proxy localhost:9050 -headless -delay 5s -rate-limit-minute 12 -silent "
                "-no-color",
            ),
            manager=manager,
        ) as output,
    ):
        for line in output.splitlines():
            if line:
                parsed_urls = urllib.parse.urlparse(line)
                new_domain_name = parsed_urls.netloc.split(":")[0]
                message_broker.dispatch_event(
                    DomainDiscovered(name=new_domain_name), manager=manager
                )

                new_domain_query = sql.select(Domain).filter(
                    Domain.name == new_domain_name
                )
                new_domain = manager.session.execute(new_domain_query).scalar_one()

                path = parsed_urls.path
                message_broker.dispatch_event(
                    WebDirectoryDiscovered(path=path, domain=new_domain, uses_ssl=True),
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

        with (
            suppress_duplicated_recon_process(),
            shell_command_execution_context(
                CommandData(
                    command="gobuster",
                    args=f"dir --url {known_url} --delay 5s --quiet "
                    f"--wordlist {content_wordlist} "
                    f"--extensions {extensions_separated_by_comma} --hide-length"
                    f"--no-status --retry --timeout 30 --useragent '{user_agent}'"
                    "--proxy socks5://localhost:9050",
                ),
                manager=manager,
            ) as output,
        ):
            for discovered_path in output.splitlines():
                if cleaned_path := discovered_path.strip():
                    message_broker.dispatch_event(
                        WebDirectoryDiscovered(
                            path=cleaned_path, domain=known_domain, uses_ssl=True
                        ),
                        manager=manager,
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

    _download_android_binaries(manager=manager)
    _discover_domains_from_known_ones_passively(manager=manager)
    _discover_domains_actively(manager=manager)
    _discover_content_actively(manager=manager)

    print(f"{OutputColor.GREEN}Reconnaissance finished{OutputColor.RESET}")
