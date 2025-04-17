import argparse
import shlex
import shutil
import subprocess
import urllib.parse

from langdon_core.models import Domain
from sqlalchemy import sql

from langdon import event_listener, task_queue
from langdon.events import DomainDiscovered, WebDirectoryDiscovered
from langdon.langdon_manager import LangdonManager
from langdon.output import OutputColor


class ScreenshotTakerNamespace(argparse.Namespace):
    url: str


def take_screenshot(args: ScreenshotTakerNamespace, *, manager: LangdonManager) -> None:
    if args.openvpn:
        openvpn_bin_path = shutil.which("openvpn")
        subprocess.Popen([openvpn_bin_path, str(args.openvpn.absolute())], check=True)

    systemctl_bin_path = shutil.which("systemctl")
    systemctl_command_line = shlex.split(f"{systemctl_bin_path} restart tor")
    subprocess.run(systemctl_command_line)

    webanalyze_bin_path = shutil.which("webanalyze")
    subprocess.run([webanalyze_bin_path, "-update"], check=True)

    parsedurl = urllib.parse.urlparse(args.url)
    urlpath = parsedurl.path or "/"

    with task_queue.task_queue_context(), event_listener.event_listener_context():
        event_listener.handle_event(
            DomainDiscovered(name=parsedurl.netloc.split(":")[0]), manager=manager
        )
        domain_query = sql.select(Domain).where(
            Domain.name == parsedurl.netloc.split(":")[0]
        )
        domain = manager.session.execute(domain_query).scalar_one()

        event_listener.handle_event(
            WebDirectoryDiscovered(
                path=urlpath,
                domain_id=domain.id,
                uses_ssl=parsedurl.scheme == "https",
            ),
            manager=manager,
        )

    print(
        f"{OutputColor.GREEN}Successfully taken shot from {args.url}{OutputColor.RESET}"
    )
