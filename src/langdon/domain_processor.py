import argparse

from langdon import event_listener, task_queue
from langdon.events import DomainDiscovered
from langdon.langdon_manager import LangdonManager
from langdon.output import OutputColor


class ProcessDomainNamespace(argparse.Namespace):
    domain: str


def internal_process_domain(domain_name: str, *, manager: LangdonManager) -> None:
    with task_queue.task_queue_context(), event_listener.event_listener_context():
        event_listener.handle_event(DomainDiscovered(name=domain_name), manager=manager)
        task_queue.wait_for_all_tasks_to_finish()
        event_listener.wait_for_all_events_to_be_handled()


def process_domain(args: ProcessDomainNamespace, *, manager: LangdonManager) -> None:
    internal_process_domain(args.domain, manager=manager)

    print(f"{OutputColor.GREEN}Domain processed successfully!{OutputColor.RESET}")
