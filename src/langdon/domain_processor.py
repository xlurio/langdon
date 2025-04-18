import argparse

from langdon import event_listener, task_queue
from langdon.events import DomainDiscovered
from langdon.langdon_manager import LangdonManager
from langdon.output import OutputColor


class ProcessDomainNamespace(argparse.Namespace):
    domain: str


def process_domain(args: ProcessDomainNamespace, *, manager: LangdonManager) -> None:
    with task_queue.task_queue_context(), event_listener.event_listener_context():
        event_listener.handle_event(DomainDiscovered(name=args.domain), manager=manager)
        task_queue.wait_for_all_tasks_to_finish(manager=manager)
        event_listener.wait_for_all_events_to_be_handled(manager=manager)

    print(f"{OutputColor.GREEN}Domain processed successfully!{OutputColor.RESET}")
