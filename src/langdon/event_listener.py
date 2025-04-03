from __future__ import annotations

import concurrent.futures as CF
import contextlib
import multiprocessing
import os
import random
import time
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, TypeVar

from langdon.abc import DataFileManagerABC
from langdon.langdon_logging import logger

if TYPE_CHECKING:
    from collections.abc import Iterator

    from langdon.events import Event
    from langdon.langdon_manager import LangdonManager

T = TypeVar("T", bound="Event")


EVENT_LISTENER_QUEUE = "event_listener"


def _handle_event(event: T, *, manager: LangdonManager) -> None:
    from langdon.event_handlers import (
        domain_discovered_handler,
        http_cookie_discovered_handler,
        http_header_dicovered_handler,
        ip_address_discovered_handler,
        port_discovered_handler,
        technology_discovered_handler,
        vulnerability_discovered_handler,
        web_directory_discovered_handler,
    )
    from langdon.events import (
        DomainDiscovered,
        HttpCookieDiscovered,
        HttpHeaderDiscovered,
        IpAddressDiscovered,
        PortDiscovered,
        TechnologyDiscovered,
        VulnerabilityDiscovered,
        WebDirectoryDiscovered,
    )

    EVENT_HANDLERS_MAPPING = {
        VulnerabilityDiscovered: vulnerability_discovered_handler.handle_event,
        TechnologyDiscovered: technology_discovered_handler.handle_event,
        DomainDiscovered: domain_discovered_handler.handle_event,
        IpAddressDiscovered: ip_address_discovered_handler.handle_event,
        PortDiscovered: port_discovered_handler.handle_event,
        WebDirectoryDiscovered: web_directory_discovered_handler.handle_event,
        HttpHeaderDiscovered: http_header_dicovered_handler.handle_event,
        HttpCookieDiscovered: http_cookie_discovered_handler.handle_event,
    }

    EVENT_HANDLERS_MAPPING[type(event)](event, manager=manager)


def _handle_event_message(body: dict[str, Any]):
    from langdon.langdon_manager import LangdonManager

    with LangdonManager() as manager:
        from langdon.events import (
            DomainDiscovered,
            HttpCookieDiscovered,
            HttpHeaderDiscovered,
            IpAddressDiscovered,
            PortDiscovered,
            TechnologyDiscovered,
            VulnerabilityDiscovered,
            WebDirectoryDiscovered,
        )

        event_type = body.pop("type")

        EVENT_CLASSES = {
            "VulnerabilityDiscovered": VulnerabilityDiscovered,
            "TechnologyDiscovered": TechnologyDiscovered,
            "DomainDiscovered": DomainDiscovered,
            "IpAddressDiscovered": IpAddressDiscovered,
            "PortDiscovered": PortDiscovered,
            "WebDirectoryDiscovered": WebDirectoryDiscovered,
            "HttpHeaderDiscovered": HttpHeaderDiscovered,
            "HttpCookieDiscovered": HttpCookieDiscovered,
        }

        event_class = EVENT_CLASSES.get(event_type)
        if not event_class:
            raise ValueError(f"Unknown event type: {event_type}")

        event = event_class(**body)
        _handle_event(event, manager=manager)


class EventListenerQueueManager(DataFileManagerABC[Sequence[Mapping[str, Any]]]):
    FILE_CONFIG_KEY = "event_queue_file"

    def get_default_file_initial_value(self) -> Sequence[Mapping[str, Any]]:
        return []


def _process_event_queue(
    *, manager: EventListenerQueueManager, executor: CF.Executor
) -> bool:
    queue = manager.read_data_file()

    if not queue:
        return

    futures = []

    for event_data in queue:
        futures.append(executor.submit(_handle_event_message, event_data))

    CF.wait(futures)
    manager.write_data_file([])


def start_event_listener() -> None:
    from langdon.langdon_manager import LangdonManager

    max_workers = os.cpu_count() or 1

    with CF.ThreadPoolExecutor(max_workers) as executor, LangdonManager() as manager:
        event_queue_manager = EventListenerQueueManager(manager=manager)

        while True:
            try:
                _process_event_queue(manager=event_queue_manager, executor=executor)

            except KeyboardInterrupt:
                break

            time.sleep(1)


@contextlib.contextmanager
def event_listener_context() -> Iterator[None]:
    process = multiprocessing.Process(target=start_event_listener)
    logger.debug("Starting event listener process")

    try:
        yield process.start()

    finally:
        process.terminate()
        process.join()


def wait_for_all_events_to_be_handled(*, manager: LangdonManager) -> None:
    """Wait for all events to be handled."""
    logger.debug("Waiting for all events to be handled")

    event_queue_manager = EventListenerQueueManager(manager=manager)
    is_event_queue_empty = False

    while not is_event_queue_empty:
        queue = list(*event_queue_manager.read_data_file(manager=manager))
        is_event_queue_empty = not queue

        if not is_event_queue_empty:
            time.sleep(random.randint(1, 3))


def send_event_message(event: T, *, manager: LangdonManager) -> None:
    """Send an event message to the event listener queue."""
    from langdon.events import Event

    event_manager = EventListenerQueueManager(manager=manager)

    if not isinstance(event, Event):
        raise ValueError("Event must be an instance of Event")

    event_data = event.model_dump(mode="json")
    event_data["type"] = type(event).__name__

    queue_data = list(event_manager.read_data_file())
    queue_data.append(event_data)
    event_manager.write_data_file(queue_data)
