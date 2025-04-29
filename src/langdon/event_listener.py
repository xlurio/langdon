from __future__ import annotations

import concurrent.futures as CF
import contextlib
import itertools
import multiprocessing
import os
import pathlib
import random
import time
from typing import TYPE_CHECKING, Any, TypeVar

from langdon_core.langdon_logging import logger

from langdon.exceptions import LangdonProgrammingError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from langdon.events import Event
    from langdon.langdon_manager import LangdonManager

T = TypeVar("T", bound="Event")


EVENT_LISTENER_QUEUE = "event_listener"


def handle_event(event: T, *, manager: LangdonManager) -> None:
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


_event_queue: multiprocessing.Queue | None = None


def _handle_event_message_chunk(
    event_queue: multiprocessing.Queue, chunk_size: int
) -> None:
    from langdon.langdon_manager import LangdonManager

    with LangdonManager() as manager:
        for _ in range(chunk_size):
            event_data = event_queue.get()

            _process_event_data(event_data)


def _process_event_data(event_data: dict[str, Any]) -> None:
    try:
        _handle_event_message(event_data.copy())
    except Exception as e:
        logger.debug(
            "Error while handling event message: %s. Event data: %s",
            e,
            event_data,
            exc_info=True,
        )


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
        handle_event(event, manager=manager)


def _process_event_queue(
    event_queue: multiprocessing.Queue, *, executor: CF.Executor
) -> bool:
    DEFAULT_CHUNK_SIZE = 8
    futures = []

    while not event_queue.empty():
        counter = itertools.count()
        next_events_to_be_handled = []
        final_chunk_size = min(DEFAULT_CHUNK_SIZE, event_queue.qsize())
        should_append_more_events = next(counter) < final_chunk_size

        while should_append_more_events:
            next_events_to_be_handled.append(event_queue.get())
            should_append_more_events = next(counter) < min(
                DEFAULT_CHUNK_SIZE, event_queue.qsize()
            )

        futures.append(
            executor.submit(_handle_event_message_chunk, event_queue, final_chunk_size)
        )

    CF.wait(futures) if futures else None


def start_event_listener(event_queue: multiprocessing.Queue) -> None:
    from langdon.langdon_manager import LangdonManager

    with LangdonManager() as manager:
        try:
            max_workers = max((os.cpu_count() or 1) // 2, 1)

            with CF.ThreadPoolExecutor(max_workers) as executor:
                while True:
                    try:
                        _process_event_queue(event_queue, executor=executor)

                    except KeyboardInterrupt:
                        break

                    time.sleep(1)

        finally:
            event_queue_file = manager.config["event_queue_file"]
            pathlib.Path(event_queue_file).unlink(missing_ok=True)


@contextlib.contextmanager
def event_listener_context() -> Iterator[None]:
    global _event_queue

    if _event_queue:
        raise LangdonProgrammingError(
            f"{event_listener_context.__name__} should be called only once"
        )

    _event_queue = multiprocessing.Queue(32)
    process = multiprocessing.Process(target=start_event_listener, args=(_event_queue,))
    logger.debug("Starting event listener process")

    try:
        yield process.start()

    finally:
        process.terminate()
        process.join()
        _event_queue.close()
        _event_queue = None


def wait_for_all_events_to_be_handled(*, timeout: int | None = None) -> None:
    """Wait for all events to be handled."""
    logger.debug("Waiting for all events to be handled")
    end_time = (time.time() + timeout) if timeout else None
    is_event_queue_empty = _event_queue.empty()

    while not is_event_queue_empty:
        time.sleep(random.randint(1, 3))
        is_event_queue_empty = _event_queue.empty()

        if end_time and time.time() > end_time:
            logger.warning(
                "Timeout reached while waiting for events to be handled, continuing"
            )
            break


def send_event_message(event: T) -> None:
    """Send an event message to the event listener queue."""
    from langdon.events import Event

    if not isinstance(event, Event):
        raise ValueError("Event must be an instance of Event")

    event_data = event.model_dump(mode="json")
    event_data["type"] = type(event).__name__
    event_data["was_handled"] = False

    if not _event_queue:
        raise LangdonProgrammingError(
            f"{send_event_message.__name__} should be called within "
            f"{event_listener_context.__name__}"
        )

    ONE_HOUR = 3600
    _event_queue.put(event_data, True, ONE_HOUR)
