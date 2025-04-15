from __future__ import annotations

import concurrent.futures as CF
import contextlib
import multiprocessing
import os
import pathlib
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


_event_queue_fallback: Sequence[Mapping[str, Any]] = []


class EventListenerQueueManager(DataFileManagerABC[Sequence[Mapping[str, Any]]]):
    FILE_CONFIG_KEY = "event_queue_file"

    def get_default_file_initial_value(self) -> Sequence[Mapping[str, Any]]:
        return _event_queue_fallback

    def read_data_file(self):
        global _event_queue_fallback

        result = super().read_data_file()

        if result:
            _event_queue_fallback = result

        return result


def _handle_event_message_chunk(start_index: int, end_index: int) -> None:
    from langdon.langdon_manager import LangdonManager

    with LangdonManager() as manager:
        for curr_index in range(start_index, end_index):
            event_data = _get_event_data(curr_index, manager)

            if _should_skip_event(event_data):
                continue

            _process_event_data(curr_index, event_data, manager)


def _get_event_data(curr_index: int, manager: LangdonManager) -> dict[str, Any]:
    with EventListenerQueueManager(manager=manager) as queue_manager:
        return queue_manager.read_data_file()[curr_index]


def _should_skip_event(event_data: dict[str, Any]) -> bool:
    return event_data.get("was_handled", False)


def _process_event_data(
    curr_index: int, event_data: dict[str, Any], manager: LangdonManager
) -> None:
    try:
        _handle_event_message(event_data.copy())
    except Exception as e:
        logger.debug(
            "Error while handling event message: %s. Event data: %s",
            e,
            event_data,
            exc_info=True,
        )
    finally:
        _mark_event_as_handled(curr_index, event_data, manager)


def _mark_event_as_handled(
    curr_index: int, event_data: dict[str, Any], manager: LangdonManager
) -> None:
    with EventListenerQueueManager(manager=manager) as queue_manager:
        queue = list(queue_manager.read_data_file())
        try:
            queue[curr_index]["was_handled"] = True
        except IndexError:
            queue.append({**event_data, "was_handled": True})
        queue_manager.write_data_file(queue)


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


def _process_event_queue(*, manager: LangdonManager, executor: CF.Executor) -> bool:
    with EventListenerQueueManager(manager=manager) as queue_manager:
        queue = queue_manager.read_data_file()

    if all(event["was_handled"] for event in queue):
        return

    futures = []

    CHUNK_SIZE = 8

    for queue_index in range(0, len(queue), CHUNK_SIZE):
        futures.append(
            executor.submit(
                _handle_event_message_chunk,
                queue_index,
                min(queue_index + CHUNK_SIZE, len(queue)),
            )
        )

    CF.wait(futures)

    with EventListenerQueueManager(manager=manager) as queue_manager:
        queue_manager.write_data_file([])


def start_event_listener() -> None:
    from langdon.langdon_manager import LangdonManager

    with LangdonManager() as manager:
        try:
            max_workers = max((os.cpu_count() or 1) // 2, 1)

            with CF.ThreadPoolExecutor(max_workers) as executor:
                while True:
                    try:
                        _process_event_queue(manager=manager, executor=executor)

                    except KeyboardInterrupt:
                        break

                    time.sleep(1)

        finally:
            event_queue_file = manager.config["event_queue_file"]
            pathlib.Path(event_queue_file).unlink(missing_ok=True)


@contextlib.contextmanager
def event_listener_context() -> Iterator[None]:
    process = multiprocessing.Process(target=start_event_listener)
    logger.debug("Starting event listener process")

    try:
        yield process.start()

    finally:
        process.terminate()
        process.join()


def wait_for_all_events_to_be_handled(
    *, manager: LangdonManager, timeout: int | None = None
) -> None:
    """Wait for all events to be handled."""
    logger.debug("Waiting for all events to be handled")
    end_time = (time.time() + timeout) if timeout else None
    is_event_queue_empty = False

    while not is_event_queue_empty:
        time.sleep(random.randint(1, 3))

        with EventListenerQueueManager(manager=manager) as event_queue_manager:
            queue = event_queue_manager.read_data_file()

        is_event_queue_empty = all(event["was_handled"] for event in queue)

        if end_time and time.time() > end_time:
            logger.warning(
                "Timeout reached while waiting for events to be handled, continuing"
            )
            break


def send_event_message(event: T, *, manager: LangdonManager) -> None:
    """Send an event message to the event listener queue."""
    from langdon.events import Event

    if not isinstance(event, Event):
        raise ValueError("Event must be an instance of Event")

    event_data = event.model_dump(mode="json")
    event_data["type"] = type(event).__name__
    event_data["was_handled"] = False

    with EventListenerQueueManager(manager=manager) as event_manager:
        queue_data = list(event_manager.read_data_file())
        queue_data.append(event_data)
        event_manager.write_data_file(queue_data)
