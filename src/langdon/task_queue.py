from __future__ import annotations

import concurrent.futures as CF
import contextlib
import multiprocessing
import os
import pathlib
import random
import re
import time
from typing import TYPE_CHECKING, Any, TypedDict

import pydantic
from langdon_core.langdon_logging import logger

from langdon.exceptions import LangdonProgrammingError
from langdon.langdon_manager import LangdonManager

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

TaskId = int


class TaskDict(TypedDict):
    func: str
    args: tuple
    was_executed: bool
    kwargs: dict


class Task(pydantic.BaseModel):
    func: str
    args: tuple[Any, ...]
    was_executed: bool = False
    kwargs: dict[str, Any]

    @pydantic.field_validator("func")
    @classmethod
    def validate_func(cls, value: str) -> str:
        function_regex = r"^(?:[a-zA-Z_][a-zA-Z0-9_.]*\.)*[a-zA-Z_][a-zA-Z0-9_]*$"
        if not re.match(function_regex, value):
            raise ValueError("Invalid function name")
        return value


_task_queue: multiprocessing.Queue | None = None


def start_task_executor() -> None:
    """
    Continuously execute tasks from the queue.
    """
    max_workers = max((os.cpu_count() or 1) // 2, 1)

    with LangdonManager() as manager:
        try:
            with CF.ThreadPoolExecutor(max_workers) as executor:
                while True:
                    try:
                        process_tasks(executor=executor)
                    except KeyboardInterrupt:
                        break

                    time.sleep(1)
        finally:
            task_queue_file = manager.config["task_queue_file"]
            pathlib.Path(task_queue_file).unlink(missing_ok=True)


def _process_task(func: Callable[..., None], *args: tuple, **kwargs: dict) -> None:
    """
    Process a single task.

    Args:
        func (Callable[..., None]): The function to be executed.
        *args (tuple): Positional arguments to be passed to the function.
        **kwargs (dict): Keyword arguments to be passed to the function.
    """
    try:
        func(*args, **kwargs)

    except Exception as e:
        logger.debug("Error executing task: %s", e, exc_info=True)


def process_tasks(*, executor: CF.ThreadPoolExecutor) -> None:
    """
    Process tasks from the task queue.

    Args:
        file_manager (TaskQueueFileManager): The file manager for the task queue.
        executor (CF.ThreadPoolExecutor): The thread pool executor.
    """
    futures = []

    while not _task_queue.empty():
        task = Task.model_validate(_task_queue.get())

        module_name, func_name = task.func.rsplit(".", 1)
        module = __import__(module_name, fromlist=[func_name])
        func = getattr(module, func_name)

        futures.append(executor.submit(_process_task, func, *task.args, **task.kwargs))

    CF.wait(futures) if futures else None


def wait_for_all_tasks_to_finish(*, timeout: int | None = None) -> None:
    """
    Wait for all tasks in the queue to finish.

    Args:
        manager (LangdonManager): The LangdonManager instance.
        timeout (int): The maximum time to wait for tasks to finish.
    """
    logger.debug("Waiting for all tasks to finish")
    end_time = (time.time() + timeout) if timeout else None

    is_task_queue_empty = _task_queue.empty()

    while not is_task_queue_empty:
        time.sleep(random.randint(1, 3))
        is_task_queue_empty = _task_queue.empty()

        if end_time and time.time() > end_time:
            logger.warning(
                "Timeout reached while waiting for tasks to finish, continuing"
            )
            break


@contextlib.contextmanager
def task_queue_context() -> Iterator[None]:
    """
    Context manager for the task queue.
    """
    global _task_queue

    if _task_queue:
        raise LangdonProgrammingError(
            f"{task_queue_context.__name__} should be called only once"
        )

    _task_queue = multiprocessing.Queue(4)

    process = multiprocessing.Process(target=start_task_executor, args=(_task_queue,))
    logger.debug("Starting task queue process")

    try:
        yield process.start()
    finally:
        process.terminate()
        process.join()
        _task_queue.close()
        _task_queue = None


def submit_task(
    func: Callable[..., None], *args: tuple, manager: LangdonManager, **kwargs: dict
) -> None:
    """
    Submit a task to the queue.

    Args:
        func (Callable[..., None]): The function to be executed.
        *args (tuple): Positional arguments to be passed to the function.
        **kwargs (dict): Keyword arguments to be passed to the function.
    """
    new_task = Task(
        func=f"{func.__module__}.{func.__name__}",
        args=args,
        kwargs=kwargs,
    )

    if not _task_queue:
        raise LangdonProgrammingError(
            f"{submit_task.__name__} should be called within "
            f"{task_queue_context.__name__}"
        )

    FIVE_MINUTES = 300
    _task_queue.put(new_task.model_dump(mode="json"), True, FIVE_MINUTES)
