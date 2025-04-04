from __future__ import annotations

import concurrent.futures as CF
import contextlib
import multiprocessing
import os
import random
import re
import time
from collections.abc import Callable, Iterator, Sequence
from typing import Any, TypedDict

import pydantic

from langdon.abc import DataFileManagerABC
from langdon.langdon_logging import logger
from langdon.langdon_manager import LangdonManager


class TaskDict(TypedDict):
    func: str
    args: tuple
    kwargs: dict


class Task(pydantic.BaseModel):
    func: str
    args: tuple[Any, ...]
    kwargs: dict[str, Any]

    @pydantic.field_validator("func")
    @classmethod
    def validate_func(cls, value: str) -> str:
        function_regex = r"^(?:[a-zA-Z_][a-zA-Z0-9_.]*\.)*[a-zA-Z_][a-zA-Z0-9_]*$"
        if not re.match(function_regex, value):
            raise ValueError("Invalid function name")
        return value


class TaskQueueFileManager(DataFileManagerABC[Sequence[TaskDict]]):
    FILE_CONFIG_KEY = "task_queue_file"

    def get_default_file_initial_value(self) -> Sequence[TaskDict]:
        return []


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

    file_manager = TaskQueueFileManager(manager)
    new_task = Task(
        func=f"{func.__module__}.{func.__name__}",
        args=args,
        kwargs=kwargs,
    )
    current_tasks = list(file_manager.read_data_file()) + [
        new_task.model_dump(mode="json")
    ]
    file_manager.write_data_file(current_tasks)


def start_task_executor() -> None:
    """
    Continuously execute tasks from the queue.
    """
    max_workers = os.cpu_count() or 1

    with CF.ThreadPoolExecutor(max_workers) as executor, LangdonManager() as manager:
        file_manager = TaskQueueFileManager(manager)
        while True:
            try:
                process_tasks(file_manager, executor)
            except KeyboardInterrupt:
                break

            time.sleep(1)


def process_tasks(
    file_manager: TaskQueueFileManager, executor: CF.ThreadPoolExecutor
) -> None:
    """
    Process tasks from the task queue.

    Args:
        file_manager (TaskQueueFileManager): The file manager for the task queue.
        executor (CF.ThreadPoolExecutor): The thread pool executor.
    """
    tasks = file_manager.read_data_file()

    if tasks:
        futures = []

        for raw_task in tasks:
            task = Task.model_validate(raw_task)

            module_name, func_name = task.func.rsplit(".", 1)
            module = __import__(module_name, fromlist=[func_name])
            func = getattr(module, func_name)

            futures.append(executor.submit(func, *task.args, **task.kwargs))

        CF.wait(futures)
        file_manager.write_data_file([])


def wait_for_all_tasks_to_finish(
    *, manager: LangdonManager, timeout: int | None
) -> None:
    """
    Wait for all tasks in the queue to finish.

    Args:
        manager (LangdonManager): The LangdonManager instance.
        timeout (int): The maximum time to wait for tasks to finish.
    """
    logger.debug("Waiting for all tasks to finish")
    end_time = (time.time() + timeout) if timeout else None

    file_manager = TaskQueueFileManager(manager)
    is_task_queue_empty = False

    while not is_task_queue_empty:
        time.sleep(random.randint(1, 3))

        tasks = file_manager.read_data_file()
        is_task_queue_empty = not tasks

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
    process = multiprocessing.Process(target=start_task_executor)
    logger.debug("Starting task queue process")

    try:
        yield process.start()
    finally:
        process.terminate()
        process.join()
