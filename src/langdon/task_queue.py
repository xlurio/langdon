from __future__ import annotations

import concurrent.futures as CF
import contextlib
import json
import multiprocessing
import os
import time
from collections.abc import Callable, Iterator, Sequence
from typing import TypedDict

from langdon.abc import DataFileManagerABC
from langdon.langdon_manager import LangdonManager


class TaskDict(TypedDict):
    func: str
    args: tuple
    kwargs: dict


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
    new_task = json.dumps({
        "func": f"{func.__module__}.{func.__name__}",
        "args": args,
        "kwargs": kwargs,
    })
    current_tasks = list(*file_manager.read_data_file()).append(new_task)
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
        for task in tasks:
            func_name = task["func"]
            args = task["args"]
            kwargs = task["kwargs"]

            module_name, func_name = func_name.rsplit(".", 1)
            module = __import__(module_name, fromlist=[func_name])
            func = getattr(module, func_name)

            executor.submit(func, *args, **kwargs)

        file_manager.write_data_file([])


def wait_for_all_tasks_to_finish(*, manager: LangdonManager) -> None:
    """
    Wait for all tasks in the queue to finish.

    Args:
        manager (LangdonManager): The LangdonManager instance.
        timeout (int): The maximum time to wait for tasks to finish.
    """
    file_manager = TaskQueueFileManager(manager)
    is_task_queue_empty = False

    while not is_task_queue_empty:
        tasks = file_manager.read_data_file()
        is_task_queue_empty = not tasks

        if not is_task_queue_empty:
            time.sleep(1)


@contextlib.contextmanager
def task_queue_context() -> Iterator[None]:
    """
    Context manager for the task queue.
    """
    process = multiprocessing.Process(target=start_task_executor)

    try:
        yield process.start()
    finally:
        process.terminate()
        process.join()
