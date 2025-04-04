import abc
import json
import multiprocessing
import pathlib
import threading
from abc import abstractmethod
from typing import Generic, TypeVar

from langdon.langdon_logging import logger
from langdon.langdon_manager import LangdonManager
from langdon.langdon_t import ConfigurationKeyT

T = TypeVar("T")


class DataFileManagerABC(abc.ABC, Generic[T]):
    FILE_CONFIG_KEY: ConfigurationKeyT

    def __init__(self, manager: LangdonManager) -> None:
        self.__manager = manager
        self.__process_queue_lock = multiprocessing.Lock()
        self.__thread_queue_lock = threading.Lock()
        self.__data_file_path = pathlib.Path(
            self.__manager.config[self.FILE_CONFIG_KEY]
        )

    @abstractmethod
    def get_default_file_initial_value(self) -> T:
        raise NotImplementedError

    def read_data_file(self) -> T:
        with self.__process_queue_lock, self.__thread_queue_lock:
            try:
                return json.loads(self.__data_file_path.read_text())

            except json.JSONDecodeError:
                logger.warning(
                    "The %s file is empty or corrupted", self.__data_file_path
                )

            except FileNotFoundError:
                logger.debug("File %s not found", self.__data_file_path)

        return self.get_default_file_initial_value()

    def write_data_file(self, data: T) -> None:
        is_data_iterable = hasattr(data, "__iter__") and not isinstance(data, str)
        is_data_mapping = hasattr(data, "keys") and not isinstance(data, str)

        if not is_data_iterable and not is_data_mapping:
            raise TypeError(
                f"Data must be iterable or mapping, got {type(data).__name__}"
            )

        with self.__process_queue_lock, self.__thread_queue_lock:
            self.__data_file_path.write_text(json.dumps(data))

    @property
    def langdon_manager(self) -> LangdonManager:
        return self.__manager
