import contextlib
import shlex
import shutil
import subprocess
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any, Generic, TypeVar

import pydantic
from sqlalchemy import sql

from langdon.exceptions import DuplicatedReconProcessException, LangdonException
from langdon.langdon_logging import logger
from langdon.langdon_manager import LangdonManager
from langdon.models import ReconProcess

T = TypeVar("T")


class CommandData(pydantic.BaseModel):
    command: str
    args: str

    @property
    def shell_command_line(self) -> list[str]:
        return shlex.split(f"{self.cleaned_command} {self.args}")

    @property
    def cleaned_command(self) -> str:
        cleaned_command = shutil.which(self.command)

        if cleaned_command is None:
            raise LangdonException(
                f"Command '{self.command}' is not available in the system"
            )

        return cleaned_command


def _try_to_execute_command(
    command: CommandData, *, ignore_exit_code: bool = False
) -> str:
    try:
        logger.debug("Executing command: %s", command.shell_command_line)
        result = subprocess.run(
            command.shell_command_line, capture_output=True, check=not ignore_exit_code
        ).stdout.decode()
        logger.debug("Output:\n%s", result)

        return result
    except subprocess.CalledProcessError as exception:
        cleaned_stderr = (
            exception.stderr.decode()
            if isinstance(exception.stderr, bytes)
            else "unknown"
        )
        error_message = (
            f"Command '{command.command}' with args '{command.args}' failed with code "
            f"{exception.returncode}: {cleaned_stderr}"
        )

        logger.debug(error_message, exc_info=True)
        raise LangdonException(error_message) from exception


@contextlib.contextmanager
def shell_command_execution_context(
    command: CommandData, *, manager: LangdonManager, ignore_exit_code: bool = False
) -> Iterator[str]:
    session = manager.session
    query = (
        sql.select(ReconProcess)
        .where(ReconProcess.name == command.command)
        .where(ReconProcess.args == command.args)
    )

    if session.execute(query).scalar_one_or_none() is not None:
        raise DuplicatedReconProcessException(
            f"Recon process '{command.command}' with args '{command.args}' was already "
            "successfully executed",
            command=command.shell_command_line,
        )

    yield _try_to_execute_command(command, ignore_exit_code=ignore_exit_code)

    session.add(ReconProcess(name=command.command, args=command.args))
    session.commit()


class FunctionData(pydantic.BaseModel, Generic[T]):
    function: Callable[..., T]
    args: Sequence[str] | None = None
    kwargs: Mapping[str, Any] | None = None

    @property
    def cleaned_args(self) -> Sequence[str]:
        return tuple(self.args or ())

    @property
    def cleaned_kwargs(self) -> Mapping[str, Any]:
        return dict(self.kwargs or {})

    @property
    def args_kwargs_str(self) -> str:
        return f"{self.cleaned_args!s} {self.cleaned_kwargs!s}"


@contextlib.contextmanager
def function_execution_context(
    func_data: FunctionData[T], *, manager: LangdonManager
) -> Iterator[T]:
    session = manager.session
    query = (
        sql.select(ReconProcess)
        .where(ReconProcess.name == func_data.function.__name__)
        .where(ReconProcess.args == func_data.args_kwargs_str)
    )

    if session.execute(query).scalar_one_or_none() is not None:
        raise DuplicatedReconProcessException(
            f"Recon process '{func_data.function.__name__}' with args "
            f"'{func_data.args_kwargs_str}' was already "
            "successfully executed",
            command=[func_data.function.__name__, func_data.args_kwargs_str],
        )

    yield func_data.function(*func_data.cleaned_args, **func_data.cleaned_kwargs)

    session.add(
        ReconProcess(
            name=func_data.function.__name__,
            args=func_data.args_kwargs_str,
        )
    )
    session.commit()


@contextlib.contextmanager
def suppress_duplicated_recon_process() -> Iterator[None]:
    """
    Context manager to suppress DuplicatedReconProcessException.
    This is useful for functions that are called multiple times with the same arguments.
    """
    try:
        yield
    except DuplicatedReconProcessException as exception:
        logger.debug("Duplicated recon process: %s", exception.command)
