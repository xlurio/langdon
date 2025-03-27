from __future__ import annotations

import contextlib
import shlex
import shutil
import subprocess
from typing import TYPE_CHECKING, Any, Generic, TypeVar

import pydantic
from sqlalchemy import sql

from langdon.exceptions import DuplicatedReconProcessException, LangdonException
from langdon.models import ReconProcess

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence

    from langdon.langdon_manager import LangdonManager


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


def _try_to_execute_command(command: CommandData) -> str:
    try:
        return subprocess.run(
            command.shell_command_line, capture_output=True, check=True
        ).stdout.decode()
    except subprocess.CalledProcessError as exception:
        cleaned_stderr = (
            exception.stderr.decode()
            if isinstance(exception.stderr, bytes)
            else "unknown"
        )

        raise LangdonException(
            f"Command '{command.command}' with args '{command.args}' failed with code "
            f"{exception.returncode}: {cleaned_stderr}"
        ) from exception


@contextlib.contextmanager
def shell_command_execution_context(
    command: CommandData, *, manager: LangdonManager
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
            "successfully executed"
        )

    yield _try_to_execute_command(command)

    session.add(ReconProcess(name=command.command, args=command.args))
    session.commit()


class FunctionData(Generic[T], pydantic.BaseModel):
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
            "successfully executed"
        )

    yield func_data.function(*func_data.cleaned_args, **func_data.cleaned_kwargs)

    session.add(
        ReconProcess(
            name=func_data.function.__name__,
            args=func_data.args_kwargs_str,
        )
    )
    session.commit()
