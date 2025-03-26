from __future__ import annotations

import contextlib
import subprocess
from typing import TYPE_CHECKING

import pydantic
from sqlalchemy import sql

from langdon.exceptions import DuplicatedReconProcessException, LangdonException
from langdon.models import ReconProcess

if TYPE_CHECKING:
    from collections.abc import Iterator

    from langdon.langdon_manager import LangdonManager


class CommandData(pydantic.BaseModel):
    command: str
    args: str

    @property
    def shell_command_line(self) -> str:
        return f"{self.command} {self.args}"


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
