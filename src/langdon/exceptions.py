class DuplicatedReconProcessException(Exception):
    def __init__(self, message: str, *, command: list[str]) -> None:
        super().__init__(message)
        self.command = command


class LangdonException(Exception): ...


class LangdonProgrammingError(Exception): ...


class AlreadyInChildThread(Exception): ...
