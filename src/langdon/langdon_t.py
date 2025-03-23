from collections.abc import Callable, Iterator
from langdon.models import Directory


EnumeratorType = Callable[[str, ...], Iterator[Directory]]  # type: ignore
