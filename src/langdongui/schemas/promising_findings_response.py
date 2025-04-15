import pydantic


class PromisingFindingsResponse(pydantic.BaseModel):
    count: int
    next: int | None
    results: list
