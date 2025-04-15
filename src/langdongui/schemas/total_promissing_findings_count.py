import pydantic


class TotalPromissingFindingsCounts(pydantic.BaseModel):
    domains: int
    technologies: int
    used_ports: int
    vulnerabilities: int
    web_directories: int
    total: int
