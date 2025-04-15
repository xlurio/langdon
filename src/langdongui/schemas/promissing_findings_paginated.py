import pydantic

from langdon.models import Domain, Technology, UsedPort, Vulnerability, WebDirectory


class PromissingFindingsPaginated(pydantic.BaseModel):
    class Config:
        arbitrary_types_allowed = True

    domains: list[Domain]
    technologies: list[Technology]
    used_ports: list[UsedPort]
    vulnerabilities: list[Vulnerability]
    web_directories: list[WebDirectory]
