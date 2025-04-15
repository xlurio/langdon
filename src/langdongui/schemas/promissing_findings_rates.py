import pydantic


class PromissingFindingsRates(pydantic.BaseModel):
    domains: float
    technologies: float
    used_ports: float
    vulnerabilities: float
    web_directories: float
