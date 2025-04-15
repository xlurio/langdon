import math
import random

import flask

from langdon.langdon_manager import LangdonManager
from langdongui.constants import PAGE_SIZE
from langdongui.repositories import (
    domains,
    technologies,
    used_ports,
    vulnerabilities,
    web_directories,
)
from langdongui.schemas.promissing_finding import PromisingFinding
from langdongui.schemas.promissing_findings_paginated import PromissingFindingsPaginated
from langdongui.schemas.promissing_findings_rates import PromissingFindingsRates
from langdongui.schemas.total_promissing_findings_count import (
    TotalPromissingFindingsCounts,
)


def calculate_total_counts(*, manager: LangdonManager) -> TotalPromissingFindingsCounts:
    num_of_domains = domains.count_promissing_domains(session=manager.session)
    num_of_technologies = technologies.count_promissing_technologies(
        session=manager.session
    )
    num_of_used_ports = used_ports.count_promissing_used_ports(session=manager.session)
    num_of_vulnerabilities = vulnerabilities.count(session=manager.session)
    num_of_web_directories = web_directories.count_promissing_web_directories(
        session=manager.session
    )
    total_num_of_objects = (
        num_of_domains
        + num_of_technologies
        + num_of_used_ports
        + num_of_vulnerabilities
        + num_of_web_directories
    )
    return TotalPromissingFindingsCounts(
        domains=num_of_domains,
        technologies=num_of_technologies,
        used_ports=num_of_used_ports,
        vulnerabilities=num_of_vulnerabilities,
        web_directories=num_of_web_directories,
        total=total_num_of_objects,
    )


def calculate_rates(
    total_counts: TotalPromissingFindingsCounts,
) -> PromissingFindingsRates:
    total = total_counts.total
    return PromissingFindingsRates(
        domains=total_counts.domains / max(total, 1),
        technologies=total_counts.technologies / max(total, 1),
        used_ports=total_counts.used_ports / max(total, 1),
        vulnerabilities=total_counts.vulnerabilities / max(total, 1),
        web_directories=total_counts.web_directories / max(total, 1),
    )


def fetch_paginated_objects(
    rates: PromissingFindingsRates, *, manager: LangdonManager
) -> PromissingFindingsPaginated:
    page = flask.request.args.get("page", 0, type=int)
    return PromissingFindingsPaginated(
        **{
            "domains": domains.list_promissing_domains(
                session=manager.session,
                offset=calculate_offset(page, rates.domains),
                limit=calculate_limit(page, rates.domains),
            ).all(),
            "technologies": technologies.list_promissing_technologies(
                session=manager.session,
                offset=calculate_offset(page, rates.technologies),
                limit=calculate_limit(page, rates.technologies),
            ).all(),
            "used_ports": used_ports.list_promissing_used_ports(
                session=manager.session,
                offset=calculate_offset(page, rates.used_ports),
                limit=calculate_limit(page, rates.used_ports),
            ).all(),
            "vulnerabilities": vulnerabilities.list_all(
                session=manager.session,
                offset=calculate_offset(page, rates.vulnerabilities),
                limit=calculate_limit(page, rates.vulnerabilities),
            ).all(),
            "web_directories": web_directories.list_promissing_web_directories(
                session=manager.session,
                offset=calculate_offset(page, rates.web_directories),
                limit=calculate_limit(page, rates.web_directories),
            ).all(),
        }
    )


def calculate_offset(page: int, rate: float):
    return math.floor(page * PAGE_SIZE * rate)


def calculate_limit(page: int, rate: float):
    return math.ceil((page + 1) * PAGE_SIZE * rate)


def serialize_and_shuffle_objects(paginated_objects: PromissingFindingsPaginated):
    all_objects = (
        paginated_objects.domains
        + paginated_objects.technologies
        + paginated_objects.used_ports
        + paginated_objects.vulnerabilities
        + paginated_objects.web_directories
    )
    serialized_objects = [
        PromisingFinding.from_model(obj).model_dump(mode="json") for obj in all_objects
    ]
    random.shuffle(serialized_objects)
    return serialized_objects
