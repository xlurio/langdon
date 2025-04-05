from __future__ import annotations

import json
from argparse import Namespace
from typing import TYPE_CHECKING, Any, Literal

from sqlalchemy import sql

from langdon.exceptions import LangdonException
from langdon.models import (
    AndroidApp,
    DirCookieRel,
    DirHeaderRel,
    Domain,
    HttpCookie,
    HttpHeader,
    IpAddress,
    IpDomainRel,
    ReconProcess,
    SqlAlchemyModel,
    Technology,
    UsedPort,
    Vulnerability,
    WebDirectory,
    WebDirectoryScreenshot,
)
from langdon.output import OutputColor

if TYPE_CHECKING:
    from collections.abc import Mapping

    from langdon.langdon_manager import LangdonManager
    from langdon.langdon_t import CrudModuleT, JsonSerializablePrimitiveT


class CrudOperationNamespace(Namespace):
    module: CrudModuleT
    operation: Literal["create", "list", "retrieve", "update", "delete"]
    id: int | None = None
    data: Mapping[str, JsonSerializablePrimitiveT] | None = None
    filter: Mapping[str, JsonSerializablePrimitiveT] | None = None
    limit: int | None = None


def _resolve_model(args: CrudOperationNamespace) -> type[SqlAlchemyModel]:
    return {
        "reconprocess": ReconProcess,
        "domain": Domain,
        "androidapp": AndroidApp,
        "ipaddress": IpAddress,
        "ipdomainrel": IpDomainRel,
        "webdirectory": WebDirectory,
        "httpheader": HttpHeader,
        "dirheaderrel": DirHeaderRel,
        "httpcookie": HttpCookie,
        "dircookierel": DirCookieRel,
        "webdirectoryscreenshot": WebDirectoryScreenshot,
        "usedport": UsedPort,
        "technology": Technology,
        "webdirtechrel": WebDirectory,
        "porttechrel": Technology,
        "vulnerability": Vulnerability,
    }[args.module]


def execute_crud_operation(
    args: CrudOperationNamespace, *, manager: LangdonManager
) -> None:
    return {
        "create": _create_object,
        "list": _list_objects,
        "retrieve": _retrieve_object,
        "update": _update_object,
        "delete": _delete_object,
    }[args.operation](args, manager=manager)


def _create_object(args: CrudOperationNamespace, *, manager: LangdonManager) -> None:
    model_cls = _resolve_model(args)
    manager.session.add(model_cls(**args.data))
    manager.session.commit()
    print(
        f"{OutputColor.GREEN} '{args.module}' object created successfully!{OutputColor.RESET}"
    )


def _list_objects(args: CrudOperationNamespace, *, manager: LangdonManager) -> None:
    model_cls = _resolve_model(args)
    query = _apply_filters(sql.select(model_cls), args, model_cls)
    result = manager.session.execute(query).scalars().all()
    _print_results_as_jsonl(result, args.module)


def _apply_filters(
    query: sql.Select, args: CrudOperationNamespace, model_cls
) -> sql.Select:
    if args.filter:
        for key, value in args.filter.items():
            query = query.where(getattr(model_cls, key) == value)

    if args.limit:
        query = query.limit(args.limit)

    return query


def _print_results_as_jsonl(result: list[Any], module: str) -> None:
    if not result:
        print(f"No {module} objects found.")
        return

    print("[")

    for obj in result:
        _print_object_as_json(obj)

    print("]")


def _retrieve_object(args: CrudOperationNamespace, *, manager: LangdonManager) -> None:
    model_cls = _resolve_model(args)
    obj = manager.session.get(model_cls, args.id)
    if not obj:
        raise LangdonException(f"Object not found!")

    _print_object_as_json(obj)


def _print_object_as_json(obj: SqlAlchemyModel) -> None:
    obj_dump = {}

    for key, value in dict(vars(obj)).items():
        if key == "_sa_instance_state":
            continue

        obj_dump[key] = value

    print(json.dumps(obj_dump, default=str))


def _update_object(args: CrudOperationNamespace, *, manager: LangdonManager) -> None:
    model_cls = _resolve_model(args)
    obj = manager.session.get(model_cls, args.id)
    if not obj:
        raise LangdonException(f"Object not found!")

    for key, value in args.data.items():
        setattr(obj, key, value)

    manager.session.commit()
    print(
        f"{OutputColor.GREEN} '{args.module}' object updated successfully!{OutputColor.RESET}"
    )


def _delete_object(args: CrudOperationNamespace, *, manager: LangdonManager) -> None:
    model_cls = _resolve_model(args)
    obj = manager.session.get(model_cls, args.id)
    if not obj:
        raise LangdonException(f"Object not found!")

    manager.session.delete(obj)
    manager.session.commit()
    print(
        f"{OutputColor.GREEN} '{args.module}' object deleted successfully!{OutputColor.RESET}"
    )
