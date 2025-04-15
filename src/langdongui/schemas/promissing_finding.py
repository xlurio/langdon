from __future__ import annotations

from typing import Self

import pydantic
from typing_extensions import Literal

from langdon import models as langdon_models


class PromisingFinding(pydantic.BaseModel):
    id: int
    label: str
    type: Literal["domain", "technology", "used_port", "vulnerability", "web_directory"]

    @classmethod
    def from_model(cls, model: langdon_models.SqlAlchemyModel) -> Self:
        _type = {
            langdon_models.Domain: "domain",
            langdon_models.Technology: "technology",
            langdon_models.UsedPort: "used_port",
            langdon_models.Vulnerability: "vulnerability",
            langdon_models.WebDirectory: "web_directory",
        }[model.__class__]
        _get_label = {
            langdon_models.Domain: lambda model_obj: model_obj.name,
            langdon_models.Technology: lambda model_obj: f"{model_obj.name} "
            f"{model_obj.version}",
            langdon_models.UsedPort: lambda model_obj: f"{model_obj.ip_address.address}"
            f":{model_obj.port}",
            langdon_models.Vulnerability: lambda model_obj: model_obj.name,
            langdon_models.WebDirectory: lambda model_obj: model_obj.get_full_url(),
        }[model.__class__]

        return cls(
            id=model.id,
            label=_get_label(model),
            type=_type,
        )
