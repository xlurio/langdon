from typing import Literal

CrudModuleT = Literal[
    "reconprocess",
    "domain",
    "androidapp",
    "ipaddress",
    "ipdomainrel",
    "webdirectory",
    "httpheader",
    "dirheaderrel",
    "httpcookie",
    "dircookierel",
    "webdirectoryscreenshot",
    "usedport",
    "technology",
    "webdirtechrel",
    "porttechrel",
    "vulnerability",
]

JsonSerializablePrimitiveT = int | float | str | None | bool
