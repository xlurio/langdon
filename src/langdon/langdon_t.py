from typing import Literal

ConfigurationKeyT = Literal[
    "cache_file",
    "content_wordlist",
    "directory",
    "dns_wordlist",
    "downloaded_apks_dir",
    "event_queue_file",
    "firefox_profile",
    "log_file",
    "resolvers_file",
    "socks_proxy_host",
    "socks_proxy_port",
    "task_queue_file",
    "user_agent",
    "web_directory_screenshots",
]

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
