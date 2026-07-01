import json
import os
from typing import Any


DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")


def load_config(path: str | None = None) -> dict[str, Any]:
    path = path or DEFAULT_CONFIG_PATH
    with open(path) as f:
        cfg = json.load(f)
    return cfg


def resolve_config(*paths: str | None) -> dict[str, Any]:
    for p in paths:
        if p and os.path.exists(p):
            return load_config(p)
    if os.path.exists(DEFAULT_CONFIG_PATH):
        return load_config(DEFAULT_CONFIG_PATH)
    msg = "No configuration file found"
    raise FileNotFoundError(msg)
