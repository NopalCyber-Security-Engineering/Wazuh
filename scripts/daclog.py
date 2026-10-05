from __future__ import annotations

import os
import sys
from typing import Any


def _clean(value: Any) -> str:
    return str(value).replace("\r", " ").replace("\n", "\\n").replace("|", "/")


def _annotation_escape(value: str) -> str:
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def log(level: str, stage: str, message: str, **fields: Any) -> None:
    level = level.upper()
    parts = ["DAC", level, f"stage={_clean(stage)}"]
    for key, value in fields.items():
        if value is not None and value != "":
            parts.append(f"{key}={_clean(value)}")
    parts.append(_clean(message))
    stream = sys.stderr if level == "ERROR" else sys.stdout
    print(" | ".join(parts), file=stream, flush=True)

    if os.getenv("GITHUB_ACTIONS") == "true" and level in {"ERROR", "WARNING"}:
        command = "error" if level == "ERROR" else "warning"
        context = " ".join(f"{key}={_clean(value)}" for key, value in fields.items() if value is not None and value != "")
        detail = f"{message} {context}".strip()
        print(
            f"::{command} title=Detection-as-Code {stage}::{_annotation_escape(detail)}",
            file=stream,
            flush=True,
        )


def info(stage: str, message: str, **fields: Any) -> None:
    log("INFO", stage, message, **fields)


def warning(stage: str, message: str, **fields: Any) -> None:
    log("WARNING", stage, message, **fields)


def error(stage: str, message: str, **fields: Any) -> None:
    log("ERROR", stage, message, **fields)
