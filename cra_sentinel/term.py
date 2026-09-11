"""Terminal presentation. ANSI only — no dependencies, degrades on dumb pipes."""
from __future__ import annotations

import os
import shutil
import sys

_ENABLED = (sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM") != "dumb")


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _ENABLED else text


def bold(t): return _c("1", t)
def dim(t): return _c("2", t)
def red(t): return _c("31", t)
def green(t): return _c("32", t)
def yellow(t): return _c("33", t)
def blue(t): return _c("34", t)
def cyan(t): return _c("36", t)
def grey(t): return _c("90", t)
def on_red(t): return _c("41;97;1", t)
def on_green(t): return _c("42;30;1", t)


SEV_COLOR = {"CRITICAL": red, "HIGH": yellow, "MEDIUM": cyan,
             "LOW": green, "UNKNOWN": grey, "NONE": grey}
STATUS_MARK = {
    "pass": lambda: green("✓"),
    "fail": lambda: red("✕"),
    "warn": lambda: yellow("!"),
    "manual": lambda: blue("◐"),
}


def width() -> int:
    return min(shutil.get_terminal_size((90, 24)).columns, 100)


def rule(char: str = "─") -> str:
    return grey(char * width())


def header(title: str, subtitle: str = "") -> str:
    lines = ["", bold(cyan("  ▚ CRA SENTINEL")) + grey("  ·  Regulation (EU) 2024/2847"), ""]
    lines.append("  " + bold(title))
    if subtitle:
        lines.append("  " + grey(subtitle))
    lines.append("")
    return "\n".join(lines)


def gauge(score: int, size: int = 28) -> str:
    filled = round(size * score / 100)
    color = green if score >= 75 else yellow if score >= 55 else red
    return color("█" * filled) + grey("░" * (size - filled))


def kv(label: str, value: str, pad: int = 22) -> str:
    return f"  {grey(label.ljust(pad))} {value}"


def truncate(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
