"""Manifest and lockfile parsers.

Each detector turns a dependency manifest into Component objects. Lockfiles are
preferred over manifests because the CRA requires the SBOM to describe what is
actually shipped, not what was requested.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ..model import Component

IGNORED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "env", "dist", "build", "target", ".tox", ".mypy_cache", ".pytest_cache", ".next",
    "site-packages", ".gradle", "bin", "obj", ".cra-sentinel", ".idea", ".vscode",
}

# Lockfiles rank above manifests: when both describe the same ecosystem in the
# same directory, the lockfile wins.
MANIFEST_FILES = {
    "package-lock.json": ("npm", 10),
    "yarn.lock": ("npm", 9),
    "pnpm-lock.yaml": ("npm", 9),
    "package.json": ("npm", 1),
    "poetry.lock": ("pypi", 10),
    "Pipfile.lock": ("pypi", 10),
    "requirements.txt": ("pypi", 5),
    "pyproject.toml": ("pypi", 2),
    "go.sum": ("golang", 9),
    "go.mod": ("golang", 8),
    "Cargo.lock": ("cargo", 10),
    "Cargo.toml": ("cargo", 2),
    "composer.lock": ("composer", 10),
    "Gemfile.lock": ("gem", 10),
    "packages.lock.json": ("nuget", 10),
    "pom.xml": ("maven", 6),
}


def discover_manifests(root: Path, max_depth: int = 6) -> list[Path]:
    """Walk the tree and return every dependency manifest worth parsing."""
    found: list[Path] = []
    root = root.resolve()

    def walk(directory: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = list(directory.iterdir())
        except (PermissionError, OSError):
            return
        for entry in entries:
            if entry.is_dir() and not entry.is_symlink():
                if entry.name not in IGNORED_DIRS and not entry.name.startswith("."):
                    walk(entry, depth + 1)
            elif entry.is_file() and entry.name in MANIFEST_FILES:
                found.append(entry)

    walk(root, 0)
    return _dedupe_by_rank(found)


def _dedupe_by_rank(paths: list[Path]) -> list[Path]:
    """Keep only the highest-ranked manifest per (directory, ecosystem)."""
    best: dict[tuple[Path, str], tuple[int, Path]] = {}
    extra: list[Path] = []
    for p in paths:
        eco, rank = MANIFEST_FILES[p.name]
        # pom.xml is kept alongside others: multi-module builds are common.
        if p.name == "pom.xml":
            extra.append(p)
            continue
        key = (p.parent, eco)
        if key not in best or rank > best[key][0]:
            best[key] = (rank, p)
    return sorted([v[1] for v in best.values()] + extra)


def parse(path: Path, root: Path) -> list[Component]:
    """Dispatch a manifest to its parser. Never raises — a broken manifest
    must not abort a compliance scan."""
    rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    handler = _HANDLERS.get(path.name)
    if handler is None:
        return []
    try:
        return handler(text, rel)
    except Exception:
        return []


# --------------------------------------------------------------------------
# npm
# --------------------------------------------------------------------------

def _split_npm_name(name: str) -> tuple[str | None, str]:
    if name.startswith("@") and "/" in name:
        ns, _, n = name.partition("/")
        return ns, n
    return None, name


def parse_package_lock(text: str, src: str) -> list[Component]:
    data = json.loads(text)
    out: list[Component] = []

    # lockfileVersion 2/3: flat "packages" map keyed by install path
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict) or meta.get("link"):
            continue
        raw = meta.get("name") or path.split("node_modules/")[-1]
        version = meta.get("version")
        if not raw or not version:
            continue
        ns, name = _split_npm_name(raw)
        lic = meta.get("license")
        out.append(Component(
            name=name, version=version, ecosystem="npm", namespace=ns,
            direct=path.count("node_modules") <= 1,
            scope="dev" if meta.get("dev") else ("optional" if meta.get("optional") else "required"),
            licenses=[lic] if isinstance(lic, str) else (lic or []),
            source=src,
        ))

    if out:
        return out

    # lockfileVersion 1: nested "dependencies" tree
    def walk(deps: dict, depth: int = 0) -> None:
        for raw, meta in (deps or {}).items():
            if not isinstance(meta, dict) or not meta.get("version"):
                continue
            ns, name = _split_npm_name(raw)
            out.append(Component(
                name=name, version=meta["version"], ecosystem="npm", namespace=ns,
                direct=depth == 0, scope="dev" if meta.get("dev") else "required", source=src,
            ))
            walk(meta.get("dependencies") or {}, depth + 1)

    walk(data.get("dependencies") or {})
    return out


def parse_package_json(text: str, src: str) -> list[Component]:
    data = json.loads(text)
    out = []
    for field_name, scope in (("dependencies", "required"), ("devDependencies", "dev"),
                              ("optionalDependencies", "optional")):
        for raw, spec in (data.get(field_name) or {}).items():
            if not isinstance(spec, str):
                continue
            version = re.sub(r"^[\^~>=<\s]+", "", spec).split(" ")[0]
            if not version or not re.match(r"^\d", version):
                continue  # git/file/workspace refs carry no resolvable version
            ns, name = _split_npm_name(raw)
            out.append(Component(name=name, version=version, ecosystem="npm",
                                 namespace=ns, scope=scope, source=src))
    return out


def parse_yarn_lock(text: str, src: str) -> list[Component]:
    out, current = [], None
    for line in text.splitlines():
        if line and not line.startswith(" ") and not line.startswith("#"):
            spec = line.split(",")[0].strip().strip('"').rstrip(":")
            at = spec.rfind("@")
            current = spec[:at] if at > 0 else spec
        elif current and line.strip().startswith("version"):
            version = line.split(None, 1)[1].strip().strip('"')
            ns, name = _split_npm_name(current)
            out.append(Component(name=name, version=version, ecosystem="npm",
                                 namespace=ns, source=src))
            current = None
    return out


def parse_pnpm_lock(text: str, src: str) -> list[Component]:
    out = []
    for m in re.finditer(r"^\s{2}/?((?:@[^/\s]+/)?[^/@\s]+)[/@](\d[^\s(:]*)", text, re.M):
        raw, version = m.group(1), m.group(2)
        ns, name = _split_npm_name(raw)
        out.append(Component(name=name, version=version, ecosystem="npm",
                             namespace=ns, source=src))
    return out


# --------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------

def parse_requirements(text: str, src: str) -> list[Component]:
    out = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9._!+-]+)", line)
        if m:
            out.append(Component(name=m.group(1), version=m.group(2),
                                 ecosystem="pypi", source=src))
    return out


def parse_poetry_lock(text: str, src: str) -> list[Component]:
    out = []
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        version = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        category = re.search(r'^category\s*=\s*"([^"]+)"', block, re.M)
        if name and version:
            out.append(Component(
                name=name.group(1), version=version.group(1), ecosystem="pypi",
                scope="dev" if category and category.group(1) == "dev" else "required",
                source=src,
            ))
    return out


def parse_pipfile_lock(text: str, src: str) -> list[Component]:
    data = json.loads(text)
    out = []
    for section, scope in (("default", "required"), ("develop", "dev")):
        for name, meta in (data.get(section) or {}).items():
            version = (meta.get("version") or "").lstrip("=")
            if version:
                out.append(Component(name=name, version=version, ecosystem="pypi",
                                     scope=scope, source=src))
    return out


def parse_pyproject(text: str, src: str) -> list[Component]:
    out = []
    block = re.search(r"^\[project\](.*?)(?=^\[|\Z)", text, re.M | re.S)
    if block:
        deps = re.search(r"dependencies\s*=\s*\[(.*?)\]", block.group(1), re.S)
        if deps:
            for raw in re.findall(r'"([^"]+)"', deps.group(1)):
                m = re.match(r"^([A-Za-z0-9._-]+).*?==\s*([A-Za-z0-9._!+-]+)", raw)
                if m:
                    out.append(Component(name=m.group(1), version=m.group(2),
                                         ecosystem="pypi", source=src))
    for m in re.finditer(r'^([A-Za-z0-9._-]+)\s*=\s*"[\^~=]*(\d[A-Za-z0-9._-]*)"',
                         text[text.find("[tool.poetry.dependencies]"):] if
                         "[tool.poetry.dependencies]" in text else "", re.M):
        if m.group(1).lower() != "python":
            out.append(Component(name=m.group(1), version=m.group(2),
                                 ecosystem="pypi", source=src))
    return out


# --------------------------------------------------------------------------
# Go / Rust / PHP / Ruby / .NET / Java
# --------------------------------------------------------------------------

def parse_go_mod(text: str, src: str) -> list[Component]:
    out, in_block = [], False
    for line in text.splitlines():
        line = line.split("//")[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?([\w.\-]+\.[\w.\-]+/[^\s]+)\s+(v[^\s]+)", line)
        if m and (in_block or line.startswith("require")):
            module, version = m.group(1), m.group(2)
            ns, _, name = module.rpartition("/")
            out.append(Component(name=name, version=version, ecosystem="golang",
                                 namespace=ns or None, source=src))
    return out


def parse_go_sum(text: str, src: str) -> list[Component]:
    seen, out = set(), []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            module, version = parts[0], parts[1].replace("/go.mod", "")
            if (module, version) in seen:
                continue
            seen.add((module, version))
            ns, _, name = module.rpartition("/")
            out.append(Component(name=name, version=version, ecosystem="golang",
                                 namespace=ns or None, direct=False, source=src))
    return out


def parse_cargo_lock(text: str, src: str) -> list[Component]:
    out = []
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        version = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        if name and version:
            out.append(Component(name=name.group(1), version=version.group(1),
                                 ecosystem="cargo", source=src))
    return out


def parse_composer_lock(text: str, src: str) -> list[Component]:
    data = json.loads(text)
    out = []
    for section, scope in (("packages", "required"), ("packages-dev", "dev")):
        for pkg in (data.get(section) or []):
            raw, version = pkg.get("name", ""), (pkg.get("version") or "").lstrip("v")
            if not raw or not version:
                continue
            ns, _, name = raw.partition("/")
            lic = pkg.get("license") or []
            out.append(Component(name=name or ns, version=version, ecosystem="composer",
                                 namespace=ns if name else None, scope=scope,
                                 licenses=lic if isinstance(lic, list) else [lic], source=src))
    return out


def parse_gemfile_lock(text: str, src: str) -> list[Component]:
    out, in_specs = [], False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            if line and not line.startswith(" "):
                in_specs = False
                continue
            m = re.match(r"^\s{4}([A-Za-z0-9._-]+) \(([^)]+)\)", line)
            if m:
                out.append(Component(name=m.group(1), version=m.group(2),
                                     ecosystem="gem", source=src))
    return out


def parse_nuget_lock(text: str, src: str) -> list[Component]:
    data = json.loads(text)
    out = []
    for framework in (data.get("dependencies") or {}).values():
        for name, meta in (framework or {}).items():
            version = meta.get("resolved") or meta.get("requested")
            if version:
                out.append(Component(name=name, version=str(version).lstrip("[]()"),
                                     ecosystem="nuget", source=src))
    return out


def parse_pom(text: str, src: str) -> list[Component]:
    root = ET.fromstring(text.encode("utf-8"))
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    prefix = "m:" if root.tag.startswith("{") else ""

    props = {}
    for prop in root.findall(f"{prefix}properties/*", ns):
        tag = prop.tag.split("}")[-1]
        if prop.text:
            props[tag] = prop.text.strip()

    def resolve(value: str) -> str:
        m = re.match(r"^\$\{([^}]+)\}$", value or "")
        return props.get(m.group(1), value) if m else value

    out = []
    for dep in root.iterfind(f".//{prefix}dependency", ns):
        gid = dep.find(f"{prefix}groupId", ns)
        aid = dep.find(f"{prefix}artifactId", ns)
        ver = dep.find(f"{prefix}version", ns)
        scope = dep.find(f"{prefix}scope", ns)
        if gid is None or aid is None or ver is None or not ver.text:
            continue
        version = resolve(ver.text.strip())
        if version.startswith("${"):
            continue
        out.append(Component(
            name=aid.text.strip(), version=version, ecosystem="maven",
            namespace=resolve(gid.text.strip()),
            scope="dev" if scope is not None and scope.text == "test" else "required",
            source=src,
        ))
    return out


_HANDLERS = {
    "package-lock.json": parse_package_lock,
    "package.json": parse_package_json,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "requirements.txt": parse_requirements,
    "poetry.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "pyproject.toml": parse_pyproject,
    "go.mod": parse_go_mod,
    "go.sum": parse_go_sum,
    "Cargo.lock": parse_cargo_lock,
    "composer.lock": parse_composer_lock,
    "Gemfile.lock": parse_gemfile_lock,
    "packages.lock.json": parse_nuget_lock,
    "pom.xml": parse_pom,
}
