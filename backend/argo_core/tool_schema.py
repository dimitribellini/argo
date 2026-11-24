"""Zero-dependency OpenAPI/Gemini-safe JSON schema helpers and ToolSpec dataclass."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Provider-neutral native tool schema specification for a single Argo action."""

    name: str
    description: str
    parameters_json_schema: dict[str, Any]


_FORBIDDEN_SCHEMA_KEYS = frozenset(
    {
        "additionalProperties",
        "$defs",
        "$ref",
        "anyOf",
        "oneOf",
        "default",
        "$schema",
        "title",
    }
)


def _resolve_json_ref(ref: str, defs: dict[str, Any]) -> dict[str, Any]:
    target_name = ref.rsplit("/", 1)[-1]
    resolved = defs.get(target_name)
    if isinstance(resolved, dict):
        return copy.deepcopy(resolved)
    return {"type": "string"}


def _simplify_union_branches(
    branches: list[Any],
    defs: dict[str, Any],
    outer_desc: Any,
) -> dict[str, Any]:
    non_null = [
        b
        for b in branches
        if isinstance(b, dict) and b.get("type") != "null"
    ]
    chosen = copy.deepcopy(non_null[0]) if non_null else {"type": "string"}
    if outer_desc and "description" not in chosen:
        chosen["description"] = str(outer_desc)
    return _sanitize_schema_node(chosen, defs)


def _sanitize_schema_node(node: Any, defs: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(node, dict):
        return {"type": "string"}

    current = copy.deepcopy(node)
    if "$ref" in current:
        outer_desc = current.get("description")
        inlined = _resolve_json_ref(str(current["$ref"]), defs)
        if outer_desc and "description" not in inlined:
            inlined["description"] = outer_desc
        current = inlined

    for union_key in ("anyOf", "oneOf"):
        if isinstance(current.get(union_key), list):
            return _simplify_union_branches(
                current[union_key],
                defs,
                current.get("description"),
            )

    cleaned: dict[str, Any] = {}
    for key, val in current.items():
        if key in _FORBIDDEN_SCHEMA_KEYS:
            continue
        if key == "properties" and isinstance(val, dict):
            cleaned["properties"] = {
                str(p_name): _sanitize_schema_node(p_schema, defs)
                for p_name, p_schema in val.items()
            }
        elif key == "items":
            cleaned["items"] = _sanitize_schema_node(val, defs)
        else:
            cleaned[key] = val

    node_type = cleaned.get("type")
    if node_type == "array" and "items" not in cleaned:
        cleaned["items"] = {"type": "string"}
    if node_type == "object":
        props = cleaned.get("properties")
        if not isinstance(props, dict) or not props:
            cleaned["properties"] = {
                "note": {
                    "type": "string",
                    "description": "Optional note for this operation.",
                }
            }
    return cleaned


def sanitize_tool_json_schema(raw_schema: dict[str, Any]) -> dict[str, Any]:
    """Normalize a JSON Schema or Pydantic v2 schema into flat OpenAPI 3.0.3 compatible form."""
    defs = raw_schema.get("$defs") if isinstance(raw_schema.get("$defs"), dict) else {}
    sanitized = _sanitize_schema_node(raw_schema, defs)
    if sanitized.get("type") != "object":
        sanitized["type"] = "object"
    props = sanitized.get("properties")
    if not isinstance(props, dict) or not props:
        sanitized["properties"] = {
            "note": {
                "type": "string",
                "description": "Optional note for this operation.",
            }
        }
    return sanitized


def validate_gemini_safe_schema(schema: dict[str, Any], *, tool_name: str = "") -> list[str]:
    """Return human-readable validation errors if a tool schema violates Gemini strict rules."""
    errors: list[str] = []
    prefix = f"{tool_name}: " if tool_name else ""

    def _walk(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            errors.append(f"{prefix}{path} is not an object schema")
            return
        for bad_key in _FORBIDDEN_SCHEMA_KEYS:
            if bad_key in node:
                errors.append(f"{prefix}{path} contains forbidden key '{bad_key}'")
        n_type = node.get("type")
        if n_type == "object":
            props = node.get("properties")
            if not isinstance(props, dict) or not props:
                errors.append(f"{prefix}{path} object schema has empty or missing properties")
            else:
                for k, sub in props.items():
                    _walk(sub, f"{path}.properties.{k}")
        elif n_type == "array":
            if "items" not in node or not isinstance(node["items"], dict):
                errors.append(f"{prefix}{path} array schema is missing concrete items")
            else:
                _walk(node["items"], f"{path}.items")

    _walk(schema, "$")
    return errors
