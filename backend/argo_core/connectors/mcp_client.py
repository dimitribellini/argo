"""Dynamic Streamable HTTP JSON-RPC 2.0 MCP connector with SSRF pinning & Gemini schema sanitization."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from argo_core.db.repositories import make_id
from argo_core.tool_schema import ToolSpec, sanitize_tool_json_schema
from argo_core.security.ssrf import (
    PublicFetchError,
    SafePublicHttpFetcher,
    SSRFBlockedError,
    validate_public_url,
)
from argo_core.security.vault import redact_secrets

if TYPE_CHECKING:
    from argo_core.db.repositories import ArgoRepository

MCPTransport = Callable[[str, dict[str, Any], dict[str, str]], Awaitable[dict[str, Any]]]

_READONLY_PREFIXES = (
    "get_",
    "list_",
    "search_",
    "read_",
    "describe_",
    "query_",
    "fetch_",
    "inspect_",
)


class MCPConfigError(ValueError):
    """Raised when an MCP connector configuration or endpoint URL is invalid."""


class MCPClientError(RuntimeError):
    """Raised when a remote MCP JSON-RPC 2.0 server call fails."""


def make_mcp_tool_name(account_slug: str, remote_name: str) -> str:
    """Build a deterministic Gemini-safe ASCII tool identifier (<= 64 chars) for an MCP tool."""
    clean_acc = re.sub(r"[^a-zA-Z0-9_]+", "_", str(account_slug or "mcp")).strip("_") or "mcp"
    clean_remote = re.sub(r"[^a-zA-Z0-9_]+", "_", str(remote_name or "tool")).strip("_") or "tool"
    raw = f"mcp__{clean_acc}__{clean_remote}"
    if len(raw) <= 64:
        return raw
    digest = hashlib.sha256(f"{account_slug}:{remote_name}".encode("utf-8")).hexdigest()[:6]
    budget = 64 - len(f"mcp__{clean_acc[:20]}__") - len(f"_{digest}")
    return f"mcp__{clean_acc[:20]}__{clean_remote[:max(4, budget)]}_{digest}"[:64]


def classify_mcp_tool_readonly(tool_def: dict[str, Any]) -> bool:
    """Determine if a remote MCP tool is safe read-only or must pass Connector RBAC."""
    annotations = tool_def.get("annotations") if isinstance(tool_def.get("annotations"), dict) else {}
    if "readOnlyHint" in annotations and annotations["readOnlyHint"] is not None:
        return bool(annotations["readOnlyHint"])
    if annotations.get("destructiveHint") is True:
        return False
    remote_name = re.sub(r"[^a-zA-Z0-9_]+", "_", str(tool_def.get("name") or "")).strip("_").lower()
    if annotations.get("destructiveHint") is None and annotations.get("idempotentHint") is None:
        return any(remote_name.startswith(pref) for pref in _READONLY_PREFIXES)
    return False


class MCPConnectorService:
    """Manages remote HTTP JSON-RPC 2.0 MCP tool discovery, caching, and execution."""

    def __init__(
        self,
        *,
        repo: ArgoRepository | None = None,
        http_fetcher: Any = None,
        transport: MCPTransport | None = None,
        url_validator: Callable[[str], tuple[str, list[str]]] | None = None,
        cache_ttl_seconds: float = 60.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._repo = repo
        self._http_fetcher = http_fetcher
        self._transport = transport
        self._url_validator = url_validator or validate_public_url
        self._cache_ttl_seconds = max(1.0, float(cache_ttl_seconds))
        self._clock = clock or time.monotonic
        # account_slug -> (cached_at_monotonic, list[dict], {namespaced_name -> dict})
        self._cache: dict[str, tuple[float, list[dict[str, Any]], dict[str, dict[str, Any]]]] = {}

    def invalidate(self, account_slug: str | None = None) -> None:
        """Clear cached discovered MCP tools for a connector or all connectors."""
        if account_slug is None:
            self._cache.clear()
        else:
            self._cache.pop(str(account_slug).strip(), None)

    def _resolve_endpoint_and_headers(self, account: dict[str, Any]) -> tuple[str, dict[str, str]]:
        if (not isinstance(account.get("secrets"), dict) or not account.get("secrets")) and self._repo is not None:
            slug = str(account.get("slug") or "").strip()
            if slug:
                hydrated = self._repo.find_integration_secrets(slug)
                if isinstance(hydrated, dict):
                    account = hydrated
        secrets = account.get("secrets") if isinstance(account.get("secrets"), dict) else {}
        raw_url = str(
            secrets.get("url")
            or secrets.get("endpoint")
            or account.get("account_identifier")
            or ""
        ).strip()
        if not raw_url:
            raise MCPConfigError(
                f"MCP connector '{account.get('slug', '')}' has no endpoint URL configured."
            )
        cleaned_url, _ = self._url_validator(raw_url)
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        custom_headers = secrets.get("headers")
        if isinstance(custom_headers, dict):
            for k, v in custom_headers.items():
                if str(k).strip() and v is not None:
                    headers[str(k).strip()] = str(v)
        raw_token = str(
            secrets.get("token")
            or secrets.get("api_key")
            or secrets.get("bearer_token")
            or ""
        ).strip()
        if raw_token and "authorization" not in {k.lower() for k in headers}:
            headers["Authorization"] = (
                raw_token if raw_token.lower().startswith("bearer ") else f"Bearer {raw_token}"
            )
        return cleaned_url, headers

    async def _rpc(
        self,
        account: dict[str, Any],
        *,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        endpoint_url, headers = self._resolve_endpoint_and_headers(account)
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": make_id("mcp"),
            "method": method,
            "params": params or {},
        }
        if self._transport is not None:
            raw_resp = await self._transport(endpoint_url, rpc_payload, headers)
        else:
            fetcher = (
                self._http_fetcher
                if self._http_fetcher is not None and hasattr(self._http_fetcher, "post_json")
                else SafePublicHttpFetcher()
            )
            try:
                http_resp = await fetcher.post_json(
                    endpoint_url,
                    rpc_payload,
                    headers=headers,
                    timeout_seconds=15.0,
                )
            except SSRFBlockedError:
                raise
            except PublicFetchError as exc:
                raise MCPClientError(str(exc)) from exc
            try:
                raw_resp = json.loads(http_resp.body)
            except json.JSONDecodeError as exc:
                raise MCPClientError(
                    f"MCP endpoint '{endpoint_url}' returned non-JSON response."
                ) from exc

        if not isinstance(raw_resp, dict):
            raise MCPClientError(f"MCP endpoint '{endpoint_url}' returned invalid JSON-RPC envelope.")
        if raw_resp.get("error"):
            err_obj = raw_resp["error"]
            msg = (
                str(err_obj.get("message") or err_obj)
                if isinstance(err_obj, dict)
                else str(err_obj)
            )
            raise MCPClientError(f"MCP '{method}' failed: {msg}")
        result = raw_resp.get("result")
        return result if isinstance(result, dict) else {"value": result}

    async def discover_tools(
        self,
        account: dict[str, Any],
        *,
        force_refresh: bool = False,
    ) -> list[dict[str, Any]]:
        """Call tools/list on an MCP server and cache normalized tool definitions."""
        acc_slug = str(account.get("slug") or "")
        now = self._clock()
        cached = self._cache.get(acc_slug)
        if not force_refresh and cached is not None and (now - cached[0]) < self._cache_ttl_seconds:
            return list(cached[1])

        result = await self._rpc(account, method="tools/list", params={})
        raw_tools = result.get("tools")
        if not isinstance(raw_tools, list):
            raw_tools = []

        normalized: list[dict[str, Any]] = []
        by_ns: dict[str, dict[str, Any]] = {}
        for item in raw_tools:
            if not isinstance(item, dict):
                continue
            remote_name = str(item.get("name") or "").strip()
            if not remote_name:
                continue
            ns_name = make_mcp_tool_name(acc_slug, remote_name)
            raw_schema = item.get("inputSchema") or item.get("input_schema") or {"type": "object"}
            if not isinstance(raw_schema, dict):
                raw_schema = {"type": "object"}
            sanitized_schema = sanitize_tool_json_schema(raw_schema)
            readonly = classify_mcp_tool_readonly(item)
            entry = {
                "namespaced_name": ns_name,
                "remote_name": remote_name,
                "account_slug": acc_slug,
                "description": str(
                    item.get("description") or f"MCP tool '{remote_name}' on {acc_slug}"
                ).strip(),
                "input_schema": sanitized_schema,
                "readonly": readonly,
            }
            normalized.append(entry)
            by_ns[ns_name] = entry

        self._cache[acc_slug] = (now, normalized, by_ns)
        return list(normalized)

    def resolve_cached_tool(self, account_slug: str, tool_name: str) -> dict[str, Any] | None:
        """Resolve a namespaced mcp__<slug>__<tool> identifier from discovery cache."""
        cached = self._cache.get(str(account_slug).strip())
        if cached is None:
            return None
        return cached[2].get(str(tool_name).strip())

    async def resolve_tool(
        self,
        account: dict[str, Any],
        tool_name: str,
    ) -> dict[str, Any] | None:
        """Resolve a namespaced MCP tool, refreshing tools/list if not yet cached."""
        acc_slug = str(account.get("slug") or "")
        found = self.resolve_cached_tool(acc_slug, tool_name)
        if found is not None:
            return found
        await self.discover_tools(account, force_refresh=True)
        return self.resolve_cached_tool(acc_slug, tool_name)

    def list_cached_tool_specs(self, account: dict[str, Any]) -> list[ToolSpec]:
        """Synchronously return ToolSpecs already present in discovery cache for account."""
        cached = self._cache.get(str(account.get("slug") or "").strip())
        if cached is None:
            return []
        return [
            ToolSpec(
                name=entry["namespaced_name"],
                description=entry["description"],
                parameters_json_schema=entry["input_schema"],
            )
            for entry in cached[1]
        ]

    async def list_tool_specs(self, account: dict[str, Any]) -> list[ToolSpec]:
        """Return Gemini-safe ToolSpecs for all tools advertised by this MCP connector."""
        tools = await self.discover_tools(account)
        return [
            ToolSpec(
                name=entry["namespaced_name"],
                description=entry["description"],
                parameters_json_schema=entry["input_schema"],
            )
            for entry in tools
        ]

    async def call_tool(
        self,
        account: dict[str, Any],
        *,
        remote_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute tools/call on a validated remote MCP endpoint with secret redaction."""
        result = await self._rpc(
            account,
            method="tools/call",
            params={"name": remote_name, "arguments": dict(arguments or {})},
        )
        content_blocks = result.get("content")
        text_parts: list[str] = []
        if isinstance(content_blocks, list):
            for block in content_blocks:
                if isinstance(block, dict) and block.get("text") is not None:
                    text_parts.append(str(block["text"]))
                elif isinstance(block, str):
                    text_parts.append(block)
        combined_text = "\n".join(text_parts).strip()
        if not combined_text and result.get("structuredContent") is not None:
            combined_text = json.dumps(result["structuredContent"], ensure_ascii=False)
        secrets = self._repo.collect_all_sensitive_secrets() if self._repo is not None else []
        scrubbed_text = redact_secrets(combined_text, secrets) if secrets and combined_text else combined_text
        if bool(result.get("isError")):
            raise MCPClientError(scrubbed_text or f"MCP tool '{remote_name}' reported an error.")
        return {
            "remote_tool": remote_name,
            "text": scrubbed_text,
            "structured_content": result.get("structuredContent"),
            "is_error": False,
        }

    async def probe(self, account: dict[str, Any]) -> dict[str, Any]:
        """Verify MCP endpoint reachability and refresh discovered tool metadata."""
        slug = str(account.get("slug") or "")
        try:
            tools = await self.discover_tools(account, force_refresh=True)
        except Exception as exc:
            if self._repo is not None and slug:
                self._repo.update_integration_health(
                    slug,
                    status="degraded",
                    last_error=str(exc)[:500],
                )
            if isinstance(exc, (SSRFBlockedError, MCPConfigError, MCPClientError)):
                raise
            raise MCPClientError(f"MCP probe failed for '{slug}': {exc}") from exc

        if self._repo is not None and slug:
            updated = self._repo.update_integration_health(slug, status="ok", last_error=None)
        else:
            updated = {**account, "status": "ok", "last_error": None}
        return {
            **updated,
            "status": "ok",
            "provider": "mcp",
            "tool_count": len(tools),
            "tools": [t["remote_name"] for t in tools[:25]],
        }
