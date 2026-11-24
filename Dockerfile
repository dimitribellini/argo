FROM registry.fedoraproject.org/fedora:45 AS frontend-builder

RUN dnf install -y nodejs npm && dnf clean all

WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM registry.fedoraproject.org/fedora:45 AS runtime

LABEL org.opencontainers.image.title="Argo" \
      org.opencontainers.image.description="Self-hosted domain-agnostic multi-bot automation workspace" \
      org.opencontainers.image.source="https://github.com/dimitribellini/argo" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ARGO_STATIC_DIR=/app/static \
    ARGO_DB_PATH=/data/argo.db \
    PATH="/opt/venv/bin:$PATH"

RUN dnf install -y --setopt=install_weak_deps=False --setopt=tsflags=nodocs python3.15 sqlite && \
    python3.15 -m venv /opt/venv && \
    dnf clean all && \
    rm -rf /var/cache/libdnf5/* /var/cache/dnf/* /var/log/* /tmp/*

# Layer Python dependencies with --no-compile under 40 MB compressed each to stay
# well below Cloudflare's 100 MB per-request upload limit on registry pushes.
RUN pip install --no-cache-dir --no-compile --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --no-compile \
        "fastapi>=0.162.7" \
        "uvicorn>=0.54.0" \
        "uvloop>=0.23.0" \
        "httptools>=0.9.0" \
        "websockets>=15.0" \
        "pydantic>=2.14.3" \
        "valkey[libvalkey]>=6.2.0" \
        "aiohttp>=3.14.5,<3.15.0" \
        "aiofiles>=23.2.1,<26.0" \
        "certifi>=2023.7.22" \
        "magic-filter>=1.0.12,<1.1" \
        "typing-extensions>=4.8.0" \
        "feedparser>=6.0.14" \
        "trafilatura>=2.3.1" \
        "lxml>=6.1.3" \
        "apscheduler>=3.11.3,<4.0" \
        "docker>=7.2.0" \
        "cryptography>=50.0.2" \
        "psutil>=7.2.2"

RUN pip install --no-cache-dir --no-compile \
        "google-auth-oauthlib>=1.5.0" \
        "google-api-python-client>=2.202.0"

RUN pip install --no-cache-dir --no-compile \
        "pydantic-ai-slim[google,anthropic,openai,xai,openrouter,mcp]>=2.68.0" && \
    pip install --no-cache-dir --no-compile --ignore-requires-python --no-deps \
        "aiogram>=3.31.0"

RUN pip install --no-cache-dir --no-compile \
        "duckdb>=2.0.0"

RUN pip install --no-cache-dir --no-compile \
        "pdfplumber>=0.11.10" \
        "pypdfium2>=5.15.2" \
        "Pillow>=13.0.0" \
        "python-calamine>=0.9.1" \
        "python-docx>=1.2.0"

RUN pip install --no-cache-dir --no-compile \
        "asyncssh>=2.24.1"

ARG APP_VERSION=dev
ARG APP_COMMIT_SHA=""
LABEL org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${APP_COMMIT_SHA}"
ENV APP_VERSION=${APP_VERSION} \
    APP_COMMIT_SHA=${APP_COMMIT_SHA}

WORKDIR /app
COPY pyproject.toml README.md ./
COPY backend/ ./backend/
COPY --from=frontend-builder /build/frontend/dist /app/static
RUN pip install --no-build-isolation --no-cache-dir --no-compile --no-deps . && \
    mkdir -p /data && \
    /opt/venv/bin/python -c "import importlib.util, argo_core.main, argo_core.tool_schema, argo_core.analytics.engine, argo_core.llm.router, argo_core.security.ssrf, argo_core.connectors.telegram_bot, argo_core.connectors.telegram_channels, argo_core.connectors.google_oauth, argo_core.connectors.linkedin, argo_core.connectors.webhooks, argo_core.connectors.mcp_client, argo_core.connectors.manager, argo_core.tools.public_web, argo_core.approvals.coordinator, argo_core.runner.bot_runner, argo_core.runner.tool_registry, argo_core.runner.tool_dispatcher, argo_core.runner.scheduler, argo_core.runner.bot_builder, argo_core.sandbox.manager, argo_core.desktop.manager, argo_core.desktop.cdp_bridge, argo_core.desktop.mcp_bridge, argo_core.ssh.vt_screen, argo_core.ssh.host_guard, argo_core.ssh.recorder, argo_core.ssh.manager, argo_core.watchdog.debug_buffer, asyncssh, docker, aiogram, pydantic_ai, valkey, feedparser, apscheduler.schedulers.asyncio, trafilatura, psutil, cryptography, aiohttp, lxml.html, google_auth_oauthlib.flow, googleapiclient.discovery, pdfplumber, pypdfium2, PIL, python_calamine, docx; from compression import zstd as _zstd_smoke; assert argo_core.ssh.recorder.zstd_decompress_bytes(argo_core.ssh.recorder.zstd_compress_frame(b'a') + argo_core.ssh.recorder.zstd_compress_frame(b'b')) == b'ab'; assert importlib.util.find_spec('duckdb') is not None; argo_core.analytics.engine.verify_analytics_runtime(); argo_core.runner.tool_registry.verify_native_tool_calling_runtime(); from aiogram.types import InlineKeyboardMarkup; from fastmcp.client.transports import StdioTransport, StreamableHttpTransport; from pydantic_ai import BinaryContent; from pydantic_ai.mcp import MCPToolset; argo_core.desktop.cdp_bridge.ChromeDevToolsBridge.create_pydantic_ai_mcp_toolset('smoke-test'); argo_core.desktop.mcp_bridge.DesktopMCPBridge.create_pydantic_ai_mcp_toolset('smoke-test'); from pydantic_ai.models.fallback import FallbackModel; from pydantic_ai.models.google import GoogleModel; from pydantic_ai.models.anthropic import AnthropicModel; from pydantic_ai.models.openai import OpenAIChatModel; from pydantic_ai.models.ollama import OllamaModel; from pydantic_ai.models.openrouter import OpenRouterModel; from pydantic_ai.models.xai import XaiModel; import tempfile, pathlib; _d = tempfile.TemporaryDirectory(); _conn = argo_core.db.sqlite.init_db(pathlib.Path(_d.name) / 'smoke.db'); argo_core.db.repositories.ArgoRepository(conn=_conn, vault=argo_core.security.vault.SecretVault()).ensure_defaults(); _conn.close(); _d.cleanup(); print('Verified runtime imports, aiogram=' + aiogram.__version__)"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD /opt/venv/bin/python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)" || exit 1

CMD ["uvicorn", "argo_core.main:app", "--host", "0.0.0.0", "--port", "8000"]
