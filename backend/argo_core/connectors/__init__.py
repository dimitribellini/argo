"""External service connector packages for argo-core."""

from argo_core.connectors.telegram_bot import (
    MAX_CALLBACK_DATA_BYTES,
    STOP_IDLE_DESKTOPS_CALLBACK,
    TelegramBotService,
    TelegramConfigError,
    TelegramIntegrationError,
    TelegramTransport,
    build_inline_keyboard,
    validate_callback_data,
)

__all__ = [
    "MAX_CALLBACK_DATA_BYTES",
    "STOP_IDLE_DESKTOPS_CALLBACK",
    "TelegramBotService",
    "TelegramConfigError",
    "TelegramIntegrationError",
    "TelegramTransport",
    "build_inline_keyboard",
    "validate_callback_data",
]
