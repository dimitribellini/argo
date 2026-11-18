"""In-process Multi-LLM Router package backed by PydanticAI v2.68+."""

from argo_core.llm.router import (
    BudgetExceededError,
    LLMExecutionError,
    LLMRequest,
    LLMResult,
    LLMRouter,
    ModelConfigurationError,
    default_thinking_level,
    estimate_cost_usd,
    validate_model_id,
)

__all__ = [
    "BudgetExceededError",
    "LLMExecutionError",
    "LLMRequest",
    "LLMResult",
    "LLMRouter",
    "ModelConfigurationError",
    "default_thinking_level",
    "estimate_cost_usd",
    "validate_model_id",
]
