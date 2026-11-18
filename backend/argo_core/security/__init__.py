"""Security primitives: Fernet vault encryption and oauth2-proxy SSO principal parsing."""

from argo_core.security.sso import extract_sso_principal
from argo_core.security.vault import SecretVault

__all__ = ["SecretVault", "extract_sso_principal"]
