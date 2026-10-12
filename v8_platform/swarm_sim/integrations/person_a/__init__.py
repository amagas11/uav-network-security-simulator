"""Person-A crypto integration without copying or modifying A's library."""

from .bridge import (
    PersonACryptoNotAvailable,
    PersonACryptoProvider,
    PersonAKeyCoordinator,
    RekeyCoordinator,
    PersonASecurityBundleFactory,
    PersonATerminalAuthorizerAdapter,
    build_aad,
)
from .leakage import PersonASecretLeakageAudit, SecretLeakageFinding

__all__ = [
    "PersonACryptoNotAvailable",
    "PersonACryptoProvider",
    "PersonAKeyCoordinator",
    "RekeyCoordinator",
    "PersonASecurityBundleFactory",
    "PersonATerminalAuthorizerAdapter",
    "PersonASecretLeakageAudit",
    "SecretLeakageFinding",
    "build_aad",
]
