"""Fresh per-run dependency construction for every formal runtime entrypoint."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable, TYPE_CHECKING

from .adapters import MockKeyProvider
from .simulation import RunConfig

if TYPE_CHECKING:
    from .calibration import CalibrationProfile
    from .runtime import PlatformRuntime


@dataclass(slots=True)
class RuntimeDependencies:
    """Factories for stateful A/C integration assets.

    Factories receive the resolved :class:`RunConfig` and are invoked once per
    runtime.  A crypto factory additionally receives the freshly-created key
    provider.  ``None`` delegates to PlatformRuntime's documented test/null
    defaults.  No provider object is shared across independent runs.
    """

    key_provider_factory: Callable[[RunConfig], Any] | None = None
    crypto_provider_factory: Callable[[RunConfig, Any], Any] | None = None
    model_adapter_factories: dict[str, Callable[[RunConfig], Any]] = field(
        default_factory=dict
    )
    terminal_authorizer_factory: Callable[[RunConfig], Any] | None = None
    terminal_profiles_factory: Callable[[RunConfig], dict[int, Any]] | None = None
    terminal_credentials_factory: Callable[[RunConfig], dict[int, str]] | None = None
    security_bundle_factory: Callable[[RunConfig], dict[str, Any]] | None = None

    def instantiate(self, config: RunConfig) -> dict[str, Any]:
        bundle = (
            dict(self.security_bundle_factory(config))
            if self.security_bundle_factory is not None
            else {}
        )
        key_provider = (
            self.key_provider_factory(config)
            if self.key_provider_factory is not None
            else bundle.get("key_provider")
        )
        if self.crypto_provider_factory is not None and key_provider is None:
            # A custom crypto factory needs the exact key-provider instance that
            # the runtime will use, even when the caller selected B's test key.
            key_provider = MockKeyProvider(config.seed)
        crypto_provider = (
            self.crypto_provider_factory(config, key_provider)
            if self.crypto_provider_factory is not None
            else bundle.get("crypto_provider")
        )
        return {
            "key_provider": key_provider,
            "crypto_provider": crypto_provider,
            "security_coordinator": bundle.get("security_coordinator"),
            "model_adapters": {
                name: factory(config)
                for name, factory in self.model_adapter_factories.items()
            }
            or None,
            "terminal_authorizer": (
                self.terminal_authorizer_factory(config)
                if self.terminal_authorizer_factory is not None
                else bundle.get("terminal_authorizer")
            ),
            "terminal_profiles": (
                self.terminal_profiles_factory(config)
                if self.terminal_profiles_factory is not None
                else bundle.get("terminal_profiles")
            ),
            "terminal_credentials": (
                self.terminal_credentials_factory(config)
                if self.terminal_credentials_factory is not None
                else bundle.get("terminal_credentials")
            ),
        }


class PlatformRuntimeFactory:
    """Create equivalent, isolated runtimes for Direct/API/Batch/RL paths."""

    def __init__(self, dependencies: RuntimeDependencies | None = None) -> None:
        self.dependencies = dependencies or RuntimeDependencies()

    def create(
        self,
        config: RunConfig | dict[str, Any] | None = None,
        *,
        run_id: str | None = None,
        calibration_profile: "CalibrationProfile | None" = None,
    ) -> "PlatformRuntime":
        from .runtime import PlatformRuntime

        actual = deepcopy(
            config if isinstance(config, RunConfig) else RunConfig.from_dict(config)
        )
        return PlatformRuntime(
            actual,
            run_id=run_id,
            calibration_profile=calibration_profile,
            **self.dependencies.instantiate(actual),
        )
