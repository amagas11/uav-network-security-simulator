"""Deterministic UAV swarm security simulation platform.

The package is the canonical V7 implementation.  Legacy top-level modules keep
their public entry points as compatibility facades.
"""

from .attacks import AttackPlan
from .calibration import (
    BaselineCalibrationFitter,
    CalibrationDataset,
    CalibrationDatasetLoader,
    CalibrationLoader,
    CalibrationProfile,
    RuntimeCalibrationValidator,
    compare_calibration_observations,
)
from .domain import EventType, NodeRole, RunState
from .normal import NormalDisturbancePlan
from .runtime import PlatformRuntime
from .factory import PlatformRuntimeFactory, RuntimeDependencies
from .scenario_validation import ScenarioMechanismValidator
from .simulation import ConfigValidationError, RunConfig, RunContext, SimulationClock, SimulationScheduler

__all__ = [
    "AttackPlan",
    "BaselineCalibrationFitter",
    "CalibrationDataset",
    "CalibrationDatasetLoader",
    "CalibrationLoader",
    "CalibrationProfile",
    "RuntimeCalibrationValidator",
    "ConfigValidationError",
    "EventType",
    "NodeRole",
    "NormalDisturbancePlan",
    "PlatformRuntime",
    "PlatformRuntimeFactory",
    "RunConfig",
    "RunContext",
    "RunState",
    "RuntimeDependencies",
    "ScenarioMechanismValidator",
    "SimulationClock",
    "SimulationScheduler",
    "compare_calibration_observations",
]
