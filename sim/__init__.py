"""Bounded, inspectable AI environment primitives."""

from sim.environment_coverage import (
    EnvironmentCoverageError,
    compare_environment_receipts,
    observe_environment,
)

__all__ = [
    "EnvironmentCoverageError",
    "compare_environment_receipts",
    "observe_environment",
]
