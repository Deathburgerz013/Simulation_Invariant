"""Bounded, verifiable AI environment presentation primitives."""

from sim.environment_coverage import (
    EnvironmentCoverageError,
    compare_environment_receipts,
    observe_environment,
)
from sim.presentation_receipts import (
    PresentationReceiptError,
    create_presentation_receipt,
    verify_presentation_receipt,
)
from sim.environment_monitor import (
    MonitorError,
    build_monitor_packet,
)
from sim.observation_packets import (
    ObservationPacketError,
    build_observation_packet,
    verify_observation_packet,
)

__all__ = [
    "EnvironmentCoverageError",
    "PresentationReceiptError",
    "MonitorError",
    "ObservationPacketError",
    "build_observation_packet",
    "build_monitor_packet",
    "compare_environment_receipts",
    "create_presentation_receipt",
    "observe_environment",
    "verify_presentation_receipt",
    "verify_observation_packet",
]
