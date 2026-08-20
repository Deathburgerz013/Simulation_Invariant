"""Command dispatcher for ``python -m sim``."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence

from sim.environment_monitor import main as monitor_main
from sim.observation_packets import main as observation_main


def _command_error(message: str) -> int:
    print(
        json.dumps(
            {
                "type": "simulation_command_error",
                "version": 1,
                "error": message,
                "accepted": False,
                "truth_claimed": False,
                "write_authority": "NONE",
                "execution_authority": "NONE",
            },
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        return _command_error("a command is required; available: inspect, monitor")
    command, *remaining = arguments
    if command == "monitor":
        return monitor_main(remaining)
    if command == "inspect":
        return observation_main(remaining)
    return _command_error(f"unknown command: {command}")


if __name__ == "__main__":
    raise SystemExit(main())
