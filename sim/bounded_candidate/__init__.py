"""Linux-only bounded candidate validation primitives.

This subpackage validates disposable candidates. It contains no live source
writer and grants no promotion authority. Modules are imported explicitly so
importing this package on Windows does not pretend POSIX containment exists.
"""

SUPPORTED_PLATFORM = "Linux/POSIX with mount, network, and PID namespaces"
WRITE_AUTHORITY = "NONE"
PROMOTION_AUTHORITY = "NONE"

__all__ = ["PROMOTION_AUTHORITY", "SUPPORTED_PLATFORM", "WRITE_AUTHORITY"]
