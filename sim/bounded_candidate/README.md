# Bounded candidate validation

This is a Linux/POSIX-only candidate-validation subpackage. It observes a
stable source, constructs and patches a disposable candidate, runs tests in a
restricted namespace, and emits hash-bound receipts.

It has no live source writer or promotion path. A successful result is only
`VALIDATED_CANDIDATE`. Real containment requires mount, network, and PID
namespace authority; the implementation never invokes `sudo` automatically.

The ledger API is append-only through this API and detects chain tampering,
truncation, stale heads, and path-identity changes. It does not claim that an
external filesystem authority cannot delete or replace the whole ledger.
