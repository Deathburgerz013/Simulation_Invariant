# Independent audit checkpoint

Audit date: 2026-08-22

This bundle remains a bounded candidate validator. It contains no live source
writer and grants no promotion or write authority.

## Corrections applied

- Partial file reads cannot produce a complete or STABLE observation.
- Ordinary directories, empty directories, and directory permission bits are
  part of portable tree identity.
- Candidate materialization preserves directory permission bits.
- Regular-file observation uses O_NOFOLLOW; a final-component symlink swap
  cannot be read as a regular file.
- Candidate patches preserve existing file permission bits and handle short
  writes.
- The executor records and executes the same resolved executable.
- Runtime binds, resource limits, and the jail method are included in the
  environment-policy hash.
- Sources and candidates overlapping runtime mounts are rejected.
- stdout/stderr are streamed with a live combined limit; exceeding it kills
  the process group and cannot pass.
- The redundant direct source-byte read in integration was removed; the stable
  manifest remains the source evidence.
- The executor receipt binds platform, kernel, machine, effective UID/GID,
  effective CAP_SYS_ADMIN state, required namespaces, and the exact namespace
  probe result.
- Missing namespace privilege fails explicitly as PRIVILEGE_REQUIRED before an
  execution clone is launched.
- Automatic elevation is forbidden by policy and recorded as false.
- The suite runner performs the same namespace preflight and exits 77 instead
  of attempting sudo.
- Receipt persistence is an explicit, flock-serialized, O_APPEND write with a
  canonical payload hash, sequence, previous-record hash, record hash, fsync,
  and expected-head guard.
- Malformed, truncated, tampered, cross-ledger, stale-head, symlink, and
  non-regular ledger targets fail before another record is appended.
- The ledger API does not claim resistance to deletion or whole-file
  replacement by an external filesystem authority; a retained external head
  hash detects that boundary.
- Exhausting max_steps appends a hash-chained BOUND_EXHAUSTED receipt with the
  observed state hash, remaining problem evidence, attempted-step count, and
  bound. It returns HUMAN_REVIEW and never resembles PASS or completion.
- A zero bound emits the same explicit boundary receipt without mutation;
  negative and boolean bounds are rejected before mutation.
- The exhaustion receipt is accepted by the durable ledger as an explicit
  append, preserving the separation between correction and persistence.
- Final source audit found and closed one authority-envelope contradiction:
  hash-valid validation packets with non-NONE write or promotion authority are
  now rejected before a ledger file is created or appended.

## Verification in the independent environment

- Every Python file compiled.
- Filesystem-observer tests passed.
- Candidate-workspace tests passed.
- Candidate-patch tests passed.
- In-memory bounded-correction tests passed.
- Integrated orchestration tests passed with the contained-command call
  replaced by a deterministic stub.

The real contained executor could not run in the independent audit container
because that container denies the required unshare namespaces. It failed
closed. On WSL, the unprivileged probe also failed closed while an explicitly
root-authorized probe, real executor suite, and integrated validation suite
passed. The environment-dependent privilege is now declared rather than
implicit.

## Still intentionally absent

- Live source writer
- Promotion path
