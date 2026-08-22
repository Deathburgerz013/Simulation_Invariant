"""Platform-neutral bounded-correction and exhaustion-receipt tests."""

from sim.bounded_candidate.bounded_correction import (
    test_bound_exhaustion_is_an_explicit_chained_receipt as _test_bound_exhaustion,
    test_honest_adapter_reaches_stop as _test_honest_stop,
    test_invalid_bound_is_rejected_before_receipt_or_mutation as _test_invalid_bound,
    test_unapproved_secondary_mutation_fails_and_rolls_back as _test_unapproved_mutation,
    test_zero_bound_emits_receipt_without_mutation as _test_zero_bound,
)


def test_embedded_bounded_correction_contract() -> None:
    _test_unapproved_mutation()
    _test_honest_stop()
    _test_bound_exhaustion()
    _test_zero_bound()
    _test_invalid_bound()
