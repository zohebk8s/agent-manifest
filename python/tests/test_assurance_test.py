"""AM-VERIFY-60..63, AM-BIND-70..73: system_prompt.assurance_test enforcement.

Covers proposed spec 3.2.1.1. Mirrors the poisoning_scan enforcement tests
(test_poisoning_scan.py, issue #153), because the proposed rules deliberately
follow the same shape:

  AM-VERIFY-60  flagged                      -> MUST NOT verify as VALID (any level)
  AM-VERIFY-61  Level 2+ + not-assessed      -> MUST NOT verify as VALID
                Level 0/1 + not-assessed     -> VALID but warnings non-empty
  AM-VERIFY-62  Level 2+ + absent            -> MUST NOT verify as VALID
                Level 0/1 + absent           -> VALID, no warnings (compatibility)
  AM-VERIFY-63  Level 2+ + pass w/o provenance -> MUST NOT verify as VALID
  AM-BIND-70..73  schema binding of the assurance_test block
"""
from datetime import datetime, timedelta, timezone

from agent_manifest._signing import Ed25519Signer, generate_ed25519
from agent_manifest._verify import (
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

NOW = datetime.now(timezone.utc)
FUTURE = (NOW + timedelta(days=90)).isoformat().replace("+00:00", "Z")
SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
MID = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"

KP = generate_ed25519()
TRUSTED_KEYS = {KP.key_id: KP.public_b64url()}

FULL_PROVENANCE = {
    "harness": "assurance-harness/0.1.0",
    "tested_at": NOW.isoformat().replace("+00:00", "Z"),
    "baseline": "neutral-control/v1",
}


def sign(m):
    m["signature"] = Ed25519Signer(KP).sign(m)
    return m


def base_manifest(assurance: dict | None):
    system_prompt = {"hash": SHA_A}
    if assurance is not None:
        system_prompt["assurance_test"] = assurance
    m = {
        "manifest_id": MID,
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": FUTURE,
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": system_prompt,
            "policy_bundle": {"hash": SHA_B},
            "model_identity": {"version": "claude-3", "deployment_type": "api"},
        },
        "delegation_chain": [],
        "hitl_record": None,
    }
    return sign(m)


def base_context(conformance_level: int = 0):
    return VerificationContext(
        system_prompt_hash=SHA_A,
        policy_bundle_hash=SHA_B,
        model_version="claude-3",
        trusted_keys=dict(TRUSTED_KEYS),
        conformance_level=conformance_level,
    )


def store():
    return RevocationStore()


def passing(**overrides):
    return {"result": "pass", **FULL_PROVENANCE, **overrides}


# ---------------------------------------------------------------------------
# AM-VERIFY-60: flagged -> non-VALID regardless of conformance level
# ---------------------------------------------------------------------------


def test_flagged_result_is_not_valid_level0():
    result = verify_manifest(base_manifest({"result": "flagged"}), base_context(0), store())
    assert result.result != OverallResult.VALID


def test_flagged_result_is_not_valid_level2():
    result = verify_manifest(base_manifest({"result": "flagged"}), base_context(2), store())
    assert result.result != OverallResult.VALID


def test_flagged_result_reports_the_offending_field():
    result = verify_manifest(base_manifest({"result": "flagged"}), base_context(0), store())
    fields = [m.field for m in result.mismatch_details]
    assert "system_prompt.assurance_test" in fields


def test_flagged_is_not_valid_even_with_full_provenance():
    """A well-documented failing assessment is still a failing assessment."""
    manifest = base_manifest({"result": "flagged", **FULL_PROVENANCE})
    result = verify_manifest(manifest, base_context(0), store())
    assert result.result != OverallResult.VALID


# ---------------------------------------------------------------------------
# AM-VERIFY-61: not-assessed is permitted below Level 2, refused at Level 2+
# ---------------------------------------------------------------------------


def test_not_assessed_level0_is_valid_with_warning():
    result = verify_manifest(base_manifest({"result": "not-assessed"}), base_context(0), store())
    assert result.result == OverallResult.VALID
    assert result.warnings != []


def test_not_assessed_level1_is_valid_with_warning():
    result = verify_manifest(base_manifest({"result": "not-assessed"}), base_context(1), store())
    assert result.result == OverallResult.VALID
    assert result.warnings != []


def test_not_assessed_level2_is_not_valid():
    result = verify_manifest(base_manifest({"result": "not-assessed"}), base_context(2), store())
    assert result.result != OverallResult.VALID


def test_not_assessed_level3_is_not_valid():
    result = verify_manifest(base_manifest({"result": "not-assessed"}), base_context(3), store())
    assert result.result != OverallResult.VALID


# ---------------------------------------------------------------------------
# AM-VERIFY-62: an absent block is the untested state, but must not break
# pre-change manifests below Level 2
# ---------------------------------------------------------------------------


def test_absent_block_level0_is_valid_no_warnings():
    """Backward compatibility: manifests issued before this change are unaffected."""
    result = verify_manifest(base_manifest(None), base_context(0), store())
    assert result.result == OverallResult.VALID
    assert result.warnings == []


def test_absent_block_level1_is_valid_no_warnings():
    result = verify_manifest(base_manifest(None), base_context(1), store())
    assert result.result == OverallResult.VALID
    assert result.warnings == []


def test_absent_block_level2_is_not_valid():
    result = verify_manifest(base_manifest(None), base_context(2), store())
    assert result.result != OverallResult.VALID


# ---------------------------------------------------------------------------
# AM-VERIFY-63: at Level 2+ a passing verdict must carry its provenance
# ---------------------------------------------------------------------------


def test_pass_with_full_provenance_level2_is_valid():
    result = verify_manifest(base_manifest(passing()), base_context(2), store())
    assert result.result == OverallResult.VALID
    assert result.warnings == []


def test_pass_without_harness_level2_is_not_valid():
    manifest = base_manifest({"result": "pass", "tested_at": FULL_PROVENANCE["tested_at"],
                              "baseline": FULL_PROVENANCE["baseline"]})
    result = verify_manifest(manifest, base_context(2), store())
    assert result.result != OverallResult.VALID


def test_pass_without_baseline_level2_is_not_valid():
    """The baseline is what makes a result reproducible rather than self-reported."""
    manifest = base_manifest({"result": "pass", "harness": FULL_PROVENANCE["harness"],
                              "tested_at": FULL_PROVENANCE["tested_at"]})
    result = verify_manifest(manifest, base_context(2), store())
    assert result.result != OverallResult.VALID


def test_pass_without_provenance_level1_is_valid():
    """Below Level 2 the verdict alone is accepted."""
    result = verify_manifest(base_manifest({"result": "pass"}), base_context(1), store())
    assert result.result == OverallResult.VALID


# ---------------------------------------------------------------------------
# AM-BIND-70: schema binding
# ---------------------------------------------------------------------------


def test_assurance_test_accepts_the_three_defined_results():
    from agent_manifest.models import AssuranceTest

    for value in ("pass", "flagged", "not-assessed"):
        assert AssuranceTest(result=value).result.value == value


def test_assurance_test_rejects_an_undefined_result():
    import pytest
    from pydantic import ValidationError
    from agent_manifest.models import AssuranceTest

    with pytest.raises(ValidationError):
        AssuranceTest(result="probably-fine")


def test_system_prompt_binding_without_assurance_test_still_validates():
    from agent_manifest.models import SystemPromptBinding

    binding = SystemPromptBinding(
        hash=SHA_A, version="1.0.0", classification="internal", bound_at=NOW,
    )
    assert binding.assurance_test is None


def test_system_prompt_binding_carries_assurance_test():
    from agent_manifest.models import SystemPromptBinding

    binding = SystemPromptBinding(
        hash=SHA_A, version="1.0.0", classification="internal", bound_at=NOW,
        assurance_test={"result": "pass", **FULL_PROVENANCE},
    )
    assert binding.assurance_test.result.value == "pass"
    assert binding.assurance_test.baseline == "neutral-control/v1"
