#!/usr/bin/env python3
"""Generate canonical-bytes parity fixtures from CIRISAgent's REAL
`AccordMetricsService._build_canonical_message` (CIRISLensCore#11 Cut 5).

This is the signature-critical parity harness: it captures the exact
bytes the agent signs over, for a battery of fixtures, so lens-core's
Rust `capture::seal::canonical_bytes` can be cross-validated
byte-for-byte against the source of truth — not against a hand-written
expected string.

Run (dev-time, needs the CIRISAgent checkout):

    python3 tests/parity/generate_canonical_fixtures.py \
        --agent ~/CIRISAgent \
        --out tests/parity/canonical_fixtures.json

The committed JSON is consumed by the hermetic Rust test
`capture::seal::tests::canonical_bytes_match_agent_fixtures` (CI runs
that test with NO agent checkout). Regenerate when the agent's §8
canonical format changes; a diff in the fixtures is the wire-format
change surfacing.
"""

import argparse
import json
import sys
from pathlib import Path


def build_service_canonicalizer(agent_root: Path):
    """Return the agent's real `_build_canonical_message` (bound to a
    bypass-constructed `Ed25519TraceSigner`) + the CompleteTrace /
    TraceComponent classes. The method lives on the signer and reads
    only its `trace` argument, so `__new__` (skipping the key-loading
    `__init__`) is sufficient."""
    sys.path.insert(0, str(agent_root))
    from ciris_adapters.ciris_accord_metrics.services import (  # type: ignore
        CompleteTrace,
        Ed25519TraceSigner,
        TraceComponent,
    )

    signer = Ed25519TraceSigner.__new__(Ed25519TraceSigner)
    return signer._build_canonical_message, CompleteTrace, TraceComponent


def fixtures(CompleteTrace, TraceComponent):
    """A battery covering the canonicalization edge cases:
    float values, empty-field stripping (None/""/[]/{}), 0/false kept,
    deployment_profile present/absent, multi-component, unicode,
    nested data, unsorted keys, the full event taxonomy."""
    ts = "2026-04-23T12:00:00+00:00"

    # The agent injects attempt_index INSIDE component data at capture
    # (services.py:1698 `component_data["attempt_index"] = attempt_index`),
    # so it lands in the signed canonical bytes (even 0 — strip_empty keeps
    # it). lens-core keeps attempt_index as a separate typed field and must
    # inject it at canonicalization. We build the agent component WITH it in
    # data here; trace_to_spec pops it back out so the fixture carries a
    # separate `attempt_index` + clean `data` — which is exactly what forces
    # lens-core's injection to be exercised.
    def comp(event_type, component_type, data, ts_=ts, aih="deadbeef", attempt_index=0):
        agent_data = dict(data)
        agent_data["attempt_index"] = attempt_index  # services.py:1698
        return TraceComponent(
            component_type=component_type,
            event_type=event_type,
            timestamp=ts_,
            data=agent_data,
            agent_id_hash=aih,
        )

    def trace(name, **kw):
        base = dict(
            trace_id="tr",
            thought_id="th",
            task_id="task-1",
            agent_id_hash="deadbeef",
            started_at=ts,
            completed_at=ts,
            trace_level="generic",
            trace_schema_version="2.7.9",
        )
        base.update(kw)
        return name, CompleteTrace(**base)

    out = []

    # 1. floats + empty-field stripping (None/[]) inside component data.
    #    attempt_index 0 (THOUGHT_START single-emit) + a non-zero retry on
    #    a multi-emit event — both must land in the signed bytes.
    out.append(trace(
        "float_and_empty_fields",
        components=[
            comp("THOUGHT_START", "observation",
                 {"k_eff": 0.9, "phase": "healthy", "empty_field": None, "empty_list": []},
                 attempt_index=0),
            comp("ACTION_RESULT", "action", {"action": "speak", "rationale": "test"},
                 attempt_index=3),
        ],
    ))

    # 2. 0 and false MUST be kept (not stripped); empty string + {} dropped.
    out.append(trace(
        "zero_false_kept_empties_dropped",
        components=[comp("DMA_RESULTS", "rationale",
                         {"count": 0, "passed": False, "blank": "", "obj": {}, "keep": "x"})],
    ))

    # 3. deployment_profile present (the 10th signed key).
    out.append(trace(
        "with_deployment_profile",
        deployment_profile={
            "agent_role": "ally", "agent_template": "ally-default",
            "deployment_domain": "general", "deployment_type": "production",
            "deployment_region": None, "deployment_trust_mode": "sovereign",
        },
        components=[comp("THOUGHT_START", "observation", {"x": 1}),
                    comp("ACTION_RESULT", "action", {"a": "y"})],
    ))

    # 4. task_id / completed_at None (top-level nulls, NOT stripped).
    out.append(trace(
        "null_task_and_completed",
        task_id=None, completed_at=None,
        components=[comp("ACTION_RESULT", "action", {"a": "z"})],
    ))

    # 5. unicode + nested data + numeric types.
    out.append(trace(
        "unicode_nested_numeric",
        components=[comp("CONSCIENCE_RESULT", "conscience",
                         {"note": "café ☕ — überwacht", "nested": {"b": [1, 2, 3], "f": -1.5e10},
                          "big": 9007199254740993}, attempt_index=2)],
    ))

    # 6. the full event taxonomy (one component per known type) — locks
    #    every event_type → component_type mapping in the signed bytes.
    taxonomy = [
        ("THOUGHT_START", "observation"), ("SNAPSHOT_AND_CONTEXT", "context"),
        ("DMA_RESULTS", "rationale"), ("IDMA_RESULT", "rationale"),
        ("ASPDMA_RESULT", "rationale"), ("TSASPDMA_RESULT", "rationale"),
        ("VERB_SECOND_PASS_RESULT", "verb_second_pass"),
        ("CONSCIENCE_RESULT", "conscience"), ("LLM_CALL", "llm_call"),
        ("DEFERRAL_ROUTED", "deferral_routed"), ("DEFERRAL_RECEIVED", "deferral_received"),
        ("DEFERRAL_RESOLVED", "deferral_resolved"), ("GRATITUDE_SIGNALED", "gratitude_signaled"),
        ("CREDIT_GENERATED", "credit_generated"), ("ACTION_RESULT", "action"),
    ]
    out.append(trace(
        "full_event_taxonomy",
        components=[comp(ev, ct, {"i": n}) for n, (ev, ct) in enumerate(taxonomy)],
    ))

    # 7. per-component agent_id_hash blank → denormalize from envelope.
    out.append(trace(
        "component_hash_denormalize",
        agent_id_hash="ENVELOPE_HASH",
        components=[comp("THOUGHT_START", "observation", {"x": 1}, aih=""),
                    comp("ACTION_RESULT", "action", {"a": "y"}, aih="")],
    ))

    return out


def _comp_spec(c):
    # Pop attempt_index back out of the agent's data dict so the fixture
    # mirrors lens-core's shape: a separate typed `attempt_index` + clean
    # `data`. lens-core re-injects it at canonicalization to reach the
    # agent's signed bytes.
    data = dict(c.data)
    attempt_index = data.pop("attempt_index", 0)
    return {
        "event_type": c.event_type,
        "component_type": c.component_type,
        "timestamp": c.timestamp,
        "agent_id_hash": c.agent_id_hash,
        "attempt_index": attempt_index,
        "data": data,
    }


def trace_to_spec(name, t):
    return {
        "name": name,
        "trace": {
            "trace_id": t.trace_id, "thought_id": t.thought_id, "task_id": t.task_id,
            "agent_id_hash": t.agent_id_hash, "started_at": t.started_at,
            "completed_at": t.completed_at, "trace_level": t.trace_level,
            "trace_schema_version": t.trace_schema_version,
            "deployment_profile": t.deployment_profile,
            "components": [_comp_spec(c) for c in t.components],
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", default=str(Path.home() / "CIRISAgent"))
    ap.add_argument("--out", default="tests/parity/canonical_fixtures.json")
    args = ap.parse_args()

    canon, CompleteTrace, TraceComponent = build_service_canonicalizer(Path(args.agent))

    entries = []
    for name, t in fixtures(CompleteTrace, TraceComponent):
        spec = trace_to_spec(name, t)
        # The source of truth: the agent's signed bytes, as a UTF-8 string.
        spec["expected_canonical"] = canon(t).decode("utf-8")
        entries.append(spec)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(entries, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {len(entries)} fixtures → {out}")


if __name__ == "__main__":
    main()
