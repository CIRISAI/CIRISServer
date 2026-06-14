"""ciris_lens_core — Science-layer runtime for the CIRIS federation.

Cohort routing + manifold-conformity scoring + hybrid-signed detection
events. As of v0.2.0 lens-core is folded into the cohabitation agent
via ``install_relay(edge)``; the v0.1.x four-function drop-in surface
is preserved as a delegating shim for the deployed-CIRISLens cutover.

Mission alignment: see ``MISSION.md`` in the repo root.

# v0.2.0 cohabitation entry — install_relay

The federation-canonical bootstrap. Every cohabitation agent (post-
fold-in) registers lens-core as a handler on the shared ``Arc<Edge>``
via:

>>> import ciris_edge
>>> import ciris_lens_core
>>>
>>> edge = ciris_edge.init_edge_runtime(...)  # host constructs Edge
>>> ciris_lens_core.install_relay(edge)        # register lens handler

Lens-core never holds keys. The Engine that signs detection events
arrives across the cohabitation boundary inside ``edge`` (Edge's
PyCapsule accessor exposes the host's ``ciris_persist.Engine``);
lens-core calls ``engine.local_sign`` / ``engine.local_pqc_sign``
through that handle. See CIRISPersist#51 for the rename history
(``steward_sign`` → ``local_sign``, Engine-as-parameter contract).

# v0.1.x deployed-lens drop-in (preserved for cutover)

The deployed Python lens replaces its in-tree ``cirislens_core``
import with this package via one-line alias:

>>> # before:
>>> # import cirislens_core
>>> # after:
>>> import ciris_lens_core as cirislens_core

# Engine-as-parameter — lens-core never holds keys

``process_trace_batch`` takes a ``ciris_persist.Engine`` instance as
its first parameter. Lens-core calls ``engine.local_sign`` +
``engine.local_pqc_sign`` + ``engine.put_detection_event`` to
sign and persist detection events through the host's identity.
Lens-core never reads key material directly — same pattern survives
the fold-into-agent (agent's Engine replaces deployed-lens's
Engine, lens-core sub-module is unchanged).

>>> import ciris_lens_core
>>> import ciris_persist as cp
>>> engine = cp.Engine(...)  # host constructs with signing keys
>>> result = ciris_lens_core.process_trace_batch(
...     engine,
...     events=trace_json_list,
...     batch_timestamp="2026-05-13T12:00:00Z",
... )
>>> # result["detections"] is a list of {detection_id, trace_id, severity}

# Surface

- ``install_relay(edge)`` — **v0.2.0 cohabitation bootstrap.** Registers
  lens-core's relay handler on the shared ``Arc<Edge>``; the host-owned
  Engine on ``edge`` becomes the signing identity for detection events.
- ``process_trace_batch(engine, events, batch_timestamp, ...)`` — full
  pipeline (cohort + projection + no-op detector + scoring +
  signing). Every trace produces ``ManifoldConformity::Indeterminate
  {CohortColdStart}`` until RATCHET centroids ship via persist's
  ``calibration_bundles``.
- ``scrub_trace(trace_json, level)`` — delegates to
  ``ciris_persist::pipeline::scrub::scrub_trace``. Returns
  ``{"trace": <json string>, "level": <str>, "stats": <dict>}``.
- ``scrub_traces_batch(traces_json, level)`` — delegates to
  ``ciris_persist::pipeline::scrub::scrub_traces_batch``.
- ``ner_is_configured() -> bool`` — delegates to
  ``ciris_persist::pipeline::scrub::ner::is_configured``.
- ``PROJECTION_VERSION: str`` — ``"crc-v1"``; the **manifold**
  (§5.5.1) 16-field projection contract. Unchanged by crc-v2 — the
  manifold projection did not change; only the F-3 + distributive
  axis-family axes were calibrated.
- ``AXIS_CALIBRATION_VERSION: str`` — ``"crc-v2"``; the **axis-family**
  (§5.5.3 F-3 + §5.5.5 distributive) calibration the live detectors
  consume. Versioned independently of ``PROJECTION_VERSION``.
- ``RATCHET_AXIS_CALIBRATION_VERSION: int`` — ``2``; the integer stamp
  copied into ``detection:*`` envelopes' ``ratchet_calibration_version``.
- ``__version__: str`` — top-level package version (Python-stdlib
  convention). Added in v0.2.2; v0.2.0 + v0.2.1 omitted this.

# What's deliberately NOT in the surface

Seven legacy ``cirislens_core`` functions are absent
(``load_schemas_from_db``, ``refresh_schema_cache``,
``get_loaded_schemas``, ``load_public_keys_from_db``,
``refresh_public_key_cache``, ``get_public_key_count``,
``check_cache_status``). Schema validation moved to edge
(verify-via-persist); public key lookup moved to persist's
``federation_keys`` table + ``Engine.lookup_public_key``. Deployed
lens deletes the obsolete call sites at swap time.
"""

from .ciris_lens_core import (  # type: ignore[attr-defined]
    AXIS_CALIBRATION_VERSION,
    PROJECTION_VERSION,
    RATCHET_AXIS_CALIBRATION_VERSION,
    LensClient,
    install_relay,
    ner_is_configured,
    process_trace_batch,
    scrub_trace,
    scrub_traces_batch,
)

__version__ = "1.4.2"

__all__ = [
    "AXIS_CALIBRATION_VERSION",
    "PROJECTION_VERSION",
    "RATCHET_AXIS_CALIBRATION_VERSION",
    "LensClient",
    "__version__",
    "install_relay",
    "ner_is_configured",
    "process_trace_batch",
    "scrub_trace",
    "scrub_traces_batch",
]
