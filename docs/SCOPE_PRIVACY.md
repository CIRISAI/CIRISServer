# Scope-native privacy (operator guide)

CIRISServer adopts the CEWP **scope-native privacy substrate** (CC 1.13.3.4) via
verify 6.3.0 / persist 9.2.0 / edge 6.1.0 (CIRISServer#38). This page is the
operator-facing privacy representation the Constitution requires.

## Privacy statement (CC 1.13.3.3 — state BOTH)

> **Default protection.** Content published below federation scope is
> **anonymous-by-default** at the chosen scope and **operator-cryptographically
> opaque** at rest: stored ciphertext reveals neither publisher identity, group
> identity, nor content to anyone holding the disk (the encryption boundary IS the
> moderation boundary). The smallest scope consistent with your stated audience is
> chosen automatically — you opt **up** to a broader scope explicitly, never down
> by accident.
>
> **Residual limit.** This does **not** provide unobservability against a *global
> passive adversary* at **federation** scope. Base CEG/RET is not sufficient for
> that strongest threat model. A deployment that needs it MUST layer the
> [Anonymous Tier](https://github.com/CIRISAI/CEWP/blob/main/FSD/ANONYMOUS_TIER.md)
> (Sphinx onion routing) separately.

Any user-facing privacy surface in a deployment (publish UI/CLI, group-creation,
privacy-settings page) MUST surface both halves. The per-publication
`PublishOutcome` scope-echo ("published at scope=X to N holders") is the runtime
surface for the default-protection half; this document is the residual.

## Default scope flip (FSD §3.2)

Post-v6.0.0, a `cohort_scope`-omitted emit resolves to the **smallest** scope for
the audience — NOT silently `federation` as before. Federation scope is now an
**explicit** operator choice.

Run the audit to review every federation-scope emit site:

```
python3 tools/audit_cohort_scope_callers.py          # advisory listing
python3 tools/audit_cohort_scope_callers.py --strict # exit 1 if any federation site
```

Current federation-scope sites are intentional (owner-bindings are
federation-tier per CC 3.2; consent:replication peering, capacity scoring, and
config objects are federation by construction). Re-run after changes.

## Archive mode (FSD §3.5) — group creation

A group/space chooses an `archive_mode` at creation:

- **`rotate-forward`** (default; 30-day window): honest-holder forward-secrecy.
  Records older than the window become unreadable; post-compromise security holds.
- **`retain`**: archive readability **at the cost of PCS**. An adversary who
  compromises a member at epoch N+k recovers everything back to that member's join
  epoch. Choosing `retain` MUST be stated to the operator at creation.

## Deployment guidance

- Prefer **scope-segregated** deployments: don't co-locate federation-scope and
  intimate-scope corpora where a single disk compromise widens the blast radius.
- Cold-state opacity is verified: a forensic disk inspection of
  `federation_scope_blobs` recovers no publisher identity, group identity, or
  content (CIRISConformance#19, §9 bullet 1).

## References

- [CEWP/FSD/SCOPE_PRIVACY.md](https://github.com/CIRISAI/CEWP/blob/main/FSD/SCOPE_PRIVACY.md) — the construction
- [CEWP/FSD/ANONYMOUS_TIER.md](https://github.com/CIRISAI/CEWP/blob/main/FSD/ANONYMOUS_TIER.md) — the GPA-residual opt-in tier
- CIRIS Constitution CC 1.13.3.x (anonymity-by-default + dual-statement)
- CIRISServer#38 (this adoption) · CIRISConformance#19 (end-to-end ratification)
