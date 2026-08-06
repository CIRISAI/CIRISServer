package ai.ciris.mobile.shared.models

import ai.ciris.mobile.shared.models.selfreader.ReaderCommitRequest
import ai.ciris.mobile.shared.models.selfreader.ReaderDecision
import ai.ciris.mobile.shared.models.selfreader.ReaderDecisionResponse
import ai.ciris.mobile.shared.models.selfreader.ReaderFoldResponse
import ai.ciris.mobile.shared.models.selfreader.ReaderStanding
import ai.ciris.mobile.shared.models.selfreader.SelfActResponse
import ai.ciris.mobile.shared.models.selfreader.SelfAxis
import ai.ciris.mobile.shared.models.selfreader.SelfCommitRequest
import ai.ciris.mobile.shared.models.selfreader.SelfStanding
import ai.ciris.mobile.shared.models.selfreader.SelfStandingResponse
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The tier S / tier R wire contract, pinned against the bodies
 * `CIRISServer/src/admin_ops.rs` actually builds
 * (`self_fold_json`, `self_standing`, `self_act_route`, `reader_fold_json`,
 * `reader_decision_route`).
 *
 * These two files must AGREE while each is individually valid, which is the
 * shape of this codebase's worst bugs — a DTO that parses without error and
 * silently drops the one field that carried the meaning. Every body below is
 * copied from the server's own builder, not from a live capture, so a rename on
 * either side lands here.
 */
class SelfAndReaderOpsWireTest {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    // ─── Tier S ──────────────────────────────────────────────────────────────

    /** `GET /v1/admin/self`, 200: three axes, three different standings. */
    private val selfStanding200 = """
    {
      "source_locale": "en",
      "tier": "S",
      "node_key_id": "key-node-1",
      "standings": {
        "load_shed": {
          "axis": "load_shed",
          "standing": "in_force",
          "message": {"id": "admin.self.standing.in_force", "text": "This node declared this and has not lifted it."},
          "since": "2026-08-05T10:00:00+00:00",
          "event_id": "ev-1",
          "delegation_id": "del-1",
          "reason": "carrying less during the migration",
          "counts": {"declarations": 2, "lifts": 1}
        },
        "accepting": {
          "axis": "accepting",
          "standing": "lifted",
          "message": {"id": "admin.self.standing.lifted", "text": "..."},
          "since": "2026-08-04T09:00:00+00:00",
          "event_id": "ev-2",
          "delegation_id": null,
          "reason": null,
          "counts": {"declarations": 1, "lifts": 1}
        },
        "legal_compulsion": {
          "axis": "legal_compulsion",
          "standing": "never_declared",
          "message": {"id": "admin.self.standing.never_declared", "text": "..."},
          "since": null,
          "event_id": null,
          "delegation_id": null,
          "reason": null,
          "counts": {"declarations": 0, "lifts": 0}
        }
      },
      "partition": {"id": "admin.self.partition", "text": "..."},
      "distinct_zeroes": {"id": "admin.self.distinct_zeroes", "text": "..."}
    }
    """

    /** The 503 half: the standings are STILL in the body. */
    private val selfStanding503 = """
    {
      "source_locale": "en",
      "tier": "S",
      "node_key_id": "key-node-1",
      "standings": {
        "load_shed": {
          "axis": "load_shed",
          "standing": "unreadable",
          "message": {"id": "admin.self.standing.unreadable", "text": "..."},
          "since": null,
          "event_id": null,
          "delegation_id": null,
          "reason": null,
          "counts": {"declarations": 0, "lifts": 0}
        },
        "accepting": {
          "axis": "accepting",
          "standing": "never_declared",
          "message": {"id": "admin.self.standing.never_declared", "text": "..."},
          "since": null,
          "event_id": null,
          "delegation_id": null,
          "reason": null,
          "counts": {"declarations": 0, "lifts": 0}
        },
        "legal_compulsion": {
          "axis": "legal_compulsion",
          "standing": "never_declared",
          "message": {"id": "admin.self.standing.never_declared", "text": "..."},
          "since": null,
          "event_id": null,
          "delegation_id": null,
          "reason": null,
          "counts": {"declarations": 0, "lifts": 0}
        }
      },
      "partition": {"id": "admin.self.partition", "text": "..."},
      "distinct_zeroes": {"id": "admin.self.distinct_zeroes", "text": "..."},
      "unreadable_axes": {"load_shed": "list hard case events: connection closed"}
    }
    """

    @Test
    fun self_standing_carries_all_three_axes_separately() {
        val decoded = json.decodeFromString(SelfStandingResponse.serializer(), selfStanding200)
        assertEquals("key-node-1", decoded.nodeKeyId)
        assertEquals(3, decoded.standings.size)
        assertEquals(SelfAxis.ALL, decoded.axes().map { it.axis })

        val shed = decoded.standings.getValue(SelfAxis.LOAD_SHED)
        assertEquals(SelfStanding.IN_FORCE, shed.standingValue)
        assertEquals("del-1", shed.delegationId)
        assertEquals("carrying less during the migration", shed.reason)
        assertEquals(2, shed.counts.declarations)
        assertEquals(1, shed.counts.lifts)
        assertEquals("admin.self.standing.in_force", shed.message?.id)

        // The three axes never collapse into one another.
        assertEquals(SelfStanding.LIFTED, decoded.standings.getValue(SelfAxis.ACCEPTING).standingValue)
        assertEquals(
            SelfStanding.NEVER_DECLARED,
            decoded.standings.getValue(SelfAxis.LEGAL_COMPULSION).standingValue,
        )
    }

    @Test
    fun the_three_zeroes_are_three_different_values() {
        val lifted = SelfStanding.LIFTED
        val never = SelfStanding.NEVER_DECLARED
        val unreadable = SelfStanding.UNREADABLE
        // None of them is "in force"…
        assertFalse(lifted.isInForce)
        assertFalse(never.isInForce)
        assertFalse(unreadable.isInForce)
        // …and no two of them are equal, so a UI keyed on the value cannot draw
        // them alike by accident.
        assertEquals(3, setOf(lifted, never, unreadable).size)
        // Only the unreadable one is a NON-answer.
        assertTrue(lifted.isKnown)
        assertTrue(never.isKnown)
        assertFalse(unreadable.isKnown)
    }

    @Test
    fun unreadable_axis_survives_the_503_half() {
        val decoded = json.decodeFromString(SelfStandingResponse.serializer(), selfStanding503)
        val shed = decoded.standings.getValue(SelfAxis.LOAD_SHED)
        assertEquals(SelfStanding.UNREADABLE, shed.standingValue)
        // The unreadable axis is NOT the never-declared one sitting beside it.
        assertTrue(shed.standingValue != decoded.standings.getValue(SelfAxis.ACCEPTING).standingValue)
        assertEquals(1, decoded.unreadableAxes?.size)
        assertTrue(decoded.unreadableAxes?.containsKey(SelfAxis.LOAD_SHED) == true)
    }

    @Test
    fun an_unknown_standing_token_is_not_a_clean_one() {
        // A future standing this client has never seen must land on UNKNOWN —
        // never on NEVER_DECLARED, which would read as "nothing in force".
        assertEquals(SelfStanding.UNKNOWN, SelfStanding.fromWire("some_new_state"))
        assertEquals(SelfStanding.UNKNOWN, SelfStanding.fromWire(null))
        assertEquals(SelfStanding.UNKNOWN, SelfStanding.fromWire(""))
        assertFalse(SelfStanding.UNKNOWN.isKnown)
        assertFalse(SelfStanding.UNKNOWN.isInForce)
    }

    @Test
    fun self_act_lift_response_carries_reversal_and_lift_note() {
        val body = """
        {
          "op": "self_compulsion_lifted",
          "tier": "S",
          "axis": "legal_compulsion",
          "source_locale": "en",
          "required_scope": "infra:serve",
          "delegation_id": "del-1",
          "event_id": "ev-9",
          "standing": {
            "axis": "legal_compulsion",
            "standing": "lifted",
            "message": {"id": "admin.self.standing.lifted", "text": "..."},
            "since": "2026-08-05T12:00:00+00:00",
            "event_id": "ev-9",
            "delegation_id": "del-1",
            "reason": "the order was withdrawn",
            "counts": {"declarations": 1, "lifts": 1}
          },
          "enforcement": {"id": "admin.self.enforcement.compelled", "text": "..."},
          "partition": {"id": "admin.self.partition", "text": "..."},
          "reversal": {"reach": "symmetric", "note": {"id": "admin.reversal.symmetric", "text": "..."}},
          "lift": {"id": "admin.self.lift.compelled", "text": "..."}
        }
        """
        val decoded = json.decodeFromString(SelfActResponse.serializer(), body)
        assertEquals("self_compulsion_lifted", decoded.op)
        assertEquals(SelfAxis.LEGAL_COMPULSION, decoded.axis)
        assertEquals(SelfStanding.LIFTED, decoded.standing?.standingValue)
        assertEquals("symmetric", decoded.reversal?.reach)
        assertEquals("admin.reversal.symmetric", decoded.reversal?.note?.id)
        assertEquals("admin.self.lift.compelled", decoded.lift?.id)
        assertEquals("admin.self.enforcement.compelled", decoded.enforcement?.id)
    }

    @Test
    fun compelled_by_is_absent_from_every_voluntary_act() {
        val voluntary = json.encodeToString(
            SelfCommitRequest.serializer(),
            SelfCommitRequest(delegationId = "del-1", reason = "planned maintenance"),
        )
        assertFalse(
            voluntary.contains("compelled_by"),
            "a voluntary stop must never carry a compelled one's marks: $voluntary",
        )

        val compelled = json.encodeToString(
            SelfCommitRequest.serializer(),
            SelfCommitRequest(
                delegationId = "del-1",
                reason = "served with an order",
                compelledBy = "a court",
            ),
        )
        assertTrue(compelled.contains("\"compelled_by\""))

        // A gagged operator records the compulsion with no authority named, and
        // the act still stands.
        val gagged = json.encodeToString(
            SelfCommitRequest.serializer(),
            SelfCommitRequest(delegationId = "del-1", reason = "served, cannot say by whom"),
        )
        assertFalse(gagged.contains("compelled_by"))
        assertTrue(gagged.contains("\"reason\""))
    }

    // ─── Tier R ──────────────────────────────────────────────────────────────

    private val readerFold200 = """
    {
      "source_locale": "en",
      "tier": "R",
      "subject_key_id": "key-subject",
      "standing": "decided",
      "message": {"id": "admin.reader.standing.decided", "text": "..."},
      "subscription": {"roots": ["key-root-a"], "count": 1},
      "counts": {"judgements_held": 2},
      "judgements": [
        {
          "judgement_id": "att-1",
          "signer_key_id": "key-root-a",
          "dimension": "quarantine:withheld:v1",
          "asserted_at": "2026-08-01T00:00:00+00:00",
          "decision": "honoured_by_subscription",
          "honoured": true,
          "message": {"id": "admin.reader.decision.honoured_by_subscription", "text": "..."}
        },
        {
          "judgement_id": "att-2",
          "signer_key_id": "key-stranger",
          "dimension": "quarantine:withheld:v1",
          "asserted_at": "2026-08-02T00:00:00+00:00",
          "decision": "declined",
          "honoured": false,
          "message": {"id": "admin.reader.decision.declined", "text": "..."}
        }
      ],
      "reader_fold": {
        "key_id": "key-subject",
        "state": "released",
        "marker_id": "att-3",
        "decided_by": "key-root-a",
        "delegation_id": "del-2",
        "effective_at": "2026-08-03T00:00:00+00:00",
        "grounds": "appeal upheld",
        "marker_ids": ["att-1", "att-3"]
      },
      "node_fold": {
        "key_id": "key-subject",
        "state": "withheld",
        "marker_id": "att-2",
        "marker_ids": ["att-1", "att-2", "att-3"]
      },
      "diverges": true,
      "advisory": {"id": "admin.reader.advisory", "text": "..."}
    }
    """

    @Test
    fun reader_fold_carries_both_folds_and_every_decision() {
        val decoded = json.decodeFromString(ReaderFoldResponse.serializer(), readerFold200)
        assertEquals(ReaderStanding.DECIDED, decoded.standingValue)
        assertEquals(2, decoded.counts.judgementsHeld)
        assertEquals(listOf("key-root-a"), decoded.subscription.roots)

        val (honoured, declined) = decoded.judgements
        assertEquals(ReaderDecision.HONOURED_BY_SUBSCRIPTION, honoured.decisionValue)
        assertTrue(honoured.decisionValue.honoured)
        assertFalse(honoured.decisionValue.isDeliberate)

        assertEquals(ReaderDecision.DECLINED, declined.decisionValue)
        assertFalse(declined.decisionValue.honoured)
        // A decline is a DECISION — the thing that separates it from the
        // undecided default, and the reason it is not an error.
        assertTrue(declined.decisionValue.isDeliberate)
        assertTrue(ReaderDecision.UNDECIDED_UNSUBSCRIBED.isDeliberate.not())

        assertEquals("released", decoded.readerFold?.state)
        assertEquals("withheld", decoded.nodeFold?.state)
        assertEquals(3, decoded.nodeFold?.markerIds?.size)
        assertTrue(decoded.diverges)
        assertEquals("admin.reader.advisory", decoded.advisory?.id)
    }

    @Test
    fun reader_fold_503_is_unreadable_and_not_empty() {
        val body = """
        {
          "source_locale": "en",
          "tier": "R",
          "subject_key_id": "key-subject",
          "standing": "unreadable",
          "message": {"id": "admin.reader.standing.unreadable", "text": "..."},
          "refusal": "reader_state_unreadable",
          "error": "read subscription set: connection closed"
        }
        """
        val decoded = json.decodeFromString(ReaderFoldResponse.serializer(), body)
        assertEquals(ReaderStanding.UNREADABLE, decoded.standingValue)
        assertFalse(decoded.standingValue.isKnown)
        // It must never be confusable with "this node holds nothing".
        assertTrue(decoded.standingValue != ReaderStanding.NO_JUDGEMENTS_HELD)
        assertEquals("reader_state_unreadable", decoded.refusal)
        assertNotNull(decoded.error)
        // An unreadable policy is not an empty one: no judgement list is a
        // CONSEQUENCE of the failure here, never evidence of a clean subject.
        assertTrue(decoded.judgements.isEmpty())
    }

    @Test
    fun a_decline_is_a_success_body_not_a_refusal() {
        val body = """
        {
          "op": "reader_decline",
          "tier": "R",
          "source_locale": "en",
          "required_scope": "infra:serve",
          "judgement_id": "att-2",
          "subject_key_id": "key-subject",
          "delegation_id": "del-1",
          "event_id": "ev-7:att-2",
          "outcome": "declined",
          "refused": false,
          "message": {"id": "admin.reader.decision.declined", "text": "..."},
          "standing": {
            "source_locale": "en",
            "tier": "R",
            "subject_key_id": "key-subject",
            "standing": "decided",
            "counts": {"judgements_held": 1},
            "judgements": [],
            "diverges": false
          }
        }
        """
        val decoded = json.decodeFromString(ReaderDecisionResponse.serializer(), body)
        assertEquals("reader_decline", decoded.op)
        assertTrue(decoded.declined)
        // The server states it in the payload, and the client honours it: this
        // is NOT a failure, and a UI branching on shape must not style it as one.
        assertFalse(decoded.refused)
        assertEquals("admin.reader.decision.declined", decoded.message?.id)
        assertEquals(ReaderStanding.DECIDED, decoded.standing?.standingValue)
    }

    @Test
    fun the_decision_route_body_names_the_judgement_it_decides() {
        val encoded = json.encodeToString(
            ReaderCommitRequest.serializer(),
            ReaderCommitRequest(
                judgementId = "att-2",
                delegationId = "del-1",
                reason = "this reader does not adopt that signer's calls",
            ),
        )
        assertTrue(encoded.contains("\"judgement_id\""))
        assertTrue(encoded.contains("\"delegation_id\""))
        assertTrue(encoded.contains("\"reason\""))
    }
}
