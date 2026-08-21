package ai.ciris.mobile.shared.ui.screens

import ai.ciris.mobile.shared.localization.localizedString
import ai.ciris.mobile.shared.models.chat.CegChatMessage
import ai.ciris.mobile.shared.platform.testable
import ai.ciris.mobile.shared.platform.testableClickable
import ai.ciris.mobile.shared.platform.testableWithHandler
import ai.ciris.mobile.shared.ui.components.AttKind
import ai.ciris.mobile.shared.ui.components.AttOp
import ai.ciris.mobile.shared.ui.components.AttStatus
import ai.ciris.mobile.shared.ui.components.Attestation
import ai.ciris.mobile.shared.ui.components.AttestationCard
import ai.ciris.mobile.shared.ui.components.CIRISIcons
import ai.ciris.mobile.shared.ui.components.ViewerAuthority
import ai.ciris.mobile.shared.ui.nav.LocalIsCompactWindow
import ai.ciris.mobile.shared.viewmodels.UserChatViewModel
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * The server's own ceiling (`src/contacts_chat.rs::MAX_MESSAGE_BYTES`).
 *
 * The server measures `req.body.len()` on a Rust `String` — that is UTF-8
 * BYTES. Kotlin's `String.length` is UTF-16 code UNITS, and the two disagree on
 * every character outside ASCII: an emoji is 4 bytes but 2 code units, most CJK
 * is 3 bytes and 1 unit. Gating on `length` therefore lets ~6,000 emoji (24 KB)
 * past the button to be refused at the wire, and would block a 16,000-character
 * ASCII message that the server would have accepted. Always compare
 * [utf8Size], never `length`.
 */
private const val MAX_MESSAGE_BYTES = 16 * 1024

/** The draft's size in the units the server counts: UTF-8 bytes. */
private fun String.utf8Size(): Int = encodeToByteArray().size

/**
 * **User-to-user chat** — a two-member community whose messages ARE CEG
 * attestations.
 *
 * Every message renders through the SAME [AttestationCard] +
 * `AttestationHamburger` every other CEG object on this client uses, with
 * [AttKind.Message]. That is not a stylistic choice: a chat row is a `scores`
 * attestation with an `attestation_id`, an attester, a cohort scope and a folded
 * status, and a bespoke bubble that hid those would be a second, weaker object
 * model for rows that are ordinary attestations. The card says what the row is;
 * the hamburger offers the same op vocabulary, gated the same way.
 *
 * [CegChatMessage.mine] drives BOTH the alignment (the reader's own messages sit
 * right) and the viewer authority handed to the op gate.
 *
 * Test tags:
 *  - ``chat_transcript``        — the LazyColumn
 *  - ``chat_msg_<attestationId>`` — one message row
 *  - ``input_chat_body``        — the composer
 *  - ``btn_chat_send``          — send
 *  - ``btn_chat_refresh``       — re-read the transcript
 *  - ``btn_chat_back``          — back navigation
 *  - ``chat_refusal``           — the typed refusal banner
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    viewModel: UserChatViewModel,
    /** The contact's fed-ID — the other member of the pair. */
    contactKeyId: String,
    /**
     * The DERIVED pair community id from the contact card — used to tell one
     * room from another, NOT as the address to send to. The ViewModel resolves
     * the authoritative community from the node before anything can be sent.
     */
    communityId: String,
    /** Display name for the other member (alias if the peer store has one). */
    contactLabel: String,
    onBack: () -> Unit,
) {
    val community by viewModel.community.collectAsState()
    val messages by viewModel.messages.collectAsState()
    val transcriptLoaded by viewModel.transcriptLoaded.collectAsState()
    val loading by viewModel.loading.collectAsState()
    val draft by viewModel.draft.collectAsState()
    val sending by viewModel.sending.collectAsState()
    val refusalReasonId by viewModel.refusalReasonId.collectAsState()
    val refusalDetail by viewModel.refusalDetail.collectAsState()

    LaunchedEffect(communityId, contactKeyId) {
        viewModel.enter(communityId, contactKeyId)
    }

    // The transcript is OLDEST FIRST, so the newest row is the last one — that
    // is what a reader entering a conversation wants under their thumb.
    val listState = rememberLazyListState()
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) listState.scrollToItem(messages.lastIndex)
    }

    var detailsFor by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(contactLabel.ifBlank { localizedString("mobile.chat_title_fallback") })
                        Text(
                            localizedString(
                                "mobile.chat_subtitle_members",
                                "count",
                                (community?.memberKeyIds?.size ?: 2).toString(),
                            ),
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                navigationIcon = {
                    if (!LocalIsCompactWindow.current) {
                        IconButton(
                            onClick = onBack,
                            modifier = Modifier.testableClickable("btn_chat_back") { onBack() },
                        ) {
                            Icon(
                                CIRISIcons.arrowBack,
                                contentDescription = localizedString("common_back"),
                            )
                        }
                    } else {
                        Spacer(Modifier.width(56.dp))
                    }
                },
                actions = {
                    IconButton(
                        onClick = { viewModel.refresh() },
                        enabled = !loading,
                        // Same rule as the send button: testableClickable appends
                        // an UNCONDITIONAL clickable, so a disabled refresh still
                        // fired — and a second loadMessages on the same epoch can
                        // finish first, letting the OLDER response overwrite the
                        // newer transcript. The handler re-checks what enabled
                        // gates.
                        modifier = Modifier.testableWithHandler("btn_chat_refresh") {
                            if (!loading) viewModel.refresh()
                        },
                    ) {
                        Icon(
                            CIRISIcons.refresh,
                            contentDescription = localizedString("common_refresh"),
                        )
                    }
                },
            )
        },
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
        ) {
            // ── The typed refusal ─────────────────────────────────────────────
            if (refusalReasonId != null || refusalDetail != null) {
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.errorContainer,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 6.dp)
                        .testable("chat_refusal"),
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        refusalReasonId?.let { id ->
                            Text(
                                localizedString(id),
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onErrorContainer,
                            )
                        }
                        refusalDetail?.takeIf { it.isNotBlank() }?.let { detail ->
                            Spacer(Modifier.height(4.dp))
                            Text(
                                detail,
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.8f),
                            )
                        }
                    }
                }
            }

            // ── Transcript ────────────────────────────────────────────────────
            Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
                when {
                    loading && messages.isEmpty() -> Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center,
                    ) { CircularProgressIndicator() }

                    transcriptLoaded && messages.isEmpty() -> Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            localizedString("mobile.chat_empty"),
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(32.dp),
                        )
                    }

                    else -> LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxSize().testable("chat_transcript"),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(2.dp),
                    ) {
                        items(messages, key = { it.attestationId }) { msg ->
                            MessageRow(
                                message = msg,
                                detailsOpen = detailsFor == msg.attestationId,
                                onOp = { op ->
                                    // Only ViewDetails / History are ever
                                    // enabled for a message; the rest are
                                    // shown-and-disabled with their reason.
                                    if (op == AttOp.ViewDetails || op == AttOp.History) {
                                        detailsFor =
                                            if (detailsFor == msg.attestationId) null else msg.attestationId
                                    }
                                },
                            )
                        }
                    }
                }
            }

            // ── Composer ──────────────────────────────────────────────────────
            // Recomputed once per keystroke rather than once per recomposition:
            // encoding a 16 KB string on every frame of a scroll would be waste.
            val draftBytes = remember(draft) { draft.utf8Size() }
            Surface(tonalElevation = 2.dp, modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                    Row(verticalAlignment = Alignment.Bottom) {
                        OutlinedTextField(
                            value = draft,
                            onValueChange = viewModel::setDraft,
                            enabled = !sending,
                            label = { Text(localizedString("mobile.chat_input_hint")) },
                            modifier = Modifier.weight(1f).testable("input_chat_body"),
                        )
                        Spacer(Modifier.width(8.dp))
                        // ONE predicate for the human and the robot. The
                        // Material `enabled` gates the real button, but
                        // `testableClickable` appends an UNCONDITIONAL
                        // clickable — a second tap mid-flight (or on an
                        // oversized draft) fired send() through the automation
                        // layer, and a message is an attestation: the duplicate
                        // is irreversible. `testableWithHandler` registers for
                        // automation without adding a clickable, and the
                        // handler re-checks the SAME predicate the button uses.
                        val canSend = !sending && draft.isNotBlank() &&
                            draftBytes <= MAX_MESSAGE_BYTES
                        Button(
                            onClick = { viewModel.send() },
                            enabled = canSend,
                            modifier = Modifier.testableWithHandler("btn_chat_send") {
                                if (canSend) viewModel.send()
                            },
                        ) {
                            Text(
                                if (sending) localizedString("mobile.chat_sending")
                                else localizedString("mobile.chat_send"),
                            )
                        }
                    }
                    // Say the ceiling BEFORE the node refuses at it — the
                    // refusal is correct but arrives after the writing.
                    if (draftBytes > MAX_MESSAGE_BYTES / 2) {
                        Text(
                            localizedString(
                                "mobile.chat_length_counter",
                                mapOf(
                                    "used" to draftBytes.toString(),
                                    "max" to MAX_MESSAGE_BYTES.toString(),
                                ),
                            ),
                            fontSize = 10.sp,
                            color = if (draftBytes > MAX_MESSAGE_BYTES) {
                                MaterialTheme.colorScheme.error
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                        )
                    }
                }
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// One message = one attestation card
// ═════════════════════════════════════════════════════════════════════════════

@Composable
private fun MessageRow(
    message: CegChatMessage,
    detailsOpen: Boolean,
    onOp: (AttOp) -> Unit,
) {
    val badge = localizedString("mobile.chat_badge_message")
    val att = Attestation(
        id = message.attestationId,
        kind = AttKind.Message,
        status = message.status.toAttStatus(),
        badge = badge,
        // The one varying metadata line: who is speaking, and the content type
        // when it is not the default. The BODY is not put here — it belongs in
        // the readable slot, not the mono metadata line.
        dimension = message.contentType.takeIf { it.isNotBlank() && it != "text/plain" },
        // TWO AXES, both stated. The node signed it; the human wrote it. Reading
        // the sender off `attesting_key_id` would label every message — yours and
        // theirs — with the box that carried it.
        attesterKeyId = message.attestingKeyId.takeIf { it.isNotBlank() },
        authorKeyId = message.author?.takeIf { it.isNotBlank() },
        timestamp = message.assertedAt.takeIf { it.isNotBlank() },
        supersededBy = message.statusAttestationId,
    )
    Row(
        modifier = Modifier.fillMaxWidth().testable("chat_msg_${message.attestationId}"),
        horizontalArrangement = if (message.mine) Arrangement.End else Arrangement.Start,
    ) {
        Box(modifier = Modifier.fillMaxWidth(0.94f)) {
            AttestationCard(
                att = att,
                // `mine` IS the viewer's authority over this row — the op gate
                // re-checks and the node 403s anyway, so this is a hint, not a
                // permission.
                viewer = ViewerAuthority(isHolder = message.mine),
                onOp = onOp,
            ) {
                // `mine` follows the AUTHOR (the server derives it from the same
                // envelope field), so this stays correct now that the attester is
                // the node. For the far side, name the person rather than "Them"
                // when the row carries an author.
                Text(
                    when {
                        message.mine -> localizedString("mobile.chat_you")
                        message.author?.isNotBlank() == true ->
                            message.speakerKeyId.take(16) + "\u2026"
                        else -> localizedString("mobile.chat_them")
                    },
                    fontSize = 10.sp,
                    fontFamily = if (!message.mine && message.author?.isNotBlank() == true) {
                        FontFamily.Monospace
                    } else {
                        FontFamily.Default
                    },
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(2.dp))
                Text(message.body, fontSize = 14.sp)
                if (detailsOpen) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        localizedString(
                            "mobile.chat_details",
                            mapOf(
                                "type" to message.attestationType,
                                "scope" to message.cohortScope,
                                "status" to message.status,
                            ),
                        ),
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    message.statusAttestationId?.let { composer ->
                        Text(
                            localizedString("mobile.chat_details_composer", "id", composer),
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (message.subjectKeyIds.isNotEmpty()) {
                        Text(
                            localizedString(
                                "mobile.chat_details_subjects",
                                "ids",
                                message.subjectKeyIds.joinToString(", ") { it.take(12) + "…" },
                            ),
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}

/**
 * The server's folded status → the card's standing.
 *
 * The vocabulary is persist's own (`memory_api`'s CEG projection uses the same
 * four tokens), so this is a rename, not a reinterpretation. An unrecognised
 * token maps to [AttStatus.Active] rather than being dropped: a message whose
 * status this client does not know is still a message that was said.
 */
private fun String.toAttStatus(): AttStatus = when (this) {
    CegChatMessage.STATUS_WITHDRAWN -> AttStatus.Withdrawn
    CegChatMessage.STATUS_SUPERSEDED -> AttStatus.Superseded
    CegChatMessage.STATUS_RECANTED -> AttStatus.Recanted
    else -> AttStatus.Active
}
