package ai.ciris.mobile.shared.ui.screens

import ai.ciris.mobile.shared.localization.localizedString
import ai.ciris.mobile.shared.models.federation.Contact
import ai.ciris.mobile.shared.models.federation.LocalPeerState
import ai.ciris.mobile.shared.models.federation.PeerTrustState
import ai.ciris.mobile.shared.platform.testable
import ai.ciris.mobile.shared.platform.testableClickable
import ai.ciris.mobile.shared.ui.components.CIRISIcons
import ai.ciris.mobile.shared.ui.nav.LocalIsCompactWindow
import ai.ciris.mobile.shared.viewmodels.ContactsViewModel
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

/**
 * **Contacts** — the node client's home surface.
 *
 * Two modes, and they read two different sets on purpose:
 *
 *  - **Browse mode** (default): the owner's CONTACTS (``GET /v1/contacts``) —
 *    the people a `consent:replication:v1` grant stands with, each carrying the
 *    derived `chat_community_id` for their two-person room. Tapping one opens
 *    the chat. When the list is EMPTY the screen lands on the add-by-fedID card
 *    as the primary action, because an empty contacts list has exactly one
 *    useful next move.
 *  - **Picker mode** ([onPeerPicked] != null): the node's KNOWN PEERS
 *    (``GET /v1/federation/peers``), each row offering a "Choose" chip.
 *    Delegation targets need not be contacts, so narrowing this to contacts
 *    would silently remove valid choices.
 *
 * Test tags:
 *  - ``contacts_list``            — the LazyColumn
 *  - ``input_contacts_search``    — the search field
 *  - ``contacts_row_<keyId>``     — each row (full key_id, no truncation)
 *  - ``btn_contacts_pick_<keyId>``— the "Choose" chip (picker mode only)
 *  - ``btn_contacts_chat_<keyId>``— open the chat with that contact
 *  - ``card_contacts_add``        — the add-a-contact card
 *  - ``input_contacts_add_key``   — the fedID field
 *  - ``btn_contacts_add_submit``  — submit the add
 *  - ``btn_contacts_add_open``    — reveal the add card when the list is non-empty
 *  - ``contacts_add_refusal``     — the typed refusal banner
 *  - ``btn_contacts_refresh``     — the refresh icon button
 *  - ``btn_contacts_back``        — back navigation
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContactsScreen(
    viewModel: ContactsViewModel,
    onBack: () -> Unit,
    /** Open the two-person chat with this contact. Browse mode only. */
    onOpenChat: (Contact) -> Unit = {},
    /** When non-null the screen is in picker mode — each row shows a "Choose" button. */
    onPeerPicked: ((LocalPeerState) -> Unit)? = null,
) {
    val pickerMode = onPeerPicked != null

    val contacts by viewModel.contacts.collectAsState()
    val contactsLoaded by viewModel.contactsLoaded.collectAsState()
    val peers by viewModel.peers.collectAsState()
    val loading by viewModel.loading.collectAsState()
    val error by viewModel.error.collectAsState()
    val searchQuery by viewModel.searchQuery.collectAsState()
    val addBusy by viewModel.addBusy.collectAsState()
    val addRefusalReasonId by viewModel.addRefusalReasonId.collectAsState()
    val addError by viewModel.addError.collectAsState()
    val justAdded by viewModel.justAdded.collectAsState()

    LaunchedEffect(Unit) { viewModel.load() }

    // The add card is ALWAYS presented over an empty contact list — that is the
    // "land on Add a Contact" rule. Over a non-empty list it is opt-in so the
    // conversations stay the first thing on screen.
    var addExpanded by remember { mutableStateOf(false) }
    var addKeyId by remember { mutableStateOf("") }
    val listIsEmpty = contacts.isEmpty() && searchQuery.isBlank()
    val showAddCard = !pickerMode && (addExpanded || (contactsLoaded && listIsEmpty))

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        if (pickerMode) localizedString("mobile.contacts_title_picker")
                        else localizedString("mobile.contacts_title"),
                    )
                },
                navigationIcon = {
                    if (!LocalIsCompactWindow.current) {
                        IconButton(
                            onClick = onBack,
                            modifier = Modifier.testableClickable("btn_contacts_back") { onBack() },
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
                    if (!pickerMode) {
                        IconButton(
                            onClick = { addExpanded = !addExpanded },
                            modifier = Modifier.testableClickable("btn_contacts_add_open") {
                                addExpanded = !addExpanded
                            },
                        ) {
                            Icon(
                                Icons.Filled.Add,
                                contentDescription = localizedString("mobile.contacts_add_title"),
                            )
                        }
                    }
                    IconButton(
                        onClick = { viewModel.refresh() },
                        enabled = !loading,
                        modifier = Modifier.testableClickable("btn_contacts_refresh") { viewModel.refresh() },
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
            // ── Search ────────────────────────────────────────────────────────
            OutlinedTextField(
                value = searchQuery,
                onValueChange = viewModel::setSearchQuery,
                singleLine = true,
                label = {
                    Text(
                        if (pickerMode) localizedString("mobile.contacts_search_peers_hint")
                        else localizedString("mobile.contacts_search_hint"),
                    )
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp)
                    .testable("input_contacts_search"),
            )

            // ── Error banner (list-level) ─────────────────────────────────────
            error?.let { msg ->
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.errorContainer,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                ) {
                    Text(
                        msg,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.padding(10.dp),
                    )
                }
            }

            // ── Add a Contact ─────────────────────────────────────────────────
            if (showAddCard) {
                AddContactCard(
                    keyId = addKeyId,
                    onKeyIdChange = { addKeyId = it; viewModel.clearAddError() },
                    busy = addBusy,
                    emptyState = listIsEmpty,
                    refusalReasonId = addRefusalReasonId,
                    refusalDetail = addError,
                    justAdded = justAdded,
                    onSubmit = { viewModel.addContact(addKeyId) },
                    onOpenChat = {
                        justAdded?.let { c ->
                            viewModel.consumeJustAdded()
                            addKeyId = ""
                            addExpanded = false
                            onOpenChat(c)
                        }
                    },
                    onDismissAdded = { viewModel.consumeJustAdded(); addKeyId = "" },
                )
            }

            // ── Loading spinner ───────────────────────────────────────────────
            val listEmptyNow = if (pickerMode) peers.isEmpty() else contacts.isEmpty()
            if (loading && listEmptyNow) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
                return@Column
            }

            // ── Empty state ───────────────────────────────────────────────────
            if (listEmptyNow) {
                // With the add card already on screen the empty list needs no
                // second "nothing here" panel — it would repeat the card's own
                // copy directly beneath it.
                if (!showAddCard) {
                    EmptyPanel(
                        message = when {
                            searchQuery.isNotBlank() && pickerMode ->
                                localizedString("mobile.contacts_peers_no_match", "query", searchQuery)
                            searchQuery.isNotBlank() ->
                                localizedString("mobile.contacts_no_match", "query", searchQuery)
                            pickerMode -> localizedString("mobile.contacts_peers_empty")
                            else -> localizedString("mobile.contacts_empty_title")
                        },
                    )
                }
                return@Column
            }

            // ── The list ──────────────────────────────────────────────────────
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .testable("contacts_list"),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (pickerMode) {
                    items(peers, key = { it.keyId }) { peer ->
                        PeerRow(peer = peer, onPick = { onPeerPicked?.invoke(peer) })
                    }
                } else {
                    items(contacts, key = { it.keyId }) { contact ->
                        ContactRow(contact = contact, onOpenChat = { onOpenChat(contact) })
                    }
                }
                item { Spacer(Modifier.height(16.dp)) }
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Add a Contact
// ═════════════════════════════════════════════════════════════════════════════

/**
 * The add-by-fedID flow, and the primary action when the contact list is empty.
 *
 * Refusals are rendered from the node's typed `reason_id` — not from the English
 * sentence — because two of them have remedies that point in opposite
 * directions: `contacts.unknown_fed_id` means the key must be ADMITTED first
 * (peering), and `contacts.self_contact` means the key is this node's own. The
 * server's English is kept as the fallback line for any id the bundle does not
 * carry, which is the designed degradation rather than an error.
 */
@Composable
private fun AddContactCard(
    keyId: String,
    onKeyIdChange: (String) -> Unit,
    busy: Boolean,
    emptyState: Boolean,
    refusalReasonId: String?,
    refusalDetail: String?,
    justAdded: Contact?,
    onSubmit: () -> Unit,
    onOpenChat: () -> Unit,
    onDismissAdded: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testable("card_contacts_add"),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
        ),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
            Text(
                localizedString("mobile.contacts_add_title"),
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                if (emptyState) localizedString("mobile.contacts_empty_body")
                else localizedString("mobile.contacts_add_hint"),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = keyId,
                onValueChange = onKeyIdChange,
                singleLine = true,
                enabled = !busy,
                label = { Text(localizedString("mobile.contacts_add_field_label")) },
                modifier = Modifier.fillMaxWidth().testable("input_contacts_add_key"),
            )

            // ── The typed refusal ─────────────────────────────────────────────
            if (refusalReasonId != null || refusalDetail != null) {
                Spacer(Modifier.height(8.dp))
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.errorContainer,
                    modifier = Modifier.fillMaxWidth().testable("contacts_add_refusal"),
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        // The localized answer for the id the node returned. An
                        // id the bundle does not carry resolves to itself, which
                        // is why the server's English follows it rather than
                        // replacing it.
                        refusalReasonId?.let { id ->
                            Text(
                                localizedString(id),
                                fontSize = 12.sp,
                                fontWeight = FontWeight.SemiBold,
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

            // ── Success ───────────────────────────────────────────────────────
            justAdded?.let { added ->
                Spacer(Modifier.height(8.dp))
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text(
                            localizedString(
                                "mobile.contacts_added",
                                "who",
                                added.keyId.take(16) + "…",
                            ),
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                        )
                        Row {
                            TextButton(
                                onClick = onOpenChat,
                                modifier = Modifier.testableClickable("btn_contacts_add_open_chat") { onOpenChat() },
                            ) { Text(localizedString("mobile.contacts_open_chat")) }
                            TextButton(
                                onClick = onDismissAdded,
                                modifier = Modifier.testableClickable("btn_contacts_add_dismiss") { onDismissAdded() },
                            ) { Text(localizedString("common_close")) }
                        }
                    }
                }
            }

            Spacer(Modifier.height(12.dp))
            Button(
                onClick = onSubmit,
                enabled = !busy && keyId.isNotBlank(),
                modifier = Modifier.testableClickable("btn_contacts_add_submit") { onSubmit() },
            ) {
                Text(
                    if (busy) localizedString("mobile.contacts_add_submit_busy")
                    else localizedString("mobile.contacts_add_submit"),
                )
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Rows
// ═════════════════════════════════════════════════════════════════════════════

@Composable
private fun ContactRow(
    contact: Contact,
    onOpenChat: () -> Unit,
) {
    val (icon, tint) = trustGlyph(contact.trust)
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testableClickable("contacts_row_${contact.keyId}") { onOpenChat() },
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            TrustGlyph(icon, tint, contact.trust)

            Column(modifier = Modifier.weight(1f)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = contact.aliasOverride ?: (contact.keyId.take(12) + "…"),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (contact.canonical) {
                        MiniBadge(
                            localizedString("mobile.contacts_badge_canonical"),
                            MaterialTheme.colorScheme.secondaryContainer,
                            MaterialTheme.colorScheme.onSecondaryContainer,
                        )
                    }
                    MiniBadge(trustLabel(contact.trust), tint.copy(alpha = 0.15f), tint)
                }
                Spacer(Modifier.height(2.dp))
                Text(
                    text = contact.keyId.take(16) + "…",
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = if (contact.chatStarted) localizedString("mobile.contacts_chat_started")
                    else localizedString("mobile.contacts_chat_not_started"),
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (contact.occurrenceKeyIds.isNotEmpty()) {
                    Text(
                        text = localizedString(
                            "mobile.contacts_occurrences",
                            "count",
                            contact.occurrenceKeyIds.size.toString(),
                        ),
                        fontSize = 10.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                    )
                }
                // The de-admitted-but-still-consented arm. Said out loud rather
                // than rendered as a normal row, because the grant is real and
                // only the human can retract it.
                if (contact.projectionMissing) {
                    Text(
                        text = localizedString("mobile.contacts_projection_missing"),
                        fontSize = 10.sp,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }

            AssistChip(
                onClick = onOpenChat,
                label = { Text(localizedString("mobile.contacts_open_chat"), fontSize = 12.sp) },
                modifier = Modifier.testableClickable("btn_contacts_chat_${contact.keyId}") { onOpenChat() },
            )
        }
    }
}

@Composable
private fun PeerRow(
    peer: LocalPeerState,
    onPick: () -> Unit,
) {
    val (icon, tint) = trustGlyph(peer.trust)
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testable("contacts_row_${peer.keyId}"),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            TrustGlyph(icon, tint, peer.trust)

            Column(modifier = Modifier.weight(1f)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        text = peer.aliasOverride ?: (peer.keyId.take(12) + "…"),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (peer.canonical) {
                        MiniBadge(
                            localizedString("mobile.contacts_badge_canonical"),
                            MaterialTheme.colorScheme.secondaryContainer,
                            MaterialTheme.colorScheme.onSecondaryContainer,
                        )
                    }
                    MiniBadge(trustLabel(peer.trust), tint.copy(alpha = 0.15f), tint)
                }
                Spacer(Modifier.height(2.dp))
                Text(
                    text = peer.keyId.take(16) + "…",
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = localizedString(
                        "mobile.contacts_pubkey",
                        "short",
                        peer.pubkeyEd25519Base64.take(10) + "…",
                    ),
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = localizedString(
                        "mobile.contacts_first_seen",
                        "when",
                        formatInstant(peer.firstSeen),
                    ),
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                )
            }

            AssistChip(
                onClick = onPick,
                label = { Text(localizedString("mobile.contacts_choose"), fontSize = 12.sp) },
                modifier = Modifier.testableClickable("btn_contacts_pick_${peer.keyId}") { onPick() },
            )
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════════════════════

@Composable
private fun TrustGlyph(icon: ImageVector, tint: Color, trust: PeerTrustState) {
    Box(
        modifier = Modifier
            .size(40.dp)
            .clip(CircleShape)
            .background(tint.copy(alpha = 0.15f)),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = trustLabel(trust),
            tint = tint,
            modifier = Modifier.size(22.dp),
        )
    }
}

/**
 * The trust state as READING MATTER, not as the wire token.
 *
 * `PeerTrustState.wire` is a protocol value — it is English by accident of the
 * protocol being written in English, and rendering it straight makes the badge
 * and its screen-reader description the one thing on this surface that never
 * translates.
 */
@Composable
private fun trustLabel(trust: PeerTrustState): String = when (trust) {
    PeerTrustState.TRUSTED -> localizedString("mobile.contacts_trust_trusted")
    PeerTrustState.UNTRUSTED -> localizedString("mobile.contacts_trust_untrusted")
    PeerTrustState.BLOCKED -> localizedString("mobile.contacts_trust_blocked")
    PeerTrustState.UNKNOWN -> localizedString("mobile.contacts_trust_unknown")
}

@Composable
private fun MiniBadge(text: String, bg: Color, fg: Color) {
    Surface(shape = RoundedCornerShape(4.dp), color = bg) {
        Text(
            text,
            fontSize = 10.sp,
            color = fg,
            modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp),
        )
    }
}

@Composable
private fun EmptyPanel(message: String) {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                Icons.Filled.Person,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                message,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontSize = 14.sp,
            )
        }
    }
}

private fun trustGlyph(trust: PeerTrustState): Pair<ImageVector, Color> = when (trust) {
    PeerTrustState.TRUSTED -> Icons.Filled.Check to Color(0xFF4CAF50)
    PeerTrustState.UNKNOWN -> Icons.Filled.Person to Color(0xFF9E9E9E)
    PeerTrustState.UNTRUSTED -> Icons.Filled.Warning to Color(0xFFFF9800)
    PeerTrustState.BLOCKED -> Icons.Filled.Warning to Color(0xFFF44336)
}

private fun formatInstant(instant: Instant): String = try {
    val local = instant.toLocalDateTime(TimeZone.currentSystemDefault())
    "${local.year}-${local.monthNumber.toString().padStart(2, '0')}-${local.dayOfMonth.toString().padStart(2, '0')}"
} catch (_: Exception) {
    instant.toString().take(10)
}
