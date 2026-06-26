package ai.ciris.mobile.shared.ui.screens.graph

import ai.ciris.mobile.shared.api.CIRISApiClient
import ai.ciris.mobile.shared.models.NodeProfile
import ai.ciris.mobile.shared.models.federation.DelegationDto
import ai.ciris.mobile.shared.platform.testableClickable
import ai.ciris.mobile.shared.viewmodels.ConsentObjectsState
import ai.ciris.mobile.shared.viewmodels.GrantDirectionState
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.TextMeasurer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ai.ciris.mobile.shared.ui.components.CIRISIcons
import kotlin.math.PI
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Node-mesh graph for the Manage Nodes screen.
 *
 * This is the GRAPH half of the graph ⇄ list toggle. It visualises the user's
 * "consent-driven network topology" as vertices + four edge types, reusing the
 * memory-graph render approach ([GraphCanvas]'s canvas/mote/edge/pan-zoom
 * pattern, [GraphColors] helpers, [GraphViewport] transform) and the agent
 * Interact page's neural animated background ([LiveGraphBackground]).
 *
 * VERTICES = { the user's Fed ID (1), each delegated Agent ID (N), each owned /
 * managed node (M) }.
 *
 * EDGES (four distinct types, by colour/style + direction):
 *  - [NodeEdgeKind.OWNER_BINDING]       human → node  (delegates_to owner-binding)
 *  - [NodeEdgeKind.DELEGATION]          human → agent (device-auth grant)
 *  - [NodeEdgeKind.AGENT_ACTS_ON]       agent → node  (the grant's authority on a node)
 *  - [NodeEdgeKind.CONSENT_REPLICATION] node  → node  (bilateral consent:replication)
 *
 * The renderer is intentionally NOT a physics engine — vertices are laid out
 * deterministically (Fed ID at the centre, owned nodes on an inner ring, agents
 * on an outer ring) so the same mesh always reads the same way.
 */

/** A vertex kind in the node mesh. */
enum class NodeVertexKind { FED_ID, NODE, AGENT }

/** One of the four edge types over the mesh. */
enum class NodeEdgeKind { OWNER_BINDING, DELEGATION, AGENT_ACTS_ON, CONSENT_REPLICATION }

/** A laid-out vertex (world coordinates centred on origin). */
data class NodeGraphVertex(
    val id: String,
    val kind: NodeVertexKind,
    val label: String,
    val keyId: String?,
    val radius: Float,
    val color: Color,
    val x: Float,
    val y: Float,
    /** The backing profile for NODE vertices (enables switch / remove). */
    val profile: NodeProfile? = null,
    val isActive: Boolean = false,
)

/** A directed edge between two vertices, typed + optionally state-bearing. */
data class NodeGraphEdge(
    val source: String,
    val target: String,
    val kind: NodeEdgeKind,
    /** Direction-state for consent:replication grants (null for the rest). */
    val state: GrantDirectionState? = null,
)

/** The fully-built mesh ready to render. */
data class NodeGraphData(
    val vertices: List<NodeGraphVertex>,
    val edges: List<NodeGraphEdge>,
) {
    val byId: Map<String, NodeGraphVertex> by lazy { vertices.associateBy { it.id } }
}

private const val NODE_RING_RADIUS = 200f
private const val AGENT_RING_RADIUS = 360f

// Vertex palette (aligned with GraphColors' type colours).
private val FedIdColor = Color(0xFF06B6D4)   // Cyan — identity
private val NodeColor = Color(0xFF3B82F6)     // Blue — node
private val AgentColor = Color(0xFF10B981)    // Green — agent

// Edge palette — each of the four types is visually distinct.
private val OwnerBindingColor = Color(0xFF3B82F6)      // Blue, solid
private val DelegationColor = Color(0xFF10B981)        // Green, solid
private val AgentActsOnColor = Color(0xFFF59E0B)       // Amber, dashed
private val ConsentColor = Color(0xFF8B5CF6)           // Purple, solid (dashed until granted)

private const val FED_ID_VERTEX = "fedid:self"

/**
 * Project the three ViewModels' state into a typed, laid-out node mesh.
 *
 * @param profiles owned / managed nodes (NodeSwitcher).
 * @param activeProfileId the currently-active node id.
 * @param delegations device-auth grants — each delegated `client_id` IS an Agent ID.
 * @param consent the bilateral consent:replication state (node A ↔ node B).
 */
fun buildNodeGraph(
    profiles: List<NodeProfile>,
    activeProfileId: String?,
    delegations: List<DelegationDto>,
    consent: ConsentObjectsState,
): NodeGraphData {
    val vertices = mutableListOf<NodeGraphVertex>()
    val edges = mutableListOf<NodeGraphEdge>()

    fun nodeVid(p: NodeProfile) = "node:${p.id}"
    fun agentVid(clientId: String) = "agent:$clientId"

    // ── Vertex: the user's Fed ID (centre) ──────────────────────────────────
    vertices += NodeGraphVertex(
        id = FED_ID_VERTEX,
        kind = NodeVertexKind.FED_ID,
        label = "You (Fed ID)",
        keyId = null,
        radius = 40f,
        color = FedIdColor,
        x = 0f,
        y = 0f,
    )

    // ── Vertices: owned / managed nodes (inner ring) ────────────────────────
    val nodeCount = profiles.size.coerceAtLeast(1)
    profiles.forEachIndexed { i, p ->
        val angle = -PI / 2 + 2 * PI * i / nodeCount
        vertices += NodeGraphVertex(
            id = nodeVid(p),
            kind = NodeVertexKind.NODE,
            label = p.name.ifBlank { p.baseUrl.ifBlank { p.id } },
            keyId = p.pinnedKeyId,
            radius = if (p.isLocal) 32f else 28f,
            color = NodeColor,
            x = (NODE_RING_RADIUS * cos(angle)).toFloat(),
            y = (NODE_RING_RADIUS * sin(angle)).toFloat(),
            profile = p,
            isActive = p.id == activeProfileId,
        )
    }

    // ── Vertices: delegated agents (outer ring) ─────────────────────────────
    val agentIds = delegations.map { it.clientId }.distinct()
    val agentCount = agentIds.size.coerceAtLeast(1)
    agentIds.forEachIndexed { i, clientId ->
        // Offset the agent ring so agents interleave between the node spokes.
        val angle = -PI / 2 + 2 * PI * i / agentCount + PI / agentCount
        vertices += NodeGraphVertex(
            id = agentVid(clientId),
            kind = NodeVertexKind.AGENT,
            label = clientId,
            keyId = clientId,
            radius = 24f,
            color = AgentColor,
            x = (AGENT_RING_RADIUS * cos(angle)).toFloat(),
            y = (AGENT_RING_RADIUS * sin(angle)).toFloat(),
        )
    }

    val present = vertices.map { it.id }.toSet()

    // ── Edge: human → node (owner-binding) ──────────────────────────────────
    profiles.filter { it.isOwned }.forEach { p ->
        edges += NodeGraphEdge(FED_ID_VERTEX, nodeVid(p), NodeEdgeKind.OWNER_BINDING)
    }

    // ── Edge: human → agent (delegation) ────────────────────────────────────
    agentIds.forEach { clientId ->
        edges += NodeGraphEdge(FED_ID_VERTEX, agentVid(clientId), NodeEdgeKind.DELEGATION)
    }

    // ── Edge: agent → node (the grant's authority to act on a node) ─────────
    // Delegations are issued by the LOCAL node, so a delegated agent has
    // authority to act ON the local node. Fall back to the active node, then
    // the first node, when no local node is listed.
    val authorityNode = profiles.firstOrNull { it.isLocal }
        ?: profiles.firstOrNull { it.id == activeProfileId }
        ?: profiles.firstOrNull()
    if (authorityNode != null) {
        agentIds.forEach { clientId ->
            edges += NodeGraphEdge(agentVid(clientId), nodeVid(authorityNode), NodeEdgeKind.AGENT_ACTS_ON)
        }
    }

    // ── Edge: node → node (bilateral consent:replication) ───────────────────
    val ca = consent.nodeA
    val cb = consent.nodeB
    if (ca != null && cb != null) {
        val aId = nodeVid(ca)
        val bId = nodeVid(cb)
        if (aId in present && bId in present) {
            edges += NodeGraphEdge(aId, bId, NodeEdgeKind.CONSENT_REPLICATION, consent.aToB)
            edges += NodeGraphEdge(bId, aId, NodeEdgeKind.CONSENT_REPLICATION, consent.bToA)
        }
    }

    // Drop any dangling edges (defensive — keeps the renderer total).
    val safeEdges = edges.filter { it.source in present && it.target in present }
    return NodeGraphData(vertices, safeEdges)
}

private fun NodeEdgeKind.color(): Color = when (this) {
    NodeEdgeKind.OWNER_BINDING -> OwnerBindingColor
    NodeEdgeKind.DELEGATION -> DelegationColor
    NodeEdgeKind.AGENT_ACTS_ON -> AgentActsOnColor
    NodeEdgeKind.CONSENT_REPLICATION -> ConsentColor
}

private fun NodeGraphEdge.dashed(): Boolean = when (kind) {
    NodeEdgeKind.AGENT_ACTS_ON -> true
    // Consent edges render dashed until the grant is actually ratified.
    NodeEdgeKind.CONSENT_REPLICATION -> state != GrantDirectionState.GRANTED
    else -> false
}

private fun NodeEdgeKind.legendLabel(): String = when (this) {
    NodeEdgeKind.OWNER_BINDING -> "owner-binding (you → node)"
    NodeEdgeKind.DELEGATION -> "delegation (you → agent)"
    NodeEdgeKind.AGENT_ACTS_ON -> "agent acts on node"
    NodeEdgeKind.CONSENT_REPLICATION -> "consent:replication (node ↔ node)"
}

/**
 * The node-mesh graph composable.
 *
 * Reuses [LiveGraphBackground] as the ambient neural backdrop (when an
 * [apiClient] is available) and the [GraphCanvas]-style canvas renderer for the
 * mesh on top. Tappable vertices select; a detail panel surfaces the selected
 * vertex's name / key_id / edges and (for nodes) the switch + remove actions.
 */
@Composable
fun NodeGraphView(
    profiles: List<NodeProfile>,
    activeProfileId: String?,
    delegations: List<DelegationDto>,
    consent: ConsentObjectsState,
    apiClient: CIRISApiClient?,
    onSwitchNode: (NodeProfile) -> Unit,
    onRemoveNode: (NodeProfile) -> Unit,
    modifier: Modifier = Modifier,
) {
    val data = remember(profiles, activeProfileId, delegations, consent) {
        buildNodeGraph(profiles, activeProfileId, delegations, consent)
    }
    val textMeasurer = rememberTextMeasurer()

    var viewport by remember { mutableStateOf(GraphViewport()) }
    var canvasSize by remember { mutableStateOf(IntSize.Zero) }
    var centered by remember { mutableStateOf(false) }
    var selectedId by remember { mutableStateOf<String?>(null) }

    // Drop a stale selection if the mesh changed underneath us.
    if (selectedId != null && data.byId[selectedId] == null) {
        selectedId = null
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .clip(RoundedCornerShape(12.dp))
            .background(GraphColors.Background)
            .onSizeChanged { sz ->
                canvasSize = sz
                if (!centered && sz.width > 0 && sz.height > 0) {
                    // Centre world-origin in the viewport (scale starts at 1f).
                    viewport = viewport.copy(
                        offsetX = sz.width / 2f,
                        offsetY = sz.height / 2f,
                    )
                    centered = true
                }
            },
    ) {
        // ── Neural animated background (reused from the Interact page) ───────
        if (apiClient != null) {
            LiveGraphBackground(
                apiClient = apiClient,
                modifier = Modifier.matchParentSize(),
                baseOpacity = 0.35f,
            )
        }

        // ── Mesh canvas (pan / zoom / tap-select) ───────────────────────────
        Canvas(
            modifier = Modifier
                .matchParentSize()
                .pointerInput(data) {
                    detectTransformGestures { _, pan, zoom, _ ->
                        val newScale = (viewport.scale * zoom).coerceIn(0.3f, 3f)
                        viewport = viewport.copy(
                            offsetX = viewport.offsetX + pan.x / viewport.scale,
                            offsetY = viewport.offsetY + pan.y / viewport.scale,
                            scale = newScale,
                        )
                    }
                }
                .pointerInput(data) {
                    detectTapGestures(
                        onTap = { offset ->
                            val worldX = viewport.inverseTransformX(offset.x)
                            val worldY = viewport.inverseTransformY(offset.y)
                            val hit = findVertexAtPosition(
                                data.vertices, worldX, worldY,
                                touchRadius = 24f / viewport.scale,
                            )
                            selectedId = hit?.id
                        },
                    )
                },
        ) {
            // Edges first (behind vertices).
            data.edges.forEach { edge ->
                val s = data.byId[edge.source] ?: return@forEach
                val t = data.byId[edge.target] ?: return@forEach
                val highlighted = selectedId == edge.source || selectedId == edge.target
                drawMeshEdge(
                    edge = edge,
                    sourceX = viewport.transformX(s.x),
                    sourceY = viewport.transformY(s.y),
                    targetX = viewport.transformX(t.x),
                    targetY = viewport.transformY(t.y),
                    targetRadius = t.radius * viewport.scale,
                    scale = viewport.scale,
                    isHighlighted = highlighted,
                )
            }
            // Vertices.
            data.vertices.forEach { v ->
                drawMeshVertex(
                    vertex = v,
                    x = viewport.transformX(v.x),
                    y = viewport.transformY(v.y),
                    radius = v.radius * viewport.scale,
                    isSelected = selectedId == v.id,
                )
                drawMeshLabel(
                    textMeasurer = textMeasurer,
                    label = v.label,
                    x = viewport.transformX(v.x),
                    y = viewport.transformY(v.y) + v.radius * viewport.scale + 8f,
                    scale = viewport.scale,
                    isSelected = selectedId == v.id,
                )
            }
        }

        // ── Invisible per-vertex tap/test targets ───────────────────────────
        // Canvas-drawn motes can't carry testTags, so we overlay a tiny
        // transparent clickable box per vertex (tag node_graph_node_<key_id>).
        // These also drive selection on platforms without gesture pointers.
        val density = LocalDensity.current
        data.vertices.forEach { v ->
            val screenX = viewport.transformX(v.x)
            val screenY = viewport.transformY(v.y)
            val rPx = (v.radius * viewport.scale).coerceAtLeast(14f)
            val sizeDp = with(density) { (rPx * 2).toDp() }
            val tagKey = (v.keyId ?: v.id).replace(Regex("[^A-Za-z0-9_-]"), "_")
            Box(
                modifier = Modifier
                    .offset { IntOffset((screenX - rPx).roundToInt(), (screenY - rPx).roundToInt()) }
                    .size(sizeDp)
                    .testableClickable("node_graph_node_$tagKey") { selectedId = v.id },
            )
        }

        // ── Legend (top-start) ──────────────────────────────────────────────
        Surface(
            modifier = Modifier.align(Alignment.TopStart).padding(8.dp),
            color = GraphColors.BackgroundLight.copy(alpha = 0.9f),
            shape = RoundedCornerShape(8.dp),
        ) {
            Column(Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    text = "Node mesh",
                    style = MaterialTheme.typography.labelMedium,
                    color = GraphColors.LabelColor,
                    fontWeight = FontWeight.Bold,
                )
                LegendRow(FedIdColor, "you · Fed ID")
                LegendRow(NodeColor, "node")
                LegendRow(AgentColor, "agent")
                Spacer(Modifier.height(2.dp))
                NodeEdgeKind.entries.forEach { kind -> LegendRow(kind.color(), kind.legendLabel()) }
            }
        }

        // ── Selected-vertex detail panel (bottom) ───────────────────────────
        selectedId?.let { id ->
            data.byId[id]?.let { v ->
                Surface(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .fillMaxWidth()
                        .padding(8.dp),
                    color = GraphColors.BackgroundLight.copy(alpha = 0.96f),
                    shape = RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp),
                ) {
                    VertexDetailPanel(
                        vertex = v,
                        data = data,
                        onClose = { selectedId = null },
                        onSwitchNode = onSwitchNode,
                        onRemoveNode = onRemoveNode,
                    )
                }
            }
        }

        // ── Empty state ─────────────────────────────────────────────────────
        if (data.vertices.size <= 1 && profiles.isEmpty()) {
            Text(
                text = "No nodes yet — add one to see your mesh.",
                modifier = Modifier.align(Alignment.Center).padding(24.dp),
                color = GraphColors.LabelColorMuted,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
private fun LegendRow(color: Color, label: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Box(modifier = Modifier.size(10.dp).clip(CircleShape).background(color))
        Text(label, style = MaterialTheme.typography.labelSmall, color = GraphColors.LabelColorMuted)
    }
}

@Composable
private fun VertexDetailPanel(
    vertex: NodeGraphVertex,
    data: NodeGraphData,
    onClose: () -> Unit,
    onSwitchNode: (NodeProfile) -> Unit,
    onRemoveNode: (NodeProfile) -> Unit,
) {
    val incident = data.edges.filter { it.source == vertex.id || it.target == vertex.id }
    Column(
        modifier = Modifier.padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(4.dp))
                        .background(vertex.color)
                        .padding(horizontal = 8.dp, vertical = 4.dp),
                ) {
                    Text(
                        text = vertex.kind.name,
                        style = MaterialTheme.typography.labelSmall,
                        color = Color.White,
                    )
                }
                if (vertex.isActive) {
                    Text("active", style = MaterialTheme.typography.labelSmall, color = GraphColors.LabelColorMuted)
                }
            }
            IconButton(onClick = onClose) {
                Icon(CIRISIcons.close, contentDescription = "Close", tint = GraphColors.LabelColorMuted)
            }
        }

        Text(
            text = vertex.label,
            style = MaterialTheme.typography.titleSmall,
            color = GraphColors.LabelColor,
            fontWeight = FontWeight.Bold,
        )
        vertex.keyId?.let {
            Text(
                text = "key_id: ${it.take(28)}${if (it.length > 28) "…" else ""}",
                style = MaterialTheme.typography.labelSmall,
                color = GraphColors.LabelColorMuted,
            )
        }

        if (incident.isNotEmpty()) {
            Spacer(Modifier.height(2.dp))
            Text("Connections", style = MaterialTheme.typography.labelMedium, color = GraphColors.LabelColorMuted)
            incident.forEach { e ->
                val outgoing = e.source == vertex.id
                val otherId = if (outgoing) e.target else e.source
                val other = data.byId[otherId]?.label ?: otherId
                val arrow = if (outgoing) "→" else "←"
                val stateSuffix = e.state?.let { " (${it.name.lowercase()})" } ?: ""
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(e.kind.color()))
                    Text(
                        text = "$arrow $other · ${e.kind.legendLabel()}$stateSuffix",
                        style = MaterialTheme.typography.labelSmall,
                        color = GraphColors.LabelColorMuted,
                    )
                }
            }
        }

        // Node actions (switch / remove) — reuse the existing NodeSwitcher ops.
        vertex.profile?.let { p ->
            Spacer(Modifier.height(4.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (!vertex.isActive) {
                    OutlinedButton(
                        onClick = { onSwitchNode(p) },
                        modifier = Modifier.testableClickable("btn_graph_node_switch_${p.id}") { onSwitchNode(p) },
                    ) {
                        Text("Set active")
                    }
                }
                OutlinedButton(
                    onClick = { onRemoveNode(p); onClose() },
                    modifier = Modifier.testableClickable("btn_graph_node_remove_${p.id}") { onRemoveNode(p); onClose() },
                ) {
                    Icon(CIRISIcons.delete, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Remove")
                }
            }
        }
    }
}

// ── Canvas drawing (adapted from GraphCanvas) ───────────────────────────────

private fun DrawScope.drawMeshEdge(
    edge: NodeGraphEdge,
    sourceX: Float,
    sourceY: Float,
    targetX: Float,
    targetY: Float,
    targetRadius: Float,
    scale: Float,
    isHighlighted: Boolean,
) {
    val base = edge.kind.color()
    val color = if (isHighlighted) GraphColors.lighten(base, 0.3f) else base.copy(alpha = 0.7f)
    val strokeWidth = if (isHighlighted) 3.5f * scale else 2f * scale
    val pathEffect = if (edge.dashed()) {
        PathEffect.dashPathEffect(floatArrayOf(10f * scale, 6f * scale), 0f)
    } else null

    val dx = targetX - sourceX
    val dy = targetY - sourceY
    val dist = sqrt(dx * dx + dy * dy).coerceAtLeast(0.001f)

    // Gentle curve (matches the memory graph's bezier feel).
    val curvature = 0.12f
    val midX = (sourceX + targetX) / 2
    val midY = (sourceY + targetY) / 2
    val perpX = -dy / dist * curvature * dist
    val perpY = dx / dist * curvature * dist
    val controlX = midX + perpX
    val controlY = midY + perpY

    val path = Path().apply {
        moveTo(sourceX, sourceY)
        quadraticBezierTo(controlX, controlY, targetX, targetY)
    }
    drawPath(
        path = path,
        color = color,
        style = Stroke(width = strokeWidth, cap = StrokeCap.Round, pathEffect = pathEffect),
    )

    // Direction arrowhead, placed just outside the target vertex along the
    // curve's incoming tangent (control-point → target).
    val tx = targetX - controlX
    val ty = targetY - controlY
    val tdist = sqrt(tx * tx + ty * ty).coerceAtLeast(0.001f)
    val ux = tx / tdist
    val uy = ty / tdist
    val tipX = targetX - ux * (targetRadius + 2f)
    val tipY = targetY - uy * (targetRadius + 2f)
    val angle = atan2(uy, ux)
    val headLen = 10f * scale
    val spread = (PI / 7).toFloat()
    val leftX = tipX - headLen * cos(angle - spread)
    val leftY = tipY - headLen * sin(angle - spread)
    val rightX = tipX - headLen * cos(angle + spread)
    val rightY = tipY - headLen * sin(angle + spread)
    drawLine(color, Offset(tipX, tipY), Offset(leftX, leftY), strokeWidth = strokeWidth, cap = StrokeCap.Round)
    drawLine(color, Offset(tipX, tipY), Offset(rightX, rightY), strokeWidth = strokeWidth, cap = StrokeCap.Round)
}

private fun DrawScope.drawMeshVertex(
    vertex: NodeGraphVertex,
    x: Float,
    y: Float,
    radius: Float,
    isSelected: Boolean,
) {
    if (isSelected) {
        drawCircle(
            color = GraphColors.SelectionColor,
            radius = radius + 4f,
            center = Offset(x, y),
            style = Stroke(width = 3f),
        )
    }
    drawCircle(
        color = GraphColors.darken(vertex.color, 0.3f),
        radius = radius,
        center = Offset(x, y),
    )
    drawCircle(
        color = if (isSelected) GraphColors.lighten(vertex.color, 0.2f) else vertex.color,
        radius = radius - 2f,
        center = Offset(x, y),
    )
    // Active node gets a small inner ring marker.
    if (vertex.isActive) {
        drawCircle(
            color = Color.White.copy(alpha = 0.8f),
            radius = radius * 0.4f,
            center = Offset(x, y),
            style = Stroke(width = 2f),
        )
    }
}

private fun DrawScope.drawMeshLabel(
    textMeasurer: TextMeasurer,
    label: String,
    x: Float,
    y: Float,
    scale: Float,
    isSelected: Boolean,
) {
    val display = if (label.length > 22) label.take(19) + "…" else label
    val fontSize = (10f * scale).coerceIn(8f, 14f)
    val layout = textMeasurer.measure(
        text = display,
        style = TextStyle(
            color = if (isSelected) GraphColors.LabelColor else GraphColors.LabelColorMuted,
            fontSize = fontSize.sp,
        ),
    )
    drawText(
        textLayoutResult = layout,
        topLeft = Offset(x - layout.size.width / 2, y),
    )
}

private fun findVertexAtPosition(
    vertices: List<NodeGraphVertex>,
    x: Float,
    y: Float,
    touchRadius: Float,
): NodeGraphVertex? {
    return vertices.lastOrNull { v ->
        val dx = v.x - x
        val dy = v.y - y
        sqrt(dx * dx + dy * dy) <= v.radius + touchRadius
    }
}
