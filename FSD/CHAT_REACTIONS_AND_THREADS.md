# FSD: Chat reactions and threads

Status: **DRAFT, for agreement with the client, edge and the constitution.** Asked for by Eric on
2026-11-19: "emoji reactions to rows in a room, and threads, and then all of the above inside the
thread, but no threads in threads. That should be it for chat." Game sharing and social activity
are out of scope here.

Who builds what:
- the **constitution** confirms the grammar (§2);
- **edge** writes and reads the rows (`src/chat.rs`, beside the supersede, withdraw and recant
  composers);
- the **server** carries the routes and the read model (§3);
- the **client** carries the UI (§4).

## 1. What a person can do

1. **React** to any message in a room with an emoji: add one, see who reacted with what, take
   yours back. One person can put several different emoji on one message, but each emoji only
   once.
2. **Reply in a thread.** Any top-level message can start a thread. A thread is flat: every reply
   names the thread's root, and a reply cannot start a thread of its own ("no threads in threads").
3. **Everything a message can do, a reply can do too:**
   - an attachment, including images, renditions and animated GIFs (`FSD/ROSTER_AND_DRIVE_CRUD.md`
     §5 point 10);
   - edits (supersede), withdrawals and recants;
   - reactions;
   - moderation (report, the 48-hour window, reveal).

   Calls stay at room level. A thread has no call of its own.

## 2. The rows (proposal, for edge and the constitution)

Both follow the composer pattern edge already has: a row that names its target message by
attestation id, in the clear, in the room's scope. Content stays sealed under the room's DEK.

- **A reply** is an ordinary `chat:message:v1` row with one more clear member,
  `replies_to_attestation_id`: the thread's ROOT message. It is CC 3.3.11's
  `topical_relation:replies_to`, carried on the message row the way `attachment_attestation_id`
  is, rather than as a second row. That keeps a reply and its edge as one atomic write.
  - **No threads in threads:**
    - The author's node refuses a reply whose named target is itself a reply
      (`chat.thread_in_thread`).
    - A reader that holds such a row anyway (an old or hostile author) files it under the target's
      root. It never opens a nested thread.
    - A reply names a message of the same room, or the author's node refuses it
      (`chat.reply_target_not_in_room`).
  - The root does not change when the thread grows: nothing is written to it.
- **A reaction** is a new row, `chat:reaction:v1` (under CC 3.1.9's NodeCore `chat:*`, open):
  - **clear members:** `community_key_id` and `target_attestation_id` (any message or reply of the
    room);
  - **sealed body:** the emoji, so which emoji someone chose is as private as what they wrote. It is
    one Unicode extended grapheme cluster of at most 32 UTF-8 bytes, checked against the emoji
    property tables; text that isn't an emoji is refused (`chat.not_an_emoji`).
  - **Taking it back** is a `withdraws` naming the reaction row, by its author only: the existing
    withdraw composer, generalised to a reaction target.
  - **One per (person, target, emoji):** the author's node refuses a duplicate
    (`chat.reaction_exists`). A reader that holds two keeps the earliest.
- Both rows are ordinary room content. They cross on the room's widening plane, are moderated like
  messages (a `content_class:reported` on a reply works unchanged), and expire with the room's
  retention.

**Persist (2026-11-19): no change needed on 61.4.x.** Persist classifies the whole `chat:` prefix
as one family (same audience rules as `chat:message`; v38.2.0, #757), and the chat family has no
closed payload list, so the extra clear member passes, on v62 too. **On v62 (edition 2)** a
reference to another row belongs in `refs` (by row id), not in the payload. So a reply's root and a
reaction's target should use a `refs` role, for example `refs.answers` or `refs.also.cites`, which
travels with its parent under CC 2.7.5's copy rule. CC names the role.

**Constitution (2026-11-19): settled.**
- `chat:reaction:v1` under the open `chat:` family is admissible as-is, with the emoji sealed and
  take-back by `withdraws`. It needs a documentation-only registry entry plus one paragraph in CC
  3.3.11.
- On 61.4.x the clear payload members (`replies_to_attestation_id`, `target_attestation_id`)
  stand; no separate `topical_relation` row is needed.
- On v62 a reply names its root, and a reaction its message, in **`refs.answers`**
  (`signed_object_v2.cddl`: "the row replied to"; an ancestor, so it travels with the reply under
  CC 2.7.5). Not `also.cites`.
- Flat threads are a product rule: "how a client threads replies is the client's choice".
- Landed in CC 3.3.11 at rc21 397100e.

## 3. Server routes (for the client)

Message listing (`GET /v1/chat/{room}/messages`) is unchanged, except:
- a top-level message gains `thread: {reply_count, last_reply_at, participants: [person…] (at most
  5)}`, or `null` when there are no replies;
- every message, top-level or reply, gains `reactions: [{emoji, count, people: [person…] (at most
  10), mine: bool, my_reaction_id}]`, ordered by first use;
- replies are not in the room's main list, unless `?with_replies=1` is passed (for search and
  export).

New:
- `GET /v1/chat/{room}/messages?thread={root_id}`: the thread, the root first and then the
  replies in order, paged like the room (`resume`). Each item has the same shape as a room item.
- `POST /v1/chat/{room}/messages` with `replies_to: {root_id}`: post a reply. The body is the
  existing message body (text, attachment). Refusals: `chat.thread_in_thread` 409 (the target is a
  reply; the body names its root as `root_attestation_id` so the client can retarget), `chat.reply_target_not_in_room` 404,
  `chat.reply_target_withdrawn` 410.
- `POST /v1/chat/{room}/messages/{id}/reactions` `{emoji}`: react. Answers `{reaction_id}`.
  Refusals: `chat.not_an_emoji` 400, `chat.reaction_exists` 409 (with the existing
  `reaction_id`), `chat.reaction_limit` 409 (20 distinct per person per message),
  `chat.reaction_target_not_in_room` 404.
- `DELETE /v1/chat/{room}/messages/{id}/reactions/{reaction_id}`: take a reaction back (the
  author's own only: `chat.not_your_reaction` 403).
- The room event stream: `reaction_added {target, emoji, person, reaction_id}`,
  `reaction_removed {...}` and `reply_added {root, attestation_id, person}`, so open screens update
  without polling.

The item actions (`messages/{id}/{action}` and `items/{id}/{action}`) work on replies unchanged.

### 3.1 Agreed with the client (2026-11-19)

1. **An edit keeps its reactions and its thread.** A supersede mints a new id, but reactions and
   replies fold by LINEAGE: the current version carries the reactions and the thread of every
   version in its chain. Reacting or replying to a superseded id is accepted and lands on the
   chain. Readers fold it; nothing is refused.
2. **Files carried by a message or a reply.** Each drive entry a chat row carries gets
   `carried_by: {attestation_id, thread_root | null}`. The room's "added a file" rows leave out
   every carried file, so a file attached in a thread never comes back as a stray room row, and the
   files panel can say "in a thread".
3. **The room event stream (new):** `WS /v1/chat/{room}/events?ticket=…`. The ticket comes from
   `POST /v1/chat/{room}/events` (owner session), as the call sockets do it. Resume after a drop
   with `&since=<cursor>`; each event carries its `cursor`. Events:
   - `message_added`;
   - `reply_added {root, attestation_id, person}`;
   - `thread_updated {root, reply_count, last_reply_at}`;
   - `reaction_added {target, reaction_id, emoji, person}` and
     `reaction_removed {target, reaction_id, emoji, person}`;
   - `item_changed {attestation_id, change: superseded | withdrawn | recanted | withheld}`.

   Until a node declares `chat:events`, the client re-reads the transcript after each act.
4. **A reply item carries `replies_to: {root}`** (the root's attestation id) wherever it appears:
   in a thread, with `?with_replies=1`, and in search.
5. **Thread paging:** `?thread={root}&from=end` gives the newest replies first, and `before=` pages
   back. The root is always the first item of every answer, so the header never goes missing.
6. **Withdrawn and recanted targets:**
   - A withdrawn root's thread stays readable, with the root shown as withdrawn and its reason.
   - `chat.reply_target_withdrawn` refuses only NEW replies.
   - Reactions on a withdrawn or recanted message are left out of the read model: no bar and no
     counts.
7. **`chat.thread_in_thread` names the root** as `root_attestation_id`. The client retargets
   silently.
8. **At most 20 distinct emoji per person per message:** `chat.reaction_limit` 409, published in
   the conformance answer so the picker can say so first. Readers count at most 20 per person, the
   earliest.
9. **Emoji are compared byte for byte, after NFC**, as fully-qualified sequences with skin-tone
   and ZWJ intact, so 👍🏽 and 👍 are different reactions.
10. **Moderation:** a flagged reply is withheld in the thread exactly as in the room (a notice and
    reveal). A withheld reply still counts in `reply_count`, and `thread.participants` leaves
    nobody out.

## 4. Client (CIRISClient)

- A reaction bar under each message, plus a quick-pick on long-press or hover. An emoji with
  `mine` toggles off.
- A thread affordance on a top-level message: the reply count, the last reply time and up to five
  participant avatars. It opens the thread view: the root, the replies and a composer.
- Inside the thread view: attachments, image renditions, animated GIFs (loop, once or still),
  reactions, edit, withdraw and moderation. There is no "reply in thread" on a reply: the composer
  always answers the root.
- Gate the whole feature on the node's conformance features (`chat:reactions`, `chat:threads`),
  not on its version.

## 5. Order of work

1. Agree §2 with the constitution and edge, and §3 with the client.
2. Edge: the two rows, in the first edge release after 45.1.7 (Eric's call: an LTS 45.1.x patch or
   the refactor cut).
3. Server: the routes and read model on that pin, with `drive_crud`-style route tests, plus a native
   harness scenario: two people, a thread with an image and reactions inside it, a refused nested
   thread, a withdrawn reaction, all crossing between nodes. CI runs it on the binary and the fold,
   like `av_share`.
4. Client: the UI against §3, dormant until the features are declared.
