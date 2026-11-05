# FSD — The WASM node: one full node, the same code on every target

**Status: DRAFT for Eric's review**, 2026-11-04. Nothing here is built. Probes run while writing it are listed in §13.3.
**Tracks:** CIRISServer#855, CIRISVerify#325.
**Direction:** Eric, 2026-11-04: "create a WASM node FSD - needs to be 100% or nothing, full WASM node so it can run EFI or browser highly efficient - our hybrid seal, we accept for now on most platforms that at best we can hardware secure the classical bits and use that to put the PQC materials under seal".

**Sources, in order of authority:** CC rc17 (`constitution/`, `manifests/choice_item.cddl`, `manifests/view.cddl`) at 7e958b6; pinned code at server v0.5.244, edge v43.4.1, persist v59.1.2, verify v20.2.0, leviculum c6d0a224; the CIRISServer#855 assessment and its addendum; the probes in §13. Line numbers will move; symbols are given with them.

**Evidence marks.** **[M]** measured at runtime here. **[C]** compiled and linked here, not run. **[R]** read in source or the CC. **[W]** published source, listed in §14. **[memory]** recorded project history, not re-derived here. **[inf]** inference nobody has measured. **SIZE** marks S (one PR, one repo), M (a few PRs), L (a release train across repos), XL (a new subsystem); these are judgement from the counts cited, not estimates of time.

**The one sentence:** the node is one `wasm32` module with no imports except a narrow capability ABI, compiled ahead of time on EFI and by the engine in a browser, and "full" means it passes the native conformance suite on every target, with every exception named in a signed host-limit table.

**The scope is settled.** One full node. There is no thin client, no client-only node and no reduced profile in this document. A browser tab that cannot accept a TCP connection is a host limit recorded in §2.4, not a smaller product.

---

## 1. Why this is feasible: what is already proven

| # | Claim | Result | Mark |
|---|---|---|---|
| 1 | The real `ciris_persist::Engine` runs in a browser Worker on OPFS | Boot, genesis `Entrenched`, self key, hybrid-signed federation emit, read back | [M] |
| 2 | A module with SQLite, ML-DSA-65, Ed25519 and all 182 persist migrations needs almost no host | Exactly 3 imports, all ours: `ciris.now_us`, `ciris.random`, `ciris.log`. No JS, no WASI, no wasm-bindgen | [M] |
| 3 | The same bytes run inside UEFI firmware with no OS | SHA-256, Ed25519, ML-DSA-65, 182 migrations, 1,000 rows, queries, in OVMF | [M] |
| 4 | Compiled ahead of time, it is not slow | 672 ms total against 36.8 s interpreted: 55× | [M] |
| 5 | A firmware app can be a network peer | DHCP, TCP dial-out, **inbound TCP accept**, request and reply, against a real host process | [M] |
| 6 | A firmware app can store durably | 1 MiB written through Simple File System and read back; file present on the host after shutdown | [M] |
| 7 | Crash durability on OPFS | Three `kill -9` rounds mid-write: `integrity_check` ok, no acked row lost | [M] |
| 8 | `leviculum-core` and `leviculum-lxmf` | Pass `cargo check` for `wasm32-unknown-unknown` | [C] |
| 9 | Edge with no transports | Passes `cargo check` over patched persist | [C] |
| 10 | Server composition | **Never type-checked.** `ciris-lens-core` stops it at 6 errors. The biggest unknown (§10.2) | not run |

What these do not prove: edge has not run; the server has not compiled; no TPM was exercised; no real motherboard, Safari, Firefox or phone was tested.

---

## 2. Goal and the 100% rule

### 2.1 Goal

One node. The same `ciris-node.wasm`, byte for byte, runs in a browser, in UEFI and under WASI. A native build of the same source stays the control. Node code contains no `cfg(target_*)`.

### 2.2 What "full" means (normative)

A target is **full** if and only if all three hold:

1. **Conformance.** It passes the suite in §11 with the same test list as the native control.
2. **Named exceptions only.** A test may be skipped only if `HOST_LIMITS.tsv` has a row for it, giving the capability, the host, the reason the host forbids it, and the Eric decision that accepted it (§2.4).
3. **Same module.** The artefact under test hashes identically to the artefact on every other wasm target. EFI compiles that same module to a PE; the input hash is what must match.

A limit is **a host limit** only if the host itself forbids the capability. "We have not built it" is never a host limit, and "it is hard in a browser" is never a host limit.

**Capacity is not capability.** A single-threaded node on a laptop-class CPU cannot carry the canonical's load. It has the same capability at less capacity, and load-shedding (CC-level `config:load`, the capacity monitor) already models that. This document never uses capacity to excuse a missing capability, and never uses capability to imply capacity.

### 2.3 Capability inventory

Every row must be present on every target unless a D-number stands against it. Built from server routes (259 `/v1` path literals at v0.5.244 [R]), the 13 loops of `loop_cadence::LOOPS`, the edge transport features and persist feature list.

| Capability | Browser | EFI | wasip2 |
|---|---|---|---|
| Identity, fedID, roster, owner-binding, consent | full | full | full |
| CEG store, admission, replication, anti-entropy | full | full | full |
| All 13 loops | full, foreground; see D2 | full | full |
| Read and control API (`/v1/*`) | in process, plus via relay; **no socket** (D1) | full, socket | full, socket |
| First-run, `choice-item`, `view` | full (§8) | full, headless flow (§8.3) | full |
| Reticulum link, inbound and outbound | full, over a carrier (§7.2) | full | full |
| Reticulum TCP client | as WS/WebTransport carrier | full [M, TCP4] | full |
| Reticulum TCP server | **forbidden** (D1) | full [M, TCP4 accept] | full |
| Reticulum UDP, AutoInterface | **forbidden**: no raw UDP (D1) | UDP4 present [M]; multicast untested | full |
| RNode, serial | WebSerial where offered (D3) | Serial I/O protocol, untested | host dependent |
| I2P | via relay only (D3) | needs local I2P router: none (D3) | host dependent |
| BLE | Web Bluetooth where offered (D3) | no protocol (D3) | host dependent |
| HTTP federation transport | client yes; server **forbidden** (D1) | full | full |
| Direct links (hole punch) | as WebRTC DataChannel (§7.3) | UDP; untested | full |
| A/V calls | full, media via browser engine (D4) | relay and keep only: no camera, mic (D4) | no devices (D4) |
| Blob swarm, drive, chat, rooms, moderation | full | full | full |
| Trace capture and shipping | full | full | full |
| NER scrub tier (`scrub-ner`) | D5 | D5 | D5 |
| Accord-holder key on a PIV token | **forbidden**: browser cannot reach it (D6) | USB token: not investigated (D6) | host dependent |
| Serving seat, mailbox, always-on replica | availability limit (D2) | full | full |
| Agent brain (PyO3, folded Python) | §12 non-goal | §12 | §12 |
| Postgres backend | not a node capability; SQLite is the wasm backend | same | same |

### 2.4 Host limits, for Eric to decide

Each is a place where "full" must be stated honestly rather than quietly narrowed. Nothing here is decided by this document.

| # | Limit | Why the host forbids it | What "full" means there | Recommended |
|---|---|---|---|---|
| **D1** | A browser tab cannot accept an inbound TCP, UDP or HTTP connection | No listen API exists in any browser | Reachable at the Reticulum layer: inbound **links** arrive through a dialled carrier (§7.2). Anything that needs a socket on the tab, including a claim by public URL, does not exist. A peer reaches it by destination hash, as a NAT'd phone is reached today | Accept. State "no listener; reachable via relay" |
| **D2** | A browser node exists only while a tab is open and foregrounded enough to run | Browsers own lifetime: SW idle kill about 30 s [W]; hidden timers 1/min after 5 min [W] | Same verbs as a phone (`enter_background`, `enter_foreground`). It can hold a seat; it cannot promise availability. A serving seat needs an always-on host: EFI, wasip2 or native | Accept. A browser may hold the role; the UI must say what it cannot do |
| **D3** | Radio and local carriers vary by browser and firmware | WebSerial, Web Bluetooth are browser-specific; EFI has no BLE or I2P | Each carrier is a capability the host reports. Absent means absent, by name | Accept per carrier |
| **D4** | EFI has no media devices | No camera or mic protocol | A/V relay, keep, key and seal duties run; capture and playout cannot | Accept |
| **D5** | NER model: `candle`, `tokenizers`, `onig` (C), 100+ MB model | Not forbidden. **So it is not a host limit by the rule above** | Either port it, or apply the existing precedent: iOS has no NER, and `EgressScrubber` relabels `detailed`, loudly | Eric: port, or extend the iOS precedent |
| **D6** | Accord-holder key on a browser | WebUSB protects the smart-card class and blocklists security keys [W]; Web NFC is NDEF-only [W] | A browser cannot be an accord holder on `YubiKey_5_FIPS`. EFI unknown | Accept for browser; investigate EFI USB |

**D1 needs care, because it is the one most easily reworded into "client".** A browser node is not a client: it holds the store, verifies, signs, replicates, serves rows to peers over links, moderates and votes. It lacks a listening socket. The test is the suite in §11: every Reticulum-reachable CSD/4 scenario must pass with a browser node as the *responder*.

---

## 3. Targets

### 3.1 The three hosts

| | Browser | EFI | wasip2 |
|---|---|---|---|
| Execution | Dedicated Worker; engine compiles the module | wasm compiled to C then to PE (§4.2) | Wasmtime |
| Threads | 1 | 1; firmware forbids others [R, rustc book] | 1 |
| Clock | `performance.now`, `Date` | TSC calibrated; `GetTime` | WASI clocks |
| Randomness | `crypto.getRandomValues` | `EFI_RNG_PROTOCOL` [M], with device | WASI random |
| Storage | OPFS sync handles | SFS or Block I/O (§6.3) | WASI filesystem |
| Network | WebSocket, WebTransport, WebRTC, `fetch` | TCP4/6, UDP4/6, SNP [M census] | WASI sockets |
| Seal root | WebAuthn PRF (§8) | TPM via TCG2 (§8) | Host keyring plugin |
| Inbound | No (D1) | Yes [M] | Yes |
| Trust root for code | The origin | Secure Boot, measured boot | The operator |

wasip2 is useful as the middle: fast to run in CI, and a proper component host. It is not on the path to EFI. **SQLite on wasip2:** `rusqlite` with `bundled` and `wasm32-wasi-vfs` builds and links (1.85 MB) [C]; it was not run, because no wasmtime is installed here.

### 3.2 EFI: what exists

**Prior art.** The only public wasm-in-UEFI work found is `jyao1/EfiSandbox`: a package wrapping WAMR's interpreter to run a `.wasm` from the UEFI shell, last pushed 2020, GCC5 X64 only [R]. No public work was found running a persistent network node, SQLite or a PQC stack this way. **What §3.3 reports is, as far as could be found, new.**

**Rust.** `x86_64-unknown-uefi` is Tier 2. `no_std` is the supported path; `std` is "present, but incomplete and extremely new" [W]. The `uefi` crate 0.41 wraps network (HTTP, IP4Config2, PXE, SNP) and TCG v1/v2; `uefi-raw` 0.17 adds raw `Tcp4Protocol`, which is what the probe used [R].

**The model.** Single address space, boot CPU only, no interrupts except the timer, drivers poll, cooperative tasks on one stack [W]. This is an excellent match for a single-threaded, tick-driven node, and it is why the design in §5 is one design rather than two.

**Boot versus runtime services (normative).** The node **MUST NOT call `ExitBootServices`.** After that call no boot service or device-handle protocol may be used [W], so network, disk, TCG2 and timers all vanish. The node is an EFI application that stays in Boot Services for its whole life. It MUST disable the 5-minute watchdog armed before a boot option runs, which the spec permits [W, M: `SetWatchdogTimer(0)`].

### 3.3 EFI: measured in OVMF

QEMU with KVM, Ubuntu EDK II (UEFI 2.70), 2 GiB, one vCPU, `virtio-net`, `virtio-rng`. **This is OVMF, not OEM firmware.** Single runs on a shared box.

**Protocol census [M]:**

| Protocol | Handles | | Protocol | Handles |
|---|---|---|---|---|
| SNP | 3 | | DHCP4 SB | 1 |
| MNP SB | 1 | | DNS4 SB | 1 |
| ARP SB | 1 | | HTTP SB | 1 |
| IP4 SB, IP6 SB | 1, 1 | | TLS SB | 1 |
| UDP4 SB | 1 | | Simple File System | 1 |
| TCP4 SB, TCP6 SB | 1, 1 | | Block I/O | 3 |
| RNG | 0 without a device, 1 with | | TCG2 | **0: no TPM attached** |

Conventional memory 1,998 MiB, largest run 1,959 MiB. **OEM firmware may ship none of the network stack above SNP, or no SNP without a loaded driver [inf].** §7.4 handles that.

**Same payload, three engines [M].** The payload is 2.4 MB of wasm: SHA-256, Ed25519, ML-DSA-65, SQLite 3.53.4 on an in-memory VFS, persist's 182 migrations, 11 KB rows.

| Operation | V8 (Node 20) | wasmi 2.0 in OVMF | wasm2c PE in OVMF |
|---|---|---|---|
| SHA-256, 1 MiB | 10.3 ms | 208 ms | **3.1 ms** |
| Ed25519 sign | 0.34 ms | 15.3 ms | **0.12 ms** |
| ML-DSA-65 keygen | 3.0 ms | 117 ms | **0.83 ms** |
| ML-DSA-65 sign | 2.7 ms | 216 ms | **1.5 ms** |
| ML-DSA-65 verify | 0.35 ms | 28 ms | **0.23 ms** |
| 182 migrations | 490 ms | 23,569 ms | **448 ms** |
| Seed 1,000 rows | 92 ms | 10,846 ms | 162 ms |
| `config:` prefix query | 0.31 ms | 0.85 ms | **0.06 ms** |
| 1000-row read, sorted | 11.4 ms | 594 ms | 22 ms |
| Whole payload | n/a | 36.8 s | **0.67 s** |
| Image size | 2.4 MB wasm | 4.1 MB PE | 4.0 MB PE |

The AOT image is slower than V8 on row seeding and row reads, which are memcpy-heavy; the suspect is `compiler_builtins` `memcpy` on this target [inf]. Worth a real `memcpy` in the host.

Two findings from the probe that any implementation must absorb:

- **wasmi's default dispatch triple-faults on this target.** It relies on tail calls, which the Win64 ABI of the UEFI target does not guarantee, and overflows the firmware stack [M]. `portable-dispatch` fixed it.
- **The firmware stack is too small for the module.** The AOT build runs on its own 64 MiB stack from `AllocatePages`, switched to by a few lines of inline assembly [M]. wasm2c uses the machine stack, so recursion depth is a host-enforced bound (§4.3).

### 3.4 Efficiency targets

"Highly efficient" is testable. Baseline: persist alone, in the browser, `opt-level=2`, no `wasm-opt`.

| Measure | Baseline [M] | Target, browser | Target, EFI |
|---|---|---|---|
| Module size | 30.7 MB raw, 6.85 MB gzip, **persist only** | ≤ 32 MB raw, ≤ 8 MB brotli, **whole node** | same module |
| Image | n/a | n/a | ≤ 60 MB PE |
| Cold start, fresh store | 1.7 s, persist only | ≤ 2.0 s to first tick | ≤ 2.0 s from image entry |
| Warm start, existing store | 119 ms, persist only | ≤ 500 ms to first tick | ≤ 500 ms |
| Peak linear memory at 10k rows | not measured | ≤ 256 MiB | ≤ 256 MiB |
| Hybrid sign | 10 ms including admission and write [M] | ≤ 15 ms | ≤ 10 ms |
| Tick slice | §5.4 | §5.4 | §5.4 |

A whole node above 30.7 MB is expected, since edge and server are not in the baseline; the ratio below suggests 32 MB raw is reachable and tight [inf].

**What shrinks them, with measured ratios on the payload [M]:**

| Step | Raw | gzip | Cost |
|---|---|---|---|
| `opt-level=3` | 2.41 MB | 787 KB | baseline |
| `opt-level="z"`, fat LTO, `codegen-units=1`, `panic=abort`, strip | 1.73 MB | 613 KB | ML-DSA sign 2.7→10 ms, 3.7× slower; migrations 490→605 ms |
| plus `wasm-opt -Oz` | 1.59 MB | 593 KB | none measured |

So size-optimise the whole and **keep crypto and SQLite C at `opt-level=3` by per-package profile** (Cargo supports this) [inf]. Further, none of which removes a capability:

- `panic=abort` and fewer formatting paths; Wasmtime's size guide names formatting as a real cost [W], not measured here.
- Move host-only code out of the module. Everything `wasm-bindgen`, `tokio` net, rustls root stores, `clap`.
- A **schema snapshot** for fresh boot, keeping migrations for upgrades only. 182 migrations are 448-490 ms of the 1.7 s [M]; the rest is genesis [inf].
- Wasm SIMD for SHA-2 and ML-DSA; V8 at 10.3 ms against native-compiled 3.1 ms shows the headroom [inf].
- Streaming compile and Cache API in the browser: repeat load should not recompile [inf].
- `sqlite3` page cache sized deliberately; persist runs the default 2 MB today.

---

## 4. Host interface: the architectural centre

### 4.1 The rule (normative)

1. The node module's **import section contains only `ciris:node/*` interfaces.** No `wasi:*`, no `env`, no wasm-bindgen.
2. Node code contains **no `cfg(target_*)`, `cfg(unix)`, `cfg(windows)`**. Today wasm is neither `unix` nor `windows`, which is how `queue::shutdown_signal` broke [C]. Differences between hosts are **runtime capability answers**, never compile-time branches.
3. **No ambient authority.** There is no path, no environment, no socket, no process. A capability the host did not grant cannot be named. Storage is a handle the host opened, not a filename the node chose.
4. Both directions are gated: CI inspects the built module's imports and fails on any import outside the WIT set; a lint fails on any target `cfg` in a node crate.

This also dissolves the `!Send` problem: JS handles stay on the host side of the ABI, so the node's `Send + Sync` traits (`HardwareSigner`, `Transport`, `Backend`) need no change.

### 4.2 Definition language and lowering

**WIT is the definition.** `wit/ciris-node.wit` is normative. It is lowered to **core wasm imports** under the canonical ABI by `wit-bindgen`.

The module is a **core module**, not a component, because:

- Browsers have no native component support; `jco transpile` makes JS glue, and jco calls itself experimental [W].
- wasm2c consumes core modules [M]. wasmi's component support is experimental [W].
- wasip2 wraps the core module into a component with `wasm-tools component new` plus an adapter, which is one step [inf].

Hand-written ABI glue was used in the probe with 3 imports [M]. **`wit-bindgen` output under wasm2c is untested.**

### 4.3 EFI execution (normative)

| Option | State | Verdict |
|---|---|---|
| **wasm2c to C to PE** | Measured here: wabt 1.0.42, zig cc -O2, 25 s for 32 MB of C, no runtime, no executable-page mapping | **Chosen** |
| wasmi 2.0 | Measured: 55× slower; about 50× V8 on SQL | Test and debug only |
| WAMR AOT | Claimed near-native, about 30 KB runtime [W]; only its interpreter is shown in UEFI [R]; loads native code at run time | Not chosen |
| Wasmtime `no_std` AOT or Pulley | Requires `wasmtime-platform.h` port; AOT-only on `no_std` [W]; not tried | Not chosen |
| wasm3 | Unmaintained since 2022 per one source [W] | Rejected |

Why wasm2c over a loader:

- **Everything is in the signed PE.** No page is ever made executable at run time, so firmware W^X policy is irrelevant, and Secure Boot and PCR measurement cover the node itself, not merely a loader. A loader would be measured while the node it runs is data.
- **No new C runtime.** About 25 lines of `rt.c` sufficed [M]: bounded linear memory, bounds checks on, no signals, no mmap, no `setjmp`.

Configuration (measured): `WASM_RT_MEMCHECK_BOUNDS_CHECK=1`, `GUARD_PAGES=0`, `USE_SEGUE=0`, `NONCONFORMING_UNCHECKED_STACK_EXHAUSTION=1`. **That last flag means a stack overflow is not trapped.** Before production the host MUST place a guard page below the node stack, or build with stack-depth counting and accept the cost.

**A Rust `no_std` host shim is required in all cases**, not an alternative. It is what implements the ABI. The probes covered clock, RNG, log, TCP and a file in very little code [M]; a production shim is a few hundred lines before the VFS and TCG2 [inf]. It owns the stack, the event loop, TCG2 and Block I/O.

Also required: an aarch64 lane. Only x86_64 was tested. wasm2c's output is portable C [inf].

### 4.4 The interface

This is the shape. Types such as `errno`, `custody`, `durability` and `phase` are elided, and the normative file is produced at work item 1. `seal` is §8. The node exports `init`, `tick`, `on-event`, `api`.

```wit
package ciris:node@0.1.0;

interface clock {
  monotonic-us: func() -> u64;          // never goes back; no sleep across suspend guarantee
  wall-ms: func() -> option<s64>;       // none until the host has a trusted time
}

interface random {
  fill: func(len: u32) -> list<u8>;     // CSPRNG or trap; there is no weak fallback
}

interface storage {                     // SYNCHRONOUS on every host. See §6.
  resource volume {
    read:  func(file: u32, offset: u64, len: u32) -> result<list<u8>, errno>;
    write: func(file: u32, offset: u64, data: list<u8>) -> result<_, errno>;
    sync:  func(file: u32) -> result<_, errno>;
    truncate: func(file: u32, size: u64) -> result<_, errno>;
    size:  func(file: u32) -> result<u64, errno>;
    open:  func(name: string, create: bool) -> result<u32, errno>;
    delete: func(name: string) -> result<_, errno>;
    free-bytes: func() -> option<u64>;  // replaces fs4; drives disk_pressure
  }
  durability: func() -> durability;     // persisted | best-effort | evictable
  primary: func() -> volume;
}

interface net {
  enum carrier { tcp, udp, ws, webtransport, webrtc, serial, ble, http-fetch }
  carriers: func() -> list<carrier>;    // runtime answer, never a cfg
  can-listen: func(c: carrier) -> bool; // false for all browser carriers (D1)
  resource stream {
    send: func(data: list<u8>) -> result<u32, errno>;  // non-blocking; partial write
    recv: func(max: u32) -> result<list<u8>, errno>;   // non-blocking; empty = would block
    close: func();
  }
  dial:   func(c: carrier, target: string, token: u64) -> result<stream, errno>;
  listen: func(c: carrier, port: u16, token: u64) -> result<u32, errno>;
  accept: func(listener: u32) -> result<option<stream>, errno>;
}

interface seal {                        // §8
  enum tier { hardware-signs, hardware-seals, software-sealed }
  describe: func() -> custody;          // per-half truth; drives hardware_custody
  provision: func(id: string, material: list<u8>) -> result<_, errno>;
  sign-classical: func(id: string, msg: list<u8>) -> result<list<u8>, errno>;
  sign-pqc: func(id: string, msg: list<u8>) -> result<list<u8>, errno>;
  // Async on every host: a passkey may need a gesture. Completion is an event.
}

interface wake {
  next-deadline: func(us: u64);         // tick me by then
  keep-alive: func(reason: string, on: bool);  // advisory
}

interface log {
  record: func(level: u8, target: string, msg: string);
  metric: func(name: string, value: f64);
}

world node {
  import clock; import random; import storage; import net;
  import seal;  import wake;   import log;

  variant event {
    readable(u64), writable(u64), connected(u64), failed(u64),
    sealed(u64), lifecycle(phase), timer,
  }
  export init: func() -> result<_, string>;
  export tick: func(budget-us: u32) -> u64;   // returns next deadline
  export on-event: func(e: event);
  export api: func(req: list<u8>, local: bool) -> list<u8>;  // in-process /v1
}
```

The probe's mapping onto SQLite shows how narrow this can be: `sqlite-wasm-rs` asks for exactly five link-time symbols (sleep, random, epoch ms, fill entropy, localtime) [R], and they were satisfied from three imports [M].

**Host implementations:**

| Capability | Browser | EFI | wasip2 |
|---|---|---|---|
| `clock.monotonic-us` | `performance.now` | TSC, calibrated against `Stall` [M] | `wasi:clocks` |
| `clock.wall-ms` | `Date.now` | `GetTime`; RTC is not trusted without roughtime or peer time [inf] | `wasi:clocks` |
| `random.fill` | `getRandomValues` | `EFI_RNG_PROTOCOL` [M]; refuse to boot without it | `wasi:random` |
| `storage` | OPFS SAH in the Worker | §6.3 | `wasi:filesystem` |
| `net` | §7.2 | §7.4 | `wasi:sockets` |
| `seal` | §8.3 | §8.4 | keyring plugin |
| `wake` | Timer in Worker | `CheckEvent` loop, `Stall` | `wasi:clocks` subscribe |

---

## 5. Concurrency

### 5.1 The model (normative)

One thread. A cooperative executor, `ciris-rt`, inside the module. The host loop is:

```
loop:
    poll host I/O; deliver events with on-event
    deadline = tick(budget)
    sleep until deadline or host event
```

**Deterministic tick.** Every source of non-determinism is an import: time, randomness, I/O, event order. A run can therefore be recorded at the ABI boundary and replayed, on any host, byte for byte. That is a debugging tool the native node does not have, and the conformance harness uses it (§11.4).

Storage is synchronous in the tick. Network, seal and timers are events. Nothing in the node blocks on anything except storage.

### 5.2 Mapping, by repo

Counts by grep at the pinned tags; some include tests [R].

| Primitive | persist | edge | server | Maps to |
|---|---|---|---|---|
| `tokio::spawn` | 52 | 81 production | 37 | `ciris_rt::spawn`; no `Send` bound needed, none removed |
| `tokio::time::{sleep,interval,timeout}` | 158 | 173 | 29 | `ciris_rt::time`; tokio's panic where timers are unsupported [R] |
| `tokio::sync`, `select!`, `macros` | retained | retained | retained | Work on wasm [C] |
| `spawn_blocking` | 149 in 42 files | 4 | 5 | `ciris_rt::blocking`: runs inline |
| `dispatch_blocking` | `sqlite_conn_model.rs:194` | | | **Already correct.** Its `Err` arm runs inline when no runtime exists, invariant I5 from #158 [R, M] |
| `block_in_place` | 0 | 30 hits; outside FFI, `runtime_budget.rs` | 11 hits; `mesh_relay.rs`, `radio.rs` | Removed: rewrite as `.await` |
| `.block_on` | see note | 19 | 41 | Removed on the node path |
| `std::thread::spawn` | 17 | 3 | 14 | Each becomes a task or a host duty (below) |
| `std::time::Instant` | 93 changed lines in 40 files with verify [M] | 354 hits | 90 hits | `web-time` or `ciris_rt::time`: `std` panics on this target [M] |
| `tokio::runtime::Builder` | | | `node_runtime.rs:270` | Removed from the node; `ciris-rt` runs under the host loop |

Note: persist's 1,042 `.block_on` hits are mostly tests; the production subset was not separated.

**Named threads and loops:**

| Today | Maps to |
|---|---|
| `loop_cadence::Cadence`, 13 loops | **Kept.** `tick()` reads `clock`; slots and the shared epoch survive unchanged. It becomes more important, because nothing else separates loops. Its raw-`interval` siblings (22 sites) move to it |
| `node_lifecycle` (`feat/mobile-lifecycle`, `adopt/edge-v44`; not in v0.5.244) | **Kept as the lifecycle mapping.** `enter_background`, `enter_foreground` driven by `on-event(lifecycle)` |
| Capacity monitor, "its own OS thread" so a read storm cannot starve it (`feat/mobile-lifecycle`) | Cannot survive as a thread. **The host samples.** It already observes every tick's duration and can tell the node its pressure at the next `on-event`. Hottest-thread CPU becomes tick overrun. Reads `/proc`, which is absent; on wasm it "reports `Normal` and says so once", which would be a silent failure here |
| `compose-watchdog`, OS thread so it works when the runtime is wedged | **Moves to the host for the same reason.** The host alone can see that `tick` did not return. Browser: `Worker` heartbeat. EFI: `SetWatchdogTimer` re-armed per tick |
| `sigterm-broker` | `on-event(lifecycle)`. No signals exist |
| `ciris-serve-rt` | Gone |
| `log-dedup-flush`, `log-retention`, `ciris-log-drain` | Tasks, on Cadence slots |
| `ciris-malloc-trim`, `ciris-mem-burst` | Gone; glibc-specific diagnostics, not capabilities |
| `ciris-persist-teardown` | Inline drop |

### 5.3 What a single thread costs: measured

Same schema, rows and queries, Chromium Worker on OPFS against native [M]. "Tick" is two reads shaped like a reconcile pass.

| Rows (DB) | `config:` selective | 1000-row prefix read | Full scan | Tick | Worker stall | **Main thread stall** |
|---|---|---|---|---|---|---|
| 1k (14 MB) | 0.1 / 0.1 ms | 13 / 22 | 3 / 4 | 12 ms | 12 ms | **0 ms** |
| 10k (106 MB) | 2 / 1.4 | 110 / 92 | 58 / 32 | 106 | 118 | **0 ms** |
| 100k (1 GB) | 27 / 21 | 490 / 276 | 551 / 236 | 513 | 523 | **0 ms** |

Three facts follow:

1. **A dedicated Worker removes UI stall entirely.** No SharedArrayBuffer, no COOP/COEP, `crossOriginIsolated=false` [M].
2. **It does not remove serialization.** The node's own event loop stalls for the query. So API, transport and loops all wait.
3. **The browser is 1-2.3× native.** The cost is query shape (§6.4), and native pays it too.

### 5.4 The bound (normative)

Reference: 2.4 GHz x86-64 core, 100k-row store.

| Measure | Bound | Today |
|---|---|---|
| Any single tick slice, p99 | **≤ 50 ms** | 513 ms at 100k; 106 ms at 10k |
| Any single tick slice, max | ≤ 100 ms | 523 ms |
| Tick slice while a call is live | ≤ 10 ms | not measured |
| Hybrid sign | ≤ 15 ms | 10 ms [M] |

- No SQL statement may run longer than the slice. Work that can exceed it MUST be cursor-paged, yielding between pages, using keyset cursors. `read()` closures are synchronous and cannot yield inside.
- CI enforces this as a test: the replay of a 100k-row store fails if any slice exceeds the bound.
- **What single-thread means for A/V.** 20 ms audio frames cannot share a 50 ms slice [inf]. In the browser, media capture, codec and DataChannel work happen in engine threads outside the module, so the node only owns keys and control, and D4 records that. A relaying node's frame path is the unsolved case: see R5.

---

## 6. Storage

### 6.1 Stack

| Layer | Version | State |
|---|---|---|
| `rusqlite` | 0.41.1 | Runs on OPFS [M]. **0.31, pinned today, has no wasm support** |
| `refinery` | 0.10.1, allows rusqlite ≤ 0.41 | Runs with `time/wasm-bindgen` [M] |
| `sqlite-wasm-rs` | 0.6.2 | SQLite 3.53.4; zig cc suffices, no emscripten [M] |
| `sqlite-wasm-vfs` sahpool | 0.3.0 | Rust port of `opfs-sahpool` [M] |

**rusqlite and refinery must move together across verify and persist.** `links = "sqlite3"` conflicts across targets even when the dependency is host-only [M]. No source edits were needed to *compile* on 0.41; native regression is untested.

Everything goes through one `sqlite-wasm` build on every wasm target, EFI included: 182 migrations applied with zero failures on V8, wasmi and PE [M]. All are plain SQL (133 tables, 421 indexes, 13 triggers, generated columns, JSON). No extension is loaded. `ciris_sha256_ed25519_raw` is Rust, registered at open.

### 6.2 Browser: OPFS `opfs-sahpool` (normative)

```
PRAGMA locking_mode = EXCLUSIVE;     -- MUST be the first statement on the connection
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON; ...
```

- **Order is load-bearing.** WASM has no shared memory, so WAL needs exclusive locking first [W]. Any prepare on a WAL-format file before that statement fails with "unable to open database file" [M], and `select sqlite_version()` counts. Without the exclusive pragma, `journal_mode=WAL` silently stays `delete` [M]. Persist's PRAGMA block needs this change.
- **WAL is required.** Migrations 0.43 s against 18.8 s, single commit 0.1 ms against 14-20 ms [M]. The DELETE run followed a 1 GB run, so its first figures may be inflated; the commit gap is the reliable one.
- **`readers = 0`.** `ReadPool` blocks on a `Condvar`, which would hang one thread forever. The docs also warn of a corruption risk with multiple same-thread connections before 3.54, and this build is 3.53.4 [W]. **Note:** the Engine probe ran with the default 2 readers and passed; do not treat that as evidence.
- **One tab holds the store.** A second instance is refused with `NoModificationAllowedError` [M]. SharedWorker has no sync handles [W, MDN: dedicated workers only]. The host elects a leader with Web Locks; other tabs talk to it. The sahpool `pause` API (3.50) hands over [W]. **Not built, not tested.**

**Durability [M].** Three `kill -9` rounds mid-write: `integrity_check` ok, no acked row lost, reopen about 20 ms on 700 MB. That is process death, not power loss. One earlier run ended with the database reinitialised while stale probe processes ran, possibly two browsers on one profile. It did not reproduce in three clean rounds and the cause is unproven: **R3**.

### 6.3 EFI: a VFS over firmware storage

| Option | For | Against |
|---|---|---|
| File on Simple File System | Proven to write and read [M]. No partition work | FAT: no journal, durability depends on firmware's `Flush`; shared with the ESP [inf] |
| **Dedicated GPT partition via Block I/O** | One extent, explicit `FlushBlocks`; the sahpool slot design maps directly; never touches the ESP | Partition creation is new work; not probed |

**Choice:** a dedicated partition with a sahpool-style slot VFS implemented in the host against `storage`. SFS remains the bootstrap for the image. `locking_mode=EXCLUSIVE`, WAL and `readers=0` carry over unchanged: no other process exists, so exclusive is simply true.

Block-device write barriers on OEM firmware are **unknown**. `FlushBlocks` semantics are a conformance test, not an assumption. Without an OS, nothing else mediates the disk [inf].

**Encryption at rest.** A store on a raw partition is readable by anyone with the disk. `sqlite-wasm-rs` supports SQLCipher and SQLite3MultipleCiphers [R]. A page key sealed under §8 is the obvious shape. Native nodes do not do this today. See D7.

### 6.4 Query shape: the 513 ms at 100k rows

The plan for the 1000-row read is `SEARCH ... USING INDEX federation_attestations_attester_dimension_citation`, then **`USE TEMP B-TREE FOR ORDER BY`** [M]. `ORDER BY asserted_at LIMIT 1000` reads every matching row, around 60k rows of 11 KB, then sorts, then discards. The same query returning 1000 rows without that sort takes 26.5 ms [M: the `config:` case at 100k].

| Fix | Effect | Where |
|---|---|---|
| Two-phase read: `(attestation_id, asserted_at)` from the index, top-N, then fetch N rows | Sort over keys, not 11 KB rows. Expect about 30-40 ms [inf from the 26.5 ms case] | Persist; **also helps the canonical** |
| Covering index ending `asserted_at DESC` for exact-dimension reads | No sort | Persist migration |
| Maintain `storage_summary`-style counters | Full scan (551 ms) stops being a loop's job | Persist |
| Keyset cursors with yield for anything still long | Meets §5.4 | Persist, callers |
| Tune `cache_size`; reconsider `page_size` for 11 KB rows | Unmeasured | Persist |

The bound in §5.4 stands regardless. This is the same defect class as #575, and #829 only moved it off the runtime: it was never fixed at the query. **Native gets this for free.**

### 6.5 Eviction (browser)

A browser may delete the store. Best-effort by default [W]; Safari caps script-writable storage at 7 days unless installed, from a secondhand source [W]; `persist()` is requested, not guaranteed.

Normative:

1. `storage.durability()` reports `persisted`, `best-effort` or `evictable`, and the node records it as a fact in `choice-item`.
2. The node MUST request `navigator.storage.persist()` at first run and re-check at every boot.
3. **Eviction is a lost device, never a new device.** A node that finds no store has lost its roster key. It MUST NOT mint silently. It offers add-device.
4. Quota and free space drive the existing `disk_pressure` and the CC 6.1 descent, which already treat pressure as a normal condition.
5. Rows come back by anti-entropy from the owner's other nodes. A person with one roster key on one evictable store has no path back: §9.3.

---

## 7. Transport

### 7.1 The seal does not change (normative)

**CC 5.3.3.5 already separates carrier from seal.** The RNS link is classical and not relied on for post-quantum confidentiality, and "every byte an edge sends over an RNS link MUST be under a hybrid transit seal" keyed by X25519 + ML-KEM-768, bound to `link_id` and to an authenticated transit pair [R]. Federation rows are hybrid-signed, content keys hybrid-wrapped.

So a carrier is just bytes:

- WSS, QUIC and DTLS are **not relied on** for anything. Their encryption is a metadata convenience.
- A relay sees sealed frames, as Forwarded links do today (CC 5.4.6).
- Link identity is the Reticulum destination and the node key. **Only `node` keys carry transport routes**, per the 10-24 ruling, unchanged.
- The transit KEX runs on the Rust side, so ML-KEM runs in the module on every host.

No CC change is needed for a new carrier [inf]. Confirm: Q-CC1.

### 7.2 Why a browser is reachable

Reticulum is not IP. A node with a single outbound link to a transport node is addressable by destination hash, and peers open links to it through that transport [R, memory: a NAT'd phone is reached by Forwarded links today]. So in a browser:

- No TCP listener exists (D1).
- **Inbound Reticulum links exist**, through the dialled carrier. A browser node can answer `ContentFetch`, serve rows and take a call. The tab is a responder.

The carrier-level peer must be a transport-enabled node. Every serving node offers one (§7.5).

| Carrier | State | Use |
|---|---|---|
| **WebSocket (`wss`)** | All browsers. **`https` pages cannot open `ws://`**, so serving nodes need a name and a certificate [inf] | First. Default |
| **WebTransport** | Baseline across majors since Safari 26.4, March 2026 by one source; WKWebView unconfirmed [W]. `serverCertificateHashes` may allow a pinned self-signed certificate [inf, verify] | Second. Unreliable datagrams suit Reticulum better than a stream |
| **WebRTC DataChannel** | Keeps timers unthrottled when hidden [W]. Needs signalling, which rides an existing RNS link, and STUN | Third. Direct browser-to-peer links; maps to `direct_link` and the facilitator role |

### 7.3 Leviculum (SIZE L)

`leviculum-core` is `no_std + alloc` and sans-IO, and passes on wasm [C]. `Interface` (`traits.rs:242`), `Clock` (`:419`) and `Storage` (`:500`) are exactly the seams needed [R].

`leviculum-std` is the problem: tokio `full`, tokio in 41 files, `InterfaceHandle` and its registry `pub(crate)` (`interfaces/mod.rs:693,811`) [R]. No host can add an interface from outside. There is no WebSocket interface and **no server-side WebSocket listener**.

Work:

1. Split the driver (`driver/`, `processor.rs`, link and resource handling) from socket interfaces, so it runs on `ciris-rt`.
2. Make interface registration public; `RNodeChannelFactory` is the only public plug today.
3. Add a `HostInterface` over `ciris:node/net`, carrying HDLC-framed RNS over any stream carrier.
4. Add `WsServerInterface` to the native and EFI side.
5. Replace `file_*_store` with `storage`-backed stores.

Edge's `src/transport/reticulum.rs` is 22,753 lines against `ReticulumNode`. **Keep that API**, or the edge cost multiplies. `leviculum_std::` appears in 10 edge files. Candidate pin v0.33 changes this; the survey is on c6d0a224.

### 7.4 EFI network

Measured: DHCP via `Ip4Config2::ifup`, `Tcp4` client, `Tcp4::accept`, request and reply [M]. Tokens and polling, single-threaded: this maps directly onto `net`.

- **Tier 1:** firmware `TCP4`/`TCP6`/`UDP4` where present.
- **Tier 2, for firmware without them:** own TCP/IP in the host shim over `SNP` [inf], for instance `smoltcp`. SNP was present with 3 handles [M], but this path is unbuilt.
- **Discovery:** host reports carriers at runtime. A board with neither has no network and is `HOST_LIMITS`-listed.
- **TLS:** `EFI_TLS` exists [M] but is not used. Reticulum needs none. A `/v1` listener needs TLS from the module or a reverse path; §10 lists this.
- **DNS:** `DNS4` present [M]. Hickory goes; `net` resolves.

### 7.5 What every serving node must add

- A WSS listener and Reticulum transport for browser carriers. **That means a name and a certificate, or a pinned WebTransport hash.** The canonical and other servers gain an inbound surface. Abuse limits: `bootstrap-abuse` work applies.
- The facilitator role from the 10-28 ruling, extended to WebRTC signalling.

---

## 8. Custody: the hybrid seal

### 8.1 The statement (normative)

**The hybrid seal.** No shipping token or TPM performs ML-DSA in hardware at scale, so a CIRIS key is not hardware-protected as a whole. On most platforms hardware protects, at best, a classical secret. That secret seals the post-quantum material. **This is accepted for now.**

Consequences that every implementation MUST honour:

1. A node MUST report custody per half: classical at use, classical at rest, PQC at use, PQC at rest. It MUST NOT report one word for a hybrid key. `hardware_backed=true` next to `SoftwareSigner: NO HARDWARE BINDING` is the defect CIRISVerify#325 §3 names.
2. A hybrid signature is only as strong in custody as the seal over its weaker half.
3. Hardware that can sign Ed25519 SHOULD sign it. Sealing it instead is permitted and is often the only option: a TPM offers P-256, not Ed25519 (`sealed_ed25519.rs`) [R].
4. The seal is the existing path: `SealedMlDsa65Signer`, `usb_wrapped_mldsa65.rs`, `HardwareSigner`, `PqcSigner`. This extends #325; it adds no trait. Keyring states that an ML-DSA token swaps in "with no change above the trait" [R].

### 8.2 Custody by target

| | Native TPM | Native PIV (YubiKey) | **EFI, TPM** | **Browser** |
|---|---|---|---|---|
| **Seal root** | TPM sealed object | Token Ed25519 signature, deterministic, HKDF | TPM sealed object, PCR policy | WebAuthn PRF (`hmac-secret`), HKDF |
| **Hardware holds** | Seal key | Ed25519 private key | Seal key | PRF secret in the authenticator |
| **Ed25519 at use** | Sealed, then software | **Hardware** | Sealed, then in vault | Sealed, then in vault |
| **Ed25519 at rest** | Sealed | Hardware | Sealed | Sealed |
| **ML-DSA at use** | Software | Software | Vault | Vault |
| **ML-DSA at rest** | Sealed | Wrapped | Sealed | Sealed |
| **Bound to** | Machine | Token + USB | Machine **+ measured code** | Authenticator + origin |
| **Who can reach seeds in use** | Root on the host | Root on the host | **Firmware, SMM, option ROMs** | **The origin, extensions, the browser** |

The browser is the honest extreme: **even the classical half is not in hardware at use.** Only the sealing secret is. Eric's statement holds there in its weakest form, and it is the right floor: hardware-derived seal, both seeds used in memory.

### 8.3 Browser (normative)

**Root.** WebAuthn PRF over a passkey, HKDF to an AES-256-GCM key. PRF support is real but uneven [W]:

- Chrome and Safari 18+ with iCloud Keychain; hardware keys are the most reliable; Windows Hello from the February 2026 update; Firefox sources conflict on 114 versus 148.
- Password managers often accept the extension and **return no PRF value** [W]. Detect by doing it, not by asking.
- Limits: the output is **visible to JS**, including injected script and extensions; there is no non-extractable PRF result [W]. Deleting the passkey destroys the data [W]. It is origin-bound: another origin is another identity.

**A passkey never signs the owner binding.** `webauthn.rs` says so, and the CC signature is over the federation preimage [R].

**No PRF.** The floor is CIRISVerify#325's "software, sealed". Is that permitted for an owner key in a browser? D8.

**Sequence.** Gesture → PRF → unwrap in the host → seeds into the vault (§8.5) → signing → re-wrap under a session key.

### 8.4 EFI (normative)

**Root.** A TPM 2.0 sealed object reached through `EFI_TCG2_PROTOCOL.SubmitCommand`, with a raw TPM2 command stream built in the shim. `GetCapability`, `HashLogExtendEvent` and `SubmitCommand` are the members used [W].

**Untested.** TCG2 showed 0 handles: QEMU had no TPM attached and `swtpm` is not installed [M]. Everything in this subsection is **[inf]** until a swtpm lane exists.

**Measured boot.** Because the node is inside the PE (§4.3), firmware measures the node itself.

- Seal policy: `TPM2_PolicyPCR` over the boot-chain PCRs (exact set, including Secure Boot state, to be fixed by test). `TPM2_PolicyAuthorize` is needed so a signed update does not brick the seal; otherwise every node update is a re-seal. D9.
- Unseal happens once at boot. A wrong PCR yields no seed and the node refuses to start.
- The node extends a PCR with its own state transitions, using `HashLogExtendEvent`, so a later attestation can say what ran.

**Reachable by:** firmware vendor code, SMM, option ROMs and any DMA device with no IOMMU set up. Boot Services is one address space with no isolation between the node and the drivers it calls [R]. An EFI node trusts its firmware as completely as a native node trusts its kernel, and that firmware is far less often patched [inf].

**TPM limits.** Firmware TPMs are common and some lack a discrete chip; `hardware_custody:tpm_firmware` is the honest report. `Curve25519` arrives in Library Spec v1.85 alongside ML-DSA and ML-KEM [W]; check before assuming.

### 8.5 What is in memory, and for how long (normative)

**A separate vault instance.** Seeds MUST NOT enter the node's linear memory. Signing runs in a second, small wasm instance with its own memory and only `seal` imports. `HardwareSigner` and `PqcSigner` are implemented by calling it over the ABI.

Reason: the node is a 30 MB module parsing peer input. The vault is a few hundred KB and parses nothing. A memory-safety bug in the node cannot read another instance's linear memory. SIZE S [inf].

| Rule | Value |
|---|---|
| Seed lifetime in vault memory | One signing burst; zeroized at idle ≤ 60 s. D10 sets the value |
| Vault linear memory | Fixed size, never grows: growth can relocate and leave stale copies [inf] |
| Keys in node memory | Handles only |
| Session re-wrap | Non-extractable WebCrypto `CryptoKey` in the browser. Requires an async step; the seal interface is async for this |

**Zeroization limits in linear memory, stated plainly:**

- `zeroize` issues volatile-equivalent stores into linear memory. Engines treat linear memory as observable, so these are not removed [inf]. wasm2c's memory is a heap pointer that escapes, likewise [inf].
- It clears the module's copy only. Engines may spill locals to machine stacks and registers the module cannot see. Inputs pass through host-side `Vec`s and JS heap copies that the ABI must also clear. JS strings cannot be cleared at all, so seeds MUST NOT pass through one.
- A browser may page memory to swap and may include it in crash dumps. EFI has no swap, and no crash reporter unless the vendor added one.
- `ml-dsa` 0.1.1 zeroizes its signing key on drop [R].

**Side channels.**

- ML-DSA and Ed25519 are not proven constant-time after compilation to wasm and then by a JIT [inf]. On the V8 tier-up path, timing is not stable.
- Same-process Spectre: browsers rely on site isolation. The vault shares a process with the node.
- SMT and shared caches are unmanaged by firmware.

**Reachable by whom:** the serving origin can ship new code at any time and read everything: §9.5. The firmware vendor can do the same on EFI. **Neither is mitigated by the seal.**

### 8.6 Accepted, and what ends "for now"

**Accepted, for now:** PQC signing in software on every target; classical signing in software on TPM, EFI and browser; seeds in memory during use; a browser's seal root held by whatever authenticator the person has; no remote attestation of a browser node.

**"For now" ends, per target, when:**

| Trigger | What changes | Above the trait? |
|---|---|---|
| A shipping TPM implements Library Spec v1.85 ML-DSA [W] | PQC half signs in hardware on TPM and EFI | No change: a hardware `PqcSigner` |
| wolfTPM-style firmware PQC TPMs are vetted [W: first firmware TPM with PQC, May 2026] | Same, on platforms that ship it | No change |
| A FIPS ML-DSA token ships | `usb_wrapped` retires, per its own doc comment [R] | No change |
| TPM exposes Ed25519 | Classical half signs in hardware | No change |
| Browsers offer ML-DSA and Ed25519 through a non-extractable API, or WebAuthn gains an arbitrary-preimage mode | Browser halves leave memory | Not on any roadmap checked; [inf] |

The keyring comment "no shipping hardware token has an ML-DSA applet (2026)" should be re-verified against v1.85 parts when a lane exists.

CIRISVerify#325 tracks tier migration. A key moving between these tiers keeps `key_id` and fedID; a browser `seal` is one more row in its table.

---

## 9. Consent, first run and governance

### 9.1 Same item, same view (normative)

The node serves `choice-item` (CC 4.5.13, `manifests/choice_item.cddl`) and `view` (`manifests/view.cddl`) identically on every target, from the same code, through `api`.

- Nothing is rendered by the host. No target has a first-run of its own.
- Declining is complete. Nothing is answered on anyone's behalf (CLM-choice-as-data, staged on CIRISServer#851, #853, both open and unbuilt).
- `impact` is derived from `manifests/family_model.json`, so it cannot differ by host.

### 9.2 Host limits appear in the item, not by omission (normative)

A capability a host lacks is an `option` with `available: false` and `unavailable` text. It MUST NOT vanish. That is what `available` is for, and it is the 100% rule on screen.

`fact.provenance` covers the rest: a browser's `durability`, a seal tier, whether `persist()` was granted are facts with `by_rule` or `wire` provenance, displayed and never chosen.

### 9.3 New items each host needs

| Target | Item | Why |
|---|---|---|
| Browser | Seal root: which authenticator, with downside "lose the passkey, lose this device" | §8.3 |
| Browser | Durability, stated as a fact, and its cost | §6.5 |
| Browser | "You have one device. If this browser clears its data, your identity is gone" | CC self-roster: **one key lost is the loss of the self**, the stated bound of `Inv_SelfSurvives` [R] |
| EFI | Boot-chain measurement and what a firmware update does | §8.4 |

Benefit and downside are required by the schema, never empty. A person may still choose it: the node is full.

### 9.4 First run per host

**`0600` claim PIN.** Depends on a filesystem mode no wasm host has. Replace with `seal.provision` and show the PIN through the host's local surface: the page in a browser, the console on EFI. `compose.rs`, `node_key.rs`, `identity.rs`, `add_device.rs`, `auth/bootstrap.rs` hold the 14 permission hits [R].

**Loopback guard.** Setup routes are restricted by `ConnectInfo<SocketAddr>` to localhost. In-process there is no socket. `api(req, local: true)` carries that fact, and only the host can set it. The browser host sets it for its own page; the EFI host for its console.

**EFI is headless.** No browser, no GPU promise. First run MUST work with: a text rendering of `view` on the console; or a LAN client claiming with the PIN shown on the console, as headless nodes do today. `GOP` graphics are a host option, not a requirement.

### 9.5 Issues for the CC

| # | Question | Why it arises |
|---|---|---|
| **Q-CC1** | Confirm a new carrier needs no CC change, since CC 5.3.3.5 is carrier-neutral | §7.1 |
| **Q-CC2** | `hardware_custody:{platform}` is open vocabulary; `hardware_class` table has no row for a browser. Mint `webauthn_prf`? Does it pair with `software_hsm_development`? | §8.2. CC 4.2.2.1 needs an evidence variant; a browser has none |
| **Q-CC3** | Should custody be reported per half? One `{platform}` value cannot state §8.2 | Eric's seal is not expressible in one word |
| **Q-CC4** | An **evictable** node as a roster device. CC 6 says "every node a person owns is one of that person's devices"; the roster model counts lost keys. Should eviction be a distinct state: lost without compromise, no revocation race? | §6.5 |
| **Q-CC5** | May an evictable key be the **only** roster key? The model says it is the loss of the self. Refuse, or allow with the item in §9.3? | D11 |
| **Q-CC6** | Default role. CC 6: personal by default, allow list "all of its owner's cohorts". On a quota-limited browser that may not fit. Does a pressure descent satisfy B2 pin-on-consent? | §6.5 |
| **Q-CC7** | Possession-bound claims (N6) and wholeness witnesses: is a holder that can vanish a valid holder? | CC 6 |
| **Q-CC8** | Device classes. CC 5.4.3 fleet defaults name `phone-wifi`, `phone-cellular`, `server`. `browser` and `efi` need rows; the server's `host_device_class` defaults to `server`, which holds no self content | [memory: S1] |
| **Q-CC9** | Anonymous mode (PRIVACY_MODES §4) on a browser: a separate identity, set up at first run or never. Does an evictable anonymous identity have any recovery, by design? | |
| **Q-CC10** | Origin trust. Whoever serves the page can replace the node. Does the CC take a position on code served per load holding an owner key? A signed release manifest pinned by a Service Worker narrows it; it cannot close it | §8.5 |
| **Q-CC11** | A `constitutional` halt and `serve_nodes` in the genesis bundle: can an EFI node, with no operator session, take these rows on the same path? | Unchecked |

---

## 10. Work, per repo

### 10.1 Order

Baseline first: **all of this targets the pins after 0.5.245** (persist v61, edge v44, verify v22, leviculum v0.33), none of which has been probed. It is **not** in 0.5.245.

Sizes are SIZE judgements. "Basis" is what the judgement rests on.

| # | Work | Repo | SIZE | Basis | Blocked by |
|---|---|---|---|---|---|
| 0 | **Server type-check spike:** stub everything, get `ciris-server` through `cargo check` for wasm, publish the error map | Server | M | §10.2 | none |
| 1 | `ciris-host-abi`: WIT, bindings, import-allowlist gate, target-`cfg` lint | New crate (D12) | S | §4 | none |
| 2 | `ciris-rt`: executor, timers, `blocking`, record and replay | New crate, same home | M | §5 | 1 |
| 3 | Verify split **and port**: see below | Verify, #325 | L | 14 modules, 16.3k lines | 1 |
| 4 | `rusqlite` 0.41, `refinery` 0.10 | Verify + Persist | M | Compiled with no edits; native regression unknown | v61 |
| 5 | Persist: §10.3 | Persist | M | Table in §10.3 | 2, 3, 4 |
| 6 | Persist query shape: §6.4 | Persist | M | Benefits the canonical now; **can start at once** | none |
| 7 | Leviculum: §7.3 | Leviculum | L | 41 tokio files, private registry | 1, 2 |
| 8 | Edge: `rt` migration, `Transport` over ABI, HTTP transport over `net` | Edge | L | 81 spawns, 173 timers, 22.7k-line transport | 2, 5, 7 |
| 9 | Keyring: `seal` adapter, vault instance, per-half report | Verify | M | §8 | 1, #325 |
| 10 | lens-core: split relay roles from sockets | Server | M | 6 errors; `node.rs` needs `RelayHandle` | 8 |
| 11 | Server: composition | Server | **XL** | §10.2 | 0, 5, 8, 10 |
| 12 | Browser host | New | M | Worker, SAH, Web Locks, carriers | 1, 7 |
| 13 | EFI host: shim, Block I/O VFS, TCP, TCG2, `wasm2c` pipeline | New | L | Clock, RNG, TCP and pipeline proven; VFS and TCG2 unproven | 1 |
| 14 | wasip2 host | New | S | | 1 |
| 15 | Serving nodes: WSS, facilitator | Edge, Server | M | §7.5 | 7 |
| 16 | CI lanes: §11 | All | L | Harness has never driven a non-process node | 11-14 |

**The verify split is larger than the earlier estimate.** The 14 modules cut in the probe were cut to compile. Under the 100% rule they cannot be dropped: `revocation`, `registry`, `engine`, `dns`, `https`, `validation` are capabilities. They must be **ported** onto `net`, with HTTP through the ABI and DNS by the host. CIRISVerify#325 §1 already asks how the pure half learns revocation; this is the answer. Only `binary_format`, `security::wheel` (goblin, zip), host CLI and `mobile_http` are truly host-side, and the first two must be restated as measured-boot or origin evidence.

### 10.2 Server: the biggest unknown

Server composition has **never been type-checked for wasm.** With no transports, patched substrates and `axum` defaults off, every dependency passes and `ciris-lens-core` stops at 6 errors: the HTTP and Reticulum relay roles, `TcpListener`, `axum::serve` [C]. `node.rs` needs `RelayHandle`, so that is real work. Nothing past it was seen.

Known surface [R]: 143k lines; `compose.rs` 6,010 lines; `std::fs` 292 hits in 42 files; 14 `0o600` sites; 21 `libc`; direct deps `fs2`, `tracing-appender`, `signal-hook-registry`, `serialport`; `flate2`; `axum::serve` and a TCP listener at the heart of the read API; `pyo3` and uniffi behind features.

`/v1` is the good news: `axum::Router` works through `tower::oneshot`, which `mesh_relay` already does in production [R]. The socket listener becomes a host adapter over `net`, and `api()` is `oneshot` directly. Hyper on the ABI's streams is needed for EFI's listener; no `tokio::net`.

**Work item 0 exists because this cannot be sized from outside.** Its error map replaces the XL with a number. It is not a scope question: it tells us the order, not whether.

### 10.3 Persist changes, measured [M]

| Change | Size |
|---|---|
| `tokio` to `rt`, `sync`, `macros`, `time`; no `signal`, `rt-multi-thread` | Cargo |
| `shutdown_signal` gated on `cfg(unix)`; wasm is neither | Moves to lifecycle event |
| `fs4::available_space` → `storage.free-bytes` | 1 site |
| `std::time` → `web-time` | 93 lines, 40 files, with verify |
| `time/wasm-bindgen`, `getrandom` backends, `uuid/js` | Replaced by ABI: custom backends, no JS |
| PRAGMA order, exclusive first | `sqlite.rs:1064` |
| `readers=0` | `open_with_readers` exists |
| `redb` journal | Replace with `storage` or remove from node path |
| Migration of `Backend`, `FederationDirectory` etc. | **None**: `Send` futures unchanged, closures synchronous |

**Open:** the self-key re-registration conflict on reboot ("different content") seen in the probe, not checked against native.

---

## 11. The test: 100% is a suite, not a claim

### 11.1 The suite

**`node-conformance`** is three existing things, run unchanged on every target:

| Part | What | Where |
|---|---|---|
| **CSD/4 catalogue** | Topology catalogue with closed vocabulary, T0-T19 plus T21, state model, planner, `harness/native` runner, requirements tied to CSD atoms | `FSD/CSD4.md`, `harness/native` |
| **CIRISConformance** | Neutral verification matrix, `matrices/current.yaml`, `tests/` | CIRISConformance |
| **Substrate suites** | `cargo nextest` for verify, persist, edge, leviculum, server. Persist has about 2,900 async tests, edge about 730 [R count] | Each repo |

Added: `HOST_LIMITS.tsv`, a replay of a 100k-row store against §5.4, a crash lane, and import and `cfg` gates.

### 11.2 Lanes

| Lane | Host | Runs |
|---|---|---|
| `native-control` | Native build | Everything; the comparison |
| `wasm-browser-chromium` | Playwright, headless | Everything except `HOST_LIMITS` |
| `wasm-browser-webkit`, `wasm-browser-firefox` | Playwright | Same. **Not tested so far** |
| `wasm-efi-x86_64` | QEMU, OVMF, swtpm | Same |
| `wasm-efi-aarch64` | QEMU, AAVMF, swtpm | Same |
| `wasm-wasip2` | Wasmtime | Same |
| `efi-oem` | Periodic, physical boards | Census, network, TCG2 |

The scarce-lane policy applies: ubuntu is fine for all of these, and KVM access worked here.

### 11.3 Harness changes

`harness/native` spawns `--binary` and talks HTTP. A wasm node is not a process. Needed:

- A **wasip2 driver** first: `ciris-node-run ciris-node.wasm`, process-shaped, so the catalogue runs at once.
- An EFI driver: QEMU with `hostfwd`, as the probe did [M].
- A browser driver: Playwright page plus a relay, reaching `api` via a page bridge. `--local` gets the same caller flag.
- `test-anchor`: the synthetic root must work; six trust values are per-pin (project memory).

### 11.4 Rules (normative)

1. Same test list on every lane. A skip needs a `HOST_LIMITS.tsv` row and a D-number.
2. A green lane proves the hash of the module it ran. Every lane reports it; all must match.
3. Replay: a record from any lane replays on any other with the same state root.
4. A release of a wasm node needs all lanes green. "100% or nothing": no partial release.

---

## 12. Non-goals

- A thin client or reduced profile. Dropped by direction.
- The agent brain. "Agent = fabric node + brain", and PyO3, uniffi and the Python runtime are not in the node module. An agent attaches to a wasm node over `/v1`, as it does remotely today. Eric may rule otherwise (D13).
- Postgres under wasm.
- Multi-threaded wasm: requires nightly `build-std`, COOP/COEP and SharedArrayBuffer, against the shared stable 1.97 pin. Nothing measured requires it [M: all results single-threaded].
- A running OS replacement. The EFI node does not manage hardware beyond what firmware exposes.
- wasm64.

---

## 13. Risks and decisions

### 13.1 Risks

| # | Risk | Impact | Treatment |
|---|---|---|---|
| R1 | Server composition has hidden OS assumptions no one has seen | Schedule | Item 0 first |
| R2 | OEM firmware lacks TCP4 or Block I/O flush semantics | EFI lane fails on real boards | Census lane, SNP tier, `efi-oem` |
| R3 | The unexplained OPFS reinitialisation | **Data and identity loss** | Reproduce or rule out, before any real key is stored |
| R4 | No TPM exercised at all | §8.4 is entirely inferred | `swtpm` lane is an early item |
| R5 | Relaying A/V on a single thread | §5.4 cannot hold | Measure; possibly a host-side frame path outside the module. Could be a real capability limit |
| R6 | §5.4 bound unachievable on some paths | Fails conformance | Query-shape work first; bound revisited only with data |
| R7 | wasm2c stack overflow is untrapped | Silent memory corruption on EFI | Guard page before production |
| R8 | Size target missed once edge and server link | "Highly efficient" fails | Per-package profiles, snapshot; measure at item 0 |
| R9 | A browser origin ships malicious wasm | All keys in that origin | Q-CC10, D14 |
| R10 | Long-lived firmware is unpatched, under SMM attackers | EFI custody | Stated in §8.4; Secure Boot state in the seal |
| R11 | Pins moved: v44, v61, v22, v0.33 | Probes stale | Redo on adoption |
| R12 | wasm-rt, zig and wabt enter the supply chain | New toolchain | Pin and vendor; `wasm2c` output is reproducible C [inf] |
| R13 | `memcpy` slower in PE | Row-heavy paths | Real `memcpy` in host |

### 13.2 Decisions for Eric

| # | Decision | Recommendation |
|---|---|---|
| D1 | Browser has no listener; reachable by Reticulum through a carrier. Does that meet "full"? | Yes, tested as responder |
| D2 | Browser may hold a seat but cannot promise availability | Accept; say so in the UI |
| D3 | Radio and local carriers are host-reported | Accept |
| D4 | No capture on EFI; A/V duty is relay and keys | Accept |
| D5 | NER tier: port it to wasm, or extend the iOS relabel | Extend the precedent now, port later. **By §2.2 this is not a host limit, so it needs your explicit exception** |
| D6 | Accord holder not possible in a browser | Accept; investigate EFI USB |
| D7 | Encrypt the store at rest on wasm targets, ahead of native? | Yes on EFI at least: a raw partition has no OS account boundary |
| D8 | Without PRF, may a browser hold an owner key under software seal? | Allow with a required `choice-item`, or refuse: your call; #325 calls it a steward decision |
| D9 | EFI seal: strict PCR, or PolicyAuthorize for signed updates? | PolicyAuthorize: strict PCR bricks on every update |
| D10 | Seed dwell in vault memory | 60 s idle |
| D11 | May an evictable key be the only roster key? | Allow, with the §9.3 item: refusing it makes the browser less than full |
| D12 | Where do `ciris-host-abi` and `ciris-rt` live? They must sit below every repo | New repo; nothing currently sits below leviculum and verify |
| D13 | Agent brain out of scope for "full"? | Yes for this FSD |
| D14 | Origin pinning for the browser: a signed release manifest, pinned by Service Worker? | Yes; narrow, not close |
| D15 | Is the vault instance required, or SHOULD? | Required |

### 13.3 Probes run for this document

All on this box, 2026-11-04, in scratch; no repo touched; nothing installed system-wide. Disk stayed above 80 GB.

| Probe | Result |
|---|---|
| `rustup target add x86_64-unknown-uefi` | Added |
| Host-neutral payload (rusqlite 0.41.1, `sqlite-wasm-rs` 0.6.2 no bindgen, ml-dsa 0.1.1, ed25519-dalek, sha2), zig cc | 2.4 MB; 3 imports |
| Payload under Node 20 V8, three runs | Baselines above |
| `uefi` 0.41 app in QEMU KVM OVMF: protocol census | Table in §3.3 |
| wasmi 2.0 in OVMF, `portable-dispatch`, `validate`, `libm` | Ran; first attempt triple-faulted |
| wabt 1.0.42 `wasm2c`, zig cc -O2, custom `rt.c`, PE link, 64 MiB stack | Ran |
| TCP4 out and in, DHCP, host Python peer | Ran; `hello-from-efi`, `ack-from-host`, `ping-inbound`, `pong-from-efi` |
| SFS 1 MiB write and read | Ran |
| Size profile, `wasm-opt -Oz` | Ratios in §3.4 |

Scratch binaries: wabt in a scratch directory; deleted. Sources and logs: `wasm855-logs/efi-probes/` and `wasm855-logs/sql-probes/` in the session scratchpad.

**Not run:** TCG2, swtpm, Secure Boot, aarch64, real firmware, real `opfs-sahpool` multi-tab, Safari, Firefox, WebTransport, WebRTC, WIT-generated bindings, Block I/O VFS, a full node of any kind.

**Disk-backed EFI SQLite was not tested.** The payload's SQLite in OVMF is in memory. Durable SQLite is proven on OPFS; durable writes are proven on EFI; the two together are not.

---

## 14. References

**UEFI and Rust.** [UEFI 2.9A Boot Services](https://uefi.org/specs/UEFI/2.9_A/07_Services_Boot_Services.html) · [rustc: `*-unknown-uefi`](https://doc.rust-lang.org/stable/rustc/platform-support/unknown-uefi.html) · [uefi-rs](https://github.com/rust-osdev/uefi-rs) · [jyao1/EfiSandbox](https://github.com/jyao1/EfiSandbox) · [iPXE watchdog](https://dox.ipxe.org/efi__watchdog_8c.html) · [EFI_TCG2_PROTOCOL struct](https://dox.ipxe.org/structtdEFI__TCG2__PROTOCOL.html) · [EDK2 RNG protocol](https://qemu.googlesource.com/edk2/+/refs/heads/master/MdePkg/Include/Protocol/Rng.h)

**Runtimes.** [wasmi](https://github.com/wasmi-labs/wasmi) · [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) · [Wasmtime platform support](https://docs.wasmtime.dev/stability-platform-support.html) · [Wasmtime minimal embedding](https://docs.wasmtime.dev/examples-minimal.html) · [wabt](https://github.com/WebAssembly/wabt) · [Embedded wasm benchmarks](https://dl.acm.org/doi/full/10.1145/3736169) · [jco](https://bytecodealliance.org/articles/five-ways-of-looking-at-jco-part-1)

**SQLite.** [SQLite wasm persistence](https://sqlite.org/wasm/doc/trunk/persistence.md) · [rusqlite](https://github.com/rusqlite/rusqlite) · [sqlite-wasm-rs](https://docs.rs/crate/sqlite-wasm-rs/latest) · [wa-sqlite examples](https://cdn.jsdelivr.net/npm/@journeyapps/wa-sqlite@1.7.0/src/examples/README.md) · [MDN createSyncAccessHandle](https://developer.mozilla.org/en-US/docs/Web/API/FileSystemFileHandle/createSyncAccessHandle)

**Browser.** [Chrome timer throttling](https://developer.chrome.com/blog/timer-throttling-in-chrome-88/) · [SW limits, Chromium extensions list](https://groups.google.com/a/chromium.org/g/chromium-extensions/c/L3EbiNMjIGI) · [WebKit storage policy](https://webkit.org/updates) · [iOS web push](https://www.moengage.com/docs/developer-guide/web-sdk/web-push/safari-web-push-for-i-os-and-i-pad-os.md) · [WebTransport baseline](https://webrtc.ventures/2026/04/webtransport-is-now-baseline-what-it-means-for-real-time-media/) · [WebTransport compatibility](https://echo.semantic-ui.com/compat) · [WebUSB unrestricted explainer](https://github.com/WICG/webusb/blob/main/unrestricted-usb-explainer.md) · [Chromium Web NFC](https://www.chromium.org/developers/design-documents/web-nfc/)

**Custody.** [CIRISVerify#325](https://github.com/CIRISAI/CIRISVerify/issues/325) · [Corbado PRF guide](https://www.corbado.com/blog/passkeys-prf-webauthn) · [Yubico PRF guide](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html) · [SimpleWebAuthn PRF](https://simplewebauthn.dev/docs/advanced/prf) · [W3C non-extractable PRF discussion](https://lists.w3.org/Archives/Public/public-webauthn/2023Jun/0000.html) · [TCG TPM 2.0 v1.85 PQC](https://trustedcomputinggroup.org/new-computing-specification-implements-pqc-measures-to-protect-users-from-quantum-attacks/) · [wolfTPM ML-DSA](https://www.wolfssl.com/post-quantum-cryptography-is-coming-to-wolftpm/) · [First firmware TPM with PQC](https://posts.wolfssl.com/2026/05/04/the-first-firmware-tpm-with-post-quantum-cryptography/)
