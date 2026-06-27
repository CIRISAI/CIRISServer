# CEWPOS — CIRIS Epistemic Web Platform OS

> **Status:** Vision / Spec skeleton.
> **Context:** With CIRISServer as the base fabric node, the addition of CIRISRegistry (authority), CIRISNodeCore (consensus), and CIRISAgent (moral reasoning and agency) completes the stack. Once these are unified into a cohesive runtime, the result ceases to be just a node or an app — it becomes an "everything app" and the foundation for an operating system environment. We call this **CEWPOS**: the CIRIS Epistemic Web Platform OS.

## 1. What is CEWPOS?

CEWPOS is the logical conclusion of the CIRIS stack: an operating system paradigm where the network, data storage, identity, trust, and intelligence are natively integrated at the substrate level.

It is the environment where `agent = fabric node + brain` evolves into `OS = fabric + brain + user interface + applications`. Instead of traditional distinct applications running in isolated silos on a local machine, everything runs as an interface over the unified CIRIS Substrate, powered by the CIRIS Epistemic Grammar (CEG) and routed through the fabric node.

### 1.1 The Name
- **CEWP:** CIRIS Epistemic Web Platform. The decentralized, meaning-oriented network formed by CEG.
- **OS:** Operating System. The cohesive runtime and user environment built on top of this platform.

(Note: Not "CIRISOS", which sounds like "cirrhosis".)

## 2. Architecture

CEWPOS stacks the existing CIRIS ecosystem components into a complete computing platform:

```text
┌─────────────────────────────────────────────────────────────┐
│                       CEWPOS UI / UX                        │
│ The "Everything App" surface (Cards, Chat, Holonomic Views) │
├─────────────────────────────────────────────────────────────┤
│                         CIRISAgent                          │
│ Agency Layer: Moral Reasoning, PDMA, CSDMA, Action Handlers │
├─────────────────────────────────────────────────────────────┤
│         CIRISRegistry  ·  CIRISNodeCore  ·  CIRISLensCore   │
│  Authority (Identity)  ·   Consensus     ·   Observation    │
├─────────────────────────────────────────────────────────────┤
│                        CIRISServer                          │
│ Base Fabric Node (Cohabitation Runtime, Substrate Host)     │
├─────────────────────────────────────────────────────────────┤
│        ciris-persist   ·   ciris-verify  ·  ciris-edge      │
│        Storage/Corpus  ·   Cryptography  ·  CEG/Reticulum   │
└─────────────────────────────────────────────────────────────┘
```

### 2.1 The Components
1. **The Base Fabric (CIRISServer + Substrate):** The root of the OS. Provides the durable SQLite corpus (`ciris-persist`), hardware-sealed cryptographic identity (`ciris-verify`), and Reticulum-based mesh transport (`ciris-edge`). It acts without agency, handling purely infrastructural tasks: attestations, data persistence, and CEG envelope routing.
2. **The Cores:**
   - **CIRISRegistry:** The authority slice, managing federation identity, licenses, revocations, and steward attestations.
   - **CIRISLensCore:** The observation slice, maintaining Coherence Ratchets and Capacity Scores (validated, not adjudicated).
   - **CIRISNodeCore:** The consensus slice, managing deferral routing, voting, and moderation.
3. **The Brain (CIRISAgent):** Provides the moral reasoning engine, natural language capabilities, and action loops. This is the OS's intelligence, processing the world through Mission Driven Development principles and the CIRIS Accord.
4. **The "Everything App" Surface:** The user interface. Instead of separate apps for messaging, banking, social media, or governance, CEWPOS renders everything as interactions with the fabric — via "Cards", conversational interfaces, and holonomic dashboards.

## 3. Core Capabilities of CEWPOS

### 3.1 Unification of App and Network
In CEWPOS, there is no distinction between "local state" and "network state" beyond what the user consents to replicate. The underlying `ciris-persist` engine handles all state. Applications do not have their own databases; they are simply views or "Cards" operating over the unified CEG corpus.

### 3.2 Inherent Agency and Moral Reasoning
Unlike traditional operating systems that passively execute code, CEWPOS integrates the CIRISAgent loop. The OS understands the intent behind actions, adheres to the CIRIS Accord, and can refuse commands that violate safety or coherence invariants. It acts as an ethical steward for the user.

### 3.3 Hardware-Rooted, Sovereign Identity
Identity is not managed by a third-party provider or a central server. It is hardware-rooted (e.g., YubiKey, TPM/SE), sealed in the substrate, and universally recognized across the CEWP. The OS *is* the user's sovereign identity agent.

### 3.4 Governance and Moderation as System Primitives
Multi-party spaces, communication, and resource sharing are moderated by default according to the named-moderator existence invariant. The OS natively supports delegations of trust, recusal, and transparent appeals.

## 4. The "Everything App" Paradigm

Because all data follows the CEG format, any interaction — a financial transaction, a social post, a moderation action, or a software license — is just a different type of CEG envelope.

- **Universal Addressability:** Everything is reachable via Reticulum network routing or CEG identifiers.
- **Composable Workflows:** The Agent can seamlessly combine a `detection` event from a Lens with a `takedown` action from the Registry, and present it to the user in a Chat interface.
- **No Walled Gardens:** Trust is a sovereign graph. The user can untrust the `ciris-canonical` default and seamlessly migrate their entire OS trust structure to a new community without losing functionality.

## 5. Summary

CEWPOS represents the culmination of the separation-of-powers invariant and the agent fold. By combining the agency-free, quorum-bound fabric infrastructure with the intelligent, ethically-bound CIRISAgent, CEWPOS delivers a computing environment that is decentralized, unified, and intrinsically safe.
