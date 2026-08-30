//! # The background-work bound — `load.ceiling`'s consumer
//!
//! Every background task this node runs acquires a slot here first. How many
//! slots exist is [`load.ceiling`](crate::mesh_config_effect::LoadCeiling),
//! governed by a trust root through `mesh_config` under CC 4.2.1.
//!
//! # Why a root sets this and the node does not
//!
//! This is the RELIEF half of the two-plane load model. A node SELF-REPORTS its
//! load (`config:load` on `infra:attest`, CC 3.1/3.4.5 self-or-owner, conferred
//! for exactly that); a trust root RELIEVES it. The node has no standing to
//! relieve itself — CIRISServer#503 tried the node-local form and was withdrawn
//! on the constitution rather than on engineering, because CC 4.2.1 puts the
//! mesh-config author on the CC 3.2 delegation plane and a node holds no
//! delegation to itself. What arrives here always came from a root; this
//! module's only job is to obey it.
//!
//! # Why the graded tier exists at all
//!
//! CIRISEdge#547 is the shape of the problem: a canonical dying after ~22h
//! because one path held the single DB connection while page-faulting, with the
//! worker floor unable to help — more workers add queue positions, not
//! throughput. "Do less work" is the handle that was missing, and CC 4.2.1
//! makes it the graded tier: TTL-bounded, so a node recovers on its own when
//! the relief expires. The halt is the other tier — different authority, no
//! TTL — and is not this module.
//!
//! # The floor is 1, never 0
//!
//! persist floors the key deliberately: *"Relief that reaches zero is a halt …
//! A node held at 1 still converges, slowly, and recovers on its own when the
//! relief expires; a node at 0 converges never and would sit there until a TTL
//! nobody is watching runs out."* Nothing here can produce a zero bound.
//!
//! # Shrinking is deferred, not forced
//!
//! Lowering the ceiling never cancels running work. Tokio's `forget_permits`
//! can only reclaim slots that are FREE, so a shrink takes back what it can
//! immediately and the remainder as tasks finish ([`TaskSlot::drop`] reconciles).
//! The alternative — aborting mid-flight tasks to hit a number — turns a
//! throttle into a correctness hazard, and relief is supposed to be the SAFE
//! tier of the graded response.

use crate::mesh_config_effect::{LoadCeiling, MeshConfigEffect};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// What the bound currently is, and what it is trying to be.
///
/// Two numbers because they legitimately differ while a shrink drains: `target`
/// is what the root asked for, `granted` is what the semaphore actually holds.
#[derive(Debug)]
struct Bound {
    target: usize,
    granted: usize,
}

/// The concurrency bound every background task acquires against.
#[derive(Debug)]
pub struct BackgroundScheduler {
    sem: Arc<Semaphore>,
    bound: Mutex<Bound>,
    /// Tasks that have run to completion. Diagnostics only.
    completed: AtomicUsize,
}

impl BackgroundScheduler {
    /// A scheduler with an explicit bound.
    ///
    /// Production builds this from the mesh-config reading via
    /// [`from_config`](Self::from_config); this exists for the pre-config
    /// bootstrap window and for tests, and clamps to at least 1 so no caller
    /// can construct a scheduler that never runs anything.
    #[must_use]
    pub fn with_bound(max_concurrent_tasks: usize) -> Arc<Self> {
        let n = max_concurrent_tasks.max(1);
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(n)),
            bound: Mutex::new(Bound {
                target: n,
                granted: n,
            }),
            completed: AtomicUsize::new(0),
        })
    }

    /// A scheduler bound by the node's current mesh-config reading.
    #[must_use]
    pub fn from_config(effect: &MeshConfigEffect) -> Arc<Self> {
        Self::with_bound(effect.load_ceiling().max_concurrent_tasks())
    }

    /// Adopt a new ceiling. Growth is immediate; a shrink reclaims what is free
    /// now and the rest as running tasks finish.
    pub fn apply(&self, ceiling: LoadCeiling) {
        {
            let mut b = self.bound.lock().expect("bound mutex");
            let target = ceiling.max_concurrent_tasks().max(1);
            if b.target == target {
                return;
            }
            tracing::info!(
                from = b.target,
                to = target,
                relieved = ceiling.relieved(),
                "background concurrency ceiling changed (load.ceiling)"
            );
            b.target = target;
        }
        self.reconcile();
    }

    /// Move `granted` toward `target` as far as the semaphore allows right now.
    fn reconcile(&self) {
        let mut b = self.bound.lock().expect("bound mutex");
        if b.granted < b.target {
            let add = b.target - b.granted;
            self.sem.add_permits(add);
            b.granted += add;
        } else if b.granted > b.target {
            // Only FREE permits can be reclaimed. Whatever is still held comes
            // back through `TaskSlot::drop`, which calls this again.
            let removed = self.sem.forget_permits(b.granted - b.target);
            b.granted -= removed;
        }
    }

    /// Take a slot, waiting if the node is at its ceiling.
    ///
    /// The returned guard must be held for the duration of the work — dropping
    /// it early releases the slot while the task is still running, which is how
    /// a bound stops bounding anything.
    pub async fn acquire(self: &Arc<Self>) -> TaskSlot {
        let permit = Arc::clone(&self.sem)
            .acquire_owned()
            .await
            .expect("background scheduler semaphore is never closed");
        TaskSlot {
            permit: Some(permit),
            scheduler: Arc::clone(self),
        }
    }

    /// The bound the node is running right now.
    #[must_use]
    pub fn granted(&self) -> usize {
        self.bound.lock().expect("bound mutex").granted
    }

    /// What the ceiling asks for. Differs from [`granted`](Self::granted) only
    /// while a shrink drains.
    #[must_use]
    pub fn target(&self) -> usize {
        self.bound.lock().expect("bound mutex").target
    }

    /// Tasks completed through this scheduler.
    #[must_use]
    pub fn completed(&self) -> usize {
        self.completed.load(Ordering::Relaxed)
    }
}

/// A held slot. Releases on drop, and lets a pending shrink make progress.
#[derive(Debug)]
pub struct TaskSlot {
    /// `Option` so [`Drop`] can RELEASE it before reconciling.
    ///
    /// A struct's own `drop` runs before its fields are dropped, so reconciling
    /// with the permit still held finds nothing free and a pending shrink never
    /// makes progress — the bug this shape exists to prevent.
    permit: Option<OwnedSemaphorePermit>,
    scheduler: Arc<BackgroundScheduler>,
}

impl Drop for TaskSlot {
    fn drop(&mut self) {
        self.scheduler.completed.fetch_add(1, Ordering::Relaxed);
        // Release FIRST, then reconcile: the permit must be back in the
        // semaphore before a pending shrink can reclaim it.
        drop(self.permit.take());
        self.scheduler.reconcile();
    }
}

/// Follow the mesh-config plane and keep the bound in step with it.
///
/// This is the call that makes `load.ceiling` a WIRED key: the reading is
/// consumed here, outside `mesh_config_effect`, in non-test code.
pub async fn govern(scheduler: Arc<BackgroundScheduler>, effect: MeshConfigEffect) {
    let mut rx = effect.subscribe();
    loop {
        scheduler.apply(effect.load_ceiling());
        if rx.changed().await.is_err() {
            // Every sender is gone — the composition is shutting down. The last
            // ceiling stays in force; there is nothing left to follow.
            tracing::debug!("mesh-config plane closed; background ceiling holds at last value");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// **The bound actually bounds.** With two slots, three tasks never run
    /// three-at-once.
    #[tokio::test]
    async fn concurrency_never_exceeds_the_ceiling() {
        let sched = BackgroundScheduler::with_bound(2);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..12 {
            let s = Arc::clone(&sched);
            let f = Arc::clone(&in_flight);
            let p = Arc::clone(&peak);
            handles.push(tokio::spawn(async move {
                let slot = s.acquire().await;
                let now = f.fetch_add(1, Ordering::SeqCst) + 1;
                p.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                f.fetch_sub(1, Ordering::SeqCst);
                drop(slot);
            }));
        }
        for h in handles {
            h.await.expect("task");
        }
        assert!(
            peak.load(Ordering::SeqCst) <= 2,
            "peak concurrency {} exceeded the ceiling of 2",
            peak.load(Ordering::SeqCst)
        );
        assert_eq!(sched.completed(), 12);
    }

    /// **A zero can never be constructed**, whichever way it is asked for.
    /// persist floors the key at 1; a node at 0 converges never.
    #[test]
    fn the_bound_is_never_zero() {
        assert_eq!(BackgroundScheduler::with_bound(0).granted(), 1);
        assert_eq!(BackgroundScheduler::with_bound(0).target(), 1);
    }

    /// Growth takes effect at once.
    #[tokio::test]
    async fn raising_the_ceiling_adds_capacity_immediately() {
        let sched = BackgroundScheduler::with_bound(1);
        let held = sched.acquire().await;
        // At the ceiling: a second acquire would block. Raise it and it does not.
        sched.apply(ceiling(4));
        assert_eq!(sched.granted(), 4);
        let second = tokio::time::timeout(std::time::Duration::from_secs(1), sched.acquire()).await;
        assert!(second.is_ok(), "a raised ceiling must free a slot at once");
        drop(held);
    }

    /// **A shrink drains rather than cancels.** It reclaims free slots now and
    /// the rest as tasks finish — it never aborts running work.
    #[tokio::test]
    async fn lowering_the_ceiling_drains_as_tasks_finish() {
        let sched = BackgroundScheduler::with_bound(4);
        let a = sched.acquire().await;
        let b = sched.acquire().await;

        sched.apply(ceiling(1));
        assert_eq!(sched.target(), 1);
        // Two slots were free, so two came back at once; the two held could not.
        assert_eq!(sched.granted(), 2, "a shrink reclaims only what is free");

        drop(a);
        assert_eq!(sched.granted(), 1, "the rest returns as work finishes");
        drop(b);
        assert_eq!(sched.granted(), 1, "and never drops below the target");
    }

    /// Re-applying the same ceiling is a no-op, so a config refresh that
    /// changed nothing does not churn the semaphore or log a change.
    #[tokio::test]
    async fn re_applying_the_same_ceiling_changes_nothing() {
        let sched = BackgroundScheduler::with_bound(3);
        sched.apply(ceiling(3));
        assert_eq!((sched.target(), sched.granted()), (3, 3));
    }

    /// Build a `LoadCeiling` the way production does — through the accessor,
    /// over a reading — rather than by constructing the type directly.
    fn ceiling(n: usize) -> LoadCeiling {
        LoadCeilingProbe::at(n)
    }

    /// The accessor's fields are private by design, so tests reach a specific
    /// value through the same clamp production uses.
    struct LoadCeilingProbe;
    impl LoadCeilingProbe {
        fn at(n: usize) -> LoadCeiling {
            crate::mesh_config_effect::LoadCeiling::for_bound(n)
        }
    }
}
