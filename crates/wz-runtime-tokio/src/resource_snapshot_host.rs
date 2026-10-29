// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A hosted node's resource snapshot: what the operating system answers, and the task that takes
//! a snapshot on the period (`docs/observation-plane.md` M4).
//!
//! The snapshot, its sampler and the message counter are `wz_session_core::resource_snapshot`'s
//! and carry no platform. This module is the hosted platform's half: [`HostResourceSource`] asks
//! the operating system for what a node can say about itself, and [`SnapshotService`] is the
//! sampler with a task that polls it, since a hosted node has tasks and the sampler holds none of
//! its own.
//!
//! # What the operating system is asked
//!
//! * The CPU use is the share of the time the machine's CPUs were busy between two readings, from
//!   the jiffy counters of `/proc/stat`. It is the machine's, not the process's: a node on a
//!   shared host reports how loaded the host it runs on is. The first reading has no earlier one to
//!   subtract and says nothing.
//! * The tasks are the threads of this process (`/proc/self/status`).
//! * The heap is not measured: the standard library keeps no count of what the allocator has
//!   handed out, and the snapshot says it was not measured and not that it is zero.
//!
//! A platform without `/proc` answers nothing, and every part of the snapshot says so.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

// The runtime's clock and not the standard one, so that the service and the sleep that paces its
// task read the same time, and a test that pauses the runtime's time pauses both.
use tokio::time::Instant;

use wz_session_core::caps::SNAPSHOT_HISTOGRAM_BUCKETS;
use wz_session_core::resource_snapshot::{
    feature_bits, BuildSampler, MessageReading, ResourceReading, ResourceSource,
};

/// The message reading a node hands the service on each sample.
pub type NodeMessageReading = MessageReading<SNAPSHOT_HISTOGRAM_BUCKETS>;

/// The jiffies the machine's CPUs have spent busy and in all, from the first line of
/// `/proc/stat` (`cpu  user nice system idle iowait irq softirq steal ...`). Idle time and the
/// time spent waiting for input and output are not busy; guest time is already in user time and
/// is not added again.
fn parse_cpu_jiffies(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().next()?;
    let mut fields = line.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let mut counts = [0u64; 8];
    for slot in &mut counts {
        *slot = fields.next()?.parse().ok()?;
    }
    let [user, nice, system, idle, iowait, irq, softirq, steal] = counts;
    let busy = user
        .checked_add(nice)?
        .checked_add(system)?
        .checked_add(irq)?
        .checked_add(softirq)?
        .checked_add(steal)?;
    let total = busy.checked_add(idle)?.checked_add(iowait)?;
    Some((busy, total))
}

/// The threads of the process, from the `Threads:` line of `/proc/self/status`.
fn parse_threads(status: &str) -> Option<u16> {
    let line = status.lines().find(|line| line.starts_with("Threads:"))?;
    let count: u64 = line["Threads:".len()..].trim().parse().ok()?;
    Some(u16::try_from(count).unwrap_or(u16::MAX))
}

/// The share of the time busy between two readings of [`parse_cpu_jiffies`], in thousandths.
/// `None` when no time passed between them, or a counter went backwards (a reset the reader
/// cannot tell from a wrap).
fn busy_permille(earlier: (u64, u64), later: (u64, u64)) -> Option<u16> {
    let busy = later.0.checked_sub(earlier.0)?;
    let total = later.1.checked_sub(earlier.1)?;
    if total == 0 || busy > total {
        return None;
    }
    // `busy <= total`, so the quotient is at most 1000.
    Some((u128::from(busy) * 1000 / u128::from(total)) as u16)
}

/// The hosted platform's [`ResourceSource`]: CPU use and threads from `/proc`, nothing else.
#[derive(Debug, Default)]
pub struct HostResourceSource {
    previous_cpu: Option<(u64, u64)>,
}

impl HostResourceSource {
    /// A source with no earlier reading, so its first answer has no CPU use.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ResourceSource for HostResourceSource {
    fn read(&mut self) -> ResourceReading {
        let now = std::fs::read_to_string("/proc/stat")
            .ok()
            .and_then(|stat| parse_cpu_jiffies(&stat));
        let cpu_permille = match (self.previous_cpu, now) {
            (Some(earlier), Some(later)) => busy_permille(earlier, later),
            _ => None,
        };
        // A failed read leaves the baseline where it was: the next reading spans the gap.
        if now.is_some() {
            self.previous_cpu = now;
        }
        let tasks = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| parse_threads(&status));
        ResourceReading {
            cpu_permille,
            heap: None,
            tasks,
            events_dropped: None,
        }
    }
}

/// The instruments of the observation plane this build has, as [`feature_bits`].
fn build_features() -> u64 {
    let mut word = feature_bits::RESOURCE_SNAPSHOT;
    if cfg!(feature = "clock-source") {
        word |= feature_bits::CLOCK_SOURCE;
    }
    if cfg!(feature = "event-ring") {
        word |= feature_bits::EVENT_RING;
    }
    word
}

/// The sampler of a hosted node and what serves its latest snapshot.
///
/// A node starts one ([`Self::spawn`]) and gives it the message reading of its receive paths; the
/// admin space asks it for the latest snapshot as JSON ([`Self::latest_json`]).
pub struct SnapshotService {
    sampler: Mutex<BuildSampler>,
    origin: Instant,
}

impl SnapshotService {
    /// A service that has taken no snapshot.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sampler: Mutex::new(BuildSampler::for_build(build_features())),
            origin: Instant::now(),
        })
    }

    /// Microseconds since the service began, in the 32 bits the sampler compares.
    fn now_us(&self) -> u32 {
        self.origin.elapsed().as_micros() as u32
    }

    /// How long until a snapshot is due: nothing when one is, the whole period right after one.
    fn due_in(&self) -> Duration {
        let now = self.now_us();
        let until = self
            .sampler
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .until_due_us(now);
        Duration::from_micros(u64::from(until))
    }

    /// Take a snapshot if one is due: `source` is asked for the platform's readings, and `messages`
    /// for what the node's receive paths have counted. Returns whether one was taken.
    ///
    /// The source is asked with no lock held, so a slow platform read never stalls a reader of
    /// the latest snapshot.
    pub fn poll(
        &self,
        source: &mut impl ResourceSource,
        messages: impl FnOnce() -> NodeMessageReading,
    ) -> bool {
        let now = self.now_us();
        if !self
            .sampler
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_due(now)
        {
            return false;
        }
        #[cfg_attr(not(feature = "event-ring"), allow(unused_mut))]
        let mut reading = source.read();
        // The event ring's loss is the library's to state, not the platform's, as the C doors do.
        #[cfg(feature = "event-ring")]
        {
            reading.events_dropped = Some(wz_node_time::event_log::global().dropped());
        }
        let messages = messages();
        self.sampler
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(now, reading, messages);
        true
    }

    /// The latest snapshot as the JSON document of
    /// [`Snapshot::write_json`](wz_session_core::resource_snapshot::Snapshot::write_json), or
    /// `None` before the first.
    pub fn latest_json(&self) -> Option<String> {
        let sampler = self.sampler.lock().unwrap_or_else(PoisonError::into_inner);
        let mut text = String::new();
        sampler.latest()?.write_json(&mut text).ok()?;
        Some(text)
    }

    /// Answer a GET for the snapshot document, as the admin space serves it under
    /// [`snapshot_key`](wz_session_core::adminspace::snapshot_key): the latest snapshot as JSON to a
    /// GET that reaches the key when `read` permits, nothing before the first snapshot, and a
    /// denial when `read` is false. The host registers a queryable on that key and calls this from
    /// its handler with the admin read permit it already resolves for every admin leg.
    #[cfg(feature = "adminspace-core")]
    pub fn answer(
        &self,
        view: &dyn wz_session_core::query_sink::QueryView,
        out: &mut dyn wz_session_core::query_sink::ReplyOut,
        zid_hex: &str,
        read: bool,
    ) -> wz_session_core::adminspace::AdminAnswerOutcome {
        wz_session_core::adminspace::answer_snapshot_query(view, out, zid_hex, read, || {
            self.latest_json()
        })
    }

    /// Poll on the build's period from a task of its own, with the hosted platform's source: the
    /// task a hosted node has and the sampler does not. The first snapshot is taken at once.
    /// Dropping or aborting the handle stops it.
    pub fn spawn(
        self: &Arc<Self>,
        messages: impl Fn() -> NodeMessageReading + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let service = Arc::clone(self);
        tokio::spawn(async move {
            let mut source = HostResourceSource::new();
            loop {
                service.poll(&mut source, &messages);
                // Sleep exactly until the next sample is due, and not a fixed period: a timer of
                // the period ticks a little less than a period after a sample taken a little
                // after its tick, finds none due, and waits out another whole period, so the
                // node would sample every other tick. The pause is never shorter than a
                // millisecond, so a source that is slow cannot make this loop spin.
                tokio::time::sleep(service.due_in().max(Duration::from_millis(1))).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::caps::SNAPSHOT_PERIOD_MS;
    use wz_session_core::resource_snapshot::HeapReading;

    const STAT: &str = "cpu  100 20 30 700 50 5 5 10 0 0\ncpu0 50 10 15 350 25 2 2 5 0 0\nintr 1\n";

    #[test]
    fn the_cpu_line_of_proc_stat_gives_busy_and_total_jiffies() {
        // busy = user + nice + system + irq + softirq + steal = 100 + 20 + 30 + 5 + 5 + 10;
        // total adds idle 700 and iowait 50.
        assert_eq!(parse_cpu_jiffies(STAT), Some((170, 920)));
        assert_eq!(
            parse_cpu_jiffies("cpu0 1 2 3 4 5 6 7 8\n"),
            None,
            "not the total line"
        );
        assert_eq!(parse_cpu_jiffies("cpu  1 2 3\n"), None, "too few fields");
        assert_eq!(parse_cpu_jiffies(""), None);
        assert_eq!(
            parse_cpu_jiffies("cpu  a 2 3 4 5 6 7 8\n"),
            None,
            "not numbers"
        );
    }

    #[test]
    fn the_share_busy_is_taken_between_two_readings_and_refuses_what_is_not_one() {
        assert_eq!(busy_permille((0, 0), (250, 1000)), Some(250));
        assert_eq!(busy_permille((100, 400), (100, 800)), Some(0), "all idle");
        assert_eq!(busy_permille((0, 0), (500, 500)), Some(1000), "all busy");
        assert_eq!(busy_permille((10, 10), (10, 10)), None, "no time passed");
        assert_eq!(
            busy_permille((10, 100), (5, 200)),
            None,
            "a counter went backwards"
        );
        assert_eq!(
            busy_permille((0, 0), (300, 200)),
            None,
            "more busy than there was time"
        );
    }

    #[test]
    fn the_threads_of_the_process_are_read_from_the_status_file() {
        assert_eq!(
            parse_threads("Name:\tx\nThreads:\t12\nSigQ:\t0/1\n"),
            Some(12)
        );
        assert_eq!(
            parse_threads("Threads:\t999999\n"),
            Some(u16::MAX),
            "clamped, not wrapped"
        );
        assert_eq!(parse_threads("Name:\tx\n"), None);
        assert_eq!(parse_threads("Threads:\tmany\n"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_source_answers_threads_at_once_and_cpu_from_the_second_reading() {
        let mut source = HostResourceSource::new();
        let first = source.read();
        assert!(
            first.tasks.is_some_and(|tasks| tasks >= 1),
            "this test is a thread"
        );
        assert_eq!(first.cpu_permille, None, "no earlier reading to subtract");
        assert_eq!(first.heap, None, "the heap is not measured");
        // Burn a little CPU so the two readings are not identical, then read again.
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(30) {
            std::hint::black_box(0u64);
        }
        let second = source.read();
        assert!(second.cpu_permille.is_none_or(|share| share <= 1000));
    }

    struct Fixed(ResourceReading);

    impl ResourceSource for Fixed {
        fn read(&mut self) -> ResourceReading {
            self.0
        }
    }

    #[test]
    fn the_service_takes_one_snapshot_per_period_and_serves_it_as_json() {
        let service = SnapshotService::new();
        assert_eq!(service.latest_json(), None, "nothing before the first poll");
        let mut source = Fixed(ResourceReading {
            cpu_permille: Some(123),
            heap: Some(HeapReading {
                in_use: 7,
                high_water: 9,
            }),
            tasks: Some(4),
            events_dropped: None,
        });
        let mut messages = NodeMessageReading::empty();
        messages.messages = 5;
        let again = messages.clone();
        assert!(service.poll(&mut source, || messages));
        assert!(
            !service.poll(&mut source, || again),
            "a second poll at once finds none due"
        );
        let json = service.latest_json().expect("a snapshot was taken");
        for part in [
            "\"cpu_permille\":123",
            "\"tasks\":4",
            "\"heap\":{\"in_use\":7,\"high_water\":9}",
            "\"messages\":5",
            "\"resource-snapshot\"",
        ] {
            assert!(json.contains(part), "`{part}` is not in {json}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_task_takes_a_snapshot_at_once_and_serves_what_the_node_counted() {
        let service = SnapshotService::new();
        let handle = service.spawn(|| {
            let mut reading = NodeMessageReading::empty();
            reading.messages = 42;
            reading
        });
        // The first tick of an interval is immediate; yield until the task has run.
        for _ in 0..50 {
            if service.latest_json().is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let json = service
            .latest_json()
            .expect("the task took the first snapshot");
        assert!(json.contains("\"messages\":42"), "{json}");
        assert!(json.contains("\"sequence\":0,"), "{json}");
        // One period on it takes the next, and the one after that a period later still: it
        // sleeps until a sample is due and does not tick on a fixed period that can fall just
        // short of the sampler's.
        for expected in 1..=2 {
            tokio::time::advance(Duration::from_millis(SNAPSHOT_PERIOD_MS as u64)).await;
            let wanted = format!("\"sequence\":{expected},");
            for _ in 0..50 {
                if service
                    .latest_json()
                    .is_some_and(|json| json.contains(&wanted))
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
            let json = service.latest_json().unwrap();
            assert!(
                json.contains(&wanted),
                "a period on, snapshot {expected} was taken: {json}"
            );
        }
        handle.abort();
    }
}
