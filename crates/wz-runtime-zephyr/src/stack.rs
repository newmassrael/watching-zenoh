// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The main thread's stack, measured, in the words the MCU lanes already use.
//!
//! A Zephyr image runs the whole node on one thread, so that thread's stack is
//! the node's memory budget for everything that nests: a frame per call, a
//! buffer per codec, a future polled inline. Nothing guards it. A stack that
//! runs out does not fault at the end of its own region; it writes into
//! whatever sits below, and the machine dies later, somewhere else, with a
//! register file that names none of it (the admin node on QEMU did exactly
//! this: its frame was the idle thread's, and the cause was a 16 KiB stack that
//! the node needed 20 KiB of).
//!
//! So the image measures it. The kernel can paint a stack at creation and say
//! how much of it was never touched (`CONFIG_INIT_STACKS`, with
//! `CONFIG_THREAD_STACK_INFO`); [`StackWatch`] turns that into a
//! `stack: peak N of M bytes` line whenever the peak has grown, which is the
//! line `deploy/mcu-*` print before they pass and `scripts/run-ci.sh` looks for.
//! A lane that sees no such line has learned the image stopped measuring, and
//! that reads exactly like one that measured and fit unless it is refused.
//!
//! The arithmetic is here, with no kernel call, so it is tested on a host. The
//! one call that reads the kernel is [`crate::glue::main_stack_usage`].

use alloc::format;
use alloc::string::String;

/// What the kernel says of a stack: how big it is, and how many of its bytes were
/// never written (the high-water mark is the rest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackUsage {
    /// The stack's size in bytes.
    pub size: u32,
    /// The bytes at its far end that the thread has never touched.
    pub unused: u32,
}

impl StackUsage {
    /// The deepest the stack has been, in bytes: its size less what was never
    /// touched. A kernel that reports more unused than the stack holds gives a
    /// peak of zero and not a wrapped number.
    pub const fn peak(self) -> u32 {
        self.size.saturating_sub(self.unused)
    }
}

/// Says when a stack's peak has grown, once for each new peak.
#[derive(Debug, Default)]
pub struct StackWatch {
    reported: Option<u32>,
}

impl StackWatch {
    /// A watch that has reported nothing.
    pub const fn new() -> Self {
        Self { reported: None }
    }

    /// The `stack: peak N of M bytes` line when `usage` is a higher peak than any
    /// this watch has reported, and nothing otherwise: not when the peak is the
    /// same (a line a second would drown the console), and not when the kernel
    /// measured nothing (`None`), which is the caller's to notice by there being no
    /// line at all.
    pub fn observe(&mut self, usage: Option<StackUsage>) -> Option<String> {
        let usage = usage?;
        let peak = usage.peak();
        if self.reported.is_some_and(|seen| peak <= seen) {
            return None;
        }
        self.reported = Some(peak);
        Some(format!("stack: peak {peak} of {} bytes", usage.size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn usage(size: u32, unused: u32) -> Option<StackUsage> {
        Some(StackUsage { size, unused })
    }

    #[test]
    fn the_peak_is_what_was_not_left_untouched_and_never_wraps() {
        assert_eq!(
            StackUsage {
                size: 32768,
                unused: 12756
            }
            .peak(),
            20012
        );
        assert_eq!(
            StackUsage {
                size: 16384,
                unused: 0
            }
            .peak(),
            16384,
            "all of it used"
        );
        assert_eq!(
            StackUsage {
                size: 16384,
                unused: 16384
            }
            .peak(),
            0,
            "none of it used"
        );
        assert_eq!(
            StackUsage { size: 100, unused: 101 }.peak(),
            0,
            "a kernel that reports more unused than the stack holds is a peak of zero, not 4 billion"
        );
    }

    /// The line is the words the MCU lanes grep for, with the numbers in the
    /// order they print them.
    #[test]
    fn the_line_says_peak_then_size_in_the_lanes_own_words() {
        let mut watch = StackWatch::new();
        assert_eq!(
            watch.observe(usage(32768, 12756)).as_deref(),
            Some("stack: peak 20012 of 32768 bytes")
        );
    }

    /// One line for each new peak, so a console is not drowned by a number that
    /// has not moved, and the LAST line is always the deepest the stack has been.
    #[test]
    fn a_line_is_printed_only_when_the_peak_has_grown() {
        let mut watch = StackWatch::new();
        assert!(
            watch.observe(usage(1000, 900)).is_some(),
            "the first reading"
        );
        assert_eq!(watch.observe(usage(1000, 900)), None, "the same peak");
        assert!(watch.observe(usage(1000, 600)).is_some(), "a deeper one");
        assert_eq!(
            watch.observe(usage(1000, 700)),
            None,
            "a shallower one is not a new peak, whatever the kernel says"
        );
        assert_eq!(
            watch.observe(usage(1000, 600)),
            None,
            "and the deepest stays the one reported"
        );
        assert_eq!(
            watch.observe(usage(1000, 100)).as_deref(),
            Some("stack: peak 900 of 1000 bytes")
        );
    }

    /// A kernel that did not measure gives no line and does not disturb what
    /// was reported before it.
    #[test]
    fn a_reading_the_kernel_did_not_make_prints_nothing_and_forgets_nothing() {
        let mut watch = StackWatch::new();
        assert_eq!(watch.observe(None), None, "nothing measured, nothing said");
        assert!(watch.observe(usage(500, 400)).is_some());
        assert_eq!(watch.observe(None), None);
        assert_eq!(
            watch.observe(usage(500, 400)),
            None,
            "the earlier peak was kept"
        );
    }
}
