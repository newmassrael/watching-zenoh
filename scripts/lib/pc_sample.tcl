# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The program counter of the T2G kit's M7_0 core, sampled through the debug port while the image
# answers (scripts/kit-lane.sh with KIT_PROFILE_OUT). It is an openocd script: the lane starts it with
# the kit's interface and target files, and it
#
#   1. resets the kit and lets the image run (the attach itself resets the device, as the lane's own
#      `reset run` does),
#   2. waits for the flag file $PROFILE_FLAG, which the lane creates when its probe starts asking,
#   3. reads DWT_PCSR (0xE000101C) of the M7_0 core as fast as the debug port allows (about 500 a
#      second) and writes each sample, eight hex digits to a line, to $PROFILE_OUT, until the flag is
#      removed.
#
# DWT_PCSR is the core's own sample of the address of an instruction it executed: a read does not
# halt the core, so the answers are the ones the image gives with the debugger attached, slowed by the
# debug port's use of the bus and by nothing else. A sample is a count of where time went, and a
# profile of it ranks the functions of the path; it is not a trace and not a verdict on the run.

init
reset run
# The image boots, brings the link up and dials the router before the lane starts asking.
sleep 3000
targets cat1c.cpu.cm70

set flag $::env(PROFILE_FLAG)
set out [open $::env(PROFILE_OUT) w]
while {![file exists $flag]} {
    sleep 20
}
set count 0
while {[file exists $flag]} {
    for {set i 0} {$i < 50} {incr i} {
        puts $out [format %08x [lindex [read_memory 0xE000101C 32 1] 0]]
        incr count
    }
}
close $out
echo "pc_sample: $count samples"
shutdown
