// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// The launcher a host bench starts a program under when it reads the program's peak resident set from
// outside it (scripts/host-bench/parity.py; docs/upstream-parity.md section 5b): upstream's example
// programs, whose source the bench does not change, print no figure of their own.
//
//   cc -O2 -o fork_rss fork_rss.c
//   fork_rss REPORT PROGRAM [ARG...]
//
// Linux keeps the resident set a process had before its exec as a floor of the maxrss getrusage gives of
// it afterwards, and a child of a Python runner is a copy of the runner until it executes the program, so
// the maxrss of a program the runner started itself is at least the runner's. This launcher forks the
// program from itself, a process of a few pages, and reads the program's maxrss from its own wait4.
//
// REPORT gets `pid=<the program's pid>` once the program is forked, so the runner reads the program's
// /proc entries and not the launcher's, and `peak_rss_kib=<the program's maxrss>` once it ended.
// SIGTERM, SIGINT and SIGHUP sent to the launcher are passed on to the program, and the program is sent
// SIGKILL when the launcher dies, so a launcher killed hard leaves no program behind. An environment the
// program needs that the launcher must not have (a preloaded shim) is set after the fork by env(1) as the
// PROGRAM.
//
// Exit status: the program's, or 128 plus the signal that ended it, as a shell reports them; 127 when the
// program could not be started or REPORT could not be written, 126 for a usage error.

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const int passed_on[] = {SIGTERM, SIGINT, SIGHUP};
#define PASSED_ON (sizeof passed_on / sizeof passed_on[0])

static volatile sig_atomic_t program = 0;

static void pass_on(int signo) {
    if (program > 0) kill((pid_t)program, signo);
}

static int report(const char *path, const char *mode, const char *key, long long value) {
    FILE *out = fopen(path, mode);
    if (out == NULL) return -1;
    const int written = fprintf(out, "%s=%lld\n", key, value);
    return (fclose(out) != 0 || written < 0) ? -1 : 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: fork_rss REPORT PROGRAM [ARG...]\n");
        return 126;
    }
    // Held from before the fork until the program's pid is known, so a stop that arrives in between is
    // passed on once there is a program to pass it to.
    sigset_t held, before;
    sigemptyset(&held);
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = pass_on;
    action.sa_flags = SA_RESTART;
    for (size_t i = 0; i < PASSED_ON; i++) {
        sigaction(passed_on[i], &action, NULL);
        sigaddset(&held, passed_on[i]);
    }
    sigprocmask(SIG_BLOCK, &held, &before);
    const pid_t launcher = getpid();
    const pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "fork_rss: fork: %s\n", strerror(errno));
        return 127;
    }
    if (child == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        // The launcher may have died before the line above took effect.
        if (getppid() != launcher) _exit(127);
        for (size_t i = 0; i < PASSED_ON; i++) signal(passed_on[i], SIG_DFL);
        sigprocmask(SIG_SETMASK, &before, NULL);
        execvp(argv[2], &argv[2]);
        fprintf(stderr, "fork_rss: %s: %s\n", argv[2], strerror(errno));
        _exit(127);
    }
    program = (sig_atomic_t)child;
    const int announced = report(argv[1], "w", "pid", (long long)child);
    sigprocmask(SIG_SETMASK, &before, NULL);
    if (announced != 0) {
        fprintf(stderr, "fork_rss: %s: %s\n", argv[1], strerror(errno));
        kill(child, SIGKILL);
    }
    int status = 0;
    struct rusage usage;
    memset(&usage, 0, sizeof usage);
    while (wait4(child, &status, 0, &usage) < 0) {
        if (errno != EINTR) {
            fprintf(stderr, "fork_rss: wait4: %s\n", strerror(errno));
            return 127;
        }
    }
    if (announced != 0 || report(argv[1], "a", "peak_rss_kib", (long long)usage.ru_maxrss) != 0) return 127;
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 127;
}
