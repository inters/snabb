// worker.c - supporting code for subprocess management
// Use of this source code is governed by the Apache 2.0 license; see COPYING.

// This file implements a SIGCHLD handler that causes the parent to exit,
// propagating its child’s exit code.

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>

static void worker_sigchld_handler(int sig, siginfo_t *si, void *unused)
{
  // Exit with child’s status if si_status != 0
  if (si->si_status != 0)
    exit(si->si_status);
}

// Setup a SIGCHLD handler to propagate child exits
void worker_sigchld_setup(bool enable)
{
  struct sigaction sa;
  if (enable) {
    // Install signal handler
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = worker_sigchld_handler;
  } else {
    // Reset to default behavior
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_DFL;
  }
  assert(sigaction(SIGCHLD, &sa, NULL) != -1);
}
