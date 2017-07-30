#include <assert.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <set>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <unistd.h>
using namespace std;

#define DR_OFFSET(x) (((struct user *)0)->u_debugreg + x)
enum Type {CODE, RWATCH, WATCH};

const char USAGE[] = "Usage: %s rwatch_address argv...";

void print_help(FILE *fh)
{
  fprintf(fh, USAGE, program_invocation_short_name);
  fputs("\n"
        "Examples:\n"
        "  ./ptrace-flag 0x6138e0 ./clemency-emu hello.bin  # return 00 if flag is read\n"
        "\n"
        , fh);
  exit(fh == stdout ? 0 : EX_USAGE);
}

int main(int argc, char* argv[])
{
  bool opt_verbose;
  int opt;
  Type opt_type = CODE;
  static struct option long_options[] = {
    {"code",      no_argument,       0,   'c'},
    {"rwatch",    no_argument,       0,   'r'},
    {"verbose",   no_argument,       0,   'v'},
    {"watch",    no_argument,        0,   'w'},
    {"help",      no_argument,       0,   'h'},
    {0,           0,                 0,   0},
  };

  while ((opt = getopt_long(argc, argv, "crhvw", long_options, NULL)) != -1) {
    switch (opt) {
    case 'c':
      opt_type = CODE;
      break;
    case 'h':
      print_help(stdout);
      break;
    case 'r':
      opt_type = RWATCH;
      break;
    case 't':
      //opt_timeout = atoi(optarg);
      break;
    case 'v':
      opt_verbose = true;
      break;
    case '?':
      break;
    }
  }
  argc -= optind;
  argv += optind;
  if (argc < 2)
    errx(1, USAGE, program_invocation_short_name);
  errno = 0;
  long rwatch = strtol(argv[0], NULL, 0);
  if (errno)
    err(1, "strtol");

  int pfd[2];
  if (pipe(pfd) < 0) err(EX_OSERR, "pipe");
  pid_t pid = fork();
  if (pid < 0) err(EX_OSERR, "fork");
  if (pid == 0) {
    read(pfd[0], &argc, 1);
    close(pfd[0]);
    close(pfd[1]);
    // int t = ptrace(PTRACE_TRACEME, 0, 0, 0);
    //   err(2, "ptrace");
    execvp(argv[1], argv + 1);
    err(2, "execv");
  }

  if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0)
    err(2, "PTRACE_ATTACH");

  write(pfd[1], &argc, 1);
  close(pfd[0]);
  close(pfd[1]);

  int sig = 0, traps = 0, status;
  for(;;) {
    pid = waitpid(-1, &status, 0);
    if (pid < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (WIFEXITED(status))
      sig = 0;
    else if (WIFSTOPPED(status)) {
      sig = WSTOPSIG(status);
      if (opt_verbose)
        printf("WIFSTOPPED %d\n", status);
      if (sig == SIGSTOP) {
        ptrace(PTRACE_CONT, pid, 0, 0);
        continue;
      }
      if (sig == SIGTRAP) {
        traps++;
        if (opt_verbose)
          printf("SIGTRAP count: %d\n", traps);
        switch (traps) {
        case 1:  // execve
          if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0))
            err(2, "PTRACE_SYSCALL");
          continue;
        case 2:  // set breakpoint/watchpoint
          if (ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(0), rwatch))
            err(2, "PTRACE_POKEUSER");
          {
            void* p;
            if (opt_type == CODE)
              p = (void*)0x101;
            else if (opt_type == RWATCH)
              p = (void*)0xf0101;
            if (ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(7), p))
              err(2, "PTRACE_POKEUSER");
          }
          if (ptrace(PTRACE_POKEUSER, pid, DR_OFFSET(6), (void*)0))
            err(2, "PTRACE_POKEUSER");
          if (ptrace(PTRACE_CONT, pid, 0, 0))
            err(2, "PTRACE_CONT");
          continue;
        case 3:  // read flag
          puts("Hit breakpoint/watchpoint");
          kill(pid, 9);
          return 99;
        }
      }
    } else if (WIFSIGNALED(status))
      sig = WTERMSIG(status);
    else
      assert(0);
    if (sig > 0) {
      ptrace(PTRACE_DETACH, pid, 0, 0);
      kill(pid, sig);
    }
  }
}
