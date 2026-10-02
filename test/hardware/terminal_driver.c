// POSIX pseudo-terminal fixture. Sends synthetic input only; no device access.
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <util.h>
#else
#include <pty.h>
#endif
int main(int argc, char **argv) {
  if (argc != 4)
    return 2;
  int master;
  pid_t child = forkpty(&master, NULL, NULL, NULL);
  if (child < 0)
    return 3;
  if (child == 0) {
    execl(argv[1], argv[1], argv[2], argv[3], (char *)NULL);
    _exit(4);
  }
  char output[16384] = {0};
  size_t used = 0;
  int sent = 0, finished = 0;
  for (int n = 0; n < 200 && !finished; ++n) {
    struct pollfd fd = {.fd = master, .events = POLLIN};
    int ready = poll(&fd, 1, 100);
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready < 0)
      break;
    if (!ready)
      continue;
    char buffer[1024];
    ssize_t count = read(master, buffer, sizeof(buffer));
    if (count <= 0) {
      finished = 1;
      break;
    }
    if (used + (size_t)count >= sizeof(output))
      break;
    memcpy(output + used, buffer, count);
    used += count;
    output[used] = 0;
    fwrite(buffer, 1, count, stdout);
    if (!sent && strstr(output, "SYNTHETIC_READY") &&
        strcmp(argv[3], "input") == 0) {
      const char input[] = "synthetic-test-pin\n";
      if (write(master, input, sizeof(input) - 1) != sizeof(input) - 1)
        break;
      sent = 1;
    }
  }
  if (!finished)
    kill(child, SIGKILL);
  close(master);
  int status;
  if (waitpid(child, &status, 0) < 0)
    return 5;
  return finished && WIFEXITED(status) ? WEXITSTATUS(status) : 124;
}
