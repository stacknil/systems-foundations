#include "boundary.hpp"
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <dirent.h>
#include <iostream>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
int count_fds() {
  DIR* directory = opendir("/proc/self/fd");
  if (directory == nullptr) return -1;
  int count = -1;
  while (const dirent* entry = readdir(directory)) {
    if (entry->d_name[0] != '.') ++count;
  }
  closedir(directory);
  return count;
}
void interrupted(int) {}
bool interrupted_wait() {
  struct sigaction action{};
  action.sa_handler = interrupted;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGALRM, &action, nullptr) != 0) return false;
  const pid_t child = fork();
  if (child == 0) { alarm(2); usleep(50000); _exit(0); }
  if (child < 0) return false;
  const int descriptor = static_cast<int>(syscall(SYS_pidfd_open, child, 0));
  if (descriptor < 0) { int status; waitpid(child, &status, 0); return false; }
  itimerval timer{};
  timer.it_value.tv_usec = 5000;
  if (setitimer(ITIMER_REAL, &timer, nullptr) != 0) return false;
  siginfo_t info{};
  const int first = waitid(P_PIDFD, static_cast<id_t>(descriptor), &info, WEXITED);
  const bool received_eintr = first < 0 && errno == EINTR;
  timer = {};
  setitimer(ITIMER_REAL, &timer, nullptr);
  int waited = first;
  if (received_eintr) {
    do { waited = waitid(P_PIDFD, static_cast<id_t>(descriptor), &info, WEXITED); }
    while (waited < 0 && errno == EINTR);
  }
  close(descriptor);
  return received_eintr && waited == 0 && info.si_pid == child && info.si_status == 0;
}
}
int main() {
  if (geteuid() == 0) return 2;
  signal(SIGPIPE, SIG_IGN);
  if (!interrupted_wait()) return 1;
  const int before = count_fds();
  const int before_nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
  const int before_seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
  rlimit before_limits{};
  if (getrlimit(RLIMIT_NOFILE, &before_limits) != 0) return 2;
  for (int iteration = 0; iteration < 12; ++iteration) {
    boundary::ExecutionRequest request;
    request.approved_executable = APPROVED_FIXTURE_PATH;
    request.scenario = iteration % 2 == 0 ? "normal" : "partial";
    request.arguments = {"boundary_fixture", request.scenario};
    request.request_id = "repeat";
    request.run_id = "repeat-" + std::to_string(iteration);
    std::string scratch = (std::filesystem::temp_directory_path() / "exec-lifecycle-XXXXXX").string();
    if (mkdtemp(scratch.data()) == nullptr) return 2;
    request.working_directory = scratch;
    const auto result = boundary::execute(request, nullptr);
    std::filesystem::remove_all(request.working_directory);
    std::filesystem::remove_all(request.working_directory); // Owned artifact cleanup is idempotent.
    if (result.state != "COMPLETED" || result.exit_code != 0 || !result.direct_reaped ||
        !result.cleanup_complete || result.owned_fd_delta != 0 || count_fds() != before) return 1;
    int status = 0;
    errno = 0;
    if (waitpid(-1, &status, WNOHANG) != -1 || errno != ECHILD) return 1;
  }
  rlimit after_limits{};
  if (getrlimit(RLIMIT_NOFILE, &after_limits) != 0 ||
      before_limits.rlim_cur != after_limits.rlim_cur ||
      before_limits.rlim_max != after_limits.rlim_max ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != before_nnp ||
      prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != before_seccomp) return 1;
  const pid_t other_child = fork();
  if (other_child == 0) { alarm(2); usleep(10000); _exit(0); }
  if (other_child < 0) return 2;
  boundary::ExecutionRequest refused;
  refused.request_id = "ownership-control";
  refused.run_id = "ownership-control";
  refused.approved_executable = APPROVED_FIXTURE_PATH;
  refused.working_directory = std::filesystem::temp_directory_path();
  refused.arguments = {"boundary_fixture", "normal"};
  const auto rejected = boundary::execute(refused, nullptr);
  int status = 0;
  while (waitpid(other_child, &status, 0) < 0 && errno == EINTR) {}
  if (rejected.state != "SUPERVISOR_ERROR" || rejected.spawned ||
      rejected.stage != "exclusive_child_ownership_required") return 1;
  std::cout << "12 repeated runs; stable FD census; ECHILD; parent policy unchanged; "
               "native waitid EINTR retried; unrelated-child ownership refused\n";
  return 0;
}
