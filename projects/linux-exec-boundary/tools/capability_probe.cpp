#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
template <class Function> bool child_test(Function function) {
  const pid_t child = fork();
  if (child == 0) {
    alarm(3);
    _exit(function() ? 0 : 1);
  }
  if (child < 0) return false;
  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) return false;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
const char* status(bool available) {
  return available ? "SUPPORTED_AND_TESTED" : "UNAVAILABLE";
}
}

int main() {
  if (geteuid() == 0) return 2;
  utsname kernel{};
  if (uname(&kernel) != 0) return 2;
  bool pidfd = false;
  bool pidfd_wait = false;
  const pid_t child = fork();
  if (child == 0) _exit(0);
  if (child < 0) return 2;
  const int descriptor = static_cast<int>(syscall(SYS_pidfd_open, child, 0));
  if (descriptor >= 0) {
    pidfd = syscall(SYS_pidfd_send_signal, descriptor, 0, nullptr, 0) == 0;
    siginfo_t info{};
    int result;
    do {
      result = waitid(P_PIDFD, static_cast<id_t>(descriptor), &info,
                      WEXITED | WNOWAIT);
    } while (result < 0 && errno == EINTR);
    pidfd_wait = result == 0 && info.si_pid == child && info.si_code == CLD_EXITED;
    close(descriptor);
  }
  int wait_status = 0;
  while (waitpid(child, &wait_status, 0) < 0 && errno == EINTR) {}
  const bool nnp = child_test([] {
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
           prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1;
  });
  const bool seccomp = child_test([] {
    sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    sock_fprog program{4, instructions};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) return false;
    errno = 0;
    return syscall(SYS_getppid) == -1 && errno == EPERM && getpid() > 0;
  });
  errno = 0;
  const int abi = static_cast<int>(syscall(SYS_landlock_create_ruleset, nullptr, 0,
                                          LANDLOCK_CREATE_RULESET_VERSION));
  const int landlock_errno = abi < 0 ? errno : 0;
  char directory[] = "/tmp/exec-boundary-probe-XXXXXX";
  if (mkdtemp(directory) == nullptr) return 2;
  const std::filesystem::path scratch(directory);
  std::ofstream(scratch / "allowed") << "synthetic";
  std::ofstream(scratch / "denied") << "synthetic";
  const bool landlock = abi > 0 && child_test([&] {
    landlock_ruleset_attr attributes{};
    attributes.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    const int rules = static_cast<int>(syscall(SYS_landlock_create_ruleset,
                                               &attributes, sizeof(attributes), 0));
    if (rules < 0) return false;
    const int file = open((scratch / "allowed").c_str(), O_PATH | O_CLOEXEC);
    if (file < 0) { close(rules); return false; }
    landlock_path_beneath_attr rule{};
    rule.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
    rule.parent_fd = file;
    bool ok = syscall(SYS_landlock_add_rule, rules, LANDLOCK_RULE_PATH_BENEATH,
                      &rule, 0) == 0 &&
              prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
              syscall(SYS_landlock_restrict_self, rules, 0) == 0;
    close(file);
    close(rules);
    if (!ok) return false;
    const int allowed = open((scratch / "allowed").c_str(), O_RDONLY | O_CLOEXEC);
    if (allowed < 0) return false;
    close(allowed);
    errno = 0;
    const int denied = open((scratch / "denied").c_str(), O_RDONLY | O_CLOEXEC);
    const bool rejected = denied < 0 && errno == EACCES;
    if (denied >= 0) close(denied);
    return rejected;
  });
  std::filesystem::remove_all(scratch);
  const bool limits = child_test([] {
    const int resources[] = {RLIMIT_CPU, RLIMIT_AS, RLIMIT_FSIZE, RLIMIT_NOFILE, RLIMIT_CORE};
    const rlim_t values[] = {2, 256 * 1024 * 1024, 1024 * 1024, 64, 0};
    for (unsigned index = 0; index < 5; ++index) {
      const rlimit limit{values[index], values[index]};
      rlimit observed{};
      if (setrlimit(resources[index], &limit) != 0 ||
          getrlimit(resources[index], &observed) != 0 ||
          observed.rlim_cur != limit.rlim_cur || observed.rlim_max != limit.rlim_max)
        return false;
    }
    return true;
  });
  std::string own_group;
  std::ifstream group_stream("/proc/self/cgroup");
  std::string line;
  while (std::getline(group_stream, line)) {
    if (line.starts_with("0::")) own_group = line.substr(3);
  }
  const bool cgroup_present = std::filesystem::exists("/sys/fs/cgroup/cgroup.controllers");
  bool writable = false;
  int delegation_errno = EACCES;
  if (cgroup_present && !own_group.empty() && own_group != "/" &&
      own_group.find("..") == std::string::npos) {
    const auto current = std::filesystem::path("/sys/fs/cgroup") / own_group.substr(1);
    const auto test_group = current / ("exec-boundary-probe-" + std::to_string(getpid()));
    if (mkdir(test_group.c_str(), 0700) == 0) {
      writable = access((test_group / "cgroup.procs").c_str(), W_OK) == 0;
      delegation_errno = writable ? 0 : errno;
      if (rmdir(test_group.c_str()) != 0) return 2;
    } else delegation_errno = errno;
  }
  std::cout << "{\"schema\":\"exec-boundary.capabilities.v1\",\"kernel\":\""
            << kernel.release << "\",\"architecture\":\"" << kernel.machine
            << "\",\"non_root\":true,\"pidfd\":\"" << status(pidfd)
            << "\",\"waitid_pidfd\":\"" << status(pidfd_wait)
            << "\",\"no_new_privs\":\"" << status(nnp)
            << "\",\"seccomp\":\"" << status(seccomp)
            << "\",\"landlock\":\"" << status(landlock)
            << "\",\"landlock_abi\":" << (abi > 0 ? abi : 0)
            << ",\"landlock_probe_errno\":" << landlock_errno
            << ",\"resource_limits\":\"" << status(limits)
            << "\",\"cgroup_v2_present\":" << (cgroup_present ? "true" : "false")
            << ",\"cgroup_delegation\":\""
            << (writable ? "SUPPORTED_NOT_TESTED" : "UNAVAILABLE")
            << "\",\"cgroup_delegation_errno\":" << delegation_errno
            << ",\"cgroup_membership_and_kill\":\"NOT_PROBED\"}\n";
  return pidfd && pidfd_wait && nnp && limits ? 0 : 1;
}
