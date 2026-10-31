#include "boundary.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace boundary {
namespace {
using Clock = std::chrono::steady_clock;
using Milliseconds = std::chrono::milliseconds;
class Fd {
 public:
  explicit Fd(int value = -1) : value_(value) {}
  ~Fd() { reset(); }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  int get() const { return value_; }
  void reset(int value = -1) {
    if (value_ >= 0) close(value_);
    value_ = value;
  }
 private:
  int value_;
};
struct Pipe {
  Fd read, write;
  bool open() {
    int descriptors[2];
    if (pipe2(descriptors, O_CLOEXEC) != 0) return false;
    read.reset(descriptors[0]);
    write.reset(descriptors[1]);
    return true;
  }
};
int fd_count() {
  DIR* directory = opendir("/proc/self/fd");
  if (directory == nullptr) return -1;
  int count = -1; // Exclude this temporary directory descriptor.
  while (const dirent* item = readdir(directory)) {
    if (item->d_name[0] != '.') ++count;
  }
  closedir(directory);
  return count;
}
int high_copy(int descriptor) { return fcntl(descriptor, F_DUPFD_CLOEXEC, 10); }
bool nonblocking(int descriptor) {
  const int flags = fcntl(descriptor, F_GETFL);
  return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}
void send_wire(int descriptor, const Wire& wire) {
  ssize_t written;
  do { written = write(descriptor, &wire, sizeof(wire)); }
  while (written < 0 && errno == EINTR);
  if (written != static_cast<ssize_t>(sizeof(wire))) _exit(126);
}
[[noreturn]] void child_error(int error) {
  Wire wire;
  wire.kind = 2;
  wire.error = error;
  send_wire(4, wire);
  _exit(127);
}
bool limit(int resource, std::uint64_t soft, std::uint64_t hard) {
  const rlimit value{static_cast<rlim_t>(soft), static_cast<rlim_t>(hard)};
  return setrlimit(resource, &value) == 0;
}
bool landlock_rule(int ruleset, const char* path, std::uint64_t rights) {
  const int descriptor = open(path, O_PATH | O_CLOEXEC);
  if (descriptor < 0) return errno == ENOENT;
  landlock_path_beneath_attr rule{};
  rule.allowed_access = rights;
  rule.parent_fd = descriptor;
  const bool ok = syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH,
                          &rule, 0) == 0;
  const int error = errno;
  close(descriptor);
  errno = error;
  return ok;
}
bool restrict_filesystem() {
  constexpr std::uint64_t read = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
  constexpr std::uint64_t rights = read | LANDLOCK_ACCESS_FS_WRITE_FILE |
      LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE;
  landlock_ruleset_attr attributes{};
  attributes.handled_access_fs = rights;
  const int rules = static_cast<int>(syscall(SYS_landlock_create_ruleset,
                                            &attributes, sizeof(attributes), 0));
  if (rules < 0) return false;
  bool ok = true;
  landlock_path_beneath_attr executable{};
  executable.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  executable.parent_fd = 3; // The exact already-open executable, not a later path lookup.
  ok = syscall(SYS_landlock_add_rule, rules, LANDLOCK_RULE_PATH_BENEATH, &executable, 0) == 0;
  for (const char* path : {"/usr", "/lib", "/lib64"})
    ok = ok && landlock_rule(rules, path, read);
  ok = ok && landlock_rule(rules, "/etc/ld.so.cache", LANDLOCK_ACCESS_FS_READ_FILE);
  ok = ok && landlock_rule(rules, "allowed", rights);
  if (ok) ok = syscall(SYS_landlock_restrict_self, rules, 0) == 0;
  const int error = errno;
  close(rules);
  errno = error;
  return ok;
}
bool restrict_syscall() {
#if defined(__x86_64__)
  constexpr unsigned architecture = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
  constexpr unsigned architecture = AUDIT_ARCH_AARCH64;
#else
  errno = ENOTSUP;
  return false;
#endif
#if defined(__x86_64__) || defined(__aarch64__)
  sock_filter instructions[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, architecture, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
  sock_fprog program{7, instructions};
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0;
#endif
}
void capture(int descriptor, Capture& output, std::size_t maximum) {
  std::array<char, 4096> bytes{};
  // A finite read budget prevents a busy writer from starving deadline checks.
  for (int pass = 0; pass < 16; ++pass) {
    const ssize_t count = read(descriptor, bytes.data(), bytes.size());
    if (count > 0) {
      const auto size = static_cast<std::size_t>(count);
      output.total += size;
      output.bytes.append(bytes.data(), std::min(size, maximum - output.bytes.size()));
    } else if (count == 0) { output.eof = true; return; }
    else if (errno == EINTR) continue;
    else if (errno == EAGAIN || errno == EWOULDBLOCK) return;
    else { output.eof = true; return; }
  }
}
bool valid_id(const std::string& value) {
  return !value.empty() && value.size() <= 64 &&
      std::all_of(value.begin(), value.end(), [](unsigned char item) {
        return (item >= 'a' && item <= 'z') || (item >= 'A' && item <= 'Z') ||
               (item >= '0' && item <= '9') || item == '-' || item == '_';
      });
}
bool valid(const ExecutionRequest& request) {
  return valid_id(request.request_id) && valid_id(request.run_id) &&
      request.timeout_ms >= 1 && request.timeout_ms <= 3000 &&
      request.cancel_after_ms >= -1 && request.cancel_after_ms <= 3000 &&
      request.output_limit <= 16384 && request.open_files >= 16 && request.open_files <= 64 &&
      request.core_size == 0 && request.cpu_soft == 1 && request.cpu_hard == 2 &&
      request.address_space >= 32 * 1024 * 1024 && request.address_space <= 256 * 1024 * 1024 &&
      request.file_size <= 1024 * 1024 && request.arguments.size() == 2 &&
      request.arguments[0] == "boundary_fixture" && request.arguments[1] == request.scenario &&
      request.environment == std::vector<std::string>{"LANG=C", "LC_ALL=C"};
}
}

ExecutionResult execute(const ExecutionRequest& request, ControlSignals* signals) {
  ExecutionResult result;
  result.inherited_seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
  result.inherited_nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
  const int initial_fds = fd_count();
  const auto started = Clock::now();
  const auto deadline = started + Milliseconds(request.timeout_ms);
  auto finish = [&] {
    if (signals != nullptr) {
      result.notifications = signals->notifications;
      result.cleanup_notifications = signals->cleanup_notifications;
      signals->cleanup_active = 0;
    }
    result.elapsed_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<Milliseconds>(Clock::now() - started).count());
    const int final_fds = fd_count();
    result.owned_fd_delta = initial_fds >= 0 && final_fds >= 0 ? final_fds - initial_fds : -1;
    if (result.owned_fd_delta != 0) {
      result.state = "SUPERVISOR_ERROR";
      result.stage = "descriptor_accounting";
    }
    return result;
  };
  if (!valid(request) || geteuid() == 0) { result.error = EINVAL; return finish(); }
  struct sigaction child_action{};
  siginfo_t existing_child{};
  errno = 0;
  const bool no_existing_children =
      waitid(P_ALL, 0, &existing_child, WEXITED | WNOHANG | WNOWAIT) < 0 && errno == ECHILD;
  if (sigaction(SIGCHLD, nullptr, &child_action) != 0 || child_action.sa_handler == SIG_IGN ||
      (child_action.sa_flags & SA_NOCLDWAIT) != 0 || !no_existing_children) {
    result.stage = "exclusive_child_ownership_required";
    result.error = EBUSY;
    return finish();
  }
  if (request.profile == "strict-tree" || request.fault == "landlock_unavailable") {
    result.state = "POLICY_UNAVAILABLE";
    result.stage = request.profile == "strict-tree" ? "no_delegated_cgroup_backend" : "landlock_unavailable_injected";
    result.cleanup_complete = true;
    result.pipes_closed = true;
    return finish();
  }
  if (request.profile != "direct" && request.profile != "landlock" && request.profile != "seccomp") {
    result.state = "POLICY_UNAVAILABLE";
    result.stage = "unsupported_profile";
    result.cleanup_complete = true;
    result.pipes_closed = true;
    return finish();
  }
  result.landlock_abi = static_cast<int>(syscall(SYS_landlock_create_ruleset, nullptr, 0,
                                               LANDLOCK_CREATE_RULESET_VERSION));
  if (result.landlock_abi < 0) result.landlock_abi = 0;
  if (request.profile == "landlock" && result.landlock_abi < 3) {
    result.state = "POLICY_UNAVAILABLE";
    result.stage = "landlock_abi_requires_3";
    result.cleanup_complete = true;
    result.pipes_closed = true;
    return finish();
  }
  int old_subreaper = 0;
  if (prctl(PR_GET_CHILD_SUBREAPER, &old_subreaper) != 0 || old_subreaper != 0 ||
      prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) {
    result.stage = "exclusive_subreaper_required";
    result.error = errno;
    return finish();
  }
  {
    Pipe output, errors, status, gate;
    Fd executable(open(request.approved_executable.c_str(), O_PATH | O_CLOEXEC));
    Fd null_input(open("/dev/null", O_RDONLY | O_CLOEXEC));
    if (executable.get() < 0 || null_input.get() < 0 || !output.open() || !errors.open() ||
        !status.open() || !gate.open()) {
      result.error = errno;
      result.stage = "parent_descriptors";
    } else {
      Fd exec_copy(high_copy(executable.get())), error_copy(high_copy(status.write.get())),
          gate_copy(high_copy(gate.read.get())), stdout_copy(high_copy(output.write.get())),
          stderr_copy(high_copy(errors.write.get())), stdin_copy(high_copy(null_input.get()));
      const bool copies = exec_copy.get() >= 0 && error_copy.get() >= 0 && gate_copy.get() >= 0 &&
          stdout_copy.get() >= 0 && stderr_copy.get() >= 0 && stdin_copy.get() >= 0;
      if (!copies || !nonblocking(output.read.get()) || !nonblocking(errors.read.get()) ||
          !nonblocking(status.read.get())) {
        result.error = errno;
        result.stage = "parent_pipe_setup";
      } else {
        std::array<char*, 3> argv{const_cast<char*>(request.arguments[0].c_str()),
                                  const_cast<char*>(request.arguments[1].c_str()), nullptr};
        std::array<char*, 3> environment{const_cast<char*>(request.environment[0].c_str()),
                                         const_cast<char*>(request.environment[1].c_str()), nullptr};
        const bool fail_early = request.fault == "exit_before_pidfd";
        const bool fail_seccomp = request.fault == "seccomp_setup";
        const bool leak_fd = request.fault == "inherit_fd";
        const bool fail_exec = request.fault == "exec";
        const pid_t child = fork();
        if (child == 0) {
          if (fail_early) _exit(0);
          if (dup3(exec_copy.get(), 3, O_CLOEXEC) < 0 ||
              dup3(error_copy.get(), 4, O_CLOEXEC) < 0 ||
              dup3(gate_copy.get(), 5, O_CLOEXEC) < 0 ||
              dup2(error_copy.get(), 6) < 0 || dup2(stdout_copy.get(), 1) < 0 ||
              dup2(stderr_copy.get(), 2) < 0 || dup2(stdin_copy.get(), 0) < 0) _exit(126);
          if (leak_fd && dup2(stdin_copy.get(), 9) < 0) child_error(errno);
          if (syscall(SYS_close_range, leak_fd ? 10U : 7U, UINT_MAX, 0) != 0) child_error(errno);
          if (leak_fd) { close(7); close(8); }
          signal(SIGPIPE, SIG_DFL);
          signal(SIGTERM, SIG_DFL);
          signal(SIGUSR1, SIG_DFL);
          if (setsid() != getpid()) child_error(errno);
          char allowed = 0;
          ssize_t count;
          do { count = read(5, &allowed, 1); } while (count < 0 && errno == EINTR);
          close(5);
          if (count != 1 || allowed != 'G') child_error(ECANCELED);
          Wire confirmed;
          confirmed.kind = 1;
          if (chdir(request.working_directory.c_str()) != 0) child_error(errno);
          confirmed.flags |= group_bit;
          if (!limit(RLIMIT_CPU, request.cpu_soft, request.cpu_hard) ||
              !limit(RLIMIT_AS, request.address_space, request.address_space) ||
              !limit(RLIMIT_FSIZE, request.file_size, request.file_size) ||
              !limit(RLIMIT_NOFILE, request.open_files, request.open_files) ||
              !limit(RLIMIT_CORE, 0, 0)) child_error(errno);
          confirmed.flags |= limits_bit;
          if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) child_error(errno);
          confirmed.flags |= nnp_bit;
          if (request.profile == "landlock") {
            if (!restrict_filesystem()) child_error(errno);
            confirmed.flags |= landlock_bit;
          }
          if (fail_seccomp) {
            sock_fprog invalid{0, nullptr};
            const int applied = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &invalid);
            child_error(applied < 0 ? errno : EPROTO);
          }
          if (request.profile == "seccomp") {
            if (!restrict_syscall()) child_error(errno);
            confirmed.flags |= seccomp_bit;
          }
          send_wire(4, confirmed);
          if (fail_exec) syscall(SYS_execveat, -1, "", argv.data(), environment.data(), AT_EMPTY_PATH);
          else syscall(SYS_execveat, 3, "", argv.data(), environment.data(), AT_EMPTY_PATH);
          child_error(errno);
        }
        if (child < 0) { result.stage = "fork"; result.error = errno; }
        else {
          result.spawned = true;
          result.child_pid = child;
          result.stage = "spawned";
          output.write.reset(); errors.write.reset(); status.write.reset(); gate.read.reset();
          exec_copy.reset(); error_copy.reset(); gate_copy.reset(); stdout_copy.reset();
          stderr_copy.reset(); stdin_copy.reset(); executable.reset(); null_input.reset();
          if (fail_early) {
            siginfo_t info{};
            int code;
            do { code = waitid(P_PID, static_cast<id_t>(child), &info, WEXITED | WNOWAIT); }
            while (code < 0 && errno == EINTR);
          }
          Fd pidfd(request.fault == "pidfd" ? -1 : static_cast<int>(syscall(SYS_pidfd_open, child, 0)));
          if (pidfd.get() < 0) {
            result.state = "LAUNCH_FAILED";
            result.stage = "pidfd_acquisition";
            result.error = request.fault == "pidfd" ? EMFILE : errno;
            // Still our unreaped direct child: its numeric PID cannot have been reused.
            if (kill(child, SIGKILL) == 0 || errno == ESRCH) result.kill_attempted = true;
            int status_value = 0;
            const auto recovery_deadline = Clock::now() + Milliseconds(300);
            while (Clock::now() < recovery_deadline) {
              const pid_t waited = waitpid(child, &status_value, WNOHANG);
              if (waited == child) { result.direct_reaped = true; break; }
              if (waited < 0 && errno != EINTR) break;
              poll(nullptr, 0, 2);
            }
            result.cleanup_complete = result.direct_reaped;
            if (!result.cleanup_complete) result.state = "CONTAINMENT_UNCONFIRMED";
          } else {
            result.pidfd = true;
            const auto group_deadline = std::min(deadline, Clock::now() + Milliseconds(100));
            while (!fail_early && Clock::now() < group_deadline) {
              if (getpgid(child) == child && getsid(child) == child) {
                result.group_confirmed = true;
                break;
              }
              pollfd exited{pidfd.get(), POLLIN, 0};
              if (poll(&exited, 1, 1) > 0) break;
            }
            if (!fail_early && !result.group_confirmed && Clock::now() >= deadline)
              result.timed_out = true;
            if (result.group_confirmed && !fail_early) {
              const char go = 'G';
              if (write(gate.write.get(), &go, 1) != 1) result.error = errno;
            }
            gate.write.reset();
            bool leader_done = false, status_eof = false, stop = false;
            bool status_error = false;
            std::array<char, sizeof(Wire)> buffer{};
            std::size_t buffered = 0;
            auto stop_time = Clock::time_point::max();
            siginfo_t final_info{};
            while (true) {
              capture(output.read.get(), result.out, request.output_limit);
              capture(errors.read.get(), result.err, request.output_limit);
              for (int pass = 0; pass < 4 && !status_eof; ++pass) {
                const ssize_t count = read(status.read.get(), buffer.data() + buffered, buffer.size() - buffered);
                if (count > 0) {
                  buffered += static_cast<std::size_t>(count);
                  if (buffered == sizeof(Wire)) {
                    Wire wire;
                    std::memcpy(&wire, buffer.data(), sizeof(wire));
                    buffered = 0;
                    if (wire.magic != wire_magic) status_error = true;
                    else if (wire.kind == 1) { result.setup_confirmed = true; result.setup_flags = wire.flags; }
                    else if (wire.kind == 2) { result.error = wire.error; status_error = true; }
                    else if (wire.kind == 3 && wire.pid == child) {
                      result.exec_observed = true;
                      result.observed = wire;
                      if (wire.unexpected_fds != 0) result.containment_unconfirmed = true;
                    } else status_error = true;
                  }
                } else if (count == 0) { status_eof = true; if (buffered != 0) status_error = true; }
                else if (errno == EINTR) { ++result.interrupted_calls; }
                else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                else { status_eof = true; status_error = true; }
              }
              siginfo_t info{};
              const int waited = waitid(P_PIDFD, static_cast<id_t>(pidfd.get()), &info, WEXITED | WNOHANG | WNOWAIT);
              if (waited == 0) result.pidfd_wait = true;
              if (waited == 0 && info.si_pid == child) { leader_done = true; final_info = info; }
              else if (waited < 0 && errno == EINTR) ++result.interrupted_calls;
              else if (waited < 0) { status_error = true; result.error = errno; }
              const auto now = Clock::now();
              if (!stop && (leader_done || now >= deadline ||
                  (signals != nullptr && signals->cancellation != 0) ||
                  (request.cancel_after_ms >= 0 && now - started >= Milliseconds(request.cancel_after_ms)) ||
                  status_error || result.containment_unconfirmed || !result.group_confirmed)) {
                stop = true;
                stop_time = now;
                if (signals != nullptr) signals->cleanup_active = 1;
                if (!leader_done && now >= deadline) result.timed_out = true;
                else if (!leader_done && ((signals != nullptr && signals->cancellation != 0) ||
                    (request.cancel_after_ms >= 0 && now - started >= Milliseconds(request.cancel_after_ms)))) result.cancelled = true;
                result.parent_sigterm = signals != nullptr && signals->cancellation == SIGTERM;
                const bool bound_group = result.group_confirmed && child > 1 &&
                    child != getpgrp() && getpgid(child) == child && getsid(child) == child;
                if (bound_group) {
                  result.group_pinned = true;
                  result.group_cleanup = true;
                  result.term_attempted = true;
                  if (kill(-child, SIGTERM) != 0 && errno != ESRCH) result.term_errno = errno;
                } else {
                  if (result.group_confirmed) result.containment_unconfirmed = true;
                  result.term_attempted = true;
                  if (syscall(SYS_pidfd_send_signal, pidfd.get(), SIGTERM, nullptr, 0) != 0 && errno != ESRCH) result.term_errno = errno;
                }
              }
              if (stop && !result.kill_attempted && now - stop_time >= Milliseconds(30)) {
                result.kill_attempted = true;
                if (result.group_pinned) {
                  if (kill(-child, SIGKILL) != 0 && errno != ESRCH) result.kill_errno = errno;
                } else if (syscall(SYS_pidfd_send_signal, pidfd.get(), SIGKILL, nullptr, 0) != 0 && errno != ESRCH) result.kill_errno = errno;
              }
              if (stop && leader_done && result.kill_attempted && result.out.eof && result.err.eof && status_eof) break;
              if (stop && now - stop_time >= Milliseconds(300)) {
                result.containment_unconfirmed = true;
                break;
              }
              pollfd poll_descriptors[] = {
                  {result.out.eof ? -1 : output.read.get(), POLLIN, 0},
                  {result.err.eof ? -1 : errors.read.get(), POLLIN, 0},
                  {status_eof ? -1 : status.read.get(), POLLIN, 0},
                  {leader_done ? -1 : pidfd.get(), POLLIN, 0}};
              if (poll(poll_descriptors, 4, 3) < 0 && errno == EINTR) {
                ++result.interrupted_calls;
                if (stop) ++result.cleanup_interruptions;
              }
            }
            if (!leader_done) {
              syscall(SYS_pidfd_send_signal, pidfd.get(), SIGKILL, nullptr, 0);
              // WNOHANG below bounds reaping observation even for an uninterruptible task.
            }
            if (leader_done) {
              result.wait_code = final_info.si_code;
              result.wait_status = final_info.si_status;
              if (final_info.si_code == CLD_EXITED) result.exit_code = final_info.si_status;
              else result.term_signal = final_info.si_status;
            }
            const auto reap_deadline = Clock::now() + Milliseconds(300);
            while (Clock::now() < reap_deadline) {
              int child_status = 0;
              const pid_t reaped = waitpid(-1, &child_status, WNOHANG);
              if (reaped == child) result.direct_reaped = true;
              else if (reaped > 0) ++result.adopted_reaped;
              else if (reaped < 0 && errno == EINTR) {
                ++result.interrupted_calls;
                ++result.cleanup_interruptions;
                continue;
              }
              else if (reaped < 0 && errno == ECHILD) { result.cleanup_complete = result.direct_reaped; break; }
              else poll(nullptr, 0, 2);
            }
            capture(output.read.get(), result.out, request.output_limit);
            capture(errors.read.get(), result.err, request.output_limit);
            if (!result.cleanup_complete) result.containment_unconfirmed = true;
            if (result.containment_unconfirmed) result.state = "CONTAINMENT_UNCONFIRMED";
            else if (result.timed_out) result.state = "TIMED_OUT";
            else if (result.cancelled) result.state = "CANCELLED";
            else if (status_error) result.state = "LAUNCH_FAILED";
            else if (!result.setup_confirmed || !result.exec_observed) result.state = "LAUNCH_FAILED";
            else if (result.term_signal != 0) result.state = "SIGNALED";
            else if (result.exit_code != 0) result.state = "EXITED_NONZERO";
            else result.state = "COMPLETED";
            result.stage = result.exec_observed ? "fixture_observed_after_exec" : "before_fixture_witness";
          }
        }
      }
    }
  }
  result.pipes_closed = true;
  if (prctl(PR_SET_CHILD_SUBREAPER, old_subreaper) != 0) {
    result.state = "SUPERVISOR_ERROR";
    result.stage = "restore_subreaper";
    result.error = errno;
  }
  return finish();
}
}
