#pragma once
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace boundary {
inline constexpr std::uint32_t wire_magic = 0x424e4431;
inline constexpr unsigned group_bit = 1, limits_bit = 2, nnp_bit = 4,
                          landlock_bit = 8, seccomp_bit = 16;
struct Wire {
  std::uint32_t magic = wire_magic;
  std::uint32_t kind = 0;
  std::uint32_t flags = 0;
  int error = 0;
  int pid = 0;
  int pgid = 0, sid = 0;
  int unexpected_fds = 0;
  int nnp = 0;
  int seccomp = 0;
  std::uint64_t cpu_soft = 0, cpu_hard = 0, address_space = 0,
                file_size = 0, open_files = 0, core_size = 0;
};
struct ExecutionRequest {
  std::string request_id;
  std::string run_id;
  std::filesystem::path approved_executable;
  std::filesystem::path working_directory;
  std::vector<std::string> arguments;
  std::vector<std::string> environment{"LANG=C", "LC_ALL=C"};
  std::string scenario = "normal";
  std::string profile = "direct";
  std::string fault = "none";
  int timeout_ms = 300;
  int cancel_after_ms = -1;
  std::size_t output_limit = 256;
  std::uint64_t cpu_soft = 1, cpu_hard = 2;
  std::uint64_t address_space = 128 * 1024 * 1024;
  std::uint64_t file_size = 4096, open_files = 32, core_size = 0;
};
struct Capture {
  std::string bytes;
  std::uint64_t total = 0;
  bool eof = false;
};
struct ControlSignals {
  volatile sig_atomic_t cancellation = 0;
  volatile sig_atomic_t notifications = 0;
  volatile sig_atomic_t cleanup_active = 0;
  volatile sig_atomic_t cleanup_notifications = 0;
};
struct ExecutionResult {
  std::string state = "SUPERVISOR_ERROR";
  std::string stage = "validation";
  int error = 0;
  bool spawned = false, pidfd = false, pidfd_wait = false;
  bool setup_confirmed = false, exec_observed = false;
  unsigned setup_flags = 0;
  int landlock_abi = 0;
  int inherited_seccomp = 0, inherited_nnp = 0;
  bool group_confirmed = false, group_cleanup = false, group_pinned = false;
  bool direct_reaped = false, cleanup_complete = false, pipes_closed = false;
  bool artifacts_removed = false, containment_unconfirmed = false;
  int adopted_reaped = 0, owned_fd_delta = 0, interrupted_calls = 0;
  int cleanup_interruptions = 0;
  int notifications = 0, cleanup_notifications = 0;
  int child_pid = 0, wait_code = 0, wait_status = 0;
  int exit_code = -1, term_signal = 0;
  bool timed_out = false, cancelled = false, parent_sigterm = false;
  bool term_attempted = false, kill_attempted = false;
  int term_errno = 0, kill_errno = 0;
  std::uint64_t elapsed_ms = 0;
  Wire observed{};
  Capture out, err;
};
ExecutionResult execute(const ExecutionRequest&, ControlSignals* signals);
std::string manifest(const ExecutionRequest&, const ExecutionResult&);
int cli_exit(const std::string& state);
}
