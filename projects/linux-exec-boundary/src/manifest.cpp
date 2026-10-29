#include "boundary.hpp"
#include <sstream>

namespace boundary {
namespace {
std::string quoted(const std::string& text) {
  std::string output = "\"";
  constexpr char hex[] = "0123456789abcdef";
  for (unsigned char character : text) {
    if (character == '"' || character == '\\') { output += '\\'; output += static_cast<char>(character); }
    else if (character < 32) { output += "\\u00"; output += hex[character >> 4]; output += hex[character & 15]; }
    else output += static_cast<char>(character);
  }
  return output + '"';
}
std::string hex(const std::string& bytes) {
  constexpr char alphabet[] = "0123456789abcdef";
  std::string result;
  for (unsigned char value : bytes) { result += alphabet[value >> 4]; result += alphabet[value & 15]; }
  return result;
}
std::string capture_json(const Capture& capture) {
  std::ostringstream stream;
  stream << "{\"captured_bytes\":" << capture.bytes.size() << ",\"total_bytes\":" << capture.total
         << ",\"truncated\":" << (capture.total > capture.bytes.size() ? "true" : "false")
         << ",\"eof_observed\":" << (capture.eof ? "true" : "false")
         << ",\"hex\":" << quoted(hex(capture.bytes)) << '}';
  return stream.str();
}
}
int cli_exit(const std::string& state) {
  const std::string states[] = {"COMPLETED", "EXITED_NONZERO", "SIGNALED", "TIMED_OUT", "CANCELLED",
    "LAUNCH_FAILED", "POLICY_UNAVAILABLE", "CONTAINMENT_UNCONFIRMED", "SUPERVISOR_ERROR"};
  for (int index = 0; index < 9; ++index) if (states[index] == state) return index;
  return 8;
}
std::string manifest(const ExecutionRequest& request, const ExecutionResult& result) {
  const bool landlock = (result.setup_flags & landlock_bit) != 0;
  const bool seccomp = (result.setup_flags & seccomp_bit) != 0;
  std::ostringstream stream;
  stream << std::boolalpha;
  stream << "{\"schema\":\"exec-boundary.execution.v1\",\"request\":{\"request_id\":" << quoted(request.request_id)
    << ",\"run_id\":" << quoted(request.run_id) << ",\"approved_executable\":\"$BUILD/boundary_fixture\""
    << ",\"working_directory\":\"owned-scratch\",\"environment\":[\"LANG=C\",\"LC_ALL=C\"]"
    << ",\"argv\":[\"boundary_fixture\"," << quoted(request.scenario) << ']'
    << ",\"scenario\":" << quoted(request.scenario) << ",\"profile\":" << quoted(request.profile)
    << ",\"injected_fault\":" << quoted(request.fault) << ",\"timeout_ms\":" << request.timeout_ms
    << ",\"cancel_after_ms\":" << request.cancel_after_ms << ",\"output_limit\":" << request.output_limit
    << ",\"limits\":{\"cpu_soft\":" << request.cpu_soft << ",\"cpu_hard\":" << request.cpu_hard
    << ",\"address_space\":" << request.address_space << ",\"file_size\":" << request.file_size
    << ",\"open_files\":" << request.open_files << ",\"core_size\":" << request.core_size << "}},"
    << "\"setup\":{\"spawned\":" << result.spawned << ",\"confirmed\":" << result.setup_confirmed
    << ",\"exec_observed\":" << result.exec_observed << ",\"stage\":" << quoted(result.stage)
    << ",\"errno\":" << result.error << "},\"features\":{\"pidfd\":" << result.pidfd
    << ",\"waitid_pidfd\":" << result.pidfd_wait << ",\"group_confirmed\":" << result.group_confirmed
    << ",\"no_new_privs\":" << ((result.setup_flags & nnp_bit) != 0)
    << ",\"limits_setup\":" << ((result.setup_flags & limits_bit) != 0)
    << ",\"landlock\":" << landlock << ",\"landlock_abi\":" << result.landlock_abi
    << ",\"landlock_rights\":[";
  if (landlock) stream << "\"READ_FILE\",\"READ_DIR\",\"WRITE_FILE\",\"MAKE_REG\",\"REMOVE_FILE\",\"TRUNCATE\"";
  stream << "],\"seccomp\":" << seccomp << ",\"cgroup\":false},\"outcome\":{\"state\":" << quoted(result.state)
    << ",\"exit_code\":" << (result.exit_code < 0 ? "null" : std::to_string(result.exit_code))
    << ",\"signal\":" << (result.term_signal == 0 ? "null" : std::to_string(result.term_signal))
    << ",\"wait_code\":" << result.wait_code << ",\"wait_status\":" << result.wait_status
    << ",\"timed_out\":" << result.timed_out << ",\"cancelled\":" << result.cancelled
    << ",\"parent_sigterm\":" << result.parent_sigterm << ",\"elapsed_ms\":" << result.elapsed_ms
    << "},\"termination\":{\"term_attempted\":" << result.term_attempted
    << ",\"kill_attempted\":" << result.kill_attempted << ",\"term_errno\":" << result.term_errno
    << ",\"kill_errno\":" << result.kill_errno << "},\"cleanup\":{\"direct_child_reaped\":" << result.direct_reaped
    << ",\"adopted_reaped\":" << result.adopted_reaped << ",\"complete\":" << result.cleanup_complete
    << ",\"pipes_closed\":" << result.pipes_closed << ",\"artifacts_removed\":" << result.artifacts_removed
    << ",\"owned_fd_delta\":" << result.owned_fd_delta << ",\"group_cleanup_attempted\":" << result.group_cleanup
    << ",\"group_identity_pinned\":" << result.group_pinned << ",\"whole_tree_confirmed\":false},"
    << "\"observed\":{\"child_pid\":" << result.child_pid << ",\"pgid\":" << result.observed.pgid
    << ",\"sid\":" << result.observed.sid << ",\"nnp\":" << result.observed.nnp
    << ",\"seccomp\":" << result.observed.seccomp << ",\"inherited_seccomp\":" << result.inherited_seccomp
    << ",\"inherited_nnp\":" << result.inherited_nnp << ",\"unexpected_fds\":" << result.observed.unexpected_fds
    << ",\"cpu_soft\":" << result.observed.cpu_soft << ",\"cpu_hard\":" << result.observed.cpu_hard
    << ",\"address_space\":" << result.observed.address_space << ",\"file_size\":" << result.observed.file_size
    << ",\"open_files\":" << result.observed.open_files << ",\"core_size\":" << result.observed.core_size
    << ",\"interrupted_calls\":" << result.interrupted_calls
    << ",\"cleanup_interruptions\":" << result.cleanup_interruptions
    << ",\"signal_notifications\":" << result.notifications
    << ",\"cleanup_signal_notifications\":" << result.cleanup_notifications << "},\"output\":{\"stdout\":"
    << capture_json(result.out) << ",\"stderr\":" << capture_json(result.err)
    << "},\"enforcement_profile\":\"direct-child-and-best-effort-process-group\","
    << "\"unsupported\":[\"strict-whole-tree-cgroup\",\"general-purpose-sandbox\"]}";
  return stream.str();
}
}
