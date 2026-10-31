#include "boundary.hpp"
#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string_view>
#include <unistd.h>

namespace {
boundary::ControlSignals signals;
void on_signal(int signal) {
  if (signal == SIGUSR1) {
    signals.notifications = signals.notifications + 1;
    if (signals.cleanup_active) signals.cleanup_notifications = signals.cleanup_notifications + 1;
  } else signals.cancellation = signal;
}
bool integer(std::string_view text, int& value) {
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
  return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}
bool member(const std::string& item, std::initializer_list<const char*> values) {
  return std::any_of(values.begin(), values.end(), [&](const char* value) { return item == value; });
}
}
int main(int argc, char** argv) {
  boundary::ExecutionRequest request;
  request.request_id = "synthetic-request";
  request.run_id = "synthetic-run";
  request.approved_executable = APPROVED_FIXTURE_PATH;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 == argc) { std::cerr << "expected option/value pairs\n"; return 8; }
    const std::string key(argv[index]), value(argv[index + 1]);
    if (key == "--scenario") request.scenario = value;
    else if (key == "--profile") request.profile = value;
    else if (key == "--fault") request.fault = value;
    else if (key == "--request-id") request.request_id = value;
    else if (key == "--run-id") request.run_id = value;
    else if (key == "--timeout-ms") { if (!integer(value, request.timeout_ms)) return 8; }
    else if (key == "--cancel-after-ms") { if (!integer(value, request.cancel_after_ms)) return 8; }
    else if (key == "--output-limit") {
      int limit = 0;
      if (!integer(value, limit) || limit < 0) return 8;
      request.output_limit = static_cast<std::size_t>(limit);
    } else { std::cerr << "unknown option\n"; return 8; }
  }
  if (!member(request.scenario, {"normal", "immediate", "nonzero", "signal", "abnormal", "sleep", "short",
      "ignore-term", "partial", "close-stdout", "broken-pipe", "flood", "cpu", "memory", "fsize",
      "nofile", "artifact-failure", "tree", "orphan", "seccomp", "landlock"}) ||
      !member(request.fault, {"none", "exec", "pidfd", "exit_before_pidfd", "landlock_unavailable",
                             "seccomp_setup", "inherit_fd"})) {
    std::cerr << "unapproved synthetic scenario or fault\n";
    return 8;
  }
  if (request.scenario == "fsize") request.file_size = 1024;
  request.arguments = {"boundary_fixture", request.scenario};
  struct sigaction action{};
  action.sa_handler = on_signal;
  sigemptyset(&action.sa_mask);
  for (int signal : {SIGTERM, SIGINT, SIGUSR1}) if (sigaction(signal, &action, nullptr) != 0) return 8;
  struct sigaction ignore{};
  ignore.sa_handler = SIG_IGN;
  sigemptyset(&ignore.sa_mask);
  if (sigaction(SIGPIPE, &ignore, nullptr) != 0) return 8;
  const auto temporary_root = std::filesystem::temp_directory_path();
  std::string temporary = (temporary_root / "exec-boundary-run-XXXXXX").string();
  if (mkdtemp(temporary.data()) == nullptr) return 8;
  request.working_directory = temporary;
  std::error_code error;
  std::filesystem::create_directory(request.working_directory / "allowed", error);
  std::filesystem::create_directory(request.working_directory / "denied", error);
  std::ofstream(request.working_directory / "allowed/input") << "synthetic-allowed";
  std::ofstream(request.working_directory / "denied/input") << "synthetic-denied";
  auto result = boundary::execute(request, &signals);
  std::filesystem::remove_all(request.working_directory, error);
  result.artifacts_removed = !error && !std::filesystem::exists(request.working_directory);
  if (!result.artifacts_removed) result.state = "SUPERVISOR_ERROR";
  std::cout << boundary::manifest(request, result) << '\n';
  return boundary::cli_exit(result.state);
}
