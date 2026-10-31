#include "boundary.hpp"
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
bool text(int descriptor, const char* value) {
  std::size_t remaining = std::strlen(value);
  while (remaining != 0) {
    const ssize_t count = write(descriptor, value, remaining);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    value += count;
    remaining -= static_cast<std::size_t>(count);
  }
  return true;
}
void nap(unsigned milliseconds) {
  timespec delay{static_cast<time_t>(milliseconds / 1000),
                 static_cast<long>((milliseconds % 1000) * 1000000)};
  while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
}
std::uint64_t value(int resource, bool hard = false) {
  rlimit limit{};
  if (getrlimit(resource, &limit) != 0) _exit(125);
  return hard ? limit.rlim_max : limit.rlim_cur;
}
}

int main(int argc, char** argv) {
  if (argc != 2 || geteuid() == 0) return 124;
  alarm(3);
  struct stat control{};
  if (fstat(6, &control) != 0 || !S_ISFIFO(control.st_mode)) return 124;
  boundary::Wire wire;
  wire.kind = 3;
  wire.pid = getpid();
  wire.pgid = getpgrp();
  wire.sid = getsid(0);
  wire.nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
  wire.seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
  wire.cpu_soft = value(RLIMIT_CPU);
  wire.cpu_hard = value(RLIMIT_CPU, true);
  wire.address_space = value(RLIMIT_AS);
  wire.file_size = value(RLIMIT_FSIZE);
  wire.open_files = value(RLIMIT_NOFILE);
  wire.core_size = value(RLIMIT_CORE);
  for (int descriptor = 3; descriptor < 64; ++descriptor) {
    if (descriptor != 6 && fcntl(descriptor, F_GETFD) >= 0) ++wire.unexpected_fds;
  }
  if (write(6, &wire, sizeof(wire)) != static_cast<ssize_t>(sizeof(wire))) return 125;
  close(6);
  const std::string mode(argv[1]);
  if (mode == "normal" || mode == "immediate") return text(1, "normal\n") ? 0 : 120;
  if (mode == "nonzero") return 42;
  if (mode == "signal") { raise(SIGUSR2); return 121; }
  if (mode == "abnormal") abort();
  if (mode == "sleep" || mode == "short") { nap(mode == "short" ? 20 : 1500); return 0; }
  if (mode == "ignore-term") { signal(SIGTERM, SIG_IGN); nap(1500); return 0; }
  if (mode == "partial") return text(1, "abc") && text(2, "error") ? 0 : 120;
  if (mode == "close-stdout") {
    close(1);
    nap(15);
    return text(2, "stderr-retained\n") ? 0 : 120;
  }
  if (mode == "broken-pipe") {
    int descriptors[2];
    if (pipe(descriptors) != 0) return 122;
    close(descriptors[0]);
    const char item = 'x';
    write(descriptors[1], &item, 1);
    return 123;
  }
  if (mode == "flood") {
    std::array<char, 4096> block{};
    block.fill('x');
    for (int index = 0; index < 64; ++index) {
      for (int descriptor : {1, 2}) {
        std::size_t offset = 0;
        while (offset < block.size()) {
          const ssize_t count = write(descriptor, block.data() + offset, block.size() - offset);
          if (count < 0 && errno == EINTR) continue;
          if (count <= 0) return 120;
          offset += static_cast<std::size_t>(count);
        }
      }
    }
    return 0;
  }
  if (mode == "cpu") {
    volatile unsigned long counter = 0;
    while (true) counter = counter + 1;
  }
  if (mode == "memory") {
    errno = 0;
    void* allocation = mmap(nullptr, 256 * 1024 * 1024, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (allocation == MAP_FAILED && errno == ENOMEM)
      return text(1, "allocation-denied-ENOMEM\n") ? 0 : 120;
    if (allocation != MAP_FAILED) munmap(allocation, 256 * 1024 * 1024);
    return 122;
  }
  if (mode == "fsize") {
    const int file = open("size-test", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (file < 0) return 122;
    std::array<char, 4096> bytes{};
    for (int index = 0; index < 4; ++index) write(file, bytes.data(), bytes.size());
    close(file);
    return 123;
  }
  if (mode == "nofile") {
    int count = 0;
    for (int index = 0; index < 64; ++index) {
      const int file = open("/dev/null", O_RDONLY | O_CLOEXEC);
      if (file < 0) return errno == EMFILE && count > 0 && text(1, "open-denied-EMFILE\n") ? 0 : 123;
      ++count;
    }
    return 123;
  }
  if (mode == "artifact-failure") {
    const int file = open("temporary-artifact", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (file < 0) return 122;
    text(file, "synthetic only");
    close(file);
    return 42;
  }
  if (mode == "tree" || mode == "orphan") {
    const pid_t descendant = fork();
    if (descendant < 0) return 122;
    if (descendant == 0) { alarm(2); nap(1200); _exit(0); }
    text(1, "cooperating-descendant-started\n");
    if (mode == "orphan") return 0;
    nap(1200);
    int status = 0;
    while (waitpid(descendant, &status, 0) < 0 && errno == EINTR) {}
    return 0;
  }
  if (mode == "seccomp") {
    errno = 0;
    const long parent = syscall(SYS_getppid);
    if (parent == -1 && errno == EPERM && getpid() > 0)
      return text(1, "getppid-denied-EPERM;getpid-allowed\n") ? 0 : 120;
    if (parent > 0) return text(1, "getppid-allowed\n") ? 0 : 120;
    return 123;
  }
  if (mode == "landlock") {
    const int allowed = open("allowed/input", O_RDONLY | O_CLOEXEC);
    if (allowed < 0) return 122;
    close(allowed);
    const int created = open("allowed/new", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (created < 0) return 122;
    text(created, "allowed");
    close(created);
    errno = 0;
    const int denied_read = open("denied/input", O_RDONLY | O_CLOEXEC);
    const bool read_rejected = denied_read < 0 && errno == EACCES;
    if (denied_read >= 0) close(denied_read);
    errno = 0;
    const int denied_write = open("denied/input", O_WRONLY | O_CLOEXEC);
    const bool write_rejected = denied_write < 0 && errno == EACCES;
    if (denied_write >= 0) close(denied_write);
    const int allowed_dir = open("allowed", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (allowed_dir < 0) return 122;
    close(allowed_dir);
    errno = 0;
    const int denied_dir = open("denied", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    const bool dir_rejected = denied_dir < 0 && errno == EACCES;
    if (denied_dir >= 0) close(denied_dir);
    errno = 0;
    const int denied_new = open("denied/new", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    const bool create_rejected = denied_new < 0 && errno == EACCES;
    if (denied_new >= 0) close(denied_new);
    if (unlink("allowed/new") != 0 || truncate("allowed/input", 0) != 0) return 122;
    errno = 0;
    const bool remove_rejected = unlink("denied/input") < 0 && errno == EACCES;
    errno = 0;
    const bool truncate_rejected = truncate("denied/input", 0) < 0 && errno == EACCES;
    return read_rejected && write_rejected && dir_rejected && create_rejected &&
        remove_rejected && truncate_rejected &&
        text(1, "read-write-dir-create-remove-truncate:allowed-and-denied\n") ? 0 : 123;
  }
  return 124;
}
