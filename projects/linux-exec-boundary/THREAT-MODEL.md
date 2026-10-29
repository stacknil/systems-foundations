# Threat and failure model

## Scope

The lab controls a locally built, trusted synthetic executable with bounded
adversarial exit, signal, output, allocation and process-tree scenarios. The
supervisor and Linux kernel are trusted. No arbitrary downloaded binary, shell
command, credentials, external target or unrelated process is an input.
Non-root execution is mandatory.

The assets are exact child ownership, correct signal targeting, bounded parent
resources, stable report structure and truthful evidence. This is empirical
qualification in one environment, not a production sandbox claim.

## Boundaries

1. Request admission fixes executable/argv/environment and bounded parameters.
2. Open executable descriptor and gated fork separate creation from exec.
3. Pidfd waiting and unreaped leader identity prevent accidental retargeting.
4. A dedicated session scopes cooperating-descendant group signals.
5. Child-local limits/no_new_privs and optional policy precede fixture exec.
6. Nonblocking bounded capture avoids pipe deadlock and unbounded retention.
7. Subreaping and an independent watchdog check direct/adopted cleanup.
8. Independent manifest checks reject claims stronger than the observations.

The exclusive supervisor checks for existing children without consuming status.
Concurrent spawning/reaping by another thread violates the API precondition.
No unrelated child may be reaped or terminated to make a report look clean.

## Optional mechanisms

Landlock handles READ_FILE, READ_DIR, WRITE_FILE, MAKE_REG, REMOVE_FILE and
TRUNCATE (ABI >=3). The exact executable and loader/libraries receive read-only
access; one owned allowed subtree permits those six classes. Another owned
subtree supplies denied-operation controls. Unhandled rights are unrestricted.
Pre-opened descriptors, filesystem metadata and non-filesystem objects have
their own kernel semantics. This is not filesystem-wide confidentiality.

The seccomp demonstration validates architecture and denies only getppid with
EPERM; getpid remains allowed across exec. It does not restrict every dangerous
syscall or establish network isolation.

Limits are per process, not aggregate tree CPU/memory quotas. AS limits virtual
address space, not RSS; FSIZE limits regular files, not pipes. The capture cap
limits retained evidence, not generated output. RLIMIT_NPROC is deliberately
not used because it can affect unrelated same-UID activity.

Current cgroup v2 delegation is not writable. No cgroup root setting, service,
namespace, sudo action or host policy changes. There is no active whole-tree
backend. strict-tree refuses before fork. Group signals cannot establish
containment of a descendant that leaves the session/group. The native
detached-descendant case is NOT_RUN; no such fixture is supplied without a
verified secondary containment envelope.

## External fixture safety

The watchdog signals only its own supervisor pidfd and its own adopted children.
It applies CPU, file-size, descriptor and core limits, a wall timeout, and AS
bounds for ordinary builds. ASan requires large shadow virtual mappings; that
parent AS bound is omitted in the sanitizer run. CPU/wall/file/FD bounds and
ASan's 128 MiB RSS watchdog remain. The non-instrumented fixture still receives
and reports its child AS limit.

Fixtures arm a three-second alarm; their single cooperating descendant arms a
two-second alarm. They fork at most once, generate a fixed finite output flood
and touch only owned paths. The memory control attempts one untouched fixed
256 MiB mapping. No UID-wide process-limit or uncontrolled stress experiment.

## Rejected alternatives

| Alternative | Decision evidence |
| --- | --- |
| Use an unheld numeric PID after reaping | PID may be reused; retain pidfd and leader ownership |
| Call group kill whole-tree isolation | Descendants can leave; always deny the stronger claim |
| Downgrade a strict unsupported profile | Misrepresents enforcement; refuse before fork |
| Infer exec from pipe EOF | Pre-exec death also closes it; require post-exec witness |
| Infer installed seccomp from mode 2 | Environment already inherits mode 2; distinguish inheritance |
| Retain every output byte | Noisy child can exhaust memory; cap retention and count dropped bytes |
| Provision cgroups or use sudo | Outside scope; retain unavailable delegation |
| Execute detached descendants for coverage | No verified secondary containment; retain NOT_RUN |

API references: Linux
[pidfd man-pages](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.16.pdf),
[Landlock](https://docs.kernel.org/userspace-api/landlock.html) and
[seccomp filters](https://www.kernel.org/doc/html/v5.9/userspace-api/seccomp_filter.html).
Runtime probes, rather than the newest upstream documentation, determine the
active ABI. Holding an inode does not authenticate or prevent all modifications
to its contents.
