# v0.4.0 — Linux execution boundary

Build the standalone C++20 supervisor to observe launch, deadlines, resource limits and cleanup for trusted synthetic fixtures. The [reviewer guide](execution-boundary-review.md) maps each claim to a test, capability result or negative control.

The four Python labs retain their existing entry points. The process lab preserves microseconds in observation timestamps and rejects overprecise timestamps, mixed snapshot instants and non-increasing before/after times. Consumers should supply coherent, strictly ordered snapshot pairs.

The process lab also rejects inconsistent saved process/socket evidence and validates saved inputs before writing artifacts. The auth normalizer now reports input-open failures. A later output failure can still leave partial artifacts.

The release qualifies bounded fixtures on the tested Linux environments. Check the runtime capability results before interpreting optional controls. Whole-tree containment and native detached-descendant cleanup remain outside the demonstrated scope.
