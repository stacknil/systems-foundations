# Independent audit

Decision: CAPABILITY_LIMITED. Independent source and native reviews accepted the final candidate with no unresolved material finding.

Frozen candidate: `37841e5daff18b50f69f99bd102d8502c8cd7acf2ad8737c281a5bab5592d40b`. Base: `2c14763864b3d26bc7a67774e22f9ba78f9329c6`. SOURCE-IDENTITY.json records the 21 reviewed files; this audit summary and the identity file itself are excluded to avoid a circular digest.

Source review independently verified all files, replayed 36 valid manifest/observer pairs, rejected 12 false-enforcement mutations, retained the valid setup-before-exec-failure control and checked five ABI/status selection controls.

Native review independently copied and built the frozen executable/test source using GCC on non-root WSL2/ext4. CTest passed 2/2 in 3.03 seconds; 39 result entries passed, E09 remained NOT_RUN and all 21 negative controls rejected. Entry counts include schedules and are not distinct semantic coverage counts. The final evidence-only refresh preserved all executed source bytes.

Earlier reviews found false enforcement acceptance on refused/failed setup and an incorrect ABI1/2 full-profile test gate. RED receipts and original review reports remain retained. Both findings were repaired and independently rechecked.

Builder GCC, Clang and ASan/UBSan CTest each passed 2/2 after repair. Six C++ translation units passed Clang static analysis without diagnostics; the dependency-free formatting gate passed. clang-format and clang-tidy were unavailable. The ASan fixture is intentionally uninstrumented to preserve its bounded address-space experiment.

Limits: no cgroup delegation (EACCES), no native detached-descendant experiment, no arbitrary-tree guarantee. Strict whole-tree execution refuses before fork. Landlock ABI7 was exercised; ABI1/2 selection was checked synthetically. Trusted fixtures and exclusive supervisor child ownership are prerequisites; no general-purpose sandbox or binary authentication is claimed.

The self-contained private handoff retains review-source/REPORT-revision3.md, review-native/REPORT-revision3.md, their independent scripts, command receipts, mutants and execution evidence. All prior review failures remain preserved.
