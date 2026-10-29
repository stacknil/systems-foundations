# Failure observations and decisions

The first native independent check rejected a direct-profile report because
the fixture inherited seccomp mode 2. Mode 2 alone could not identify this
request's filter. The contract and oracle now record inherited mode separately
from request-local installation. An unfiltered getppid control and the filtered
EPERM result distinguish the controlled experiment.

A Landlock setup succeeded but execveat failed with EACCES. The selected
executable also needed READ_FILE admission. The correction grants that right
to its already-open descriptor, not a new pathname lookup. The final native
fixture executes and verifies all six allowed/denied access classes.

A one-millisecond deadline could expire during spawn/session setup, followed
by cancellation of the launch gate. Classifying the consequent setup error
as the primary launch failure discarded the earlier timeout decision. The
classifier now retains the stop decision and records the actual wait status
separately. Fixed early/boundary/late schedules cover this race.

Closed pipes originally remained in poll, permitting HUP-ready busy loops.
EOF descriptors are now removed from the poll set. Native cleanup control
records actual EINTR and signal notifications during the grace period.

These are development RED/GREEN observations, not vulnerabilities asserted
against the four existing labs. Initial failed receipts and final native
manifest/observer/oracle records remain in the private qualification package.
GCC, Clang and ASan/UBSan each reached green on the bounded scenarios.

The cgroup delegation experiment stopped at EACCES. No host configuration was
changed. An escaped descendant was not executed to fill a matrix cell:
E09 remains NOT_RUN and strict whole-tree admission is refused before fork.

Independent review exposed false enforcement claims accepted by the oracle on
pre-spawn refusals and failed child setup. The checker now requires a spawned
child for request-local controls and setup confirmation for child-installed
controls. Native qualification rejects 21 corruptions across normal, refused
and failed-setup records; original observations remain accepted.

Review also found that a basic Landlock probe on ABI 1/2 did not establish
the full profile requiring ABI 3. Qualification now gates that profile on ABI
3 or later; synthetic boundary checks cover ABI 1, 2, 3 and 7 and unavailable
support. Older-ABI behavior was checked by synthetic gating, not a second kernel.
