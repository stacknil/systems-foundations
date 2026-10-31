# Native reproduction

Use a non-root Linux/WSL2 user with GCC or Clang, CMake, CTest and Python 3.11+.
Build/test on native ext4, rather than a Windows-backed mount. No packages,
downloaded fixtures, sudo, cloud service or root CI change is required.

~~~sh
cmake -S . -B build-gcc -DCMAKE_CXX_COMPILER=g++ -DCMAKE_BUILD_TYPE=Debug
cmake --build build-gcc -j2
ctest --test-dir build-gcc --output-on-failure

cmake -S . -B build-clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug
cmake --build build-clang -j2
ctest --test-dir build-clang --output-on-failure

cmake -S . -B build-asan -DCMAKE_CXX_COMPILER=clang++ -DBOUNDARY_SANITIZERS=ON
cmake --build build-asan -j2
ctest --test-dir build-asan --output-on-failure

python3 tools/check_style.py
~~~

The fixture is deliberately not ASan-instrumented so its small virtual-address
limit remains meaningful. Supervisor/core code is instrumented with ASan/UBSan.
There are no external pytest dependencies in this lab.

CTest runs an in-process repeated-lifecycle/FD/reaping/parent-policy check and
a separate bounded watchdog. The latter creates a fresh evidence directory
(PID suffix on repetition), probes real capability support, runs fixed
scenarios/schedules, checks an independent oracle and rejects corrupted
manifests. Unsupported tests remain UNSUPPORTED/NOT_RUN, never native passes.

~~~sh
build-gcc/capability_probe > capabilities.json
build-gcc/exec_boundary --scenario normal --run-id manual-run > execution.json
python3 tools/render_report.py execution.json execution.md

python3 tests/qualify.py --supervisor "$PWD/build-gcc/exec_boundary" \
  --probe "$PWD/build-gcc/capability_probe" --output "$PWD/build-gcc/another-evidence"

python3 tests/oracle.py build-gcc/evidence/normal/stdout.json \
  build-gcc/evidence/normal/observer.json build-gcc/evidence/capabilities.json
~~~

Use the actual evidence directory printed by the watchdog if a previous one
already exists. The manual CLI is for finite approved scenarios; run CPU,
resource-failure and tree experiments through the watchdog. It supplies a
second wall/resource bound and exclusive descendant census. Never add or run
an escaped-descendant case without verified secondary containment.

Clang's built-in static analyzer was run on each C++ translation unit with
C++20, the include directory and CMake-built fixture definition. clang-tidy
and clang-format were unavailable; neither was installed or reported passing.
The dependency-free style gate checks LF, final newline, tabs/NUL and trailing
whitespace, supplemented by source review and warnings-as-errors.

Qualification environment: WSL2 x86_64, kernel
6.18.54.1-microsoft-standard-WSL2, native ext4, GCC 13.3.0, Clang 18.1.3,
CMake/CTest 3.28.3, Python 3.12.3. Landlock ABI 7 was tested; cgroup delegation
is unavailable (EACCES). These observations do not cover all WSL2 kernels.

The four older Python labs were separately tested using the existing Windows
runtime: 143 passed and 12 native-condition skips. Tracked source, schema,
fixtures, goldens and root workflow remain unchanged. Those skips are not new
native qualification evidence for the old projects.
