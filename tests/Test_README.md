# 1000-Test Suite 


## Build + Run

```bash
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release -j$(nproc)
./build/AuthTests
# or via ctest:
ctest --test-dir build --output-on-failure -j$(nproc)
```

## Output

After all tests, a perf report prints to stdout:

```
══════════════════════════════════════════
  Auth Protocol Performance Report
══════════════════════════════════════════
  Tests passed: 1080 / 1080

── Registration (Protocol 1) (n=...) ──────────────────────────
  avg:     2841.3 µs
  min:      400.1 µs
  p50:     2800.0 µs
  p95:     3200.0 µs
  p99:     3800.0 µs
  max:     5000.0 µs

── Authentication (Protocol 2) (n=...) ─────────────────────────
  avg:     2750.5 µs
  min:      380.0 µs
  p50:     2700.0 µs
  p95:     3100.0 µs
  p99:     3600.0 µs
  max:     4900.0 µs
══════════════════════════════════════════
```

Raw CSV written to `/tmp/auth_perf.csv` — columns: `type,latency_us`.

## Test Distribution (1080 instances)

| Section | What | Count |
|---------|------|-------|
| 1 | Registration structure (username, salt size, E/ED non-empty + size) | 100 |
| 2 | Password wipe after registration | 40 |
| 3 | Salt uniqueness across registrations | 50 |
| 4 | Correct password succeeds (50 passwords × 2 tests) | 100 |
| 5 | Wrong password fails + no-throw guarantee | 90 |
| 6 | Empty/single-byte boundary passwords | 30 |
| 7 | Client hash determinism | 50 |
| 8 | Hash differs for different passwords | 50 |
| 9 | Server username validation | 50 |
| 10 | Password wipe after auth (success + fail) | 50 |
| 11 | Multi-user isolation | 50 |
| 12 | Cross-payload attack resistance | 50 |
| 13 | Password length spectrum (1–512 bytes) | 60 |
| 14 | All-byte-values passwords (0x01–0x32) | 50 |
| 15 | Stress: rapid sequential auths | 50 |
| 16 | Concurrent registration + auth | 30 |
| 17 | Crypto properties (E≠ED, probabilistic OAEP) | 20 |
| 18 | No-throw guarantees | 30 |
| 19 | Special character passwords | 30 |
| 20 | Case sensitivity | 20 |
| 21 | Tampered salt detection | 30 |
| 22 | VerifyOnServer direct | 30 |
| 23 | Misc edge cases + fixture tests | 20 |
| **Total** | | **1080** |