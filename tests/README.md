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
  Tests passed: 1400 / 1400
  
── Registration  (Protocol 1) (n=1374) ──────────────────────────
  avg:     161.6 µs
  min:      89.8 µs
  p50:     135.8 µs
  p95:     211.3 µs
  p99:     283.8 µs
  max:   23870.4 µs

── Authentication (Protocol 2) (n=1250) ──────────────────────────
  avg:    1251.7 µs
  min:    1092.7 µs
  p50:    1196.0 µs
  p95:    1808.0 µs
  p99:    1979.9 µs
  max:    2450.0 µs
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