# Protocol test suite

The GTest suite in `test_auth.cpp` exercises the authentication and cryptographic protocol library. It does not currently cover the Qt Auth screens, tab gating, Password Manager UI, or Android packaging.

## Build and run

From the repository root, configure and build the desktop test target:

```bash
cmake -B build -S . \
  -DCMAKE_TOOLCHAIN_FILE="$HOME/vcpkg/scripts/buildsystems/vcpkg.cmake" \
  -DVCPKG_TARGET_TRIPLET=x64-linux
cmake --build build --target AuthTests -j2
ctest --test-dir build --output-on-failure
```

Or use the Makefile targets:

```bash
make build
make test
```

`make test` builds the desktop targets before running CTest. GTest is declared as a host dependency and the test target is not configured for Android.
