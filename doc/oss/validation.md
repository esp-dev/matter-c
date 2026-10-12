# Clean snapshot validation

This is the publication snapshot. Later three-phase changes and their focused
CSA/controller/memory acceptance are recorded in [MP02 validation](mp02-validation.md).

Executed 2026-10-12 from the isolated source export, with official upstream
mbedTLS 3.6.0. The Linux source archive contained no private audit history,
captured certificates, build outputs or external product checkout.

| Check | Result |
| --- | --- |
| Linux Debug CMake build and default CTest | 76/76 PASS |
| Separate Linux ASan/UBSan/LSan CMake build and default CTest | 76/76 PASS, no findings |
| Windows MinGW GCC 15.2.0 build and focused CTest | 14/14 PASS |
| Relocated installed package, including two runtimes | PASS on both platforms, included above |
| Inventory | 219 fixture/test/controller files, 71 closed public headers |
| TLV fuzz seed replay with GCC | Empty input + 61 files PASS; not a fuzz campaign |
| TLV/hash generator repeatability | Byte-identical regenerated output |
| Independent IM schema generator | Request/report bytes equal the previous reference fixture |
| Compiler logs | No warning/error diagnostics in final builds |

Commands (paths to compilers/dependency seeds are operator supplied):

```sh
python tools/matter/bootstrap_mbedtls.py --source <offline-upstream-checkout>
cmake -S . -B build/check -DCMAKE_BUILD_TYPE=Debug
cmake --build build/check -j 3
ctest --test-dir build/check --output-on-failure
cmake -S . -B build/sanitize -DCMAKE_BUILD_TYPE=Debug -DMATTER_SANITIZE=ON
cmake --build build/sanitize -j 3
ctest --test-dir build/sanitize --output-on-failure
```

Windows used `-G "MinGW Makefiles"`, explicit native GCC/Python paths and:

```powershell
ctest --test-dir build/check --output-on-failure -R 'test_(tlv|attestation|im_read|acl|crypto|spake|operational_cert|server_time)|inventory|installed_consumer'
./tools/matter/run_fuzz.ps1 -Compiler gcc -ReplayOnly
```

Sanitized CTest enables `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1` on Linux. Negative profile,
bounds, truncation and allocation-failure cases remain part of the tests.

No new CSA/controller commissioning, Memcheck scenario, long fuzz campaign,
MSan/TSan or hardware test was run for this fixture/export-only step. The prior
runtime was tested under Memcheck and sanitizers; those results are historical,
not a claim of a new acceptance run. See status.md for four open CSA failures.
A targeted source/history scan excludes known private paths, addresses, branding,
PEM private-key blocks and captured certificate blobs. Reproducible public test
keys remain intentionally present; this scan is not a guarantee against every
possible encoding of sensitive data.
