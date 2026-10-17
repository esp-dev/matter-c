# CSA25: NotifyUpdateApplied after a simulated OTA restart

Prior CSA24b acceptance was committed as **`720b830`**. This step changes
documentation and acceptance records only. The current C implementation already
supports the required notification; no C/H, API, persistence, PICS or SDK source
change was necessary. Existing paired Windows nodes remain untouched.

## Result and normative basis

**TC-SU-2.6 manual PASS in TH run452.** The installed SDK provides one disabled
YAML verification step in SDK YAML Tests / FirstManualSuite, not a Python
automatic case. The coding agent evaluated actual peer traces before answering
the verification prompt and uploading its evidence. Both TH steps pass. This
is manual acceptance, not automatic assertions, certification or an accredited
laboratory result.

Only the manual TC-SU-2.6 row changes from BLOCKED to MANUAL with result PASS.
Counts become **97 PASS, 15 FAIL, 8 BLOCKED, 38 MANUAL, 704 NA**, still 862 rows.
Other rows are inherited, not rerun. In particular, the unmodified Python
TC_SU_2_5 remains FAIL; CSA24b run451 remains a separate LOCAL-PATCH PASS.
See the [machine-readable result and evidence hashes](csa25-results.json).

Matter Core R1.6.1 **11.20.3.6** says a requestor SHOULD notify the provider that
supplied the initial response after completing an update. It SHALL NOT retry
the invocation at application level if no response arrives. A reboot to apply
the update SHALL expose BootReason SoftwareUpdateCompleted. The Notify command
definition in **11.20.6.5** requires an 8..32-byte UpdateToken under the usage
rules of **11.20.3.6.1**, and SoftwareVersion equal to Basic Information.
These fixtures retain the token; token-loss fallback is outside their scope.

The unchanged YAML SHA-256 is
`37200cd4f4389b7d7470f43ea36ae2c5d83f6bd0363652e2cd0c1ab958188f4e`.
The execution PICS matches the preflight snapshot. Requestor is enabled;
consent, HTTPS and transfer resumption remain disabled. No test patch was used.

## Executed acceptance

The unmodified CHIP Provider/chip-tool come from SDK commit
`3bcdd56ba54fb88b2afb4bfef575014671df7aa7`; its checkout is clean. The compiled
requestor's 360 C/H source hashes match the current repository before and after
the scenarios. Existing normal and sanitizer binaries were reused, not rebuilt.
Both use three subscriptions per fabric and compiled transport capacity 128.

| Independent fixture | Result |
| --- | --- |
| Fresh version 1 to signed simulated version 2, full two-boot Memcheck | 15 checks PASS |
| Fresh version 1 to signed simulated version 3, separate two-boot ASan/UBSan/LSan | 15 checks PASS |

Each scenario commissions disposable peers, downloads over BDX, authenticates the
image, receives Apply approval, journals the simulated install and restarts the
same executable. The provider receives NotifyUpdateApplied after restart. The
independent trace reader checks endpoint 0 / cluster 0x0029 / command 4, the
actual token against the latest Query response and Apply request, and the actual
version against the offered/authenticated image. A fresh CASE controller then
reads Basic Information version 2 or 3 and BootReason 5.

Both observed notifications carry a 32-byte token. Their different token hashes
and versions are recorded publicly; token bytes and controller state are not.
Each loss-free fixture has one logged application attempt and one received
Notify. This observation is not a dropped-response/retransmission test.

The trace oracle also rejects six controls, applied to in-memory copies of the
captured commands: changed Notify token, changed Notify version, a seven-byte
token, a string instead of the version integer, missing Notify and missing Apply.
These validate the checker; they are not hostile commands sent to the requestor.

Memcheck across both requestor boots reports **55118 allocations and frees,
zero errors, zero live bytes and no suppressions**. The separate sanitizer run
exits cleanly with empty host stderr. These tools instrument the C host, not
the independent CHIP processes.

Two existing journal CTests pass in each build: `test_ota_update` and
`test_ota_update_alloc`. They cover durable single claim, storage faults, orphan
fabrics, corruption and rollback. Source review confirms that the runtime claims
the pending context durably before dispatch, so later application processing does
not reclaim it; MRP retry belongs to the existing exchange. A live lost-Notify-
response scenario was not executed here.

After acceptance, all fixture UDP ports are released, TH is idle, the original
TC-SU-2.6 YAML and restored TC_SU_2_5 Python source retain their pinned hashes.
No administrator action or further TH patch was needed.

## Commands and changed files

```sh
python tools/matter/tests/test_ota_chip_provider.py \
  --exe /path/to/normal/matter-node --provider /path/to/chip-ota-provider-app \
  --chip-tool /path/to/chip-tool --paa /path/to/paa \
  --credentials /path/to/development-credentials --interface 2 \
  --subscriptions-per-fabric 3 --mode update --apply-binding --image-version 2 \
  --valgrind --output build/csa25-memcheck-v2

# A separate fresh output/state directory and sanitizer binary:
python tools/matter/tests/test_ota_chip_provider.py \
  --exe /path/to/sanitize/matter-node --provider /path/to/chip-ota-provider-app \
  --chip-tool /path/to/chip-tool --paa /path/to/paa \
  --credentials /path/to/development-credentials --interface 2 \
  --subscriptions-per-fabric 3 --mode update --apply-binding --image-version 3 \
  --output build/csa25-sanitizer-v3

ctest --test-dir /path/to/normal-build --output-on-failure -R '^test_ota_update(_alloc)?$'
ctest --test-dir /path/to/sanitize-build --output-on-failure -R '^test_ota_update(_alloc)?$'
python tools/matter/check_test_map.py
git diff --check
```

For TH, select only TC-SU-2.6, verify the captured command against the original
manual step and upload the evidence log. The local runner accepts that one
verification prompt and upload only; an unexpected prompt aborts the run.

`csa25-validation.md` and `csa25-results.json` record the evidence and limits.
README, status and roadmap identify the current result and next task.
`doc/ota-host.md` documents reuse of the existing trace-verification mode for
Notify acceptance. No source/test inventory entry was added or removed.

No physical firmware/bootloader, full campaign rerun, 128 kB target fit,
Apple/Google Home presentation or live lost-response behavior is verified here.
The planned on-demand allocation migration remains future work.

Next: **CSA26 — TC-SU-2.7 / TC_SU_2_7, OTA Requestor events**, checking both
installed procedures and the applicable consent-disabled PICS before execution.
