# Memory28: consume ready RX before admitting a new packet

Memory27 is committed as `7e44437`. A natural C6 14/15 startup failure was
captured without ACK injection. This incident differs from Memory26/27's
wrong-role fallback ACK in the pinned peer: MRP **did receive a valid ACK**,
but the reliable IM StatusResponse was repeatedly rejected at core RX admission.

The failed exchange transmitted ReportData at154084ms. Its StatusResponse
(counter248264948) arrived five times with MATTER_WOULD_BLOCK. The standalone
ACK (counter248264950) was accepted at155593ms and completed ReportData MRP
on attempt3. The IM exchange still timed out at183303ms, leaving14/15, including
only2/3 on the primary fabric. No raw UDP drop was observed in154000–184000ms;
nonzero wire-header drop records occurred earlier, during warmup/commissioning.
The machine-readable [timeline/results](memory28-results.json) retain the
failure instead of counting its clean shutdown as protocol success.

A second, pre-fix core observer capture shows ready old RX delivery occurring
*after* the new inbox was attempted. Its34 admission-block events still recover
to15/15; not every WOULD_BLOCK is fatal. The native regression authenticates a
new inbox frame behind a ready old RX slot and checks secure last-received time,
borrowed views and full cleanup. It fails against the old ordering and passes
after the change.

## Change and physical regression

The dispatcher extracts the existing RX process/delivery/release sequence into
`process_rx`. When an inbox is queued, it consumes ready retained RX **before**
admitting that inbox, then runs the existing post-ingress RX step. Work is bounded
to one retained frame plus one inbox. There are no new allocations, fields,
limits, protocol timers or public API changes; ciphertext, ACK role/counter
matching, retained session pins and actual UDP completion barriers remain intact.
`process_rx` has a16-byte C6 frame; dispatch_process176, public process16,
process_transaction144 and send_ack64. These are compiler frame measurements,
not whole-task stack bounds. Normal system heap/stack measurements follow in
Memory29 because these RX captures have diagnostic instrumentation.

|C6 capture|Controller outcome|Observed core admission blocks|Seconds|
|---|---|---:|---:|
|initial-original01|FAIL,14/15|unobserved|149.27|
|initial-corrected01|PASS|34|147.26|
|initial-fixed-corrected02|PASS|0|150.20|
|initial-fixed-original03|PASS|1|149.31|
|soak-fixed-corrected|PASS|0|567.69|

Post-fix original and explicitly corrected peers both start15/15. One original-
peer admission block remains and recovers: a genuinely unavailable RX slot is
still bounded backpressure, not an excuse to grow limits. Observer layout/timing
and the non-statistical number of captures preclude a zero-loss guarantee.
The historical Memory23 incident cannot be retroactively attributed.

The extended corrected-peer C6 run passes567.69s, including363.51s sustained
load,71 full171-attribute Reads,60 subscription snapshots and40 CASE pair/
resumption cycles. It exercises one OOM, one injected RX loss, one Wi-Fi
reconnect and one held-TX stop. OOM and loss each retire one subscription and
explicitly rebuild15/15. Healthy operation errors, unexpected subscription
closures and SDK allocation failures remain zero. Actual completion delays
stop3.605s; tracked core live allocations/bytes reach zero. Boot's13 deliberately
failed core-allocation fixture calls are separate from the one workload OOM.

## Host checks and retained failed coverage attempt

Windows native CTest passes102/102 and all six final wire scenarios. Linux
passes99/99 normally and separately ASan/UBSan/LSan; full two-instance scenarios
pass6/6 under Memcheck and separately sanitizers. All six final wire cases pass
under each of those variants. Memcheck requires zero errors and zero exit
bytes/blocks. The build logs contain no new C warnings. Inventory passes266
mapped files,99 native definitions,59 core sources and75 closed public headers.
See [runner commands](../runtime-wire-tests.md) and source hashes in the results.

The first sanitizer wire matrix stopped at single-original-after: it correctly
observed one suppressed ACK, wrong-role rejection, five MRP attempts,14/15,
all15 existing CASE Reads and zero-live cleanup, but **did not observe an ACK
before the nominal25ms completion**. That is a coverage failure, retained in
the results, not a weakened oracle or claimed ACK-matching defect.
The test fixture now explicitly holds the next accepted reliable TX completion
until it observes a new matching ACK, then releases the real completion and
requires all five parallel Reads to succeed. Standalone ACKs are not selected.
The complete six-case matrix was repeated with this final fixture under
Memcheck and separately sanitizers. Production protocol behavior is unchanged
by this test-only scheduling control.

## Files, commands and limits

* `main/apps/matter/runtime/matter_dispatch.c`: shared RX sequence and admission
  ordering fix; `tools/matter/tests/test_dispatch.c`: before/after regression.
* `runtime_wire_host.c`, `wire_dispatch.c`, `wire_faults.h`, `wire_scenarios.mjs`,
  `runtime_wire.py`: deterministic ACK-before-completion coverage and acceptance.
* `examples/esp32-runtime/tests/rx_trace.py`: bounded, lab-only UDP/core observers;
  `uart_capture.py`: parse metadata. The lwIP callback never prints/allocates.
* Runtime/wire guides, README/status and this report/results document the change.

Executed: CMake build; CTest excluding opt-in runtime_wire; runtime_wire.py with
all six cases on Windows, Linux --memcheck and separate sanitized binaries;
chip_tool_three_phase.py with --source-registers --meter-services against the
pair fixture; check_test_map.py; Python syntax compilation and Node --check;
IDF6.1 C6 builds, UART1000000 captures and the physical workload above.

No official CSA run, certification, fresh Apple/Google Home pairing or exhaustive
OOM-at-every-allocation campaign was performed. Limits, persistent format and
fail-safe behavior are covered by existing native/pair regressions, not a new
certification claim. Final normal-firmware/state restoration and network cleanup
are recorded with Memory29. Next: normal-image system heap profiling plus a
separate, capacity-checked allocation-site observer to select the next RAM work.
