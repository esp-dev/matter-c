# Memory27: reproducible single-ACK wire regression

Memory26 is committed as `b77dd1c`. Production C code, resource limits, packet
formats, ACK matching and drain ownership are unchanged by this commit.

The native fixture now suppresses exactly one authenticated ACK of one
SubscribeResponse, selected by session/exchange/role/counter on the first
non-primary fabric. It observes the terminal MRP outcome and attempts, rather
than interpreting a transaction's previous-packet flag. The original pinned
Matter.js0.17.9 peer must send an observed wrong-role fallback ACK, exhaust five
attempts and end at14/15. The explicitly corrected diagnostic peer must finish
ACKNOWLEDGED on attempt2 with15/15. A core accepting the wrong role fails this
negative oracle. No retry counter or protocol timer is shortened.

Both peers run before/after UDP polling and immediate/deferred local completion.
All15 existing CASE sessions must complete full Reads before any reconnect;
five concurrent Reads remain a separate baseline. The fixture then rebuilds the
full load, holds an actual accepted TX completion and requires orderly stop,
zero tracked live bytes/allocations and closure of all15 peer sessions.

`peer_role.mjs` checks the UTF-8/LF SHA256 of the unmodified installed factory
and passes the inverse incoming Initiator role through its existing options.
It changes no dependency files. Every result explicitly labels original versus
corrected peer and records the source hash. This diagnostic override is scoped
to these unicast tests, not qualified as a general Matter.js release.

|Platform|Case|Controller seconds|Live subscriptions|Target attempts|Wrong-role ACKs|
|---|---|---:|---:|---:|---:|
|Windows|single-original-before|124.57|14|5|4|
|Windows|single-original-after|163.06|14|5|3|
|Windows|single-corrected-before|138.89|15|2|0|
|Windows|single-corrected-after|163.16|15|2|0|
|Linux Memcheck|single-original-before|154.82|14|5|3|
|Linux Memcheck|single-original-after|203.13|14|5|3|
|Linux Memcheck|single-corrected-before|155.73|15|2|0|
|Linux Memcheck|single-corrected-after|203.78|15|2|0|
|Linux sanitizers|single-original-before|121.48|14|5|3|
|Linux sanitizers|single-original-after|162.64|14|5|4|
|Linux sanitizers|single-corrected-before|125.28|15|2|0|
|Linux sanitizers|single-corrected-after|162.98|15|2|0|

Windows native CTest passes102/102, plus all four new direct wire cases. Linux
native CTest passes99/99 normally and separately with ASan/UBSan/LSan. All six
wire cases, including the existing three-ordinal OOM and ACK-blackhole cases,
pass under Memcheck and separately sanitizers. The full two-instance scenario
passes all six groups under Memcheck and on the sanitizer repeat. Memcheck
requires zero errors and zero bytes/blocks at exit. See the source-matched
[results](memory27-results.json) and [runner commands](../runtime-wire-tests.md).
The test inventory passes266 files/99 native definitions/59 core sources/75
closed public headers. No new C compiler warning was observed.

## Failures retained and limits

The first sanitizer pair run passed three groups, then failed because B's OnOff
subscription did not report TRUE within the existing five-second check after A
teardown. Sanitizer stderr was empty; the unchanged repeat passed all six.
The exact cause is unproven and is carried into RX investigation. It is not
silently removed from the results or claimed as a fixed regression. Both runs
use the same production source as Memory26; only the separate wire fixture changed.

A setup attempt rejected the peer hash: Memory26's private hash script decoded
through Windows' default encoding. This guard now explicitly uses UTF-8/LF
(`8fcefa35...95099`); the installed file is unchanged. A subsequent first oracle
attempt launched15 full Reads concurrently, exceeding the existing per-fabric
Read budget. It failed Busy as expected. The final session-survival check reads
all15 connections sequentially and retains five-way concurrent baseline coverage.

Native requested-byte peaks exclude allocator metadata, SDK/Mbed TLS internals
and the peer process; they are not C6 system heap, fragmentation or stack bounds.
This commit performs no board/AP action and claims no new official CSA,
certification, phone-app pairing or specification-wide RAM bound.

## Files and next task

* `wire_dispatch.c`, `wire_faults.h`: one-shot ACK selection, strict-role
  observations and exact terminal MRP metadata in the test executable only.
* `runtime_wire_host.c`: expose the single-shot command and metadata to the oracle.
* `wire_scenarios.mjs`, `runtime_wire.py`: shared load, four role/order cases,
  CASE-survival and cleanup acceptance.
* `peer_role.mjs`, `examples/esp32-runtime/tests/soak.mjs`: explicit, hashed,
  in-memory diagnostic peer override for host and C6 comparisons.
* `cmake/tests/CMakeLists.txt`, `doc/oss/test-map.json`: optional registration and
  complete inventory; configuration downloads nothing.
* `doc/runtime-wire-tests.md`, README/status and this report/results: commands,
  actual results, failed attempts and interpretation limits.

Next: correlate raw UDP drops and core RX admission on C6, including the retained
RX slot after TX completion, before making further memory changes.
