# CSA57: actual stalled BDX recovery

**The same native requestor recovers and completes the update** under Memcheck and separately ASan/UBSan/LSan:24 checks per variant. Original **TC-BDX-2.3 remains FAIL, run495**, for one literal BlockAck requirement; actual restarted ReceiveInit/Accept and EOF/AckEOF steps pass. [Machine-readable receipts](csa57-results.json). Source, support and PICS remain unchanged in TH.

## Real interruption and recovery

The separate existing fault-only provider stops supplying blocks after 5,120 bytes while retaining MRP. Actual idle failure is observed after 300.201s under Memcheck and 300.310s under sanitizers. Both scenarios observe at least 301 real seconds, verify Idle, remove the partial file and retain SoftwareVersion 1. No accelerated requestor clock or shortened timeout.

Only the provider restarts, keeping its KVS, image and operational identity. The requestor remains the same process; no factory reset or recommissioning. An explicit SimpleAnnouncement reason 0 selects this implementation's query opportunity. The old CASE session first fails normally, then retry establishes fresh CASE. The successful query appears after 130.859s / 130.614s from the recovery trigger. The original 120s query floor remains intact; peer received-query gaps are recorded separately. Each restarted provider logs five datagrams for the old unknown session; the first requestor lifetime records three query attempts, including the initial query and recovered one.

The restarted transfer negotiates synchronous receiver-drive (0x20) and a 1024-byte bound. ReceiveInit has no offset field, so effective offset is 0. BlockQuery and Block counters are exactly 0..16; BlockEOF16 receives BlockAckEOF16. The reassembled 16,585-byte image/hash match the reference. Authentication, simulated installation/reboot, latest offered token/version in ApplyUpdateRequest and NotifyUpdateApplied, then fresh CASE readback of version 2 and BootReason 5 all pass. This is a complete new download after interruption, not partial-range resumption or a physical firmware flash.

## Fixture change and original-test discrepancy

The runner gains `--recovery-announcement-reason`, valid only in interrupt-retry mode. Omitting it preserves earlier behavior. With `--default-provider`, the initial reason remains UpdateAvailable (reason 1); the explicit recovery override 0 is independent. It records requestor continuity, provider restart count, recovery delay and observed rate floor. Documentation and the existing inventory entry explain the option. No C/H implementation, public API, timer, capacity or PICS change.

CSA45's run481 used reason1, which retains the next daily query; its 240-second observer expired before another CASE attempt. That earlier failure remains in history. The new actual recovery closes that attribution question.

The unchanged TC-BDX-2.3 second step specifically requests ordinary BlockAck. Actual receiver-drive instead acknowledges each preceding Block through the next BlockQuery, as Core1.6.1 11.22.6.2 permits. Core11.22.6.6 makes an explicit BlockAck optional in this mode; none appears on the wire. Therefore this literal step is recorded FAIL pending CSA clarification. Do not infer a broken recovered transfer or silently turn the original result into PASS. The other two transfer steps now pass.

## Validation and limits

Frozen CSA56 hosts were checked against all 362 current C/H inputs. Each memory variant has two native process lifetimes: before and after simulated OTA reboot. Memcheck totals 56,120 matched allocations/frees, zero errors/live bytes; both sanitizer stderr logs are empty and clean stops pass. The unmodified provider is used for recovery; the separate fault peer is identified explicitly by its hash. Raw traces, controller state, keys and images remain ignored.

Four focused CTests per Linux build pass: BDX/Query plus allocation-failure variants; no compiler warnings observed. Local Python syntax compilation passes. Windows Python lacks cryptography, so help/argument validation and the actual external tests run on Linux. Incompatible recovery option/mode is rejected before creating fixtures. Inventory, campaign consistency, privacy/link and diff checks are recorded. Test nodes are stopped and TH idle; paired Windows nodes untouched. No full-matrix, physical/radio, Home UI, embedded RAM-fit or deferred DGGEN rerun. No push.

Counts unchanged:99 automatic PASS/18 FAIL/1 BLOCKED; manual24 PASS/9 FAIL/4 BLOCKED;707 NA. Total123 PASS/27 FAIL/5 prerequisites. Next:CSA58, bounded stable rerun of previously passing automatic suites with explicit reset/lifecycle groups and retained external boundaries.
