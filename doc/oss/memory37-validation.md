# Memory37: RMT startup-order experiment

The RMT-only reorder is rejected. The original startup remains in the normal
application; this commit records the experiment and its negative result.

The candidate moves `matter_lab_led_new()` from after RGB model attachment to
before `matter_runtime_new()` in `start()`. The channel/encoder lifecycle,
application scheduler, model limits, OOM ordinals and ACK/drain code stay unchanged.
It uses supported driver APIs and does not free SDK globals or cancel timers.

## C6 comparison

ESP32-C6 on COM23, UART 1000000, TL-MR3020, the same saved initial fabric/NVS and
controller state for every run. The baseline normal image is exact Memory35;
the long baseline is the exact Memory36 final attribution probe using that core.
The candidate uses the same core, the startup move and matching configurations.
All image hashes and actual workload counts are in [results](memory37-results.json).

| Image | Sampled whole-heap peak B | Min sampled free B | Min sampled largest B | Cleaned free B | Cleaned largest B |
|---|---:|---:|---:|---:|---:|
| Baseline normal | 316244 | 101748 | 77824 | 390200 | 167936 |
| Early RMT normal | 316372 | 101828 | 79872 | 390188 | 167936 |
| Baseline long probe | 317508 | 88132 | 63488 | 377860 | 249856 |
| Early RMT long probe | 316984 | 88748 | 65536 | 377892 | 221184 |

Normal-image totals show no useful saving or post-teardown improvement. Probe
metadata changes available heap/layout; its totals must not be compared with the
normal rows. Finite traffic/SDK timing also changes transient peaks and placement.

The baseline long map has a persistent 92-byte RMT allocation between free spans
36472/250280 B. Moving RMT removes that main separator, but a 100-byte allocation
at `uart_vfs_dev_use_nonblocking` becomes the main separator, between free spans
66556/224464 B. These layouts persist from 5 through 65 seconds and owner-thread
cleanup. API largest-free uses SDK fit-size rounding, not the raw walked size.
The early candidate ends 28672 B below the baseline largest block. Free totals
differ only 32 B; relocating one persistent SDK object is not a reliable global
fragmentation improvement. The UART owner is an attribution site, not permission
to free its SDK-owned resource.

## Validation

Four complete physical fault workloads pass: five fabrics, fifteen protected CASE
sessions/subscriptions, full wildcard Read/Subscribe, injected OOM with recovery,
RX loss, Wi-Fi reconnect and retained TX completion/ACK drain. Healthy-operation
errors and unexpected subscription closures are zero; deliberate-fault rebuilds
and counts are recorded individually. All runs end with zero core live objects
and bytes, zero SDK allocation failures and successful SDK heap integrity checks.
The maximum observed owner stack use is 3224/12800 B; this is a sampled watermark,
not a worst-case call-chain proof. Six complete/stable paginated maps are decoded
against the exact ELF with checked fingerprints and owner attribution.

Both candidate C6 builds complete. The unchanged decoder's 14 offline tests pass.
A runner-path preflight stopped before flashing; the corrected invocation ran both
long workloads. No retained runnable/portable code changes remain, so no new full
host Memcheck/sanitizer campaign is claimed for this documentation-only stage.
There is no new CSA, phone pairing or ESP-Matter reference campaign.

The lab proceeds directly to Memory38. Final normal firmware, original fabric and
network cleanup will be recorded at the end of the three-step sequence.

Next task: phase-owned OTA Requestor memory, followed by a measured Read/Subscribe
block-occupancy audit. Consider grouped persistent SDK initialization only as a
separate experiment; this result does not justify another unmeasured startup move.
