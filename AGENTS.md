# Contributor instructions

Read README.md and doc/oss/status.md. Preserve the C API, per-instance ownership
and application-owned scheduler. Inspect definitions/callers before editing;
avoid unrelated refactors and large task-stack buffers. Keep third-party notices.
Run focused tests and report actual results. Runnable-host changes require a full
Linux scenario under Memcheck, then separately ASan/UBSan/LSan. Never relabel a
local test as CSA PASS. Record limitations and one next task. Do not publish,
configure remotes, commit private credentials/state or change licensing without
the owner's request. Keep local paths/configuration in ignored local/ or build/.
