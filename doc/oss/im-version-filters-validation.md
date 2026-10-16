# DataVersionFilters resubscription recovery

Validated on 2026-10-16. This is a local interoperability regression, not a CSA
PASS or certification. Previously pending CSA21 work remains separate.

This records the original 1024-byte-budget repair. The later
[CSA22 update](csa22-validation.md) migrates RX/TX buffers and derives larger
Read/Subscribe budgets from the UDP ceiling; its current tests use 83 filters.

## Failure and implementation

Live metadata-only debugging showed ResourceExhausted (0x89) while decoding a
547-byte Apple SubscribeRequest: one attribute selector, 16 filters already
stored, no expanded results. The initial subscription worked; resubscription
with cached cluster versions reached the implementation's fixed table limit.
The old Read/Subscribe decoders fail the new native regression tests.

Core R1.6.1 sections 8.4, 8.5.3.4, 10.6.3 and 10.7.2.4 define version filtering
and its priming-only Subscribe semantics; 16 is not a normative filter limit.
Both decoders now validate/count every filter before allocating exactly that
many entries. Each table belongs to its interaction; empty lists need no table.
Read deletes it with its handler; Subscribe frees it after priming and on
error/cancel/delete. Allocation failure returns ResourceExhausted before value
callbacks or subscription reservation. Duplicate conflicting filters still
prevent suppression, and malformed late entries still invalidate the request.

The existing implementation budget is 1024 bytes per IM request. The defensive
filter count bound derives from a minimum 14-byte concrete DataVersionFilterIB;
it is not a preallocated table or a standard limit. TLV token validation now
allows up to that byte budget, because every token consumes at least one byte.
This change does not expand supported message sizes, path counts or SDU limits.
Other fixed tables are outside this fix.

## Executed validation

- Windows and Linux Debug builds: four focused CTests each, all PASS.
- Separate Linux ASan/UBSan/LSan build: the same four CTests PASS.
- Native cases: 70 filters, more than 256 TLV tokens, conflicting duplicate at
  the end, malformed final filter, priming-only suppression, allocation failure,
  subscription reservation failure and deletion during collection.
- Complete Linux host with unmodified chip-tool under Memcheck: 25 checks PASS,
  31,177 allocations and frees, zero live bytes, zero errors, empty host stderr.
- Separate complete sanitizer host: 24 checks PASS, clean exit, empty stderr.
- Both network runs: verified development attestation, complete inventory above
  256 attributes, 17 distinct cluster filters, suppressed unchanged priming,
  subsequent On/Off report, controller restart, discovery plus fresh CASE,
  repeated filtered subscription, opposite On/Off report and RemoveFabric reply.
- Windows node retained its paired fabrics. The user confirmed Apple Home online
  and working On/Off. The diagnostic debugger was detached afterwards.

The controller initially rejected unequal CLI vector lengths before transmitting
Subscribe; the driver now supplies equally sized endpoint/cluster/attribute
vectors. Another initial oracle incorrectly required constant DataVersion across
an entire chunked read; diagnostics can change during collection, so the driver
retains the latest received version. Only the completed runs above count as PASS.

Controller SHA-256:
`7203652c18c2773274d738506fce137598e1478b28502259e8751c7d9b30b459`.
Network-tested host hashes: Memcheck
`a038b5d3e15f46292a6344800b7f18f9fa3bae69e48ee22065cbecb99e8ab779`,
sanitizers `588b1722aace60cef51c1a5514876c846b818fc2e8d1487ef9031714018db405`.
Subsequent source changes only formatted those decoder loops, clarified header
comments and added cleanup tests; both final builds passed the focused CTests.
No full CSA campaign, long-duration Home reliability run, physical target or
Google Home regression was performed. Private captures/state remain outside Git.

## Reproduction

```sh
cmake --build build/cmake --target matter-node test_im_read test_im_read_alloc test_im_subscribe test_im_subscribe_alloc
ctest --test-dir build/cmake --output-on-failure -R '^test_im_(read|subscribe)(_alloc)?$'
python tools/matter/tests/test_im_version_filters_chip.py \
  --exe build/cmake/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/paa --credentials /path/to/credentials \
  --interface 2 --output build/filter-memcheck --memcheck
# Repeat with a separately built MATTER_SANITIZE=ON host, a fresh output directory
# and without --memcheck. Outputs/controller state are private ignored artifacts.
```

Next planned CSA task remains CSA22 — TC-SU-2.4 ApplyUpdateRequest fields and
token/version binding.
