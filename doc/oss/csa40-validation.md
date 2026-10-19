# CSA40: TC-SC-1.1 MRP Max Message Size

CSA39 is committed as **`6c46cfd`**. Original **TC-SC-1.1** has **manual PASS**
in **TH v2.15.1+summer2026 run475**: both procedure steps and evidence upload
pass. The test source, support files and PICS are unchanged. The existing Linux
transport already enforces the required boundary; **no native C/H fix** was
needed. See [record and receipts](csa40-results.json).

## Meaning of 1280 bytes

Core1.6.1 **4.4.4** requires UDP messages, including transport headers, to fit
within the minimum IPv6 MTU. **4.15** explicitly describes MRP datagrams fitting
within an IPv6 MTU of1280 bytes to avoid fragmentation/reassembly. With no IPv6
extension headers, that is **40 IPv6 + 8 UDP + 1232 Matter bytes**. A1280-byte
Matter/UDP payload would occupy1328 bytes and exceed the limit.

The procedure's wording, “1280 bytes inclusive of headers”, is applied with
this normative accounting. Both boundary packets and the alternative1280-byte
UDP-payload size are exercised, without changing the original procedure. No
test/spec discrepancy or request to enlarge the native limit is identified.

The Linux backend already checks complete IPv6 payload length in its socket
filter, rejects fragments/truncation and exposes at most1232 bytes to the core.
The runtime/retransmission ceilings agree. IPv6 extension headers reduce the
usable payload; this campaign does not rerun the earlier extension/fragment lab.

## Actual messages and observations

The existing external recorder gains mutually exclusive **`--mrp-size`**. It
constructs reliable unsecured PBKDFParamRequests with valid small application
TLV. Core **4.4.1.7 Message Extensions (MX)** supplies skip-only padding to reach
the exact datagram lengths. These are Matter extensions, not IPv6 extensions;
the receiver must skip the block. This keeps PASE application-buffer limits
separate from the transport-size test.

| Matter / UDP payload | Complete IPv6 packet | DUT observation |
| --- | --- | --- |
| 1231 B | 1279 B | Matching ACK and valid PBKDFParamResponse |
| 1232 B | 1280 B | Matching ACK and valid PBKDFParamResponse |
| 1233 B | 1281 B | No response |
| 1280 B | 1328 B | No response |
| 1281 B | 1329 B | No response |

Each input has a unique ephemeral source, exchange and counter; oversize inputs
are not duplicates of an already acknowledged packet. Fresh Linux IPv6 UDP
sockets have no IPv6 extension options and set DONTFRAG. Every send succeeds.
Packet totals are derived from the actual datagram lengths plus fixed40+8
headers; no privileged full-packet capture is claimed. Observe each case for
**2 seconds**. The positive response must acknowledge the sent counter/exchange
and address the original source; the PBKDF response must echo its request random.
Private raw records are checked independently against all ten public receipts.

The fixture ACKs each reliable PBKDF response, then sends a malformed Pake1 only
to terminate that deliberately incomplete positive handshake. This cleanup is
separate from the size verdict and **does not claim to repair CSA39**. Its
missing terminal error StatusReport remains in the deferred failure backlog.

Without restarting the DUT, unmodified chip-tool then commissions a fabric,
verifies attestation/CommissioningComplete, reads through CASE, opens an enhanced
window, commissions a second independent fabric and confirms the first still
works. The shared positive-PASE transcript checks remain active.

## Validation

Two full scenarios pass **32 checks each**: first under **Memcheck**, separately
under **ASan/UBSan/LSan**. Together they cover ten size probes and four subsequent
full commissions with CASE. Both nodes exit0 and both stderr files are empty.
Memcheck has **43,533 allocations / 43,533 frees**, zero errors and zero live
bytes. The native host binaries match the recorded CSA35 builds; all362 native
source/header manifest entries match locally and on the build VM.

The focused targets `test_message_header`, `test_retransmission`,
`test_retransmission_sender`, `test_udp` and `test_unsecured_rx` were built and
pass **5/5 per normal/sanitizer build**, with no compiler warnings observed.
The first CTest invocation failed because these executables did not yet exist
in the reused build directory. After building them, the final runs pass; this
setup failure is retained privately and is not classified as a native defect.
The host itself was not recompiled. Inventory/hash/count/link checks and
`git diff --check` pass. TH is idle and disposable nodes are stopped. Paired
Windows nodes were not restarted or changed.

```sh
python tools/matter/tests/test_pase_exchange_chip.py \
  --node /path/to/normal/matter-node --chip-tool /path/to/chip-tool \
  --paa /path/to/development-paa --credentials /path/to/development-credentials \
  --interface INTERFACE_ID --ipv6 SELECTED_INTERFACE_IPV6 \
  --output /path/to/fresh-private-output --mrp-size --valgrind
# Repeat separately with the sanitizer node, without --valgrind.
cmake --build BUILD --target test_message_header test_retransmission \
  test_retransmission_sender test_udp test_unsecured_rx -j2
ctest --test-dir BUILD --output-on-failure \
  -R '^(test_message_header|test_retransmission|test_retransmission_sender|test_udp|test_unsecured_rx)$'
python tools/matter/check_test_map.py
git diff --check
```

This is evidence-backed operator acceptance in the **original manual TH
procedure**, not a fully automatic CSA test or certification. Finite silence
observations do not prove every future/internal state. Physical firmware/radio,
Windows transport, Home UI, embedded RAM-fit and the complete CSA matrix were
not rerun. Legacy TC-SC-2.1 discrepancy fields in the shared private reports are
not this case verdict and are excluded from the public JSON projection. Raw
packets, logs, credentials and controller state stay outside Git.

Only TC-SC-1.1 gains `manual_result=PASS`. Category totals remain **97 PASS,
18 FAIL, 3 BLOCKED, 39 MANUAL, 705 NA**,862 positions. MANUAL now contains
**13 PASS, 4 FAIL and 22 without an outcome**. Continue initial coverage of
**22 manual plus 3 BLOCKED**; the18 automatic and4 manual failures remain
deferred as requested. Earlier outcomes are inherited.

**Next: CSA41 — TC-SC-1.2, MRP Message Flows.** Review reliable replies,
piggyback/standalone ACKs and unreliable replies against Core before executing
the original procedure. No result for CSA41 is claimed.
