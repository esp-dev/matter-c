# CSA52: authenticated IM without request ACK

Original **TC-SC-1.2 now PASS, TH run489:7 passed steps**, unchanged test/support/PICS. Supersedes run476's native rejection of all R=0 IM. [Evidence and commands](csa52-results.json).

New supported authenticated IM transactions no longer require R=1. PASE/CASE remain reliable; vendor, protocol, initiator, secure-session and quota checks stay intact. ACK metadata follows each received R flag, including resource BUSY output, so R=0 produces no request ACK. Response packets independently keep reliable MRP and its lifecycle. No API, allocation budget or timing constant changes.

Independent wire peer verifies actual reliable PASE confirmation using affine SPAKE2+ test arithmetic and cryptography AES-CCM. Five distinct authenticated R=0 VendorID reads each receive correct data with A=0/R=1. R=1 controls before and after work in the same session. Reliable PBKDF data piggybacks the matching ACK; an exact duplicate gets only an empty standalone ACK. CloseSession then releases this PASE context, followed by two real unmodified chip-tool commissions and CASE reads without node restart.

Both complete Memcheck and separate ASan/UBSan/LSan scenarios pass26 functional and7 conformance checks each. Memcheck:48,362 allocations/frees, zero errors/live bytes. Both nodes exit0 with empty stderr. Eight focused CTests pass per normal/sanitizer build, no compiler warnings observed. Private admission regression covers R=0/R=1 and capacity BUSY. Its initial mock omitted RX action and correctly failed as DROP; this tester error is retained and corrected to NEW_RESPONDER.

Only portable dispatcher and existing dispatcher test change, plus this evidence and campaign state. Full Linux hosts were rebuilt. No physical/Windows/Home UI, embedded RAM fit, all loss/command combinations or full matrix rerun. Finite0.7-second observations and live peer decryption are distinguished from later raw capture inspection; no keys are exported. Disposable nodes stopped, TH idle, paired Windows nodes untouched. No push.

Automatic totals remain98 PASS/19 FAIL/1 BLOCKED,37 MANUAL,707 NA. Manual:24 PASS/9 FAIL/4 BLOCKED.150 applicable positions have outcomes,5 prerequisites remain. Next:CSA53, group unresolved assertions using earlier analyses and run bounded remaining automatic rechecks where prerequisites are satisfied.
