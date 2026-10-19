# CSA54: two actual factory setup codes

Original automatic **TC_SC_7_1 PASS, TH run492:6 passed steps**. Correct two-device inputs replace historical run208's invalid discriminator-only invocation; native code, original test/support and PICS unchanged. [Evidence](csa54-results.json).

Two real simultaneous x86 node processes have separate listener ports/private stores and different configured PINs/discriminators. Current C GUI pairing code generates both QR payloads. The TH qr-code parameter supplies the two actual codes and avoids discriminator-only arguments. Original SDK resolves both nodes, establishes PASE, reads empty TrustedRootCertificates from each, then compares distinct discriminators/passcodes. No post-cert single-device shortcut, test patch or PICS bypass.

C payload helper compiled with gcc C99 O2 Wall Wextra Werror without warnings; current source hashes match. Native host is byte-identical CSA52. Both nodes exit0 with empty stderr, TH idle and paired Windows nodes untouched. QR/setup values, project configuration, state and raw logs remain ignored. No new native build or memory scenario: CSA52's full Memcheck/sanitizer recovery and8 CTests per build are inherited, not new CSA54 tests.

This proves the configured simulator inputs and PASE behavior. Manufacturing randomness, persistent per-unit secret provisioning, physical labels/radio and product certification remain separate. No full-matrix rerun or push.

Campaign:99 automatic PASS/18 FAIL/1 BLOCKED,37 MANUAL (24 PASS/9 FAIL/4 BLOCKED),707 NA. Across155 applicable positions:123 PASS,27 FAIL and5 unresolved prerequisites. Every currently executable position has an outcome, but several FAILs still require attribution/CSA or fixture resolution. Next:CSA55, independent GroupKeyMap write-status and optional Leave EventStatus observations, avoiding another blind rerun.
