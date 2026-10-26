# Validation report index

These reports retain their original revision/profile, outcomes and limitations.
They are historical evidence, not a declaration that the current branch passed
every listed case. Begin with [current status](status.md), the
[test map](test-map.md) and the [CSA queue](csa-campaign-status.md).

## Memory and ESP integration

| Report | Scope |
| --- | --- |
| [memory01-validation](memory01-validation.md) | Memory01: operation-owned storage scratch and demand-sized event snapshots |
| [memory02-validation](memory02-validation.md) | Memory02: live transaction nodes and demand-sized TX packets |
| [memory03-validation](memory03-validation.md) | Memory03: demand-allocated event retention and atomic batch staging |
| [memory04-validation](memory04-validation.md) | Memory04: shared demand-sized Read/Subscribe value snapshots |
| [memory05-validation](memory05-validation.md) | Memory05: demand allocation for Invoke, Write and client messages |
| [memory06-validation](memory06-validation.md) | Memory06: transient IM workspaces and demand CASE resumption cache |
| [memory07-validation](memory07-validation.md) | Memory07: Fabric publication peak |
| [memory08-validation](memory08-validation.md) | Memory08: handshake phase storage and memory budget |
| [memory09-validation](memory09-validation.md) | Memory09: concurrent reporting storage and transient secure RX |
| [memory10-validation](memory10-validation.md) | Memory10: shared event snapshots and compact Read delivery tails |
| [memory11-validation](memory11-validation.md) | Memory11: stable demand-allocated Read/Subscribe result blocks |
| [memory12-validation](memory12-validation.md) | Memory12: demand-allocated Read/Subscribe event path metadata |
| [memory13-validation](memory13-validation.md) | Memory13 — initial ESP-IDF integration and physical memory laboratory |
| [memory14-validation](memory14-validation.md) | Memory14 — C6 UDP/IPv6, discovery and durable runtime |
| [memory15-validation](memory15-validation.md) | Memory15 — sustained C6 concurrency validation |
| [memory16-validation](memory16-validation.md) | Memory16: RGB laboratory and lower concurrent-report peak |
| [memory17-validation](memory17-validation.md) | Memory17: inline short snapshots and packet-buffer audit |
| [memory18-validation](memory18-validation.md) | Memory18: delivery/plain storage shared across phases |
| [memory19-validation](memory19-validation.md) | Memory19: borrow RX queue bytes through delivery |
| [memory20-validation](memory20-validation.md) | Memory20: one Read/Subscribe encoding area per dispatcher |
| [memory21-validation](memory21-validation.md) | Memory21: settled heap, SDK attribution and a physical reference |
| [memory22-validation](memory22-validation.md) | Memory22: own-fabric response progress and C6 RAM attribution |
| [memory23-validation](memory23-validation.md) | Memory23: bounded Fabric undo and committed TLV projection |
| [memory24-validation](memory24-validation.md) | Memory24: host isolation of subscription startup |
| [memory25-validation](memory25-validation.md) | Memory25: reusable native runtime wire regression |
| [memory26-validation](memory26-validation.md) | Memory26: C6 startup 14/15, UART 1M and ACK role tracing |
| [memory27-validation](memory27-validation.md) | Memory27: reproducible single-ACK wire regression |
| [memory28-validation](memory28-validation.md) | Memory28: consume ready RX before admitting a new packet |
| [memory29-validation](memory29-validation.md) | Memory29: normal C6 peak and allocation-site attribution |
| [memory30-validation](memory30-validation.md) | Memory30: compact shared Read/Subscribe report plans |
| [memory31-validation](memory31-validation.md) | Memory31: selective stable Subscribe value blocks |
| [memory32-validation](memory32-validation.md) | Memory32: demand-sized Diagnostics encoding |
| [memory33-validation](memory33-validation.md) | Memory33: demand-sized ACL encoding |
| [memory34-validation](memory34-validation.md) | Memory34: demand-sized Fabric encoding and VID scratch |
| [memory35-validation](memory35-validation.md) | Memory35: phase-owned Operational Credentials workspaces |
| [memory36-validation](memory36-validation.md) | Memory36: settled heap and SDK allocation islands after fault teardown |
| [memory37-validation](memory37-validation.md) | Memory37: RMT startup-order experiment |
| [memory38-validation](memory38-validation.md) | Memory38: phase-owned OTA Requestor memory |
| [memory39-validation](memory39-validation.md) | Memory39: Read/Subscribe block occupancy |
| [memory40-validation](memory40-validation.md) | Memory40: retire acknowledged Read prefix blocks |
| [memory41-validation](memory41-validation.md) | Memory41: application headroom and lifecycle comparison |
| [memory42-validation](memory42-validation.md) | Memory42 — signed native ESP OTA |
| [memory43-validation](memory43-validation.md) | Memory43 — same-IDF user case, including real OTA |

## CSA procedure investigations

Original, manual, local-patch and compatibility results remain distinct.

| Report | Scope |
| --- | --- |
| [csa01-validation](csa01-validation.md) | CSA01: complete installed-catalog matrix for the x86 profile |
| [csa02-validation](csa02-validation.md) | CSA02: commissioning and fabric lifecycle |
| [csa03-validation](csa03-validation.md) | CSA03: Descriptor and endpoint composition |
| [csa04-validation](csa04-validation.md) | CSA04: subscription reporting and fabric-removal notifications |
| [csa05-validation](csa05-validation.md) | CSA05: invalid Read/Subscribe attribute paths |
| [csa06-validation](csa06-validation.md) | CSA06: Access Control validation |
| [csa07-validation](csa07-validation.md) | CSA07: discovery on repeated commissioning |
| [csa08-validation](csa08-validation.md) | CSA08: General Diagnostics runtime acceptance |
| [csa09-validation](csa09-validation.md) | CSA09: invalid CASE input and failure report delivery |
| [csa10-validation](csa10-validation.md) | CSA10: Commissionable Node Discovery |
| [csa11-validation](csa11-validation.md) | CSA11: resource minima and concurrent subscriptions |
| [csa12-validation](csa12-validation.md) | CSA12: incorrect passcodes and commissioning-window closure |
| [csa13-validation](csa13-validation.md) | CSA13: full fabric table and commissioning failure status |
| [csa14-validation](csa14-validation.md) | CSA14: connected Wi-Fi host simulation and CNET 4.1/4.4 |
| [csa15-validation](csa15-validation.md) | CSA15: Wi-Fi removal and two-network migration |
| [csa16-validation](csa16-validation.md) | CSA16: PASE RevokeCommissioning response discrepancy |
| [csa17-review-validation](csa17-review-validation.md) | CSA17 follow-up: reporting repair and RemoveFabric acceptance |
| [csa17-validation](csa17-validation.md) | CSA17 validation - 2026-10-14: STOP for review |
| [csa18-validation](csa18-validation.md) | CSA18: targeted three-phase energy test inputs |
| [csa19-validation](csa19-validation.md) | CSA19: OTA provider, image and restart fixture |
| [csa20-validation](csa20-validation.md) | CSA20: QueryImageResponse acceptance and the announcement timing floor |
| [csa21-validation](csa21-validation.md) | CSA21: OTA transfer interruption and peer-session recovery |
| [csa22-validation](csa22-validation.md) | CSA22: ApplyUpdateRequest binding and dynamic IM buffers |
| [csa23-validation](csa23-validation.md) | CSA23: ApplyUpdateResponse actions, delays and retries |
| [csa24-validation](csa24-validation.md) | CSA24: automatic ApplyUpdateResponse acceptance |
| [csa24a-validation](csa24a-validation.md) | CSA24a: configurable subscription capacity |
| [csa24b-validation](csa24b-validation.md) | CSA24b: chronological progress and subscription cleanup in the SDK test |
| [csa25-validation](csa25-validation.md) | CSA25: NotifyUpdateApplied after a simulated OTA restart |
| [csa26-validation](csa26-validation.md) | CSA26: OTA Requestor events |
| [csa27-validation](csa27-validation.md) | CSA27: OTA Requestor attributes |
| [csa28-validation](csa28-validation.md) | CSA28: automatic QueryImageResponse scenarios |
| [csa29-validation](csa29-validation.md) | CSA29: Identify and laboratory recovery |
| [csa30-validation](csa30-validation.md) | CSA30: General Diagnostics, Node time and transport interfaces |
| [csa31-validation](csa31-validation.md) | CSA31: onboarding QR and manual setup payloads |
| [csa32-validation](csa32-validation.md) | CSA32: last-fabric removal and discovery |
| [csa33-validation](csa33-validation.md) | CSA33: commission, remove and recommission |
| [csa34-validation](csa34-validation.md) | CSA34: Commissionable Node announcements |
| [csa35-validation](csa35-validation.md) | CSA35: PH and Extended Discovery policy |
| [csa36-validation](csa36-validation.md) | CSA36: Commissioner Discovery / UDC applicability |
| [csa37-validation](csa37-validation.md) | CSA37: original manual PASE exchange procedure |
| [csa38-validation](csa38-validation.md) | CSA38: bidirectional PASE and decryption errors |
| [csa39-validation](csa39-validation.md) | CSA39: invalid passcodeID and Pake3.cA |
| [csa40-validation](csa40-validation.md) | CSA40: TC-SC-1.1 MRP Max Message Size |
| [csa41-validation](csa41-validation.md) | CSA41: TC-SC-1.2 MRP Message Flows |
| [csa42-validation](csa42-validation.md) | CSA42: TC-SC-1.3 MRP Retransmissions |
| [csa43-validation](csa43-validation.md) | CSA43: TC-SC-1.4 counters and duplicates |
| [csa44-validation](csa44-validation.md) | CSA44: Descriptor profile and endpoint hierarchy |
| [csa45-validation](csa45-validation.md) | CSA45: BDX receiver and real IM Invoke client |
| [csa46-validation](csa46-validation.md) | CSA46: diagnostic events, network reorder and group-key policy |
| [csa47-validation](csa47-validation.md) | CSA47: applicability and concrete prerequisites |
| [csa48-validation](csa48-validation.md) | CSA48: five-fabric subscription resources |
| [csa49-validation](csa49-validation.md) | CSA49: event Read/Subscribe and fabric-sensitive data |
| [csa50-validation](csa50-validation.md) | CSA50: keyset capacity and actual factory reset |
| [csa51-validation](csa51-validation.md) | CSA51: terminal PASE error delivery |
| [csa52-validation](csa52-validation.md) | CSA52: authenticated IM without request ACK |
| [csa53-validation](csa53-validation.md) | CSA53: remaining assertions, without repeating resolved diagnosis |
| [csa54-validation](csa54-validation.md) | CSA54: two actual factory setup codes |
| [csa55-validation](csa55-validation.md) | CSA55: GroupKeyMap status and optional Leave attribution |
| [csa56-validation](csa56-validation.md) | CSA56: host UDP receive starvation repaired |
| [csa57-validation](csa57-validation.md) | CSA57: actual stalled BDX recovery |
| [csa58-validation](csa58-validation.md) | CSA58: frozen automatic regression sweep |
| [csa59-validation](csa59-validation.md) | CSA59: Timed Write interval and MRP retry attribution |
| [csa60-validation](csa60-validation.md) | CSA60: application query trigger; original OTA FAIL retained |
| [csa61-validation](csa61-validation.md) | CSA61: OTA event startup order; original FAIL retained |
| [csa62-validation](csa62-validation.md) | CSA62: drain Applying reports before simulated OTA reboot |
| [csa63-validation](csa63-validation.md) | CSA63: QueryImage provider handoff and retry attribution |
| [csa64-validation](csa64-validation.md) | CSA64: OTA recovery through a new CASE session after backoff |
| [csa65-validation](csa65-validation.md) | CSA65: VM network outage during the early OTA failure |
| [csa66-validation](csa66-validation.md) | CSA66: same-instance OTA recovery after a resolver send failure |
| [csa67-validation](csa67-validation.md) | CSA67: host resolver recovery after a fatal receive error |
| [csa68-validation](csa68-validation.md) | CSA68: automatic ApplyUpdateResponse test review |
| [csa69-validation](csa69-validation.md) | CSA69: attestation identity and provisioning prerequisites |
| [csa70-validation](csa70-validation.md) | CSA70: distinct attestation credentials on two native instances |
| [csa71-validation](csa71-validation.md) | CSA71: reuse the TC_SU_4_1 status-vector attribution |
| [csa72-questions](csa72-questions.md) | CSA72: consolidated questions and rerun gates |
| [csa72-validation](csa72-validation.md) | CSA72: consolidated questions, rerun gates and VM activity |
| [csa73-integration-plan](csa73-integration-plan.md) | CSA73: frozen memory-branch integration and regression gates |
| [csa73-validation](csa73-validation.md) | CSA73: frozen Memory39 integration and regression |
| [csa74-comparison](csa74-comparison.md) | CSA74: compare historical failures with independent implementations |
| [csa75-compatibility](csa75-compatibility.md) | CSA75: explicit legacy SDK/test compatibility |
| [csa-campaign-plan](csa-campaign-plan.md) | Completing the CSA campaign |
| [csa-campaign-status](csa-campaign-status.md) | CSA campaign progress |

## Other validation and integration

| Report | Scope |
| --- | --- |
| [ble-transport](ble-transport.md) | Optional BLE commissioning transport |
| [bulb-integration](bulb-integration.md) | RGB bulb integration in the shared Matter library |
| [desktop-validation](desktop-validation.md) | Native desktop acceptance |
| [plug-energy-validation](plug-energy-validation.md) | Metered socket interoperability |
| [power-only-validation](power-only-validation.md) | Separate power-only sensor |
| [provenance](provenance.md) | Source and license inventory |
| [sensor-energy-validation](sensor-energy-validation.md) | Separate cumulative import/export on the minimal sensor |
| [sensor-only-validation](sensor-only-validation.md) | Root plus a power sensor only |
| [status](status.md) | Development status |
| [test-map](test-map.md) | Test inventory |
| [documentation-review](documentation-review.md) | README organization and scoped repository privacy review |
