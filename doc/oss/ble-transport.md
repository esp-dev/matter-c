# Optional BLE commissioning transport

`MATTER_C_ESP32_BLE` enables the ESP-IDF NimBLE peripheral and the UDP/BTP
network multiplexer. It is off by default. Enable NimBLE peripheral/broadcaster
roles in the product configuration. The existing IPv6-only port remains usable
without Bluetooth. Commissioning policy is explicit: setting runtime
`ble_commissioning_only` rejects new UDP PASE requests while retaining UDP CASE
and operational traffic. The product controls commissionable advertisements.

`Matter_Udp_Path_T.transport` selects UDP (zero, compatible with zero-initialized
callers) or BTP. Rebuild consumers after this structure extension. BTP uses
`interface_id` as a non-reused physical link generation; its IP endpoints are
unused. UDP backends reject BTP paths. BTP CASE initiation and MRP flags on BTP
are rejected at admission. Protocol quotas are shared between both bearers.

The portable `matter_btp` engine negotiates BTPv4, up to 244-byte fragments and
a four-fragment window. The existing 1232-byte datagram ceiling is unchanged.
RX SDU storage is allocated to the announced size and wiped/freed after owner
delivery. TX borrows an immutable caller buffer. An output proposal is stable
until `matter_btp_sent` commits the accepted copy; it must not be committed when
the lower-layer send fails. ACK, sequence wrap, malformed input, handshake and
ACK deadlines are handled by the engine. Allocation failure terminates that
link rather than publishing a partial SDU.

The SDK port implements FFF6/C1/C2 GATT, with four phase-owned RX frame slots.
NimBLE callbacks enqueue frames under a short lock; the application owner runs
the protocol engine. The multiplexer delivers at most one RX SDU per poll and
alternates bearer priority. Holding RX delivery does not suspend TX completion.
Hardware host ownership is exclusive until host stop, task deletion and
controller deinitialization form the callback lifetime barrier. A closed
commissioning window stops advertising; an established link may drain before
closure. Host/controller storage is then released without irreversible memory
release, allowing later commissioning windows to initialize Bluetooth again.

BTP sends bypass MRP; they complete only after the BTP acknowledgement and
confirmed ATT indication. The dispatcher keeps ciphertext alive through this
completion and uses the common transaction-sent transition. Stop/drain waits
for outstanding direct completions. After physical disconnect, the product
forwards `matter_idf_network_closed_take` to `matter_runtime_link_closed` on the
owner thread. This retires only routes/transactions for that generation and
does not tear down unrelated UDP sessions. Reentrant closure returns BUSY.

`test_btp` covers 20/244-byte fragmentation, maximum SDUs, sequence wrap,
negotiation, malformed traffic, deadlines and allocator failure. Dispatcher
tests cover bearer admission, immutable direct TX, drain, generation retirement
and reentrancy. Native tests do not emulate the SDK allocator, controller,
radio timing or phone applications; physical acceptance is recorded by the
separate bulb application. These results are not CSA certification.
