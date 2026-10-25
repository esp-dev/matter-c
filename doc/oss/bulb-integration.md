# RGB bulb integration in the shared Matter library

Development profile for the separate bulb application. The integration base
combines the main repository through Memory39/CSA73 with Memory40 and native
ESP OTA (Memory42/43). Application-specific LED, HTTP factory
provisioning and partition layout belong to the product repository. Protocol,
cluster and reusable ESP-port changes belong here.

`matter_light` provides Identify/Lighting OnOff/Lighting Level and HS/XY/CT
Color Control for an Extended Color Light endpoint (device revision 5).
`matter_light_groups` composes Groups, Scenes Management and optional root
Groupcast Listener/PerGroup. This helper currently supports one light endpoint;
it is not a general bridge or multi-light aggregator. Optional color-loop,
enhanced-hue, scene names, group names, Groupcast Sender and CacheAndSync are
not selected. Existing runtime configurations default to the previous profile.

The optional runtime group composition binds the existing atomic fabric key and
ACL backends. Extra group/scene metadata uses a separate application-owned atomic
blob. A root-public-key/FabricID binding prevents index reuse from resurrecting
old data. Cleanup failure closes group/configuration admission and commissioning
without bypassing ordinary unicast ACK/TX drain. Groupcast Leave uses durable
tombstones so interrupted key cleanup can resume. InputKeys are never persisted
by this metadata store. The core fabric persistence format is unchanged.

Limits are 40 demand-allocated group records, at most 20 per fabric, with room
reserved for the four-group minimum of each of five fabrics. Scene capacity is
16, at most seven per fabric. Multicast join precedes persistent publication;
unused addresses remain owned until a successful leave, retried by process.
Group RX has at most eight queued datagrams within the existing 1232-byte ceiling.
TrustFirst replay records are allocated only after authentication, at most 128
source/key pairs, and never evicted. Preserve the group owner across runtime
restarts in one node boot; destroying and recreating it with unchanged keys is
not a permitted way to reset replay protection.

Group commands reuse the existing IM parser/normalizer and authorization order.
They expand an endpoint-less path to the configured non-root endpoint and never
create an exchange, response packet, ACK or MRP state. Command argument/body
depth is now five and the response envelope depth nine for real scene extension
lists; the 1024-byte request/provider-body ceilings and one-path limit remain.
Providers that generate command responses still receive demand-owned response
storage before side effects, even though group responses are discarded.

Public additions require consumers to rebuild: optional runtime configuration,
trusted group request provenance, ACL/group-key extension ports, group-only ACL
grants and callback-compatible AES privacy. No CASE identity is synthesized for
group traffic. Auxiliary ACL writes are rejected; generated entries do not
consume the writable ACL table. Auxiliary updates prepare their event before
the metadata store, and abort it if that store fails. Leaving a fabric emits no
auxiliary-update event.

Focused host tests cover lighting transitions/startup/store failure, group/scene
publication/reboot/OOM, fabric separation/index reuse, multicast join/leave
failures, AES-CCM/privacy RX, replay, group ACL, shared IM depth and runtime
stop/delete/rebind. The privacy vector also has an independent AES-CTR oracle;
the replay model compares 60000 sequences against an explicit history model.
These are engineering tests, not certification results. The final portable
snapshot passes all 117 native definitions plus inventory/installed-consumer
checks on Linux, normally and separately under ASan/UBSan/LSan. Fourteen focused
fixtures and the complete two-instance lifecycle also pass Memcheck; the same
two-instance lifecycle passes sanitizers. The six faulted wire cases pass under
Memcheck and separately sanitizers on the preceding profile snapshot. Initial
wire deadlines and one missing subscription report in an intermediate two-node
run are retained in the evidence; isolated reruns and final runs pass.

Physical ESP32-C6 / IDF6.1 acceptance includes factory provisioning, retained
fabric, Read/Invoke/Subscribe, HSV/XY/CT transitions, Groups/Scenes/global scene,
Identify and a real signed OTA installation/reboot. The provider receives
NotifyUpdateApplied and subsequent control succeeds. Unmodified chip-tool also
commissions a second fabric, including attestation and final CASE, through a
byte-preserving SSH/UDP lab bridge with an operational DNS-SD alias. This is not
a native VM-to-WLAN discovery/routing test. Original short OO/LVL/CC YAML cases
are run by the separate product repository with explicit feature PICS; they do
not close historical main-repository CSA findings or prove Apple/Google Home.

Physical two-fabric acceptance also covers a two-second AP ban with continued
subscription reporting, and a twenty-second ban followed by fresh CASE/control
and subscription re-establishment. Next: product factory-reset acceptance. Physical group
multicast and a complete lighting certification campaign remain separate gates.

The optional joint `store_light` callback publishes global scene 0/0 and the
new light operating state in one application record. Failure publishes neither.
The portable default uses the existing light port; a durable product supplies
joint storage. HS/CT changes maintain XY for scene capture; HS recall reconstructs
eight-bit hue from stored XY, retaining the exact scene XY to avoid repeated
quantization. Pixel conversion is shared with scene/live-state conversion.

The ESP port supplies gated Wi-Fi reconnect with bounded jittered backoff, one
link-local creation per association (DAD must not be restarted every tick), and
demand-owned multicast memberships under the lwIP lock. It borrows the started
driver/netif and never stops a shared AP. The application gates passive reconnect
until runtime recovery and outside an armed fail-safe. External authenticated
network replacement requires runtime stop/drain and explicit persisted Wi-Fi
provisioning, followed by recreation/reboot; fabrics remain intact.

Restored OTA notification now prepares DNS/CASE and waits for handshake drain
before claiming its durable at-most-once application attempt. Offline boot,
resolver/CASE failure and a busy outgoing slot preserve the claim; failed peer
preparation retries after five seconds. After a claim, existing Invoke/MRP
semantics apply. Stop/delete also wait for preparation cancellation/drain. The
general outgoing peer API shares the existing single bounded slot and allocates
no IM request when only preparing a session. A prepared session is protected
from idle eviction until take; credential/fabric changes invalidate it.

General Commissioning persists Location even when the platform reports an
unsupported country, as required by the Root port contract; storage failure
still publishes neither setting. The ESP Wi-Fi adapter uses one common security
bitmap mapping for scan/observation, including mixed WPA/WPA2 and WPA2/WPA3;
unknown/enterprise modes are not misreported as WPA2-Personal.

Transient UDP OFFLINE now consumes the existing bounded MRP retry rather than
terminating a retained response/report immediately. The ESP port also reports a
temporarily missing pinned IPv6 source during reassociation/DAD as OFFLINE,
instead of a permanent argument error. Physical traces show both link-down and
link-up/source-not-ready phases. Limits, retry count, packet/counter identity
and stop/ACK/UDP drain are unchanged; offline retries do not hold work forever.
`MATTER_C_ESP32_UDP_TRACE`, off by default, logs only transport error/state flags,
never packet payloads. Silent applications leave it disabled.
