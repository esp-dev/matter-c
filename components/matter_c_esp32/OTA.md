# Native ESP image installation

`matter_idf_ota` is an application-owned installer for ESP-IDF 6.0.2/6.1. It
streams a standard Matter OTA image into the inactive ESP OTA app partition.
It does not use the runtime's optional **WWOTA simulation** journal.

Requirements:

- Two OTA app partitions and `otadata`, with SDK app rollback enabled.
- `SECURE_SIGNED_APPS_NO_SECURE_BOOT` and
  `SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT`. Sign the initial app as well as each
  update; the SDK obtains the trusted public signing key from the current image.
  This adapter does not configure hardware Secure Boot or write eFuses.
- An unsigned decimal ESP app descriptor version equal to Matter SoftwareVersion.
  The new descriptor must identify the same `project_name`. Matter VID/PID,
  applicability range, offered version, payload size and SHA-256 must match.
- A dedicated NVS namespace, initialized by the application, and one writer.
  The existing atomic blob adapter publishes a separate fixed `MOTA01` record;
  the Matter fabric checkpoint and ESP app image formats are unchanged.
- An operational resolver and outbound UDP path for CASE, BDX and notification.
  Pin the concrete local IPv6 source in that path; a wildcard cannot match the
  received reverse handshake route. The C6 LAN fixture uses its stable link-local
  address, including after Wi-Fi reconnect. Route admission stays strict.
  The C6 user-case fixture uses the same copied mDNS 1.14.0 component as its
  ESP-Matter reference. Older component versions need their async lifetime
  behavior reviewed before use with `matter_idf_resolver`.

Create the installer, borrow `matter_idf_ota_port()` into
`matter_runtime_set_ota()` **before start**, and keep it alive until runtime
stop/drain/delete completes. `config.update` (simulation) and the real installer
are mutually exclusive. Without either installer, the runtime retains its
existing download-only behavior and rejects installation.

The application owns the schedule and these boot decisions:

1. Download workspace, TLV tags and PSA hash state are allocated on demand.
   Writes are sequential and bounded by the inactive partition. The sink's
   `finish` checks the payload digest, descriptor and SDK image signature; it
   stages an image, never selects a boot partition.
2. The runtime calls `commit` after BDX retirement. Before accepting Apply, the
   adapter rereads and authenticates the same artifact. It publishes the provider
   context and fabric fingerprint before selecting the boot partition. Flash/NVS
   uncertainty latches further installations offline until reboot.
3. After `matter_runtime_ota_reboot_requested()`, keep pumping RX/TX until
   `matter_runtime_ota_reboot_ready()`, then perform normal runtime stop/drain and
   release its borrowed backends before restarting. A timeout never permits
   freeing an active transaction or ciphertext still owned by TX/MRP.
4. On boot, the adapter reconciles the journal with the **actual running**
   partition, version and payload hash. An incomplete handoff or SDK rollback
   clears the old candidate and reports recovery; it cannot claim installation.
   Corrupt metadata fails closed. Do not erase commissioning state to hide a
   constructor error or confirm an unknown pending image.
5. Once the application has started and checked its required services, call
   `matter_runtime_ota_boot_ready()`. The real SDK image is confirmed first,
   followed by durable notification readiness and VersionApplied publication.
   OOM during event publication can be retried. A reset between SDK confirmation
   and journal publication is recoverable.
6. NotifyUpdateApplied is bound to the original fabric's certificate fingerprint.
   A removed/replaced fabric drops the notification. Consumption is persisted
   **before** the single application-level attempt; normal MRP retries still
   apply. As with the existing simulation policy, a crash between consumption
   and dispatch can lose this notification: this is not an exactly-once delivery
   guarantee across power loss.

The resolver has eight demand-owned jobs and monotonic IDs. It queries SRV,
then the target's AAAA when needed, and optional TXT for MRP intervals. An SDK `ANY` service query can finish with
TXT alone and cannot establish a usable route. Cancellation drains the SDK
search before releasing the job. Keep mDNS and the borrowed netif alive through
runtime drain and resolver deletion. No new network or Matter task is created.

The default historical runtime image still uses its factory-only partition map
and has native OTA disabled. The separate user-case profile selects dual OTA,
local NVS Wi-Fi provisioning and signed numeric versions. The private signing
key, AP credentials, controller fabrics and flash backups belong in ignored
`local/` or `build/`, never in source archives.
