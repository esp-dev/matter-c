// Independent Matter.js 0.17.9 CASE/IM/OTA server; deterministic image catalogue.
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { writeFile, readFile, access } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import dgram from "node:dgram";
import { syncBuiltinESMExports } from "node:module";
// Same pinned-peer OS corrections as host_rediscovery.mjs: mDNS hop limit255
// and numeric IPv6 scopes mapped to interface names. CASE/IM remain unmodified.
let dropBlock = false, droppedBlock, duplicatedRetry = false;
let dropNotifyReply = false;
const createSocket = dgram.createSocket;
dgram.createSocket = (...args) => {
    const socket = createSocket(...args);
    socket.once("listening", () => { if (socket.address().port === 5353) socket.setMulticastTTL(255); });
    const send = socket.send.bind(socket);
    socket.send = (...sendArgs) => {
        const data = sendArgs[0];
        if (dropNotifyReply) {
            const callback = sendArgs.at(-1);
            if (typeof callback === "function") queueMicrotask(() => callback(null, data.length));
            return;
        }
        if (Buffer.isBuffer(data) || data instanceof Uint8Array) {
            const packet = Buffer.from(data);
            if (dropBlock && packet.length > 1024) {
                dropBlock = false; droppedBlock = packet;
                console.log("BDX_FAULT dropped first encrypted Block");
                const callback = sendArgs.at(-1);
                if (typeof callback === "function") queueMicrotask(() => callback(null, packet.length));
                return;
            }
            if (droppedBlock && !duplicatedRetry && packet.equals(droppedBlock)) {
                duplicatedRetry = true;
                console.log("BDX_FAULT identical ciphertext retry duplicated");
                const duplicate = [...sendArgs];
                if (typeof duplicate.at(-1) === "function") duplicate[duplicate.length-1] = () => {};
                send(...duplicate);
            }
        }
        return send(...sendArgs);
    };
    return socket;
};
syncBuiltinESMExports();
const [modules, address, port, directory, mode] = process.argv.slice(2);
const load = path => import(pathToFileURL(resolve(modules, path)).href);
const { NodeJsEnvironment } = await load("@matter/nodejs/dist/esm/index.js");
const { NodeJsNetwork } = await load("@matter/nodejs/dist/esm/net/NodeJsNetwork.js");
const namedInterface = intf => Object.entries(networkInterfaces()).find(([, addresses]) =>
    addresses.some(a => a.scopeid !== undefined && String(a.scopeid) === intf))?.[0] ?? intf;
const getIpMac = NodeJsNetwork.prototype.getIpMac;
NodeJsNetwork.prototype.getIpMac = function(intf) { return getIpMac.call(this, namedInterface(intf)); };
const createUdpSocket = NodeJsNetwork.prototype.createUdpSocket;
NodeJsNetwork.prototype.createUdpSocket = function(options) {
    return createUdpSocket.call(this, { ...options, netInterface: namedInterface(options.netInterface) });
};
const { CommissioningController } = await load("@project-chip/matter.js/dist/esm/CommissioningController.js");
const { OtaSoftwareUpdateProviderServer } = await load("@matter/node/dist/esm/behaviors/ota-software-update-provider/OtaSoftwareUpdateProviderServer.js");
const { OtaSoftwareUpdateRequestor } = await load("@matter/types/dist/esm/clusters/ota-software-update-requestor.js");
const { Descriptor } = await load("@matter/types/dist/esm/clusters/descriptor.js");
let queries = 0, applies = 0, notifications = 0, updateToken, firstApplyTime;
const sim = mode?.startsWith("bdx-sim-");
const applyMode = mode?.startsWith("bdx-apply-");
const bdx = mode?.startsWith("bdx");
if (mode === "bdx-fault") {
    const { BdxMessenger } = await load("@matter/protocol/dist/esm/bdx/BdxMessenger.js");
    const sendBdx = BdxMessenger.prototype.send;
    BdxMessenger.prototype.send = async function(message) {
        if (message.kind === 0x11 && !droppedBlock) dropBlock = true;
        return sendBdx.call(this, message);
    };
}
const { PersistedFileDesignator } = await load("@matter/protocol/dist/esm/bdx/PersistedFileDesignator.js");
const query = OtaSoftwareUpdateProviderServer.prototype.queryImage;
OtaSoftwareUpdateProviderServer.prototype.checkUpdateAvailable = async function () {
    let retry = false;
    if (mode === "bdx-sim-retry" && applies < 2) { try { await access(resolve(directory,"retry-ready")); retry = true; } catch {} }
    if (!bdx || ((mode === "bdx-apply-restart" || sim) && queries > 1 && !retry)) return undefined;
    const fd = new PersistedFileDesignator("image", this.updateStorage);
    await fd.writeFromStream(new Blob([await readFile(resolve(directory, "source.ota"))]).stream());
    return { fileDesignator: fd, newSoftwareVersion: 2, newSoftwareVersionString: "v2", consentRequired: false };
};
OtaSoftwareUpdateProviderServer.prototype.queryImage = async function (request) {
    if (request.vendorId !== 0xfff1 || request.productId !== 0x8001 || (request.softwareVersion !== 1 && !(sim && request.softwareVersion === 2)) ||
        (bdx ? (request.protocolsSupported.length !== 1 || request.protocolsSupported[0] !== 0) : request.protocolsSupported.length !== 0) || request.requestorCanConsent !== false) throw new Error("QueryImage identity/capabilities mismatch");
    queries++;
    console.log("PROVIDER_QUERY", queries, JSON.stringify(request));
    await writeFile(resolve(directory, `query-${queries}`), "received");
    if (!bdx && queries === 1) return { status: 1, delayedActionTime: 120 };
    const response = await query.call(this, request);
    if (response.updateToken) updateToken = Buffer.from(response.updateToken);
    return response;
};
const apply = OtaSoftwareUpdateProviderServer.prototype.applyUpdateRequest;
OtaSoftwareUpdateProviderServer.prototype.applyUpdateRequest = async function (request) {
    if (request.newVersion !== 2 || !updateToken || !Buffer.from(request.updateToken).equals(updateToken)) {
        throw new Error("ApplyUpdateRequest does not match QueryImageResponse token/version");
    }
    applies++;
    const now = Date.now();
    if (applies === 1) firstApplyTime = now;
    if (mode === "bdx-apply-await" && applies === 2 && now-firstApplyTime < 119900) throw new Error("Await floor bypassed");
    const response = await apply.call(this, request); // independent session/token/BDX bookkeeping
    if (applyMode || sim) {
        if (mode === "bdx-apply-discontinue") { response.action = 2; response.delayedActionTime = 86400; }
        else if (mode === "bdx-apply-await" && applies === 1) { response.action = 1; response.delayedActionTime = 0; }
        else { response.action = 0; response.delayedActionTime = mode === "bdx-apply-restart" || mode === "bdx-sim-interrupt" ? 30 : 2; }
    }
    await writeFile(resolve(directory, `apply-${applies}.json`), JSON.stringify({ action: response.action, delay: response.delayedActionTime, time: now }));
    console.log("PROVIDER_APPLY", applies, response.action, response.delayedActionTime);
    return response;
};
const notify = OtaSoftwareUpdateProviderServer.prototype.notifyUpdateApplied;
OtaSoftwareUpdateProviderServer.prototype.notifyUpdateApplied = async function(request) {
    if (!sim) return notify.call(this, request);
    if (request.softwareVersion !== 2 || !updateToken || !Buffer.from(request.updateToken).equals(updateToken)) throw new Error("Notify token/version mismatch");
    notifications++;
    await notify.call(this, request);
    if (mode === "bdx-sim-notify-timeout") dropNotifyReply = true;
    await writeFile(resolve(directory, `notify-${notifications}`), "valid token/version and CASE");
    console.log("PROVIDER_NOTIFY", notifications);
    if (mode === "bdx-sim-notify-error") throw new Error("Injected Notify failure");
};
const env = NodeJsEnvironment();
env.vars.set("storage.path", resolve(directory, "controller-store"));
const { Logger } = await load("@matter/general/dist/esm/log/Logger.js");
Logger.level = "info";
const controller = new CommissioningController({ environment: { environment: env, id: "ota-m14b" },
    autoConnect: false, enableOtaProvider: true, adminFabricLabel: "M14b query test" });
const waitFor = async (test, timeout = 35000) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) { if (await test()) return; await new Promise(r => setTimeout(r, 100)); }
    throw new Error("OTA acceptance timeout");
};
try {
    await controller.start();
    const { DeviceAdvertiser } = await load("@matter/protocol/dist/esm/protocol/DeviceAdvertiser.js");
    controller.node.env.get(DeviceAdvertiser).enterOperationalMode();
    controller.node.env.get(DeviceAdvertiser).restartAdvertisement();
    console.log("PROVIDER_DNS", controller.fabric.globalId.toString(16), controller.nodeId.toString(16), controller.node.state.network.operationalPort);
    const id = await controller.commissionNode({ passcode: 20202021,
        discovery: { identifierData: { longDiscriminator: 3840 }, knownAddress: { type: "udp", ip: address, port: Number(port) } },
        commissioning: { regulatoryLocation: 0, regulatoryCountryCode: "PL" } }, { connectNodeAfterCommissioning: false });
    const client = await controller.createInteractionClient(id);
    const clients = await client.getAttribute({ endpointId: 0, clusterId: 0x1d, attribute: Descriptor.Cluster.attributes.clientList });
    if (!clients.includes(0x29)) throw new Error("Missing Provider client role");
    const types = await client.getAttribute({ endpointId: 0, clusterId: 0x1d, attribute: Descriptor.Cluster.attributes.deviceTypeList });
    if (types.some(t => t.deviceType === 0x12 && t.revision === 1) !== !!sim || !types.some(t => t.deviceType === 0x16 && t.revision === 5)) throw new Error("OTA type activation mismatch");
    if (sim) {
        const { Global } = await load("@matter/types/dist/esm/cluster/Global.js");
        const servers = await client.getAttribute({ endpointId: 0, clusterId: 0x1d, attribute: Descriptor.Cluster.attributes.serverList });
        if (!servers.includes(0x2a)) throw new Error("Missing Requestor server");
        for (const [name,expected] of [["featureMap",0],["clusterRevision",1],["updatePossible",true]]) {
            const value = await client.getAttribute({ endpointId: 0, clusterId: 0x2a, attribute: (Global.attributes[name] ?? OtaSoftwareUpdateRequestor.Cluster.attributes[name]) });
            if (value !== expected && !(name === "featureMap" && typeof value === "object" && !Object.values(value).some(Boolean))) throw new Error(`OTA profile ${name}: ${JSON.stringify(value)}`);
        }
        const accepted = await client.getAttribute({ endpointId:0, clusterId:0x2a, attribute:Global.attributes.acceptedCommandList });
        const generated = await client.getAttribute({ endpointId:0, clusterId:0x2a, attribute:Global.attributes.generatedCommandList });
        if (accepted.length !== 1 || accepted[0] !== 0 || generated.length) throw new Error("OTA command lists mismatch");
    }
    await client.setAttribute({ attributeData: { endpointId: 0, clusterId: 0x2a,
        attribute: OtaSoftwareUpdateRequestor.Cluster.attributes.defaultOtaProviders,
        value: [{ providerNodeId: controller.nodeId, endpoint: controller.otaProvider.number, fabricIndex: 1 }] } });
    if (sim) {
        const exists = async name => { try { await access(resolve(directory, name)); return true; } catch { return false; } };
        await waitFor(() => exists("verify-restart"), 180000);
        const success = ["bdx-sim-ok", "bdx-sim-notify-error", "bdx-sim-notify-timeout"].includes(mode);
        if (success) await waitFor(() => notifications === 1, 90000);
        dropNotifyReply = false; // Requestor has completed (or timed out) its single attempt.
        // Explicit fresh CASE after restart, independent of cached pre-reboot session.
        await controller.disconnectNode(id, true);
        const fresh = await controller.createInteractionClient(id);
        const { BasicInformation } = await load("@matter/types/dist/esm/clusters/basic-information.js");
        const { GeneralDiagnostics } = await load("@matter/types/dist/esm/clusters/general-diagnostics.js");
        const version = await fresh.getAttribute({ endpointId: 0, clusterId: 0x28, attribute: BasicInformation.Cluster.attributes.softwareVersion, requestFromRemote: true });
        const boot = await fresh.getAttribute({ endpointId: 0, clusterId: 0x33, attribute: GeneralDiagnostics.Cluster.attributes.bootReason, requestFromRemote: true });
        if (version !== (success ? 2 : 1) || boot !== (success ? 5 : 1)) throw new Error(`Restored identity mismatch ${version}/${boot}`);
        if (!success && notifications) throw new Error("Rejected image notified");
        const applied = (await fresh.getEvent({ endpointId:0, clusterId:0x2a, event:OtaSoftwareUpdateRequestor.Cluster.events.versionApplied })) ?? [];
        if (success ? (applied.length !== 1 || applied[0].data.softwareVersion !== version || applied[0].data.productId !== 0x8001 || applied[0].priority !== 2) : applied.length) throw new Error("VersionApplied mismatch");
        if (["bdx-sim-rollback","bdx-sim-crash","bdx-sim-retry"].includes(mode)) {
            const report = await fresh.getMultipleAttributesAndEvents({ events:[{endpointId:0, clusterId:0x2a, eventId:0}] });
            const transitions = report.eventReports.flatMap(r => r.events);
            if (!transitions.some(e => e.data.newState === 7 && e.data.reason === 2 && e.data.targetSoftwareVersion === 1) ||
                !transitions.some(e => e.data.previousState === 7 && e.data.newState === 1)) throw new Error("Missing rollback transition events");
        }
        await writeFile(resolve(directory, "restart-verified"), JSON.stringify({version,boot}));
        if (mode === "bdx-sim-retry") {
            await waitFor(() => exists("retry-verify"), 120000);
            await waitFor(() => notifications === 1);
            await controller.disconnectNode(id,true);
            const updated = await controller.createInteractionClient(id);
            const v = await updated.getAttribute({ endpointId:0, clusterId:0x28, attribute:BasicInformation.Cluster.attributes.softwareVersion, requestFromRemote:true });
            const events = (await updated.getEvent({ endpointId:0, clusterId:0x2a, event:OtaSoftwareUpdateRequestor.Cluster.events.versionApplied })) ?? [];
            if (v !== 2 || events.length !== 1 || events[0].data.softwareVersion !== 2 || applies !== 2) throw new Error("Retry update did not confirm exactly once");
            await writeFile(resolve(directory,"retry-verified"),"PASS");
        }
        await waitFor(() => exists("download-result"), 90000);
        if (notifications !== (success || mode === "bdx-sim-retry" ? 1 : 0)) throw new Error("Repeated application notification");
        if (applies !== (mode === "bdx-sim-retry" ? 2 : success || ["bdx-sim-tamper","bdx-sim-interrupt","bdx-sim-rollback","bdx-sim-crash"].includes(mode) ? 1 : 0)) throw new Error("Invalid Apply count");
        console.log("PASS signed OTA simulation", mode, version, boot, notifications);
        await writeFile(resolve(directory, "provider-pass"), "PASS");
    } else if (bdx) {
        await waitFor(async () => { try { await access(resolve(directory, "download-result")); return true; } catch { return false; } }, applyMode ? 200000 : 65000);
        if (applyMode && applies !== (mode === "bdx-apply-await" ? 2 : 1)) throw new Error("Apply request count mismatch");
        if (mode === "bdx-apply-restart" && queries !== 2) throw new Error("Restart must query again");
        if (mode === "bdx-fault" && !duplicatedRetry) throw new Error("BDX fault not exercised");
        console.log("PASS BDX provider transfer", mode);
        await writeFile(resolve(directory, "provider-pass"), "PASS");
    } else {
    await waitFor(() => queries === 1);
    await new Promise(r => setTimeout(r, 700));
    const state = await client.getAttribute({ endpointId: 0, clusterId: 0x2a,
        attribute: OtaSoftwareUpdateRequestor.Cluster.attributes.updateState, requestFromRemote: true });
    if (state !== 3) throw new Error(`Expected DelayedOnQuery, got ${state}`);
    await writeFile(resolve(directory, "restart-ready"), "Busy and state verified");
    await waitFor(() => queries >= 2, 65000);
    await new Promise(r => setTimeout(r, 1200));
    console.log("PASS QueryImage CASE/Invoke: Busy -> DelayedOnQuery; restart -> outgoing discovery/CASE -> NotAvailable");
    await writeFile(resolve(directory, "provider-pass"), "PASS");
    }
    await waitFor(async () => { try { await access(resolve(directory, "node-stopped")); return true; } catch { return false; } });
} finally { await controller.close(); }
