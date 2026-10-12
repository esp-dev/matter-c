// Independent Matter.js oracle. Explicit CASE creates distinct authenticated
// sessions without shutting down the previous one or restarting the C host.
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
const [modules, ip, port, storage] = process.argv.slice(2);
const load = path => import(pathToFileURL(resolve(modules, path)).href);
const { NodeJsCrypto, NodeJsEnvironment } = await load("@matter/nodejs/dist/esm/index.js");
const { CommissioningController } = await load("@project-chip/matter.js/dist/esm/CommissioningController.js");
const { SessionManager } = await load("@matter/protocol/dist/esm/session/SessionManager.js");
const { ExchangeManager } = await load("@matter/protocol/dist/esm/protocol/ExchangeManager.js");
const { CaseClient } = await load("@matter/protocol/dist/esm/session/case/CaseClient.js");
const { ChannelStatusResponseError } = await load("@matter/protocol/dist/esm/securechannel/SecureChannelMessenger.js");
const { AdministratorCommissioning: AC } = await load("@matter/types/dist/esm/clusters/administrator-commissioning.js");
const { ElectricalEnergyMeasurement: EEM } = await load("@matter/types/dist/esm/clusters/electrical-energy-measurement.js");
const { Spake2p } = await load("@matter/general/dist/esm/crypto/Spake2p.js");
const { TlvSubscribeRequest } = await load("@matter/types/dist/esm/protocol/messages/TlvSubscribeRequest.js");
const { TlvStatusResponse } = await load("@matter/types/dist/esm/protocol/messages/TlvStatusResponse.js");
const { TlvDataReport } = await load("@matter/types/dist/esm/protocol/messages/TlvDataReport.js");
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const check = (value, message) => { if (!value) throw new Error(message); };
const env = NodeJsEnvironment(); env.vars.set("storage.path", resolve("build/matter-controller/storage"));
const controllers = [];
async function controller(suffix, discriminator) {
    const c = new CommissioningController({ environment: { environment: env, id: `${storage}-${suffix}` }, autoConnect: false, adminFabricLabel: suffix });
    controllers.push(c); await c.start();
    const id = await c.commissionNode({ passcode: 20202021,
        discovery: { identifierData: { longDiscriminator: discriminator }, knownAddress: { type: "udp", ip, port: Number(port) } },
        commissioning: { regulatoryLocation: 0, regulatoryCountryCode: "PL" } }, { connectNodeAfterCommissioning: false });
    await c.createInteractionClient(id);
    const sessions = c.node.env.get(SessionManager);
    const session = [...sessions.sessionsFor(c.fabric.addressOf(id))].find(s => !s.isClosing);
    check(session, "Missing initial CASE session");
    return { c, id, sessions, session, client: await c.createInteractionClient(session) };
}
async function next(a) {
    const unsecured = a.sessions.createUnsecuredSession({ channel: a.session.channel.transportChannel, isInitiator: true });
    const exchange = a.c.node.env.get(ExchangeManager).initiateExchangeForSession(unsecured, 0);
    try {
        const { session, resumed } = await new CaseClient(a.sessions).pair(exchange, a.c.fabric, a.id, { abort: AbortSignal.timeout(10000) });
        check(!resumed, "Unexpected resumption (full CASE required)");
        return { session, client: await a.c.createInteractionClient(session) };
    } finally { await exchange.close(); await unsecured.close(); }
}
const energy = { endpointId: 1, clusterId: 0x91, attribute: EEM.Complete.attributes.cumulativeEnergyImported };
async function subscribe(client, keepSubscriptions = true) {
    const reports = { count: 0 };
    await client.subscribeAttribute({ ...energy, keepSubscriptions, minIntervalFloorSeconds: 1, maxIntervalCeilingSeconds: 3,
        listener: value => { check(value?.energy !== undefined, "Invalid energy"); reports.count++; } });
    return reports;
}
async function read(client) { check((await client.getAttribute({ ...energy, requestFromRemote: true }))?.energy !== undefined, "Read failed"); }
async function replaceRequest(a, session) {
    // The high-level SDK also deletes local listeners on keep=false, which can
    // conceal a publisher bug. Use its wire codecs/exchange directly so old
    // listeners stay alive and would observe any wrongly retained reports.
    const exchange = a.c.node.env.get(ExchangeManager).initiateExchangeForSession(session, 1);
    try {
        await exchange.send(3, TlvSubscribeRequest.encode({ keepSubscriptions: false, minIntervalFloorSeconds: 1,
            maxIntervalCeilingSeconds: 3, isFabricFiltered: true, interactionModelRevision: 12,
            attributeRequests: [{ endpointId: 1, clusterId: 0x91, attributeId: 1 }] }));
        const prime = await exchange.nextMessage({ abort: AbortSignal.timeout(10000) });
        check(prime.payloadHeader.messageType === 5 && TlvDataReport.decode(prime.payload).subscriptionId !== undefined, "Missing prime");
        // Abort only this new subscription after the publisher accepted it.
        // Previous subscriptions must already be gone (Core 8.5.2.3).
        await exchange.send(1, TlvStatusResponse.encode({ status: 125, interactionModelRevision: 12 }));
    } finally { await exchange.close(); }
}
try {
    const a = await controller("A", 3840), ar = await subscribe(a.client);
    const salt = randomBytes(16), iterations = 1000;
    const { w0, L } = await Spake2p.computeW0L(new NodeJsCrypto(), { salt, iterations }, 20202021);
    const pakePasscodeVerifier = Buffer.concat([Buffer.from(w0.toString(16).padStart(64, "0"), "hex"), Buffer.from(L)]);
    await a.client.invoke({ endpointId: 0, clusterId: 0x3c, command: AC.Cluster.commands.openCommissioningWindow, asTimedRequest: true,
        request: { commissioningTimeout: 180, pakePasscodeVerifier, discriminator: 1234, iterations, salt } });
    const b = await controller("B", 1234), br = await subscribe(b.client);
    const a1 = await next(a), r1 = await subscribe(a1.client);
    const a2 = await next(a), r2 = await subscribe(a2.client);
    await pause(3300);
    check([ar, br, r1, r2].every(r => r.count >= 2), "keep=true lost an existing session subscription");
    try { await next(a); throw new Error("Full protected session pool accepted another CASE"); }
    catch (error) { check(error instanceof ChannelStatusResponseError && error.generalStatusCode === 8 && error.protocolStatusCode === 4 && error.busyDelay === 500, `Expected explicit BUSY: ${error}`); }
    console.log("PASS protected pool BUSY and four live subscriptions");
    await replaceRequest(a, a2.session);
    const replacement = await subscribe(a2.client);
    await pause(600); const stopped = [ar.count, r1.count, r2.count], bBefore = br.count;
    await pause(3300);
    check([ar, r1, r2].every((r, i) => r.count === stopped[i]), "keep=false failed across sessions");
    check(replacement.count >= 2 && br.count > bBefore, "Replacement or other fabric lost");
    // Keep the new subscription and its authenticated socket as the reconnect anchor.
    const original = a.session; a.session = a2.session;
    await original.initiateForceClose({ cause: new Error("Test peer disappears without CloseSession") });
    await a1.session.initiateForceClose({ cause: new Error("Test peer disappears without CloseSession") });
    let peerClosed = false;
    for (let i = 0; i < 12; i++) {
        const fresh = await next(a); await read(fresh.client);
        // Leave one idle peer listening to verify encrypted CloseSession on wire.
        if (!i) fresh.session.closedByPeer.on(() => { peerClosed = true; });
        else await fresh.session.initiateForceClose({ cause: new Error("Test peer disappears without CloseSession") });
        await pause(150);
        console.log(`PASS reconnect ${i + 1}`);
    }
    check(peerClosed, "Idle session did not receive CloseSession eviction");
    const last = replacement.count, other = br.count; await pause(3300);
    check(replacement.count > last && br.count > other, "Reconnect evicted a protected subscription");
    await read(a2.client); await read(b.client);
    console.log("PASS reconnect: scoped keep=false, idle eviction, 12 CASE reconnects with abrupt peers, live other fabric, one host lifetime");
} finally { for (const c of controllers.reverse()) await c.close(); }
