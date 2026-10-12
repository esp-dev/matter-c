// Independent Matter.js oracle. Explicit CASE creates distinct authenticated
// sessions without shutting down the previous one or restarting the C host.
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { writeFileSync, existsSync } from "node:fs";
import { networkInterfaces } from "node:os";
import dgram from "node:dgram";
import { syncBuiltinESMExports } from "node:module";
import { randomBytes } from "node:crypto";
// Pinned Matter.js 0.17.9 NodeJsUdpSocket leaves the OS multicast hop limit
// at 1 on this Windows host. Explicit test transport configuration (RFC6762
// section 11): mDNS uses 255. Do not relax the C ingress policy or modify SDK
// files, DNS records, CASE/IM encoders or crypto to accommodate this peer issue.
const createSocket = dgram.createSocket;
dgram.createSocket = (...args) => {
    const socket = createSocket(...args);
    socket.once("listening", () => { if (socket.address().port === 5353) socket.setMulticastTTL(255); });
    return socket;
};
syncBuiltinESMExports();
const [modules, ip, port, storage, proxyPort, coordination] = process.argv.slice(2);
const load = path => import(pathToFileURL(resolve(modules, path)).href);
const { NodeJsCrypto, NodeJsEnvironment } = await load("@matter/nodejs/dist/esm/index.js");
const { NodeJsNetwork } = await load("@matter/nodejs/dist/esm/net/NodeJsNetwork.js");
// Windows socket RX supplies a numeric IPv6 scope, while MdnsServer indexes
// records via OS interface names. Accept scopes at the test OS adapter boundary
// too; keep numeric RX metadata because the scanner uses it as an IPv6 zone.
const namedInterface = intf => Object.entries(networkInterfaces()).find(([, addresses]) =>
    addresses.some(a => a.scopeid !== undefined && String(a.scopeid) === intf))?.[0] ?? intf;
const getIpMac = NodeJsNetwork.prototype.getIpMac;
NodeJsNetwork.prototype.getIpMac = function(intf) { return getIpMac.call(this, namedInterface(intf)); };
const createUdpSocket = NodeJsNetwork.prototype.createUdpSocket;
NodeJsNetwork.prototype.createUdpSocket = function(options) {
    return createUdpSocket.call(this, { ...options, netInterface: namedInterface(options.netInterface) });
};
const { CommissioningController } = await load("@project-chip/matter.js/dist/esm/CommissioningController.js");
const { SessionManager } = await load("@matter/protocol/dist/esm/session/SessionManager.js");
const { ExchangeManager } = await load("@matter/protocol/dist/esm/protocol/ExchangeManager.js");
const { CaseClient } = await load("@matter/protocol/dist/esm/session/case/CaseClient.js");
const { AdministratorCommissioning: AC } = await load("@matter/types/dist/esm/clusters/administrator-commissioning.js");
const { ElectricalEnergyMeasurement: EEM } = await load("@matter/types/dist/esm/clusters/electrical-energy-measurement.js");
const { Spake2p } = await load("@matter/general/dist/esm/crypto/Spake2p.js");
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const check = (value, message) => { if (!value) throw new Error(message); };
const env = NodeJsEnvironment(); env.vars.set("storage.path", resolve("build/matter-controller/storage"));
const interfaceName = Object.entries(networkInterfaces()).find(([, addresses]) => addresses.some(a => a.address === ip.split("%")[0]))?.[0];
check(interfaceName, "Missing explicit IPv6 interface");
env.vars.set("mdns.networkInterface", interfaceName);
env.vars.set("mdns.ipv4", false);
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
try {
    const a = await controller("A", 3840);
    const salt = randomBytes(16), iterations = 1000;
    const { w0, L } = await Spake2p.computeW0L(new NodeJsCrypto(), { salt, iterations }, 20202021);
    const pakePasscodeVerifier = Buffer.concat([Buffer.from(w0.toString(16).padStart(64, "0"), "hex"), Buffer.from(L)]);
    await a.client.invoke({ endpointId: 0, clusterId: 0x3c, command: AC.Cluster.commands.openCommissioningWindow, asTimedRequest: true,
        request: { commissioningTimeout: 180, pakePasscodeVerifier, discriminator: 1234, iterations, salt } });
    const b = await controller("B", 1234), br = await subscribe(b.client);
    // Full CASE and subscription through a transparent UDP proxy. The host learns
    // its source port as the route; no keys/packets are changed by the proxy.
    a.session.channel.transportChannel.networkAddress = { type: "udp", ip, port: Number(proxyPort) };
    const fresh = await next(a), reports = await subscribe(fresh.client);
    const session = fresh.session;
    const hex = value => value.toString(16).padStart(16, "0").toUpperCase();
    writeFileSync(resolve(coordination, "peer.json"), JSON.stringify({
        instance: `${hex(a.c.fabric.globalId)}-${hex(a.c.fabric.nodeId)}`
    }));
    for (let i = 0; !existsSync(resolve(coordination, "cut")); i++) {
        check(i < 200, "Proxy harness did not arm discovery"); await pause(100);
    }
    const initial = reports.count, other = br.count;
    // No controller-initiated exchange during recovery: a retained server report
    // must trigger first-retry discovery and reach the direct socket by itself.
    await pause(11000);
    check(reports.count >= initial + 2, "Subscription did not recover after route loss");
    check(br.count >= other + 2, "Another fabric stopped reporting");
    check(!session.isClosing, "Recovery replaced/closed the CASE session");
    await read(fresh.client); await read(b.client);
    console.log("PASS rediscovery: same CASE/subscription, encrypted MRP, new UDP route, live other fabric");
} finally { for (const c of controllers.reverse()) await c.close(); }
