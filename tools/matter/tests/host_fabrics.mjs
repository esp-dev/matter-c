// Independent two-fabric oracle; uses the same pinned packages as host_controller.mjs.
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
const [modules, mode, ip, port, storage] = process.argv.slice(2);
const load = path => import(pathToFileURL(resolve(modules, path)).href);
const { NodeJsCrypto, NodeJsEnvironment } = await load("@matter/nodejs/dist/esm/index.js");
const { CommissioningController } = await load("@project-chip/matter.js/dist/esm/CommissioningController.js");
const { OperationalCredentials: OC } = await load("@matter/types/dist/esm/clusters/operational-credentials.js");
const { AdministratorCommissioning: AC } = await load("@matter/types/dist/esm/clusters/administrator-commissioning.js");
const { ElectricalEnergyMeasurement: EEM } = await load("@matter/types/dist/esm/clusters/electrical-energy-measurement.js");
const { Spake2p } = await load("@matter/general/dist/esm/crypto/Spake2p.js");
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const check = (value, message) => { if (!value) throw new Error(message); };
const env = NodeJsEnvironment(); env.vars.set("storage.path", resolve("build/matter-controller/storage"));
const controllers = [];
async function controller(suffix) {
    const c = new CommissioningController({ environment: { environment: env, id: `${storage}-${suffix}` }, autoConnect: false, adminFabricLabel: `Fabric ${suffix}` });
    controllers.push(c); await c.start(); return c;
}
async function commission(c, discriminator) {
    return c.commissionNode({ passcode: 20202021,
        discovery: { identifierData: { longDiscriminator: discriminator }, knownAddress: { type: "udp", ip, port: Number(port) } },
        commissioning: { regulatoryLocation: 0, regulatoryCountryCode: "PL" } }, { connectNodeAfterCommissioning: false });
}
const fabrics = client => client.getAttribute({ endpointId: 0, clusterId: 0x3e, attribute: OC.Cluster.attributes.fabrics, isFabricFiltered: false, requestFromRemote: true });
const index = client => client.getAttribute({ endpointId: 0, clusterId: 0x3e, attribute: OC.Cluster.attributes.currentFabricIndex, requestFromRemote: true });
const command = (client, name, request) => client.invoke({ endpointId: 0, clusterId: 0x3e, command: OC.Cluster.commands[name], request });
async function open(client) {
    const salt = randomBytes(16), iterations = 1000;
    const { w0, L } = await Spake2p.computeW0L(new NodeJsCrypto(), { salt, iterations }, 20202021);
    const pakePasscodeVerifier = Buffer.concat([Buffer.from(w0.toString(16).padStart(64, "0"), "hex"), Buffer.from(L)]);
    await client.invoke({ endpointId: 0, clusterId: 0x3c, command: AC.Cluster.commands.openCommissioningWindow, asTimedRequest: true,
        request: { commissioningTimeout: 180, pakePasscodeVerifier, discriminator: 1234, iterations, salt } });
}
async function subscribe(client, reports) {
    await client.subscribeAttribute({ endpointId: 1, clusterId: 0x91, attribute: EEM.Complete.attributes.cumulativeEnergyImported,
        minIntervalFloorSeconds: 1, maxIntervalCeilingSeconds: 3, listener: value => { check(value?.energy !== undefined, "Invalid EEM"); reports.count++; } });
}
try {
    const a = await controller("A"), aid = mode === "pair" ? await commission(a, 3840) : 1n;
    const ac = await a.createInteractionClient(aid), ai = await index(ac);
    if (mode === "last") {
        check((await fabrics(ac)).length === 1 && (await fabrics(ac))[0].label === "saved A", "Fabric/label did not survive restart");
        // TH01c host policy exceeds the spec's SHOULD NOT expect a response:
        // require the real NOCResponse before the process resets.
        const response = await command(ac, "removeFabric", { fabricIndex: ai });
        check(response.statusCode === 0 && response.fabricIndex === ai, "Last fabric response missing");
        console.log("LAST_REMOVE_CONFIRMED");
    } else {
        if (mode === "self") check((await fabrics(ac)).length === 1 && (await fabrics(ac))[0].label === "saved A", "Deleted fabric reappeared after restart");
        const ar = { count: 0 }, br = { count: 0 }; await subscribe(ac, ar);
        await open(ac);
        const b = await controller(mode === "pair" ? "B" : "C"), bid = await commission(b, 1234);
        const bc = await b.createInteractionClient(bid), bi = await index(bc);
        check(ai !== bi && (await fabrics(ac)).length === 2, "Two fabrics not present");
        await subscribe(bc, br); await pause(3300);
        check(ar.count >= 2 && br.count >= 2, "Concurrent subscriptions missing");
        check((await command(ac, "updateFabricLabel", { label: "saved A" })).statusCode === 0, "Label update failed");
        check((await command(bc, "updateFabricLabel", { label: "saved A" })).statusCode === 10, "Duplicate label accepted");
        const before = JSON.stringify(await fabrics(ac), (_, value) => typeof value === "bigint" ? String(value) : value);
        check((await command(ac, "removeFabric", { fabricIndex: 254 })).statusCode === 11, "Missing fabric status");
        check(JSON.stringify(await fabrics(ac), (_, value) => typeof value === "bigint" ? String(value) : value) === before, "Invalid removal changed state");
        if (mode === "pair") check((await command(ac, "removeFabric", { fabricIndex: bi })).statusCode === 0, "Other fabric removal failed");
        else {
            const response = await command(bc, "removeFabric", { fabricIndex: bi });
            check(response.statusCode === 0 && response.fabricIndex === bi, "Own fabric response missing");
        }
        await pause(1000); const bStopped = br.count, aBefore = ar.count;
        await pause(4200);
        const remaining = await fabrics(ac);
        check(remaining.length === 1 && remaining[0].fabricIndex === ai && remaining[0].label === "saved A", "Wrong fabric removed");
        check(ar.count > aBefore && br.count === bStopped, "Subscription retirement was not selective");
        console.log(`PASS ${mode}: two fabrics, labels/conflict, invalid index, selective removal and live subscription`);
    }
} finally {
    for (const c of controllers.reverse()) await c.close();
}
