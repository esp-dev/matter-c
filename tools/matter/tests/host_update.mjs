// Independent Matter.js certificate issuer/controller. No C fixtures or keys.
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { serialize, deserialize } from "node:v8";
const [modules, mode, ip, port, storage, caPath] = process.argv.slice(2);
const load = path => import(pathToFileURL(resolve(modules, path)).href);
const { NodeJsCrypto, NodeJsEnvironment } = await load("@matter/nodejs/dist/esm/index.js");
const { CommissioningController } = await load("@project-chip/matter.js/dist/esm/CommissioningController.js");
const { CertificateAuthority } = await load("@matter/protocol/dist/esm/certificate/CertificateAuthority.js");
const { Certificate } = await load("@matter/protocol/dist/esm/certificate/kinds/Certificate.js");
const { TlvCertSigningRequest } = await load("@matter/protocol/dist/esm/common/OperationalCredentialsTypes.js");
const { SessionManager } = await load("@matter/protocol/dist/esm/session/SessionManager.js");
const { ExchangeManager } = await load("@matter/protocol/dist/esm/protocol/ExchangeManager.js");
const { CaseClient } = await load("@matter/protocol/dist/esm/session/case/CaseClient.js");
const { OperationalCredentials: OC } = await load("@matter/types/dist/esm/clusters/operational-credentials.js");
const { GeneralCommissioning: GC } = await load("@matter/types/dist/esm/clusters/general-commissioning.js");
const { AdministratorCommissioning: AC } = await load("@matter/types/dist/esm/clusters/administrator-commissioning.js");
const { ElectricalEnergyMeasurement: EEM } = await load("@matter/types/dist/esm/clusters/electrical-energy-measurement.js");
const { Spake2p } = await load("@matter/general/dist/esm/crypto/Spake2p.js");
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const check = (value, message) => { if (!value) throw new Error(message); };
const env = NodeJsEnvironment(); env.vars.set("storage.path", resolve("build/matter-controller/storage"));
const crypto = new NodeJsCrypto();
const ca = await CertificateAuthority.create(crypto, mode === "pair" ? true : deserialize(readFileSync(caPath)));
const controllers = [];
async function controller(suffix) {
    const c = new CommissioningController({ environment: { environment: env, id: `${storage}-${suffix}` }, autoConnect: false,
        adminFabricLabel: suffix, ...(suffix === "A" ? { rootCertificateAuthority: ca } : {}) });
    controllers.push(c); await c.start(); return c;
}
async function commission(c, discriminator) {
    return c.commissionNode({ passcode: 20202021,
        discovery: { identifierData: { longDiscriminator: discriminator }, knownAddress: { type: "udp", ip, port: Number(port) } },
        commissioning: { regulatoryLocation: 0, regulatoryCountryCode: "PL" } }, { connectNodeAfterCommissioning: false });
}
async function connect(c, id) {
    const sessions = c.node.env.get(SessionManager), exchanges = c.node.env.get(ExchangeManager);
    const channel = await exchanges.interfaceFor("udp", "::").openChannel({ type: "udp", ip, port: Number(port) });
    const unsecured = sessions.createUnsecuredSession({ channel, isInitiator: true });
    const exchange = exchanges.initiateExchangeForSession(unsecured, 0);
    try {
        const { session, resumed } = await new CaseClient(sessions).pair(exchange, c.fabric, id, { abort: AbortSignal.timeout(7000) });
        check(!resumed, "Expected full CASE"); return await c.createInteractionClient(session);
    } finally { await exchange.close(); await unsecured.close(); }
}
const invoke = (c, cluster, name, request) => c.invoke({ endpointId: 0, clusterId: cluster.id, command: cluster.commands[name], request });
const oc = (c, name, request) => invoke(c, OC.Cluster, name, name === "updateNoc" ? { icacValue: ca.icacCert, ...request } : request);
const arm = async (c, seconds = 45) => check((await invoke(c, GC.Cluster, "armFailSafe", { expiryLengthSeconds: seconds, breadcrumb: 0n })).errorCode === 0, "ArmFailSafe failed");
const complete = async c => check((await invoke(c, GC.Cluster, "commissioningComplete", undefined)).errorCode === 0, "Complete failed");
const fabrics = c => c.getAttribute({ endpointId: 0, clusterId: 0x3e, attribute: OC.Cluster.attributes.fabrics, isFabricFiltered: false, requestFromRemote: true });
async function expectStatus(action, status) {
    try { await action(); throw new Error("Expected IM failure"); }
    catch (e) { check(e.code === status, `Expected IM ${status}, got ${e} (code=${e.code})`); }
}
async function csr(c, update = true) {
    const { nocsrElements } = await oc(c, "csrRequest", { csrNonce: randomBytes(32), isForUpdateNoc: update });
    const { certSigningRequest } = TlvCertSigningRequest.decode(nocsrElements);
    return Certificate.getPublicKeyFromCsr(crypto, certSigningRequest);
}
async function rotate(c, controller, nodeId, seconds = 45) {
    await arm(c, seconds);
    const key = await csr(c);
    const nocValue = await ca.generateNoc(key, controller.fabric.fabricId, nodeId);
    check((await oc(c, "updateNoc", { nocValue })).statusCode === 0, "UpdateNOC failed");
}
async function subscribe(c) {
    const r = { count: 0 };
    await c.subscribeAttribute({ endpointId: 1, clusterId: 0x91, attribute: EEM.Complete.attributes.cumulativeEnergyImported,
        minIntervalFloorSeconds: 1, maxIntervalCeilingSeconds: 3, listener: v => { check(v?.energy !== undefined, "Missing energy"); r.count++; } });
    return r;
}
try {
    const a = await controller("A");
    if (mode === "pair") {
        const id = await commission(a, 3840); check(id === 1n, "Unexpected initial Node ID");
        const ac = await connect(a, id), ar = await subscribe(ac);
        const salt = randomBytes(16), iterations = 1000;
        const { w0, L } = await Spake2p.computeW0L(crypto, { salt, iterations }, 20202021);
        await ac.invoke({ endpointId: 0, clusterId: 0x3c, command: AC.Cluster.commands.openCommissioningWindow, asTimedRequest: true,
            request: { commissioningTimeout: 180, discriminator: 1234, iterations, salt,
                pakePasscodeVerifier: Buffer.concat([Buffer.from(w0.toString(16).padStart(64, "0"), "hex"), Buffer.from(L)]) } });
        const b = await controller("B"); await commission(b, 1234); const bc = await connect(b, 1n), br = await subscribe(bc);
        await expectStatus(() => csr(ac), 0xca);
        await arm(ac);
        const busy = await invoke(bc, GC.Cluster, "armFailSafe", { expiryLengthSeconds: 30, breadcrumb: 0n });
        check(busy.errorCode === 4, "Other fabric acquired fail-safe");
        await expectStatus(() => csr(bc), 0xca);
        const wrongPurpose = await csr(ac, false);
        const wrongNoc = await ca.generateNoc(wrongPurpose, a.fabric.fabricId, 2n);
        await expectStatus(() => oc(ac, "updateNoc", { nocValue: wrongNoc }), 0x87);
        const key = await csr(ac), invalid = await ca.generateNoc(key, a.fabric.fabricId + 1n, 2n);
        check((await oc(ac, "updateNoc", { nocValue: invalid })).statusCode === 3, "Changed fabric accepted");
        const nocValue = await ca.generateNoc(key, a.fabric.fabricId, 2n);
        check((await oc(ac, "updateNoc", { nocValue, icacValue: ca.rootCert })).statusCode === 3, "Invalid ICAC accepted");
        check((await oc(ac, "updateNoc", { nocValue })).statusCode === 0, "Update failed");
        // A successful Invoke means the reply arrived on the old encrypted CASE.
        await pause(1000); const stopped = ar.count, before = br.count;
        const fresh = await connect(a, 2n); await complete(fresh); const fr = await subscribe(fresh);
        await pause(3600);
        check(ar.count === stopped && br.count > before && fr.count >= 2, "Rotation retirement was not selective");
        check((await fabrics(fresh)).some(f => f.nodeId === 2n && f.label === "A"), "Node ID/label not updated");
        console.log("PASS pair: CASE CSR, fail-safe fabric isolation, purpose/fabric rejection, UpdateNOC response, new CASE/Complete and selective subscriptions");
    } else {
        let ac = await connect(a, 2n); check((await fabrics(ac)).some(f => f.nodeId === 2n), "Committed credential missing after restart");
        const b = await controller("B"), bc = await connect(b, 1n), br = await subscribe(bc);
        if (mode === "timeout") {
            await rotate(ac, a, 3n, 8); ac = await connect(a, 3n);
            check((await fabrics(ac)).some(f => f.nodeId === 3n), "Tentative credential missing");
            await pause(9500); ac = await connect(a, 2n); await fabrics(ac); check(br.count >= 3, "Other fabric lost on rollback");
            console.log("PASS timeout: committed restart, tentative new CASE, fail-safe restores old credentials and preserves other fabric");
        } else if (mode === "crash") {
            await rotate(ac, a, 4n); ac = await connect(a, 4n); await fabrics(ac);
            console.log("CRASH_READY"); // Runner kills host before fail-safe/clean shutdown.
        } else {
            await fabrics(bc);
            console.log("PASS recovery: unfinished durable UpdateNOC journal restores old key/NOC; both fabrics establish CASE");
        }
    }
} finally {
    writeFileSync(caPath, serialize(ca.config));
    for (const c of controllers.reverse()) await c.close();
    await ca.close();
}
