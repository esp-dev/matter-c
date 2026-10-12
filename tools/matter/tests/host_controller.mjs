// Independent oracle: npm packages pinned in the runner, no C fixture imports.
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { mkdir, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
const [modules, mode, target, port, storageId] = process.argv.slice(2);
const load = path => import(pathToFileURL(resolve(modules, path)).href);
const { NodeJsCrypto, NodeJsEnvironment } = await load("@matter/nodejs/dist/esm/index.js");
if (mode === "credentials") {
    const { AttestationCertificateManager } = await load("@matter/protocol/dist/esm/certificate/AttestationCertificateManager.js");
    const { CertificationDeclaration } = await load("@matter/protocol/dist/esm/certificate/kinds/CertificationDeclaration.js");
    const { TestCert_PAA_NoVID_Cert } = await load("@matter/protocol/dist/esm/certificate/ChipPAAuthorities.js");
    const crypto = new NodeJsCrypto();
    const manager = await AttestationCertificateManager.create(crypto, 0xfff1);
    const { keyPair, dac } = await manager.getDACert(0x8001);
    await mkdir(target, { recursive: true });
    for (const [name, bytes] of Object.entries({ "dac.der": dac, "pai.der": await manager.getPAICert(),
        "paa.der": TestCert_PAA_NoVID_Cert, "dac-key.bin": keyPair.privateKey,
        "cd.der": await CertificationDeclaration.generate(crypto, 0xfff1, 0x8001) })) {
        await writeFile(resolve(target, name), new Uint8Array(bytes));
    }
    console.log("Generated development credentials (VID fff1/PID 8001), not production provisioning.");
} else {
    const { CommissioningController } = await load("@project-chip/matter.js/dist/esm/CommissioningController.js");
    const env = NodeJsEnvironment();
    env.vars.set("storage.path", resolve("build/matter-controller/storage"));
    const controller = new CommissioningController({ environment: { environment: env, id: storageId ?? `m12b-${Date.now()}` }, autoConnect: false, adminFabricLabel: "M12b host test" });
    try {
        await controller.start();
        const id = mode === "reconnect" ? 1n : await controller.commissionNode({ passcode: 20202021,
            discovery: { identifierData: { longDiscriminator: 3840 }, knownAddress: { type: "udp", ip: target, port: Number(port) } },
            commissioning: { regulatoryLocation: 0, regulatoryCountryCode: "PL" } }, { connectNodeAfterCommissioning: false });
        console.log(mode === "reconnect" ? "RECONNECT" : "COMMISSIONED", String(id));
        const client = await controller.createInteractionClient(id);
        const { BasicInformation } = await load("@matter/types/dist/esm/clusters/basic-information.js");
        const { ElectricalPowerMeasurement } = await load("@matter/types/dist/esm/clusters/electrical-power-measurement.js");
        const { ElectricalEnergyMeasurement } = await load("@matter/types/dist/esm/clusters/electrical-energy-measurement.js");
        const power = { endpointId: 1, clusterId: 0x90, attribute: ElectricalPowerMeasurement.Complete.attributes.activePower };
        const energy = { endpointId: 1, clusterId: 0x91, attribute: ElectricalEnergyMeasurement.Complete.attributes.cumulativeEnergyImported };
        const label = { endpointId: 0, clusterId: 0x28, attribute: BasicInformation.Cluster.attributes.nodeLabel };
        const value = await client.getAttribute(power);
        if (value !== 3600000 && value !== -1800000) throw new Error(`Unexpected power ${value}`);
        const total = await client.getAttribute(energy);
        if (total?.energy === undefined) throw new Error("Missing EEM register");
        await client.setAttribute({ attributeData: { ...label, value: "M12b controller" } });
        if (await client.getAttribute({ ...label, requestFromRemote: true }) !== "M12b controller") throw new Error("Write/readback mismatch");
        let reports = 0;
        await client.subscribeAttribute({ ...energy, minIntervalFloorSeconds: 1, maxIntervalCeilingSeconds: 3,
            listener: value => { if (value?.energy === undefined) throw new Error("Invalid EEM report"); reports++; } });
        await new Promise(resolve => setTimeout(resolve, 4200));
        if (reports < 2) throw new Error(`Missing subscription updates: ${reports}`);
        console.log("PASS CASE EPM/EEM Read, NodeLabel Write/readback and EEM Subscribe", reports);
        // Google Home requests wildcard attributes AND urgent wildcard events.
        // Exercise the complete host profile, including chunk acknowledgements.
        let fullUpdates = 0, eventUpdates = 0;
        const full = await client.subscribeAllAttributesAndEvents({ minIntervalFloorSeconds: 0,
            maxIntervalCeilingSeconds: 3, keepSubscriptions: false, isUrgent: true,
            attributeListener: () => fullUpdates++, eventListener: () => eventUpdates++ });
        if (full.attributeReports.length <= 120 || !full.eventReports.length)
            throw new Error(`Incomplete wildcard subscription: ${full.attributeReports.length} attributes, ${full.eventReports.length} events`);
        await new Promise(resolve => setTimeout(resolve, 3200));
        if (!fullUpdates || !eventUpdates) throw new Error(`Missing wildcard updates: ${fullUpdates}/${eventUpdates}`);
        console.log("PASS full-profile wildcard Subscribe", full.attributeReports.length, full.eventReports.length, fullUpdates, eventUpdates);
        const { AdministratorCommissioning } = await load("@matter/types/dist/esm/clusters/administrator-commissioning.js");
        const { Spake2p } = await load("@matter/general/dist/esm/crypto/Spake2p.js");
        const salt = randomBytes(16), iterations = 1000;
        const { w0, L } = await Spake2p.computeW0L(new NodeJsCrypto(), { salt, iterations }, 20202021);
        const verifier = Buffer.concat([Buffer.from(w0.toString(16).padStart(64, "0"), "hex"), Buffer.from(L)]);
        const admin = AdministratorCommissioning.Cluster;
        await client.invoke({ endpointId: 0, clusterId: 0x3c, command: admin.commands.openCommissioningWindow,
            asTimedRequest: true, request: { commissioningTimeout: 180, pakePasscodeVerifier: verifier, discriminator: 1234, iterations, salt } });
        const window = { endpointId: 0, clusterId: 0x3c, attribute: admin.attributes.windowStatus, requestFromRemote: true };
        if (await client.getAttribute(window) !== 1) throw new Error("ECM not open");
        console.log("ECM_OPEN discriminator=1234");
        await new Promise(resolve => setTimeout(resolve, 4200));
        await client.invoke({ endpointId: 0, clusterId: 0x3c, command: admin.commands.revokeCommissioning, request: undefined, asTimedRequest: true });
        if (await client.getAttribute(window) !== 0 || await client.getAttribute(power) === undefined) throw new Error("ECM revoke damaged CASE");
        console.log("PASS timed ECM open/revoke, CASE preserved");
    } finally { await controller.close(); }
}
