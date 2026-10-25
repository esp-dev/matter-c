// Independent Matter.js 0.17.9 C6 concurrency oracle. All output/state is private.
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {readFile,writeFile,rename} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {performance} from 'node:perf_hooks';
const [modules,ip,stateRoot,uartRoot,secondsText='3600',iface='Wi-Fi',mode='run',readWorkload='bounded']=process.argv.slice(2);
const seconds=Number(secondsText),hostMode=mode==='host';
const port=hostMode?Number(process.env.MATTER_WIRE_PORT??5540):5540;
if(hostMode && ip!=='::1') throw Error('Host fixture must use IPv6 loopback');
const expectedAttributes=Number(process.env.MATTER_SOAK_ATTRIBUTES??133);
if(!Number.isSafeInteger(expectedAttributes) || expectedAttributes<133) throw Error('Invalid MATTER_SOAK_ATTRIBUTES');
if(!modules || !ip || !stateRoot || !uartRoot || !['run','probe','cleanup','host'].includes(mode) || !['bounded','wildcard'].includes(readWorkload) || !Number.isFinite(seconds) || seconds<60)
    throw Error('Usage: soak.mjs <pinned-node_modules> <scoped-ipv6> <private-controller-state> <private-uart-dir> [seconds>=60] [interface] [run|probe|cleanup|host] [bounded|wildcard]');
const load=p=>import(pathToFileURL(resolve(modules,p)).href);
if(JSON.parse(await readFile(resolve(modules,'@project-chip/matter.js/package.json'),'utf8')).version!=='0.17.9')
    throw Error('Expected pinned Matter.js0.17.9');
const {Logger,LogLevel,Seconds}=await load('@matter/general/dist/esm/index.js');
const {NodeJsEnvironment,NodeJsCrypto}=await load('@matter/nodejs/dist/esm/index.js');
const {CommissioningController}=await load('@project-chip/matter.js/dist/esm/CommissioningController.js');
const {InteractionClientProvider}=await load('@project-chip/matter.js/dist/esm/cluster/client/InteractionClient.js');
const {SessionManager}=await load('@matter/protocol/dist/esm/session/SessionManager.js');
const {ExchangeManager}=await load('@matter/protocol/dist/esm/protocol/ExchangeManager.js');
const {CaseClient}=await load('@matter/protocol/dist/esm/session/case/CaseClient.js');
const {ClientSubscriptions}=await load('@matter/protocol/dist/esm/action/client/subscription/ClientSubscriptions.js');
const {Spake2p}=await load('@matter/general/dist/esm/crypto/Spake2p.js');
const {AdministratorCommissioning}=await load('@matter/types/dist/esm/clusters/administrator-commissioning.js');
const {OperationalCredentials}=await load('@matter/types/dist/esm/clusters/operational-credentials.js');
const {BasicInformation}=await load('@matter/types/dist/esm/clusters/basic-information.js');
const {GeneralDiagnostics}=await load('@matter/types/dist/esm/clusters/general-diagnostics.js');
Logger.level=process.env.MATTER_SOAK_LOG==='info'?LogLevel.INFO:LogLevel.WARN;
const env=NodeJsEnvironment(); env.vars.set('storage.path',resolve(stateRoot)); if(iface) env.vars.set('mdns.networkInterface',iface);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const started=performance.now(),summary={mode,read_workload:readWorkload,expected_attributes:expectedAttributes,requested_seconds:seconds,rounds:0,full_reads:0,read_attributes:0,concrete_reads:0,concrete_read_attributes:0,
    subscription_snapshots:0,subscription_updates:0,subscription_closed:0,case_pairs:0,case_resumed:0,
    session_busy_probes:0,oom_cycles:0,fault_operations_rejected:0,reconnect_cycles:0,loss_cycles:0,
    delayed_completion_cycles:0,healthy_operation_errors:0,checkpoints:[],phases:[]};
summary.unexpected_subscription_closures=0; summary.oom_lost_subscriptions=0;
summary.oom_rebuilt_load_cycles=0; summary.fault_operation_errors=[];
summary.loss_operations_rejected=0; summary.loss_rebuilt_load_cycles=0;
summary.loss_lost_subscriptions=0; summary.loss_operation_errors=[];
summary.host_close_reconnect_cycles=0; summary.recovery_busy_retries=0; summary.recovery_busy_wait_ms=0;
const readTimings={full:[],concrete:[]};
const emit=(kind,data={})=>console.log(JSON.stringify({kind,elapsed_seconds:(performance.now()-started)/1000,...data}));
if(process.env.MATTER_TEST_PEER_ROLE) {
    const {peerRole}=await import('../../../tools/matter/tests/peer_role.mjs');
    summary.diagnostic_peer=await peerRole(modules,process.env.MATTER_TEST_PEER_ROLE);
    emit('DIAGNOSTIC_PEER',summary.diagnostic_peer);
}
function errorInfo(e,depth=0) {
    if(!e || depth>3) return undefined;
    return {type:e.constructor?.name,name:e.name,message:e.message,code:e.code,
        cause:typeof e.cause==='object'?errorInfo(e.cause,depth+1):e.cause};
}
const controlRun=randomBytes(8).toString('hex'); let serial=0;
async function control(command,timeout=20000) {
    const id=`${controlRun}:${++serial}`,temporary=resolve(uartRoot,'control-request.tmp');
    await writeFile(temporary,hostMode?`${id} ${command}\n`:JSON.stringify({id,command}));
    await rename(temporary,resolve(uartRoot,hostMode?'wire-request.txt':'control-request.json'));
    const end=performance.now()+timeout;
    while(performance.now()<end) {
        try { const text=await readFile(resolve(uartRoot,'control-replies.jsonl'),'utf8');
            // Only complete appended lines are visible as acknowledgements.
            for(const line of text.slice(0,text.lastIndexOf('\n')).split('\n').reverse()) {
                if(!line) continue;
                const result=JSON.parse(line);
                if(result.id===id) return result.record.data??result.record;
            }
        } catch(e) { if(e.code!=='ENOENT' && !(e instanceof SyntaxError)) throw e; }
        await sleep(100);
    }
    throw Error(`UART control ${command} did not complete`);
}
const manifestPath=resolve(uartRoot,'topology.json');
let topology;
try { topology=JSON.parse(await readFile(manifestPath,'utf8')); }
catch(e) { if(e.code!=='ENOENT') throw e; topology=[{environment:'c6-memory14',node:'1',original:true}]; }
const contexts=[];
const clientNames=new WeakMap();
const saveTopology=()=>writeFile(manifestPath,JSON.stringify(topology,null,2)+'\n');
async function startController(entry) {
    const controller=new CommissioningController({environment:{environment:env,id:entry.environment},autoConnect:false,
        adminFabricLabel:entry.original?'C6 memory14':entry.environment});
    let flow;
    if(hostMode) {
        const {ControllerCommissioningFlow,PeerSet}=await load('@matter/protocol/dist/esm/index.js');
        flow=class extends ControllerCommissioningFlow {
            constructor(...args) {
                const connect=args[4];
                args[4]=async (address,concurrent)=>{
                    const peer=controller.node.env.get(PeerSet).for(address);
                    peer.descriptor.operationalAddress={type:'udp',ip,port};
                    peer.service.addresses.add({type:'udp',ip,port});
                    return connect(address,concurrent);
                };
                super(...args);
            }
        };
    }
    const ctx={entry,controller,flow,clients:[],subscriptions:[],sessions:[],generation:0}; contexts.push(ctx);
    await controller.start(); return ctx;
}
async function peerClient(ctx) {
    const cached=await ctx.controller.createInteractionClient(BigInt(ctx.entry.node),undefined,
        ctx.disconnected?{forcedConnection:true}:undefined);
    ctx.disconnected=false;
    ctx.provider??=new InteractionClientProvider(ctx.controller.node);
    return ctx.provider.interactionClientFor(cached.address);
}
async function attribute(client,cluster,definition) {
    return client.getAttribute({endpointId:0,clusterId:cluster,attribute:definition,requestFromRemote:true});
}
async function fabricCount(ctx,expected) {
    const count=await attribute(ctx.clients[0],0x3e,OperationalCredentials.Cluster.attributes.commissionedFabrics);
    if(count!==expected) throw Error(`Fabric count ${count}, expected ${expected}`);
}
async function openWindow(ctx) {
    const salt=randomBytes(16),iterations=1000;
    const {w0,L}=await Spake2p.computeW0L(new NodeJsCrypto(),{salt,iterations},20202021);
    const verifier=Buffer.concat([Buffer.from(w0.toString(16).padStart(64,'0'),'hex'),Buffer.from(L)]);
    await ctx.clients[0].invoke({endpointId:0,clusterId:0x3c,command:AdministratorCommissioning.Cluster.commands.openCommissioningWindow,
        asTimedRequest:true,request:{commissioningTimeout:180,pakePasscodeVerifier:verifier,discriminator:1234,iterations,salt}});
}
async function fullRead(client) {
    const begin=performance.now();
    try {
    const response=await client.getAllAttributesAndEvents({dataVersionFilters:[],eventFilters:[]});
    if(response.attributeReports.length!==expectedAttributes) throw Error(`Incomplete full Read: ${response.attributeReports.length}`);
    const paths=response.attributeReports.map(r=>`${r.path.endpointId}/${r.path.clusterId}/${r.path.attributeId}`);
    if(new Set(paths).size!==paths.length) throw Error('Duplicate attribute paths');
    ++summary.full_reads; summary.read_attributes+=paths.length;
    readTimings.full.push(performance.now()-begin);
    return response;
    } catch(e) {
        emit('READ_FAILURE',{client:clientNames.get(client),...errorInfo(e),stack:e.stack});
        throw e;
    }
}
async function concreteRead(client) {
    const begin=performance.now();
    const report=await client.getMultipleAttributes({attributes:[
        {endpointId:0,clusterId:0x28,attributeId:BasicInformation.Cluster.attributes.nodeLabel.id},
        {endpointId:0,clusterId:0x33,attributeId:GeneralDiagnostics.Cluster.attributes.upTime.id},
        {endpointId:0,clusterId:0x3e,attributeId:OperationalCredentials.Cluster.attributes.commissionedFabrics.id}],dataVersionFilters:[]});
    if(report.length!==3) throw Error(`Incomplete concrete Read: ${report.length}`);
    ++summary.concrete_reads; summary.concrete_read_attributes+=report.length;
    readTimings.concrete.push(performance.now()-begin);
    return report;
}
const burstRead=client=>readWorkload==='wildcard'?fullRead(client):concreteRead(client);
async function addSubscription(ctx,client) {
    const registry=ctx.controller.node.env.get(ClientSubscriptions),before=new Set(registry);
    const generation=ctx.generation;
    const response=await client.subscribeAllAttributesAndEvents({minIntervalFloorSeconds:1,maxIntervalCeilingSeconds:5,
        keepSubscriptions:true,isUrgent:true,dataVersionFilters:[],eventFilters:[],
        attributeListener:()=>{},eventListener:()=>{},updateReceived:()=>{++summary.subscription_updates;},
        updateTimeoutHandler:()=>{++summary.subscription_closed;
            emit('SUBSCRIPTION_TIMEOUT',{client:clientNames.get(client),subscription_generation:generation,
                current_generation:ctx.generation,expected:ctx.generation!==generation||ctx.expectedLoss});
            if(ctx.generation===generation && !ctx.expectedLoss) ++summary.unexpected_subscription_closures;}});
    if(response.attributeReports.length!==expectedAttributes) throw Error(`Incomplete Subscribe: ${response.attributeReports.length}`);
    const added=[...registry].filter(s=>!before.has(s));
    if(added.length!==1) throw Error(`SDK subscription registration count ${added.length}`);
    ctx.subscriptions.push(...added); ++summary.subscription_snapshots;
}
async function pairSession(ctx) {
    const sessions=ctx.controller.node.env.get(SessionManager),exchanges=ctx.controller.node.env.get(ExchangeManager);
    const transport=exchanges.interfaceFor('udp',ip); if(!transport) throw Error('No UDP transport');
    const channel=await transport.openChannel({type:'udp',ip,port});
    const unsecured=sessions.createUnsecuredSession({channel,isInitiator:true});
    const exchange=exchanges.initiateExchangeForSession(unsecured,0);
    try {
        const {session,resumed}=await new CaseClient(sessions).pair(exchange,ctx.controller.fabric,BigInt(ctx.entry.node),
            {expectedProcessingTime:Seconds(10)});
        ++summary.case_pairs; if(resumed) ++summary.case_resumed;
        ctx.sessions.push(session); return ctx.provider.interactionClientFor(session);
    } finally { await exchange.close(); await unsecured[Symbol.asyncDispose](); }
}
async function recoveryAdmission(operation,recovering) {
    const deadline=performance.now()+90000;
    for(;;) {
        try { return await operation(); }
        catch(e) {
            if(!recovering || !/busy|resource.?exhaust|no available session/i.test(`${e.name} ${e.message}`) || performance.now()>=deadline) throw e;
            ++summary.recovery_busy_retries;
            emit('RECOVERY_ADMISSION_BUSY',{retry:summary.recovery_busy_retries});
            // Session close is best effort on the wire. Preserve protected
            // slots while the old peer's MRP/subscription retirement drains.
            await sleep(2000); summary.recovery_busy_wait_ms+=2000;
        }
    }
}
async function loadSessions(ctx,recovering=false) {
    const client=await recoveryAdmission(()=>peerClient(ctx),recovering);
    await attribute(client,0x28,BasicInformation.Cluster.attributes.nodeLabel);
    const sessions=ctx.controller.node.env.get(SessionManager);
    const current=sessions.maybeSessionFor(ctx.controller.fabric.addressOf(BigInt(ctx.entry.node)));
    if(!current) throw Error('No initial CASE session');
    ctx.sessions=[current]; ctx.clients=[await ctx.provider.interactionClientFor(current)];
    for(let j=0;j<3;++j) {
        if(j) ctx.clients.push(await recoveryAdmission(()=>pairSession(ctx),recovering));
        clientNames.set(ctx.clients[j],`${ctx.entry.environment}/session${j}`);
        await addSubscription(ctx,ctx.clients[j]);
    }
}
async function assertLoad(total,own=3) {
    if(summary.unexpected_subscription_closures) throw Error('Subscription closed outside a deliberate fault/drain window');
    const load=await attribute(contexts[0].clients[0],0x33,GeneralDiagnostics.Cluster.attributes.deviceLoadStatus);
    if(load.currentSubscriptions!==total || load.currentSubscriptionsForFabric!==own)
        throw Error(`Unexpected live subscription load: ${JSON.stringify(load)}`);
    const active=contexts.filter(c=>!c.removed);
    emit('LOAD_PASS',{fabrics:active.length,verified_sessions:active.reduce((n,c)=>n+c.clients.length,0),load});
}
async function closeLoad() {
    for(const ctx of contexts) { ++ctx.generation; for(const sub of ctx.subscriptions) await sub.close(); ctx.subscriptions=[]; }
    for(const ctx of contexts) {
        await ctx.controller.disconnectNode(BigInt(ctx.entry.node),true);
        ctx.disconnected=true;
        ctx.sessions=[]; ctx.clients=[];
        await sleep(100); // Avoid a 15-datagram close burst into the bounded RX FIFO.
    }
    await sleep(1500);
}
async function buildLoad(recovering=false) { for(const ctx of contexts) await loadSessions(ctx,recovering); await sleep(500); await assertLoad(contexts.length*3); }
async function recoverFaultLoad(kind) {
    const health=await Promise.allSettled(contexts.map(c=>burstRead(c.clients[0])));
    let needsRebuild=health.some(r=>r.status==='rejected') || contexts.some(c=>c.sessions.some(s=>s.isClosed));
    if(!needsRebuild) {
        try {
            const load=await attribute(contexts[0].clients[0],0x33,GeneralDiagnostics.Cluster.attributes.deviceLoadStatus);
            if(load.currentSubscriptions!==15) {
                summary[`${kind}_lost_subscriptions`]+=15-load.currentSubscriptions;
                emit('FAULT_SUBSCRIPTIONS_ENDED',{fault:kind,remaining:load.currentSubscriptions}); needsRebuild=true;
            }
        } catch(e) {
            // A peer timeout may retire a bound session after its Read resolves.
            // Do not query that stale handle as proof of post-fault health.
            emit('FAULT_LOAD_QUERY_FAILED',{fault:kind,...errorInfo(e)}); needsRebuild=true;
        }
    }
    if(needsRebuild) {
        emit('FAULT_REESTABLISH_LOAD',{fault:kind,failed_health_reads:health.filter(r=>r.status==='rejected').length});
        await closeLoad(); for(const ctx of contexts) ctx.expectedLoss=false;
        await buildLoad(true); ++summary[`${kind}_rebuilt_load_cycles`];
    }
    await Promise.all(contexts.map(c=>burstRead(c.clients[0])));
    // A delayed MRP expiry can end a subscription during those health Reads,
    // after the first count was still 15. This remains the deliberate fault
    // window: allow one logged rebuild, then require the full load strictly.
    const verified=await attribute(contexts[0].clients[0],0x33,GeneralDiagnostics.Cluster.attributes.deviceLoadStatus);
    if(verified.currentSubscriptions!==15) {
        summary[`${kind}_lost_subscriptions`]+=15-verified.currentSubscriptions;
        emit('FAULT_LATE_SUBSCRIPTIONS_ENDED',{fault:kind,remaining:verified.currentSubscriptions});
        await closeLoad(); for(const ctx of contexts) ctx.expectedLoss=false;
        await buildLoad(true); ++summary[`${kind}_rebuilt_load_cycles`];
        await Promise.all(contexts.map(c=>burstRead(c.clients[0])));
    }
    for(const ctx of contexts) ctx.expectedLoss=false;
    await assertLoad(15);
}
async function checkpoint(phase) {
    const data=await control('m'); summary.checkpoints.push({phase,...data}); emit('CHECKPOINT',{phase,...data});
}
async function reconnectLoad() {
    await checkpoint('full-load-before-radio-reconnect');
    for(const ctx of contexts) ctx.expectedLoss=true;
    await control('w');
    const interrupted=await Promise.allSettled(contexts.map(c=>burstRead(c.clients[0])));
    emit('RECONNECT_INTERRUPTED_OPERATIONS',{fulfilled:interrupted.filter(r=>r.status==='fulfilled').length,
        rejected:interrupted.filter(r=>r.status==='rejected').length});
    await closeLoad(); for(const ctx of contexts) ctx.expectedLoss=false;
    await sleep(2000); await buildLoad(true); ++summary.reconnect_cycles;
    await checkpoint('reconnected-full-load');
}
async function removeFabric(ctx) {
    if(!ctx.clients.length) ctx.clients=[await peerClient(ctx)];
    const cluster=OperationalCredentials.Cluster;
    const index=await attribute(ctx.clients[0],0x3e,cluster.attributes.currentFabricIndex);
    const response=await ctx.clients[0].invoke({endpointId:0,clusterId:0x3e,command:cluster.commands.removeFabric,request:{fabricIndex:index}});
    if(response.statusCode!==0) throw Error('Own test fabric removal failed');
    emit('REMOVE_FABRIC_ACK_PASS',{environment:ctx.entry.environment,index});
    topology=topology.filter(t=>t.environment!==ctx.entry.environment); await saveTopology();
    ctx.removed=true;
}
async function cleanupFabrics() {
    for(const ctx of contexts.slice(1).reverse()) if(!ctx.removed) await removeFabric(ctx);
    const primary=contexts[0]; if(!primary.clients.length) primary.clients=[await peerClient(primary)];
    await fabricCount(primary,1);
    await primary.clients[0].setAttribute({attributeData:{endpointId:0,clusterId:0x28,
        attribute:BasicInformation.Cluster.attributes.nodeLabel,value:'C6 durable label'}});
}
try {
    const primary=await startController(topology[0]);
    if(hostMode) {
        primary.entry.node=String(await primary.controller.commissionNode({passcode:20202021,
            discovery:{identifierData:{longDiscriminator:3840},knownAddress:{type:'udp',ip,port}},
            commissioning:{regulatoryLocation:0,regulatoryCountryCode:'XX'}},
            {connectNodeAfterCommissioning:false,commissioningFlowImpl:primary.flow}));
        await saveTopology();
    }
    primary.clients=[await peerClient(primary)];
    for(const entry of topology.slice(1)) { const ctx=await startController(entry); ctx.clients=[await peerClient(ctx)]; }
    if(mode!=='cleanup') {
        while(topology.length<5) {
            const entry={environment:`c6-memory15-${topology.length}`,original:false};
            await openWindow(primary); const ctx=await startController(entry);
            entry.node=String(await ctx.controller.commissionNode({passcode:20202021,
                discovery:{identifierData:{longDiscriminator:1234},knownAddress:{type:'udp',ip,port}},
                commissioning:{regulatoryLocation:0,regulatoryCountryCode:'XX'}},{connectNodeAfterCommissioning:false,...(hostMode?{commissioningFlowImpl:ctx.flow}:{})}));
            topology.push(entry); await saveTopology(); ctx.clients=[await peerClient(ctx)];
            await fabricCount(ctx,topology.length); emit('FABRIC_ADDED',{count:topology.length});
        }
        await checkpoint('five-fabrics-before-subscriptions');
        await buildLoad(); await checkpoint('five-fabrics-fifteen-sessions-fifteen-subscriptions');
        try { await pairSession(primary); throw Error('Fourth protected CASE unexpectedly accepted'); }
        catch(e) { if(!/busy|resource.?exhaust|no available session/i.test(`${e.name} ${e.message}`)) throw e; ++summary.session_busy_probes; emit('PROTECTED_CASE_LIMIT_PASS'); }
        if(hostMode) {
            const {hostScenarios}=await import('../../../tools/matter/tests/wire_scenarios.mjs');
            await hostScenarios({contexts,summary,control,emit,sleep,fullRead,assertLoad,closeLoad,buildLoad,
                loadSessions,attribute,GeneralDiagnostics,recoverFaultLoad,write:async value=>primary.clients[0].setAttribute({attributeData:{endpointId:0,
                    clusterId:0x28,attribute:BasicInformation.Cluster.attributes.nodeLabel,value}})});
        } else {
        const profile=process.env.MATTER_SOAK_MEMORY_PROFILE==='1';
        if(profile) {
            const {memoryProfile}=await import('./memory_profile.mjs');
            await memoryProfile({contexts,summary,fullRead,assertLoad,checkpoint,OperationalCredentials,removeFabric,emit});
        } else {
        const loadStarted=performance.now(); let faultAt=loadStarted+60000,reconnectAt=loadStarted+300000,lossAt=loadStarted+150000,writeAt=loadStarted+30000,fullAt=loadStarted+30000;
        emit('SOAK_STARTED',{seconds,read_workload:readWorkload});
        while(performance.now()-loadStarted<seconds*1000) {
            const tick=performance.now();
            if(tick>=reconnectAt) {
                await reconnectLoad(); reconnectAt=performance.now()+300000;
            } else if(tick>=lossAt) {
                for(const ctx of contexts) ctx.expectedLoss=true;
                const before=await control('d');
                const interrupted=await Promise.allSettled(contexts.map(c=>burstRead(c.clients[0])));
                summary.loss_operations_rejected+=interrupted.filter(r=>r.status==='rejected').length;
                summary.loss_operation_errors.push(...interrupted.filter(r=>r.status==='rejected').map(r=>errorInfo(r.reason)));
                // Confirm the target's deliberate three-second loss window has
                // elapsed even when the first operations finish very quickly.
                await sleep(Math.max(0,3000-(performance.now()-tick)));
                const after=await control('m'); if(after.rx_dropped_by_lab<=before.rx_dropped_by_lab) throw Error('RX-loss fixture not exercised');
                await recoverFaultLoad('loss');
                ++summary.loss_cycles; emit('RX_LOSS_RECOVERY_PASS'); lossAt=performance.now()+180000;
            } else if(tick>=faultAt) {
                for(const ctx of contexts) ctx.expectedLoss=true;
                const before=await control(String(1+summary.oom_cycles%9));
                const results=await Promise.allSettled(contexts.map(c=>burstRead(c.clients[0])));
                summary.fault_operations_rejected+=results.filter(r=>r.status==='rejected').length;
                summary.fault_operation_errors.push(...results.filter(r=>r.status==='rejected').map(r=>errorInfo(r.reason)));
                await control('a'); const after=await control('m');
                if(after.core_failures<=before.core_failures) throw Error('Allocation fault was not consumed');
                await recoverFaultLoad('oom'); ++summary.oom_cycles;
                emit('OOM_RECOVERY_PASS',{position:1+(summary.oom_cycles-1)%9}); faultAt=performance.now()+60000;
            } else {
                const results=await Promise.allSettled(contexts.map(c=>burstRead(c.clients[summary.rounds%3])));
                const rejected=results.filter(r=>r.status==='rejected');
                if(rejected.length) { summary.healthy_operation_errors+=rejected.length;
                    throw new AggregateError(rejected.map(r=>r.reason),'Healthy concurrent reads failed'); }
            }
            if(readWorkload==='bounded' && performance.now()>=fullAt) {
                await fullRead(contexts[summary.rounds%contexts.length].clients[summary.rounds%3]);
                fullAt=performance.now()+30000;
            }
            if(performance.now()>=writeAt) {
                await primary.clients[0].setAttribute({attributeData:{endpointId:0,clusterId:0x28,
                    attribute:BasicInformation.Cluster.attributes.nodeLabel,value:`C6 soak ${summary.rounds%10}`}});
                writeAt=performance.now()+30000;
            }
            ++summary.rounds;
            if(summary.rounds%10===0) { await assertLoad(15); await checkpoint('steady-load'); }
            await sleep(300);
        }
        // Recovery/rebuilding can consume a short timed window. A complete run
        // must still exercise the physical radio with all fifteen subscriptions.
        if(mode==='run' && !summary.reconnect_cycles) {
            emit('RECONNECT_REQUIRED_AFTER_TIMED_WINDOW'); await reconnectLoad();
        }
        summary.sustained_seconds=(performance.now()-loadStarted)/1000;
        }
        await assertLoad(profile?3:15); await closeLoad(); await sleep(12000);
        await checkpoint('all-subscriptions-and-sessions-drained-idle-trim');
        for(const ctx of contexts) if(!ctx.removed) ctx.clients=[await peerClient(ctx)];
    }
    }
    if(!hostMode) {
    await cleanupFabrics(); await checkpoint('original-fabric-restored');
    if(mode==='run') {
        // Stop while the core still awaits a deliberately deferred accepted TX.
        // Warm the post-cleanup CASE path, then observe the actual held send;
        // a fixed host delay can expire before a new exchange has even sent.
        await fullRead(contexts[0].clients[0]);
        await control('h'); const pending=fullRead(contexts[0].clients[0]).then(()=>({status:'fulfilled'}),e=>({status:'rejected',name:e.name}));
        const until=performance.now()+10000; let held;
        do { held=await control('m'); if(held.held_completion) break; await sleep(50); } while(performance.now()<until);
        if(!held.held_completion) throw Error('TX completion was not held');
        const stopStarted=performance.now(); await control('q',90000);
        summary.stop_wait_seconds=(performance.now()-stopStarted)/1000; summary.stop_read_outcome=await pending;
        ++summary.delayed_completion_cycles; emit('STOP_DRAIN_PASS',{wait_seconds:summary.stop_wait_seconds});
    }
    }
    summary.pass=true; emit('SOAK_PASS',summary);
} catch(e) { summary.pass=false; summary.error={name:e.name,message:e.message,stack:e.stack}; emit('SOAK_FAIL',summary.error); process.exitCode=1; }
finally {
    for(const ctx of contexts.reverse()) {
        ++ctx.generation;
        try { await ctx.controller.close(); } catch(e) { emit('CONTROLLER_CLOSE_ERROR',{name:e.name,message:e.message}); process.exitCode=1; summary.pass=false; }
    }
    summary.elapsed_seconds=(performance.now()-started)/1000;
    summary.successful_read_latency_ms={};
    for(const [kind,values] of Object.entries(readTimings)) {
        values.sort((a,b)=>a-b);
        summary.successful_read_latency_ms[kind]={count:values.length,min:values[0],
            median:values[Math.floor(values.length*.5)],p95:values[Math.min(values.length-1,Math.floor(values.length*.95))],max:values.at(-1)};
    }
    await writeFile(resolve(uartRoot,'controller-results.json'),JSON.stringify(summary,null,2)+'\n');
}
