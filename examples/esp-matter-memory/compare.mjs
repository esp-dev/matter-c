// Common wire workload for C6 C runtime and the pinned ESP-Matter RGB light.
// Private controller state/logs only; development attestation is not certification.
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {readFile,writeFile,rename} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {performance} from 'node:perf_hooks';
const [modules,ip,stateRoot,storageId,uartRoot,kind,mode='reuse',iface='Wi-Fi',cleanup='drained']=process.argv.slice(2);
if(!modules || !uartRoot || !['reference','c'].includes(kind) || !['reuse','commission'].includes(mode) || !['drained','live','local-close'].includes(cleanup))
    throw Error('Usage: compare.mjs <node_modules> <scoped-ipv6> <private-state> <storage-id> <private-uart> <reference|c> [reuse|commission] [interface] [drained|live|local-close]');
const load=p=>import(pathToFileURL(resolve(modules,p)).href);
if(JSON.parse(await readFile(resolve(modules,'@project-chip/matter.js/package.json'),'utf8')).version!=='0.17.9') throw Error('Expected Matter.js0.17.9');
const {Logger,LogLevel,Seconds}=await load('@matter/general/dist/esm/index.js'); Logger.level=LogLevel.WARN;
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
const {OnOff}=await load('@matter/types/dist/esm/clusters/on-off.js');
const {LevelControl}=await load('@matter/types/dist/esm/clusters/level-control.js');
const {ColorControl}=await load('@matter/types/dist/esm/clusters/color-control.js');
const env=NodeJsEnvironment(); env.vars.set('storage.path',resolve(stateRoot)); env.vars.set('mdns.networkInterface',iface);
const sleep=ms=>new Promise(r=>setTimeout(r,ms)), started=performance.now(), run=randomBytes(6).toString('hex');
const emit=(phase,data={})=>console.log(JSON.stringify({phase,seconds:(performance.now()-started)/1000,...data}));
const summary={kind,mode,cleanup,inventory:0,reads:0,reports:0,writes:0,invokes:0,casePairs:0,resumed:0,subscriptions:0,updates:0,busyRetries:0,colorSettlePolls:0,unexpectedClosures:0,removals:[],checkpoints:[]};
const contexts=[];
const paths=[{endpointId:0,clusterId:0x28,attributeId:BasicInformation.Cluster.attributes.nodeLabel.id},
    {endpointId:0,clusterId:0x3e,attributeId:OperationalCredentials.Cluster.attributes.commissionedFabrics.id},
    {endpointId:1,clusterId:6,attributeId:0},{endpointId:1,clusterId:8,attributeId:0},
    {endpointId:1,clusterId:0x300,attributeId:0},{endpointId:1,clusterId:0x300,attributeId:1},
    {endpointId:1,clusterId:0x300,attributeId:8}];
const subscriptionPaths=[{endpointId:1,clusterId:0x300,attributeId:0}];
summary.readPaths=paths; summary.subscriptionPaths=subscriptionPaths;
let serial=0,closing=false;
async function checkpoint(label) {
    const id=`${run}:${++serial}`, temporary=resolve(uartRoot,'control-request.tmp');
    await writeFile(temporary,JSON.stringify({id,command:kind==='c'?'m':'checkpoint',label}));
    await rename(temporary,resolve(uartRoot,'control-request.json'));
    const until=performance.now()+20000;
    while(performance.now()<until) {
        try {
            const rows=(await readFile(resolve(uartRoot,'control-replies.jsonl'),'utf8')).split('\n').filter(Boolean);
            for(const row of rows) {
                let reply; try {reply=JSON.parse(row);} catch {continue;}
                if(reply.id===id) { const result={label,...reply.record.data}; summary.checkpoints.push(result); emit('CHECKPOINT',result); return; }
            }
        } catch(e) {if(e.code!=='ENOENT') throw e;}
        await sleep(100);
    }
    throw Error(`Checkpoint timed out: ${label}`);
}
async function start(id,commission=false,discriminator=1234) {
    const controller=new CommissioningController({environment:{environment:env,id},autoConnect:false,adminFabricLabel:id.slice(-28)});
    const ctx={controller,id,clients:[],subs:[],seenHues:[]}; contexts.push(ctx); await controller.start();
    ctx.node=commission?await controller.commissionNode({passcode:20202021,
        discovery:{identifierData:{longDiscriminator:discriminator},knownAddress:{type:'udp',ip,port:5540}},
        commissioning:{regulatoryLocation:0,regulatoryCountryCode:'XX'}},{connectNodeAfterCommissioning:false}):1n;
    const cached=await controller.createInteractionClient(ctx.node);
    ctx.provider=new InteractionClientProvider(controller.node);
    const initial=await ctx.provider.interactionClientFor(cached.address);
    await attr(initial,0,0x28,BasicInformation.Cluster.attributes.nodeLabel);
    const sessions=ctx.controller.node.env.get(SessionManager);
    // Bind the already established session explicitly, as for the other two.
    const session=sessions.maybeSessionFor(ctx.controller.fabric.addressOf(ctx.node));
    if(!session) throw Error('Missing initial CASE session');
    ctx.clients.push(await ctx.provider.interactionClientFor(session));
    await writeFile(resolve(uartRoot,'comparison-topology.json'),JSON.stringify(contexts.map(c=>({id:c.id,node:String(c.node??'pending')})),null,2));
    return ctx;
}
const attr=(client,ep,cluster,attribute)=>client.getAttribute({endpointId:ep,clusterId:cluster,attribute,requestFromRemote:true});
const invoke=(client,cluster,command,request,ep=1)=>client.invoke({endpointId:ep,clusterId:cluster,command,request});
async function read(client) {
    for(let attempt=0;;++attempt) {
        try {
            const reports=await client.getMultipleAttributes({attributes:paths,dataVersionFilters:[]});
            if(reports.length!==paths.length || new Set(reports.map(r=>`${r.path.endpointId}/${r.path.clusterId}/${r.path.attributeId}`)).size!==paths.length)
                throw Error('Incomplete or duplicate common Read');
            ++summary.reads; summary.reports+=reports.length; return reports;
        } catch(e) {if(e.code!==0x9c || attempt>=9) throw e; ++summary.busyRetries; await sleep(100+attempt*50);}
    }
}
async function pair(ctx) {
    const sessions=ctx.controller.node.env.get(SessionManager),exchanges=ctx.controller.node.env.get(ExchangeManager);
    const transport=exchanges.interfaceFor('udp',ip); if(!transport) throw Error('No UDP transport');
    const channel=await transport.openChannel({type:'udp',ip,port:5540});
    const unsecured=sessions.createUnsecuredSession({channel,isInitiator:true});
    const exchange=exchanges.initiateExchangeForSession(unsecured,0);
    try {
        const {session,resumed}=await new CaseClient(sessions).pair(exchange,ctx.controller.fabric,ctx.node,{expectedProcessingTime:Seconds(10)});
        ++summary.casePairs; if(resumed) ++summary.resumed;
        return await ctx.provider.interactionClientFor(session);
    } finally {await exchange.close(); await unsecured[Symbol.asyncDispose]();}
}
async function subscribe(ctx,client) {
    const registry=ctx.controller.node.env.get(ClientSubscriptions),before=new Set(registry);
    const seen=new Set(); ctx.seenHues.push(seen);
    const report=await client.subscribeMultipleAttributesAndEvents({attributes:subscriptionPaths,minIntervalFloorSeconds:1,maxIntervalCeilingSeconds:5,
        keepSubscriptions:true,isUrgent:true,dataVersionFilters:[],attributeListener:r=>{++summary.updates; seen.add(r.value);},
        updateTimeoutHandler:()=>{if(!closing && !ctx.removed) ++summary.unexpectedClosures;}});
    if(report.attributeReports.length!==subscriptionPaths.length) throw Error('Incomplete common Subscribe snapshot');
    const added=[...registry].filter(s=>!before.has(s)); if(added.length!==1) throw Error('Subscription registry mismatch');
    ctx.subs.push(...added); ++summary.subscriptions;
}
async function openWindow(ctx) {
    const salt=randomBytes(16),iterations=1000;
    const {w0,L}=await Spake2p.computeW0L(new NodeJsCrypto(),{salt,iterations},20202021);
    const verifier=Buffer.concat([Buffer.from(w0.toString(16).padStart(64,'0'),'hex'),Buffer.from(L)]);
    await ctx.clients[0].invoke({endpointId:0,clusterId:0x3c,command:AdministratorCommissioning.Cluster.commands.openCommissioningWindow,
        asTimedRequest:true,request:{commissioningTimeout:180,pakePasscodeVerifier:verifier,discriminator:1234,iterations,salt}});
}
async function loadContext(ctx) {
    for(let j=0;j<3;++j) {
        if(j) ctx.clients.push(await pair(ctx));
        await read(ctx.clients[j]); await subscribe(ctx,ctx.clients[j]);
    }
}
async function removeFabric(client) {
    const index=await attr(client,0,0x3e,OperationalCredentials.Cluster.attributes.currentFabricIndex);
    const started=performance.now();
    const result=await invoke(client,0x3e,OperationalCredentials.Cluster.commands.removeFabric,{fabricIndex:index},0);
    if(result.statusCode!==0) throw Error('Fabric removal response failed');
    const removed={index,milliseconds:performance.now()-started}; summary.removals.push(removed);
    emit('REMOVE_FABRIC_ACK',removed);
}
let primary,oldLabel;
try {
    await checkpoint('before-controller');
    primary=await start(storageId,mode==='commission',3840);
    oldLabel=await attr(primary.clients[0],0,0x28,BasicInformation.Cluster.attributes.nodeLabel);
    if(await attr(primary.clients[0],0,0x3e,OperationalCredentials.Cluster.attributes.commissionedFabrics)!==1) throw Error('Baseline needs exactly one fabric');
    const inventory=await primary.clients[0].getAllAttributesAndEvents({dataVersionFilters:[],eventFilters:[]});
    summary.inventory=inventory.attributeReports.length;
    await sleep(2000); await checkpoint('one-fabric-idle');
    await loadContext(primary); await checkpoint('one-fabric-three-sessions-subscriptions');
    for(let n=1;n<5;++n) {
        await openWindow(primary);
        const ctx=await start(`${storageId}-${run}-${n}`,true);
        await loadContext(ctx); emit('FABRIC_LOAD',{fabrics:n+1});
    }
    if(await attr(primary.clients[0],0,0x3e,OperationalCredentials.Cluster.attributes.commissionedFabrics)!==5) throw Error('Five fabrics missing');
    await checkpoint('five-fabrics-fifteen-sessions-subscriptions');
    for(let round=0;round<6;++round) {
        const label=`memory-compare-${round}`,hue=[0,85,170][round%3];
        await primary.clients[0].setAttribute({attributeData:{endpointId:0,clusterId:0x28,attribute:BasicInformation.Cluster.attributes.nodeLabel,value:label}}); ++summary.writes;
        if(await attr(primary.clients[0],0,0x28,BasicInformation.Cluster.attributes.nodeLabel)!==label) throw Error('Write readback mismatch');
        await invoke(primary.clients[0],6,OnOff.Cluster.commands.on); ++summary.invokes;
        await invoke(primary.clients[0],8,LevelControl.Cluster.commands.moveToLevelWithOnOff,{level:127,transitionTime:0,optionsMask:0,optionsOverride:0}); ++summary.invokes;
        await invoke(primary.clients[0],0x300,ColorControl.Cluster.commands.moveToHueAndSaturation,{hue,saturation:254,transitionTime:0,optionsMask:0,optionsOverride:0}); ++summary.invokes;
        const until=performance.now()+2000;
        for(;;) {
            const actual=await attr(primary.clients[0],1,0x300,ColorControl.Cluster.attributes.currentHue);
            if(actual===hue) break;
            if(performance.now()>=until) throw Error(`RGB readback mismatch: expected ${hue}, got ${actual}`);
            ++summary.colorSettlePolls; await sleep(100);
        }
        // One outstanding Read/fabric, five fabrics concurrently; unchanged admission limits.
        for(let session=0;session<3;++session) await Promise.all(contexts.map(ctx=>read(ctx.clients[session])));
        await sleep(5000);
    }
    await checkpoint('loaded-after-thirty-seconds');
    if(summary.unexpectedClosures || contexts.some(ctx=>ctx.seenHues.some(seen=>!seen.has(85) || !seen.has(170))))
        throw Error('Subscription loss or missing hue updates');
    if(cleanup==='drained') {
        closing=true;
        for(const ctx of contexts) for(const sub of ctx.subs) await sub.close();
        for(const ctx of contexts) {
            await ctx.controller.disconnectNode(ctx.node,true);
            ctx.clients=[];
            await sleep(100); // Stagger the bounded RX queue's close traffic.
        }
        await sleep(12000); await checkpoint('subscriptions-closed');
        for(const ctx of contexts.slice(1).reverse()) {
            const cached=await ctx.controller.createInteractionClient(ctx.node,undefined,{forcedConnection:true});
            await removeFabric(await ctx.provider.interactionClientFor(cached.address));
        }
    } else {
        if(cleanup==='local-close') {
            closing=true;
            for(const ctx of contexts) for(const sub of ctx.subs) await sub.close();
            await sleep(2000); // Sessions remain open; server can still owe ACKs.
        }
        for(const ctx of contexts.slice(1).reverse()) {
            ctx.removed=true;
            await removeFabric(ctx.clients[0]); // Three live CASE sessions/fabric.
            for(const survivor of contexts.filter(c=>!c.removed))
                for(const client of survivor.clients) await read(client);
            if(cleanup==='live') {
                const hue=10+summary.removals.length;
                await invoke(primary.clients[0],0x300,ColorControl.Cluster.commands.moveToHueAndSaturation,
                    {hue,saturation:254,transitionTime:0,optionsMask:0,optionsOverride:0});
                ++summary.invokes;
                const until=performance.now()+10000;
                while(contexts.filter(c=>!c.removed).some(c=>c.seenHues.some(seen=>!seen.has(hue)))) {
                    if(performance.now()>=until) throw Error('Surviving fabric subscription stopped after removal');
                    await sleep(100);
                }
            }
        }
        closing=true;
        for(const ctx of contexts) for(const sub of ctx.subs) await sub.close();
    }
    const cached=await primary.controller.createInteractionClient(primary.node,undefined,{forcedConnection:true});
    primary.clients=[await primary.provider.interactionClientFor(cached.address)];
    await primary.clients[0].setAttribute({attributeData:{endpointId:0,clusterId:0x28,attribute:BasicInformation.Cluster.attributes.nodeLabel,value:oldLabel}});
    await invoke(primary.clients[0],6,OnOff.Cluster.commands.off);
    if(await attr(primary.clients[0],0,0x3e,OperationalCredentials.Cluster.attributes.commissionedFabrics)!==1) throw Error('Temporary fabrics remain');
    await sleep(5000); await checkpoint('one-fabric-after-cleanup');
    emit('COMMON_PASS',summary);
} catch(e) {emit('COMMON_FAIL',{message:e.message,code:e.code,stack:e.stack,summary}); throw e;}
finally {closing=true; for(const ctx of contexts.reverse()) await ctx.controller.close();}
