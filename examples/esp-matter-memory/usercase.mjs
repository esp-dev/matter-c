// Matched physical C6 workload. Private state/images/UART directory arguments;
// never interprets simulator version changes as a physical firmware update.
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {readFile,writeFile,rename} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {networkInterfaces} from 'node:os';
import dgram from 'node:dgram';
import {syncBuiltinESMExports} from 'node:module';
const [modules,ip,directory,kind,iface='Wi-Fi',mode='full']=process.argv.slice(2);
if(!modules || !directory || !['c','reference'].includes(kind) || !['full','ota-only','commission-only','commission-ota','serve'].includes(mode))
    throw Error('usercase.mjs <node_modules> <scoped-ipv6> <private-output> <c|reference> [interface] [full|ota-only|commission-only|commission-ota|serve]');
const root=resolve(directory),load=p=>import(pathToFileURL(resolve(modules,p)).href);
const expected=process.env.MATTER_USERCASE_OTA_EXPECT??'success';
if(!['success','reject','rollback','interrupt'].includes(expected) || (expected!=='success' && kind!=='c'))throw Error('Invalid physical OTA fault selection');
let armed=false,bdxBlockObserved=false;
if(JSON.parse(await readFile(resolve(modules,'@project-chip/matter.js/package.json'),'utf8')).version!=='0.17.9') throw Error('Expected pinned Matter.js0.17.9');
const createSocket=dgram.createSocket;
dgram.createSocket=(...args)=>{
    const socket=createSocket(...args);let localPort=0;
    socket.once('listening',()=>{localPort=socket.address().port;if(localPort===5353)socket.setMulticastTTL(255);else if(mode==='serve')console.log('UDP_LISTEN',localPort);});
    if(mode==='serve')socket.on('message',(data,remote)=>{if(localPort!==5353)console.log(JSON.stringify({wire:'rx',localPort,remote:remote.address,port:remote.port,size:data.length,header:Buffer.from(data).subarray(0,40).toString('hex')}));});
    const send=socket.send.bind(socket);
    socket.send=(...a)=>{if(armed && expected==='interrupt' && (Buffer.isBuffer(a[0])||a[0] instanceof Uint8Array) && a[0].byteLength>1024)bdxBlockObserved=true;if(mode==='serve'&&localPort&&localPort!==5353)console.log(JSON.stringify({wire:'tx',localPort,port:a[1],remote:a[2],size:a[0].length,header:Buffer.from(a[0]).subarray(0,40).toString('hex')}));return send(...a);};
    return socket;
};
syncBuiltinESMExports();
const {peerRole}=await import('../../tools/matter/tests/peer_role.mjs');
const peer=await peerRole(modules,'corrected');
const {NodeJsEnvironment,NodeJsCrypto}=await load('@matter/nodejs/dist/esm/index.js');
const {NodeJsNetwork}=await load('@matter/nodejs/dist/esm/net/NodeJsNetwork.js');
const named=intf=>Object.entries(networkInterfaces()).find(([,list])=>list.some(a=>String(a.scopeid)===intf))?.[0]??intf;
const getMac=NodeJsNetwork.prototype.getIpMac,udp=NodeJsNetwork.prototype.createUdpSocket;
NodeJsNetwork.prototype.getIpMac=function(i){return getMac.call(this,named(i));};
NodeJsNetwork.prototype.createUdpSocket=function(o){return udp.call(this,{...o,netInterface:named(o.netInterface)});};
const {Logger,LogLevel,Seconds}=await load('@matter/general/dist/esm/index.js');Logger.level=LogLevel.WARN;
const {CommissioningController}=await load('@project-chip/matter.js/dist/esm/CommissioningController.js');
const {InteractionClientProvider}=await load('@project-chip/matter.js/dist/esm/cluster/client/InteractionClient.js');
const {SessionManager}=await load('@matter/protocol/dist/esm/session/SessionManager.js');
const {ExchangeManager}=await load('@matter/protocol/dist/esm/protocol/ExchangeManager.js');
const {CaseClient}=await load('@matter/protocol/dist/esm/session/case/CaseClient.js');
const {ClientSubscriptions}=await load('@matter/protocol/dist/esm/action/client/subscription/ClientSubscriptions.js');
const {Spake2p}=await load('@matter/general/dist/esm/crypto/Spake2p.js');
const {SoftwareUpdateManager}=await load('@matter/node/dist/esm/behavior/system/software-update/SoftwareUpdateManager.js');
const {DeviceAdvertiser}=await load('@matter/protocol/dist/esm/protocol/DeviceAdvertiser.js');
const {OtaSoftwareUpdateProviderServer}=await load('@matter/node/dist/esm/behaviors/ota-software-update-provider/OtaSoftwareUpdateProviderServer.js');
const {PersistedFileDesignator}=await load('@matter/protocol/dist/esm/bdx/PersistedFileDesignator.js');
const clusters={};for(const [symbol,file] of Object.entries({BasicInformation:'basic-information',OperationalCredentials:'operational-credentials',AdministratorCommissioning:'administrator-commissioning',OnOff:'on-off',LevelControl:'level-control',ColorControl:'color-control',OtaSoftwareUpdateRequestor:'ota-software-update-requestor'}))
    clusters[symbol]=(await load(`@matter/types/dist/esm/clusters/${file}.js`))[symbol];
const {BasicInformation,OperationalCredentials,AdministratorCommissioning,OnOff,LevelControl,ColorControl,OtaSoftwareUpdateRequestor}=clusters;
const env=NodeJsEnvironment();env.vars.set('storage.path',resolve(root,'controller-state'));env.vars.set('mdns.networkInterface',iface);
const sleep=ms=>new Promise(r=>setTimeout(r,ms)),contexts=[];
const result={kind,mode,expected,peer,phases:[],casePairs:0,subscriptions:0,reports:0,invokes:0,reads:0,busyRetries:0,unexpectedClosures:0,queries:0,applies:0,notifications:0};
const emit=(phase,data={})=>console.log(JSON.stringify({phase,unix_ms:Date.now(),...data}));
let token,closing=false,serial=0;
const query=OtaSoftwareUpdateProviderServer.prototype.queryImage,apply=OtaSoftwareUpdateProviderServer.prototype.applyUpdateRequest,notify=OtaSoftwareUpdateProviderServer.prototype.notifyUpdateApplied;
OtaSoftwareUpdateProviderServer.prototype.checkUpdateAvailable=async function(request){
    if(!armed || request.softwareVersion!==1) return undefined;
    const fd=new PersistedFileDesignator('physical-c6-image',this.updateStorage);
    await fd.writeFromStream(new Blob([await readFile(resolve(root,'source.ota'))]).stream());
    return {fileDesignator:fd,newSoftwareVersion:2,newSoftwareVersionString:'2',consentRequired:false};
};
OtaSoftwareUpdateProviderServer.prototype.queryImage=async function(request){
    ++result.queries;emit('OTA_QUERY',{version:request.softwareVersion});
    if(request.vendorId!==0xfff1 || request.productId!==0x8000)throw Error('Unexpected OTA product');
    const response=await query.call(this,request);if(response.updateToken)token=Buffer.from(response.updateToken);return response;
};
OtaSoftwareUpdateProviderServer.prototype.applyUpdateRequest=async function(request){
    if(request.newVersion!==2 || !token?.equals(Buffer.from(request.updateToken)))throw Error('Apply token/version mismatch');
    const response=await apply.call(this,request);++result.applies;emit('OTA_APPLY');
    return {...response,action:0,delayedActionTime:2};
};
OtaSoftwareUpdateProviderServer.prototype.notifyUpdateApplied=async function(request){
    if(request.softwareVersion!==2 || !token?.equals(Buffer.from(request.updateToken)))throw Error('Notify token/version mismatch');
    await notify.call(this,request);++result.notifications;emit('OTA_NOTIFY');
};
async function events(){try{return (await readFile(resolve(root,'events.jsonl'),'utf8')).split('\n').filter(Boolean).flatMap(s=>{try{return [JSON.parse(s)];}catch{return [];}});}catch(e){if(e.code==='ENOENT')return [];throw e;}}
async function control(command){const tmp=resolve(root,'control-request.tmp');await writeFile(tmp,JSON.stringify({id:++serial,command}));await rename(tmp,resolve(root,'control-request.json'));}
async function waitFor(test,timeout=30000){const end=Date.now()+timeout;while(Date.now()<end){if(await test())return;await sleep(100);}throw Error('User-case deadline exceeded');}
async function phase(n){await control(String(n));await sleep(500);const row={number:n,begin_ms:Date.now()};result.phases.push(row);emit('PHASE_BEGIN',row);}
async function checkpoint(){await control('m');await sleep(600);const row=result.phases.at(-1);if(row)row.end_ms=Date.now();emit('CHECKPOINT',{number:row?.number});}
const attr=async(client,ep,cluster,attribute)=>{
    ++result.reads;
    for(let attempt=0;;++attempt){
        try{return await client.getAttribute({endpointId:ep,clusterId:cluster,attribute,requestFromRemote:true});}
        catch(e){if(e.code!==0x9c || attempt>=9)throw e;++result.busyRetries;await sleep(100+attempt*50);}
    }
};
const invoke=async(client,cluster,command,request,endpointId=1)=>{++result.invokes;return client.invoke({endpointId,clusterId:cluster,command,...(request===undefined?{}:{request})});};
async function start(id,commission,disc=3840,provider=false){
    const controller=new CommissioningController({environment:{environment:env,id},autoConnect:false,enableOtaProvider:provider,adminFabricLabel:id.slice(-28)});
    const ctx={controller,subs:[],clients:[],hues:[],removed:false};contexts.push(ctx);await controller.start();
    if(provider){await controller.otaProvider.setStateOf(SoftwareUpdateManager,{announceAsDefaultProvider:false});controller.node.env.get(DeviceAdvertiser).enterOperationalMode();controller.node.env.get(DeviceAdvertiser).restartAdvertisement();}
    ctx.node=commission?await controller.commissionNode({passcode:20202021,discovery:{identifierData:{longDiscriminator:disc},knownAddress:{type:'udp',ip,port:5540}},commissioning:{regulatoryLocation:0,regulatoryCountryCode:'XX'}},{connectNodeAfterCommissioning:false}):BigInt(JSON.parse(await readFile(resolve(root,'primary-node.json'),'utf8')));
    if(provider && commission)await writeFile(resolve(root,'primary-node.json'),JSON.stringify(String(ctx.node)));
    ctx.provider=new InteractionClientProvider(controller.node);return ctx;
}
async function fresh(ctx){const cached=await ctx.controller.createInteractionClient(ctx.node,undefined,{forcedConnection:true});const c=await ctx.provider.interactionClientFor(cached.address);ctx.clients=[c];return c;}
async function pair(ctx){
    const sessions=ctx.controller.node.env.get(SessionManager),exchanges=ctx.controller.node.env.get(ExchangeManager);
    const channel=await exchanges.interfaceFor('udp',ip).openChannel({type:'udp',ip,port:5540});
    const unsecured=sessions.createUnsecuredSession({channel,isInitiator:true}),exchange=exchanges.initiateExchangeForSession(unsecured,0);
    try{const {session}=await new CaseClient(sessions).pair(exchange,ctx.controller.fabric,ctx.node,{expectedProcessingTime:Seconds(10)});++result.casePairs;return await ctx.provider.interactionClientFor(session);}finally{await exchange.close();await unsecured[Symbol.asyncDispose]();}
}
async function subscribe(ctx,client){
    const registry=ctx.controller.node.env.get(ClientSubscriptions),before=new Set(registry),hues=new Set();ctx.hues.push(hues);
    const report=await client.subscribeMultipleAttributesAndEvents({attributes:[{endpointId:1,clusterId:6,attributeId:0},{endpointId:1,clusterId:8,attributeId:0},{endpointId:1,clusterId:0x300,attributeId:0}],minIntervalFloorSeconds:1,maxIntervalCeilingSeconds:5,keepSubscriptions:true,isUrgent:true,dataVersionFilters:[],attributeListener:r=>{++result.reports;if(r.path.clusterId===0x300)hues.add(r.value);},updateTimeoutHandler:()=>{if(!closing&&!ctx.removed){++result.unexpectedClosures;emit('SUBSCRIPTION_TIMEOUT');}}});
    if(report.attributeReports.length!==3)throw Error('Incomplete three-path subscription');
    const added=[...registry].filter(s=>!before.has(s));if(added.length!==1)throw Error('Subscription identity mismatch');ctx.subs.push(...added);++result.subscriptions;
}
async function rgb(client,hue){
    await invoke(client,6,OnOff.Cluster.commands.on);
    await invoke(client,8,LevelControl.Cluster.commands.moveToLevelWithOnOff,{level:127,transitionTime:0,optionsMask:0,optionsOverride:0});
    await invoke(client,0x300,ColorControl.Cluster.commands.moveToHueAndSaturation,{hue,saturation:254,transitionTime:0,optionsMask:0,optionsOverride:0});
    await waitFor(async()=>await attr(client,1,0x300,ColorControl.Cluster.attributes.currentHue)===hue,5000);
}
async function remove(ctx){const index=await attr(ctx.clients[0],0,0x3e,OperationalCredentials.Cluster.attributes.currentFabricIndex);const response=await invoke(ctx.clients[0],0x3e,OperationalCredentials.Cluster.commands.removeFabric,{fabricIndex:index},0);if(response.statusCode!==0)throw Error('RemoveFabric response missing/failed');ctx.removed=true;emit('FABRIC_REMOVED',{index});}
try{await(async()=>{
    if(mode==='serve'){
        const primary=await start('usercase42-primary',false,3840,true);
        emit('PROVIDER_READY',{port:primary.controller.node.state.network.operationalPort});
        await control('reset');await waitFor(()=>result.queries>0,90000);
        emit('PROVIDER_QUERY_PROBE_PASS');return;
    }
    await waitFor(async()=>(await events()).some(e=>e.text.includes(kind==='c'?'RUNTIME_READY':'REFERENCE_READY')),90000);
    if(mode!=='ota-only')await phase(1);
    const primary=await start('usercase42-primary',mode!=='ota-only',3840,true);
    if(mode!=='ota-only')await checkpoint();
    await phase(2);let client=await fresh(primary);
    if(await attr(client,0,0x28,BasicInformation.Cluster.attributes.softwareVersion)!==1)throw Error('Expected physical version 1');
    if(await attr(client,0,0x3e,OperationalCredentials.Cluster.attributes.commissionedFabrics)!==1)throw Error('Expected one initial fabric');
    await sleep(2000);await checkpoint();
    if(mode==='commission-only'){
        result.pass=true;await writeFile(resolve(root,'result.json'),JSON.stringify(result,null,2));emit('USERCASE_COMMISSION_PASS');return;
    }
    if(mode==='full'){
        await phase(3);await subscribe(primary,client);await rgb(client,85);await sleep(5000);await checkpoint();
        await phase(4);for(let n=0;n<2;++n){const c=await pair(primary);primary.clients.push(c);await subscribe(primary,c);}
        for(const hue of [170,85,170,85]){await rgb(client,hue);await Promise.all(primary.clients.map(c=>attr(c,1,6,OnOff.Cluster.attributes.onOff)));await sleep(5000);}
        if(primary.hues.some(h=>!h.has(85)||!h.has(170)))throw Error('Missing updates on one of three phone sessions');await checkpoint();
        await phase(5);
        // Timed commissioning window uses the same verifier as the common lab.
        const salt=randomBytes(16),iterations=1000,{w0,L}=await Spake2p.computeW0L(new NodeJsCrypto(),{salt,iterations},20202021);
        await client.invoke({endpointId:0,clusterId:0x3c,command:AdministratorCommissioning.Cluster.commands.openCommissioningWindow,asTimedRequest:true,request:{commissioningTimeout:180,pakePasscodeVerifier:Buffer.concat([Buffer.from(w0.toString(16).padStart(64,'0'),'hex'),Buffer.from(L)]),discriminator:1234,iterations,salt}});
        const other=await start('usercase42-second-admin',true,1234);await fresh(other);await subscribe(other,other.clients[0]);await rgb(client,170);await sleep(5000);await checkpoint();
        if(await attr(client,0,0x3e,OperationalCredentials.Cluster.attributes.commissionedFabrics)!==2)throw Error('Second fabric missing');
        await phase(6);await remove(other);if(await attr(client,0,0x3e,OperationalCredentials.Cluster.attributes.commissionedFabrics)!==1)throw Error('Removed fabric still present');await sleep(5000);await checkpoint();
    }
    if(result.unexpectedClosures)throw Error('Unexpected subscription closure before OTA');
    closing=true;for(const ctx of contexts)for(const sub of ctx.subs)await sub.close();
    await primary.controller.disconnectNode(primary.node,true);await sleep(12000);client=await fresh(primary);
    await phase(7);armed=true;
    if(expected==='rollback'){await control('x');await sleep(500);}
    if(await attr(client,0,0x2a,OtaSoftwareUpdateRequestor.Cluster.attributes.updatePossible)!==true)throw Error('Physical firmware does not expose an active installer');
    const fabricIndex=await attr(client,0,0x3e,OperationalCredentials.Cluster.attributes.currentFabricIndex);
    await client.setAttribute({attributeData:{endpointId:0,clusterId:0x2a,attribute:OtaSoftwareUpdateRequestor.Cluster.attributes.defaultOtaProviders,value:[{providerNodeId:primary.controller.nodeId,endpoint:primary.controller.otaProvider.number,fabricIndex}]}});
    await control('u');
    if(expected!=='success'){
        if(expected==='reject')await waitFor(async()=>(await events()).some(e=>e.text.includes('OTA_DOWNLOAD_FAILED')),240000);
        if(expected==='rollback'){
            await waitFor(async()=>{const rows=await events(),i=rows.findIndex(e=>e.text.includes('NATIVE_OTA_TRIAL_INTERRUPTED'));return i>=0&&rows.slice(i+1).some(e=>e.text.includes('NATIVE_OTA_BOOT_READY version=1'));},300000);
        }
        if(expected==='interrupt'){
            await waitFor(()=>bdxBlockObserved,180000);await sleep(750);armed=false;
            const before=(await events()).filter(e=>e.text.includes('NATIVE_OTA_BOOT_READY version=1')).length;
            await control('reset');
            await waitFor(async()=>(await events()).filter(e=>e.text.includes('NATIVE_OTA_BOOT_READY version=1')).length>before,60000);
        }
        armed=false;await primary.controller.disconnectNode(primary.node,true);client=await fresh(primary);
        result.version=await attr(client,0,0x28,BasicInformation.Cluster.attributes.softwareVersion);
        if(result.version!==1 || result.notifications || result.applies!==(expected==='rollback'?1:0))throw Error('Rejected/interrupted image changed firmware or notified success');
        const applied=await client.getEvent({endpointId:0,clusterId:0x2a,event:OtaSoftwareUpdateRequestor.Cluster.events.versionApplied});
        if(applied?.length)throw Error('Rejected/interrupted image published VersionApplied');
        await rgb(client,85);await checkpoint();result.pass=true;
        const failures=(await events()).filter(e=>e.text.startsWith('USERCASE_OOM ')).map(e=>JSON.parse(e.text.slice(13)).failures);
        if(!failures.length || failures.some(n=>n!==0))throw Error('Unexpected SDK OOM in OTA fault case');
        await writeFile(resolve(root,'result.json'),JSON.stringify(result,null,2));emit('USERCASE_FAULT_PASS',result);return;
    }
    await waitFor(()=>result.notifications===1,420000);
    await waitFor(async()=>(await events()).some(e=>e.text.includes(kind==='c'?'NATIVE_OTA_BOOT_READY version=2':'REFERENCE_READY version=2')),60000);
    await checkpoint();
    await phase(8);await primary.controller.disconnectNode(primary.node,true);client=await fresh(primary);
    const version=await attr(client,0,0x28,BasicInformation.Cluster.attributes.softwareVersion);
    if(version!==2 || result.applies!==1)throw Error('Physical reboot/version/Apply verification failed');
    if(await attr(client,0,0x3e,OperationalCredentials.Cluster.attributes.commissionedFabrics)!==1)throw Error('Fabric not retained across physical OTA');
    const uart=await events();
    if(kind==='c'&&!uart.some(e=>e.text.includes('NATIVE_OTA_RESTART drained')))throw Error('Missing real C reboot/drain marker');
    if(!uart.some(e=>e.text.includes(kind==='c'?'NATIVE_OTA_BOOT_READY version=2':'REFERENCE_READY version=2')))throw Error('Missing new physical firmware boot');
    closing=false;primary.subs=[];await subscribe(primary,client);await rgb(client,85);await sleep(6000);await checkpoint();
    await invoke(client,6,OnOff.Cluster.commands.off);closing=true;for(const sub of primary.subs)await sub.close();
    await primary.controller.disconnectNode(primary.node,true);await sleep(12000);
    result.phases.push({number:9,begin_ms:Date.now()});await control('q');
    if(kind==='reference')await waitFor(async()=>(await events()).some(e=>e.text.includes('LIFECYCLE_SHUTDOWN_COMPLETE')),90000);
    else{await sleep(65000);await control('m');await sleep(1000);}
    if(result.unexpectedClosures)throw Error('Unexpected subscription closure');
    const oom=(await events()).filter(e=>e.text.startsWith('USERCASE_OOM ')).map(e=>JSON.parse(e.text.slice(13)).failures);
    if(!oom.length || oom.some(n=>n!==0))throw Error('SDK allocation failure during user-case run');
    result.version=version;result.pass=true;result.phases.at(-1).end_ms=Date.now();
    await writeFile(resolve(root,'result.json'),JSON.stringify(result,null,2));emit('USERCASE_PASS',result);
})()}catch(e){result.pass=false;result.error=e.message;await writeFile(resolve(root,'result.json'),JSON.stringify(result,null,2));emit('USERCASE_FAIL',{error:e.message,stack:e.stack});throw e;}
finally{closing=true;for(const ctx of contexts.reverse())await ctx.controller.close();}
