import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {readFile,writeFile} from 'node:fs/promises';
// Independent Matter.js0.17.9 oracle; public TEST DAC/CD only. State is private.
const [modules,ip,mode='reconnect',stateRoot='build/esp32-runtime-controller',interfaceName,storageId='c6-lab']=process.argv.slice(2);
if(!modules || !ip || !interfaceName || !['commission','reconnect','recovered','open','second'].includes(mode))
    throw Error('Usage: controller.mjs <pinned-node_modules> <scoped-ipv6> <commission|reconnect|recovered|open|second> <private-state-dir> <interface> [storage-id]');
const load=p=>import(pathToFileURL(resolve(modules,p)).href);
const sdk=JSON.parse(await readFile(resolve(modules,'@project-chip/matter.js/package.json'),'utf8'));
if(sdk.version!=='0.17.9') throw Error(`Expected Matter.js0.17.9, found ${sdk.version}`);
const {Logger,LogLevel}=await load('@matter/general/dist/esm/index.js');
Logger.level=LogLevel.INFO;
const {NodeJsEnvironment}=await load('@matter/nodejs/dist/esm/index.js');
const {CommissioningController}=await load('@project-chip/matter.js/dist/esm/CommissioningController.js');
const env=NodeJsEnvironment();
env.vars.set('storage.path',resolve(stateRoot));
env.vars.set('mdns.networkInterface',interfaceName);
const secondary=mode==='second';
const controller=new CommissioningController({environment:{environment:env,id:secondary?`${storageId}-second`:storageId},autoConnect:false,adminFabricLabel:'C6 memory14'});
try {
    await controller.start();
    const id=mode==='commission' || secondary?await controller.commissionNode({passcode:20202021,
        discovery:{identifierData:{longDiscriminator:secondary?1234:3840},knownAddress:{type:'udp',ip,port:5540}},
        // This pinned wrapper's knownAddress branch does not forward an
        // attestation callback. Its development default accepts findings;
        // inspect warnings and never use this oracle as an attestation test.
        commissioning:{regulatoryLocation:0,regulatoryCountryCode:'XX'}},{connectNodeAfterCommissioning:false}):1n;
    console.log(mode==='commission' || secondary?'C6_COMMISSIONED':'C6_CASE_RECONNECTED',String(id));
    const cached=await controller.createInteractionClient(id);
    // Use the SDK's public unbound-client factory for a wire oracle. Its normal
    // ClientNode wrapper injects cached version filters even for an empty list.
    const {InteractionClientProvider}=await load('@project-chip/matter.js/dist/esm/cluster/client/InteractionClient.js');
    const client=await new InteractionClientProvider(controller.node).interactionClientFor(cached.address);
    if(mode==='open') {
        const {AdministratorCommissioning}=await load('@matter/types/dist/esm/clusters/administrator-commissioning.js');
        const {Spake2p}=await load('@matter/general/dist/esm/crypto/Spake2p.js');
        const {NodeJsCrypto}=await load('@matter/nodejs/dist/esm/index.js');
        const {randomBytes}=await import('node:crypto'); const salt=randomBytes(16),iterations=1000;
        const {w0,L}=await Spake2p.computeW0L(new NodeJsCrypto(),{salt,iterations},20202021);
        const verifier=Buffer.concat([Buffer.from(w0.toString(16).padStart(64,'0'),'hex'),Buffer.from(L)]);
        await client.invoke({endpointId:0,clusterId:0x3c,command:AdministratorCommissioning.Cluster.commands.openCommissioningWindow,
            asTimedRequest:true,request:{commissioningTimeout:180,pakePasscodeVerifier:verifier,discriminator:1234,iterations,salt}});
        console.log('C6_ECM_OPEN');
    } else {
    const {BasicInformation}=await load('@matter/types/dist/esm/clusters/basic-information.js');
    const label={endpointId:0,clusterId:0x28,attribute:BasicInformation.Cluster.attributes.nodeLabel};
    const before=await client.getAttribute({...label,requestFromRemote:true}); console.log('READ_LABEL',before);
    if((mode==='reconnect' || mode==='recovered') && before!=='C6 durable label') throw Error('persistent label missing after reboot');
    if(mode==='reconnect' || mode==='recovered') console.log('C6_PERSISTENT_LABEL_PASS');
    const {OperationalCredentials}=await load('@matter/types/dist/esm/clusters/operational-credentials.js');
    const fabricCount=await client.getAttribute({endpointId:0,clusterId:0x3e,
        attribute:OperationalCredentials.Cluster.attributes.commissionedFabrics,requestFromRemote:true});
    if(fabricCount!==(secondary?2:1)) throw Error(`unexpected fabric count ${fabricCount}`);
    console.log('C6_FABRIC_COUNT_PASS',fabricCount);
    await client.setAttribute({attributeData:{...label,value:'C6 durable label'}});
    if(await client.getAttribute({...label,requestFromRemote:true})!=='C6 durable label') throw Error('write/read mismatch');
    console.log('C6_CASE_READ_WRITE_PASS');
    const full=await client.subscribeAllAttributesAndEvents({minIntervalFloorSeconds:0,maxIntervalCeilingSeconds:3,
        keepSubscriptions:false,isUrgent:true,dataVersionFilters:[],eventFilters:[],attributeListener:()=>{},eventListener:()=>{}});
    console.log('C6_SUBSCRIBE_INITIAL_COUNTS',full.attributeReports.length,full.eventReports.length);
    if(full.attributeReports.length<60 || !full.eventReports.length) throw Error('incomplete subscription');
    await new Promise(r=>setTimeout(r,3500));
    console.log('C6_SUBSCRIBE_PASS',full.attributeReports.length,full.eventReports.length);
    const numbers=full.eventReports.flatMap(report=>report.events.map(event=>BigInt(event.eventNumber)));
    if(!numbers.length) throw Error('missing event numbers');
    const low=numbers.reduce((a,b)=>a<b?a:b),high=numbers.reduce((a,b)=>a>b?a:b);
    const watermark=resolve(stateRoot,`${storageId}-event-watermark.json`);
    if(mode==='recovered') {
        const previous=JSON.parse(await readFile(watermark,'utf8'));
        if(low<=BigInt(previous.high)) throw Error('event numbering reused across restart');
        console.log('C6_EVENT_REBOOT_WATERMARK_PASS',String(low),String(high));
    }
    if(!secondary) await writeFile(watermark,JSON.stringify({high:String(high)})+'\n');
    if(secondary) {
        const cluster=OperationalCredentials.Cluster;
        const index=await client.getAttribute({endpointId:0,clusterId:0x3e,attribute:cluster.attributes.currentFabricIndex});
        const result=await client.invoke({endpointId:0,clusterId:0x3e,command:cluster.commands.removeFabric,request:{fabricIndex:index}});
        if(result.statusCode!==0) throw Error('RemoveFabric failed');
        console.log('C6_REMOVE_FABRIC_RESPONSE_PASS',index);
    }
    }
} finally { await controller.close(); }
