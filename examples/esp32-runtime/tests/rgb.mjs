// Independent Matter.js0.17.9 wire oracle for the experimental EP1 RGB model.
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {readFile} from 'node:fs/promises';
const [modules,ip,stateRoot,iface='Wi-Fi',storageId='c6-memory14']=process.argv.slice(2);
if(!modules || !ip || !stateRoot) throw Error('Usage: rgb.mjs <pinned-node_modules> <scoped-ipv6> <private-state> [interface] [storage-id]');
const load=p=>import(pathToFileURL(resolve(modules,p)).href);
if(JSON.parse(await readFile(resolve(modules,'@project-chip/matter.js/package.json'),'utf8')).version!=='0.17.9') throw Error('Expected Matter.js0.17.9');
const {Logger,LogLevel}=await load('@matter/general/dist/esm/index.js'); Logger.level=LogLevel.WARN;
const {NodeJsEnvironment}=await load('@matter/nodejs/dist/esm/index.js');
const {CommissioningController}=await load('@project-chip/matter.js/dist/esm/CommissioningController.js');
const {InteractionClientProvider}=await load('@project-chip/matter.js/dist/esm/cluster/client/InteractionClient.js');
const {OnOff}=await load('@matter/types/dist/esm/clusters/on-off.js');
const {LevelControl}=await load('@matter/types/dist/esm/clusters/level-control.js');
const {ColorControl}=await load('@matter/types/dist/esm/clusters/color-control.js');
const env=NodeJsEnvironment(); env.vars.set('storage.path',resolve(stateRoot)); env.vars.set('mdns.networkInterface',iface);
const controller=new CommissioningController({environment:{environment:env,id:storageId},autoConnect:false,adminFabricLabel:'C6 memory14'});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
let client;
// Two parallel readbacks may compete for the unchanged one-Read/fabric budget.
// Retry only explicit resource Busy; timeouts, values and other statuses still fail.
let busyReadRetries=0;
const read=async(cluster,attribute)=>{
    for(let attempt=0;;++attempt) {
        try { return await client.getAttribute({endpointId:1,clusterId:cluster,attribute,requestFromRemote:true}); }
        catch(error) {
            if(error.code!==0x9c || attempt>=9) throw error;
            ++busyReadRetries; console.log('RGB_READ_BUSY_RETRY',JSON.stringify({cluster,attribute:attribute.id,attempt:attempt+1}));
            await sleep(Math.min(100*(attempt+1),500));
        }
    }
};
const invoke=(cluster,command,request)=>client.invoke({endpointId:1,clusterId:cluster,command,request});
try {
    await controller.start();
    const cached=await controller.createInteractionClient(1n);
    client=await new InteractionClientProvider(controller.node).interactionClientFor(cached.address);
    const initial=await client.getAllAttributesAndEvents({dataVersionFilters:[],eventFilters:[]});
    if(initial.attributeReports.length!==171) throw Error(`Expected 171 root+RGB attributes, found ${initial.attributeReports.length}`);
    const attrs=initial.attributeReports.filter(r=>r.path.endpointId===1);
    if(attrs.length!==38) throw Error(`Expected 38 EP1 attributes, found ${attrs.length}`);
    console.log('RGB_TOPOLOGY_PASS',initial.attributeReports.length,attrs.length);
    await invoke(6,OnOff.Cluster.commands.on,undefined);
    await invoke(8,LevelControl.Cluster.commands.moveToLevelWithOnOff,{level:127,transitionTime:0,optionsMask:0,optionsOverride:0});
    const updates=[];
    await client.subscribeMultipleAttributesAndEvents({attributes:[{endpointId:1,clusterId:0x300,attributeId:0}],
        minIntervalFloorSeconds:0,maxIntervalCeilingSeconds:2,keepSubscriptions:false,dataVersionFilters:[],
        attributeListener:r=>updates.push(r.value)});
    for(const hue of [0,85,170]) {
        await invoke(0x300,ColorControl.Cluster.commands.moveToHueAndSaturation,{hue,saturation:254,transitionTime:0,optionsMask:0,optionsOverride:0});
        const reports=await Promise.all([read(0x300,ColorControl.Cluster.attributes.currentHue),read(8,LevelControl.Cluster.attributes.currentLevel)]);
        if(reports[0]!==hue || reports[1]!==127) throw Error('RGB value readback mismatch');
        await sleep(1200); console.log('RGB_PRIMARY_PASS',hue);
    }
    await invoke(8,LevelControl.Cluster.commands.moveToLevel,{level:254,transitionTime:10,optionsMask:0,optionsOverride:0});
    await invoke(0x300,ColorControl.Cluster.commands.moveToHueAndSaturation,{hue:85,saturation:254,transitionTime:10,optionsMask:0,optionsOverride:0});
    await sleep(1500);
    if(await read(8,LevelControl.Cluster.attributes.currentLevel)!==254 || await read(0x300,ColorControl.Cluster.attributes.currentHue)!==85) throw Error('Concurrent transitions did not complete');
    await sleep(2200);
    if(!updates.includes(85) || !updates.includes(170)) throw Error('Missing RGB subscription updates');
    await invoke(6,OnOff.Cluster.commands.off,undefined);
    if(await read(6,OnOff.Cluster.attributes.onOff)!==false) throw Error('Off readback mismatch');
    console.log('RGB_WIRE_PASS',JSON.stringify({updates:updates.length,concurrent_transitions:true,final_on:false,busyReadRetries}));
} finally { await controller.close(); }
