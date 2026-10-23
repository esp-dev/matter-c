// Fixed-workload C6 peak profiling; shares all wire operations with soak.mjs.
export async function memoryProfile(o) {
    const {contexts,summary,fullRead,assertLoad,checkpoint,OperationalCredentials,removeFabric,emit}=o;
    if(contexts.length!==5 || contexts.some(c=>c.clients.length!==3)) throw Error('Profile requires the full 5/15 load');
    summary.memory_profile={parallel_read_rounds:0,publication_rounds:0,live_removals:0};
    await assertLoad(15); await checkpoint('profile-loaded');
    for(let round=0;round<3;++round) {
        await Promise.all(contexts.map(c=>fullRead(c.clients[round])));
        ++summary.memory_profile.parallel_read_rounds;
        await assertLoad(15); await checkpoint('profile-parallel-full-read');
    }
    // Update only a disposable fabric. The publication transaction overlaps
    // five full Reads while all fifteen subscriptions and CASE sessions live.
    for(let round=0;round<3;++round) {
        const publishing=contexts[1].clients[round].invoke({endpointId:0,clusterId:0x3e,
            command:OperationalCredentials.Cluster.commands.updateFabricLabel,
            request:{label:`memory profile ${round}`}});
        const [result]=await Promise.all([publishing,...contexts.map(c=>fullRead(c.clients[round]))]);
        if(result.statusCode!==0) throw Error('Profile Fabric publication failed');
        ++summary.memory_profile.publication_rounds;
        await assertLoad(15); await checkpoint('profile-fabric-with-parallel-full-read');
    }
    for(const ctx of contexts.slice(1).reverse()) {
        ctx.expectedLoss=true;
        const survivors=contexts.filter(c=>c!==ctx && !c.removed);
        await Promise.all([removeFabric(ctx),...survivors.map(c=>fullRead(c.clients[0]))]);
        ++summary.memory_profile.live_removals;
        await Promise.all(survivors.map(c=>fullRead(c.clients[0])));
        await assertLoad(survivors.length*3); await checkpoint('profile-live-fabric-removal');
    }
    emit('MEMORY_PROFILE_PASS',summary.memory_profile);
}
