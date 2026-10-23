// Host-only scenarios, sharing the C6 oracle's controller and load operations.
export async function hostScenarios(o) {
    const {contexts,summary,control,emit,sleep,fullRead,assertLoad,closeLoad,buildLoad,
        loadSessions,attribute,GeneralDiagnostics,write,recoverFaultLoad}=o;
    const require=(ok,message)=>{if(!ok) throw Error(message);};
    const reads=()=>Promise.all(contexts.map(c=>fullRead(c.clients[0])));
    await reads(); await write('Host wire baseline'); await assertLoad(15);
    const before=await control('r'); await reads(); const reordered=await control('m');
    require(reordered.rx_held===before.rx_held+1 && reordered.rx_reordered>before.rx_reordered,'RX reorder was not exercised');
    await assertLoad(15); emit('WIRE_REORDER_PASS',reordered);
    if(process.env.MATTER_WIRE_SINGLE_ACK==='1') {
        await closeLoad(); const before=await control('s'); contexts[1].expectedLoss=true;
        for(const ctx of contexts) await loadSessions(ctx,true);
        const corrected=summary.diagnostic_peer?.mode==='corrected';
        const end=performance.now()+15000; let load,stats;
        do {
            load=await attribute(contexts[0].clients[0],0x33,GeneralDiagnostics.Cluster.attributes.deviceLoadStatus);
            stats=await control('m'); if(stats.target_outcome) break;
            await sleep(100);
        } while(performance.now()<end);
        require(stats.ack_dropped===before.ack_dropped+1,'Single ACK fault not consumed exactly once');
        require(stats.target_outcome===(corrected?1:2) && stats.target_attempts===(corrected?2:5),
            `Unexpected target MRP result: ${JSON.stringify(stats)}`);
        require(load.currentSubscriptions===(corrected?15:14) && load.currentSubscriptionsForFabric===3,
            `Unexpected single-ACK load: ${JSON.stringify(load)}`);
        require(corrected || stats.wrong_role_acks>before.wrong_role_acks,'Original peer did not exercise wrong-role ACK rejection');
        summary.single_ack={corrected,load,stats}; emit('WIRE_SINGLE_ACK_PASS',summary.single_ack);
        // Read every surviving CASE connection, including the exact session
        // whose SubscribeResponse exhausted MRP. No reconnect/rebuild first.
        for(const ctx of contexts) for(const client of ctx.clients) await fullRead(client);
        summary.single_ack.case_reads=15; await control('l');
        for(const ctx of contexts) ctx.expectedLoss=false;
    }
    if(process.env.MATTER_WIRE_FAULTS==='1') {
        for(const position of [1,3,7]) {
            for(const ctx of contexts) ctx.expectedLoss=true;
            const before=await control(String(position));
            const results=await Promise.allSettled(contexts.map(c=>fullRead(c.clients[0])));
            await control('a'); const after=await control('m');
            require(after.core_failures===before.core_failures+1,`OOM position ${position} not consumed exactly once`);
            summary.fault_operations_rejected+=results.filter(r=>r.status==='rejected').length;
            await recoverFaultLoad('oom'); ++summary.oom_cycles;
            emit('WIRE_OOM_PASS',{position,...after});
        }
        await closeLoad(); await control('k'); contexts[1].expectedLoss=true;
        for(const ctx of contexts) await loadSessions(ctx,true);
        const end=performance.now()+15000; let load,stats;
        do {
            load=await attribute(contexts[0].clients[0],0x33,GeneralDiagnostics.Cluster.attributes.deviceLoadStatus);
            stats=await control('m'); if(load.currentSubscriptions===14 && stats.unacknowledged) break;
            await sleep(100);
        } while(performance.now()<end);
        require(load.currentSubscriptions===14 && load.currentSubscriptionsForFabric===3 && stats.ack_dropped && stats.unacknowledged,
            `Expected one missing-ACK retirement: ${JSON.stringify({load,stats})}`);
        summary.ack_negative_controls=1; summary.ack_lost_subscriptions=0; summary.ack_rebuilt_load_cycles=0;
        emit('WIRE_MISSING_ACK_PASS',{load,...stats}); await control('l');
        await reads(); summary.ack_session_survived=true;
        await recoverFaultLoad('ack');
    }
    // Explicitly close all fifteen sessions/subscriptions, then require a fresh
    // full load. No hidden rebuild is permitted outside a named fault phase.
    await closeLoad(); await buildLoad(true); ++summary.host_close_reconnect_cycles;
    await reads(); await assertLoad(15);
    const stats=await control('m');
    require(stats.ack_after_completion>0,'No ACK after local completion observed');
    if(Number(process.env.MATTER_WIRE_COMPLETION_MS)>0) {
        // A fixed25ms delay cannot guarantee a standalone ACK beats completion
        // on every scheduler. Hold the next accepted reliable TX explicitly;
        // release its actual completion only after observing its matching ACK.
        const before=await control('b');
        const pending=Promise.allSettled(contexts.map(c=>fullRead(c.clients[0])));
        const end=performance.now()+10000; let held;
        do {
            held=await control('m');
            if(held.held_completion && held.ack_before_completion>before.ack_before_completion) break;
            await sleep(20);
        } while(performance.now()<end);
        await control('j'); const results=await pending;
        require(held.held_completion===1 && held.ack_before_completion>before.ack_before_completion &&
            results.every(r=>r.status==='fulfilled'),'No matching ACK during held reliable TX or follow-up Read failed');
        summary.ack_held_completion_cycles=1; emit('WIRE_ACK_BEFORE_COMPLETION_PASS',held);
    }
    await control('h');
    // Record the rejection immediately so stop/close cannot create an unhandled
    // promise. Runtime stop is allowed to cancel this Read, after TX drain.
    const pending=fullRead(contexts[0].clients[0]).then(()=>({status:'fulfilled'}),e=>({status:'rejected',name:e.name}));
    const end=performance.now()+10000; let held;
    do { held=await control('m'); if(held.held_completion) break; await sleep(20); } while(performance.now()<end);
    require(held.held_completion===1,'No accepted TX completion held');
    for(const ctx of contexts) ctx.expectedLoss=true;
    const start=performance.now(),drained=await control('q',40000);
    require(drained.core_live===0 && drained.core_bytes===0,'Stop leaked tracked allocations');
    require(performance.now()-start>=100,'Held completion did not delay drain');
    summary.host_stats=drained; ++summary.delayed_completion_cycles;
    emit('WIRE_DRAIN_PASS',drained);
    // The runtime has already drained and deleted everything. Explicitly close
    // the peer's exchanges now instead of waiting for its unrelated MRP timeout.
    const sessions=contexts.flatMap(c=>c.sessions);
    await Promise.all(sessions.map(s=>s.initiateForceClose({cause:new Error('Host runtime drained')})));
    summary.stop_read_outcome=await pending; summary.host_peer_closes=sessions.length;
    emit('WIRE_PEER_CLEANUP_PASS',{sessions:sessions.length});
}
