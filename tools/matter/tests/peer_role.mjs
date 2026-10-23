// Explicit diagnostic override for the pinned test peer; never changes packages.
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

export async function peerRole(modules,mode) {
    if(!['original','corrected'].includes(mode)) throw Error('Unknown diagnostic peer role');
    const file=resolve(modules,'@matter/protocol/dist/esm/protocol/MessageExchange.js');
    const source=(await readFile(file,'utf8')).replaceAll('\r\n','\n');
    const sha256=createHash('sha256').update(source).digest('hex');
    if(sha256!=='8fcefa35f0429d4a4f125613a66635c567e2cc3c7fb3c0a0085a87253ac95099')
        throw Error('Diagnostic peer override requires unmodified Matter.js0.17.9 MessageExchange');
    if(mode==='corrected') {
        const {MessageExchange}=await import(pathToFileURL(file).href);
        const original=MessageExchange.fromInitialMessage;
        MessageExchange.fromInitialMessage=function(context,message,options) {
            return original.call(this,context,message,{...options,isInitiator:!message.payloadHeader.isInitiatorMessage});
        };
    }
    return {mode,package:'@matter/protocol',version:'0.17.9',source_lf_sha256:sha256,
        override:mode==='corrected'?'fromInitialMessage: inverse incoming Initiator bit':null};
}
