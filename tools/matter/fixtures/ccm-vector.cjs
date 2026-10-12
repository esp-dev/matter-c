// Independent OpenSSL AES-CCM through Node, not the C backend. Core 1.6.1 4.8:
// nonce = security flags || LE message counter || unspecified PASE Node ID.
const { createCipheriv } = require('node:crypto');
const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const aad = Buffer.from('00c8010004030201', 'hex');
const nonce = Buffer.from('00040302010000000000000000', 'hex');
const plain = Buffer.from('050134120400a1b2c3', 'hex');
const cipher = createCipheriv('aes-128-ccm', key, nonce, { authTagLength: 16 });
cipher.setAAD(aad, { plaintextLength: plain.length });
const data = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
console.log('cipher+MIC:', data.toString('hex'));
console.log('packet:', Buffer.concat([aad, data]).toString('hex'));
