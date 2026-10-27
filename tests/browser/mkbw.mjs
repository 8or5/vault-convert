import { encryptBitwardenExport } from '../../src/js/bwcrypto.js';
import { writeFileSync } from 'node:fs';
const inner = JSON.stringify({ encrypted:false, folders:[{id:'f1',name:'Work'}], items:[{id:'i1',organizationId:null,folderId:'f1',type:1,reprompt:0,name:'BW Site',notes:null,favorite:true,login:{username:'u1',password:'p1',totp:null,uris:[{match:null,uri:'https://bw.example.org'}]},collectionIds:null}]});
writeFileSync(process.argv[2], JSON.stringify(await encryptBitwardenExport(inner,'bw pass',{kdf:'pbkdf2',iterations:5000}),null,2));
