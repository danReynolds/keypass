// Public evidence fixture from synthetic credentials; never a provider PRF log.
import {runProbe} from '../../tool/browser/ceremony.mjs';
import {fakeCredentials} from './fake_credentials.mjs';
import {encode} from '../../tool/browser/protocol.mjs';
const origin='https://vault.example.com';
const credentials=await fakeCredentials(origin);
const random=()=>encode(crypto.getRandomValues(new Uint8Array(32)));
const request={version:1,evidenceVersion:1,domain:'vault.example.com',binding:null,userId:random(),input:random(),registrationChallenge:random(),challenges:[random(),random()]};
const result=await runProbe(request,origin,credentials,(_,action)=>action());
const metadata=JSON.parse(new TextDecoder().decode(result.subarray(33))); result.fill(0);
const reuse={...request,binding:metadata.binding,registrationChallenge:random(),challenges:[random(),random()]};
credentials.create=()=>{throw new Error('Unexpected enrollment');};
const reused=await runProbe(reuse,origin,credentials,(_,action)=>action());
const reuseMetadata=JSON.parse(new TextDecoder().decode(reused.subarray(33))); reused.fill(0);
console.log(JSON.stringify({origin,request,metadata,reuse,reuseMetadata}));
