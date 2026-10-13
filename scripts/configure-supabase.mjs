// Server deployment configuration for the user-selected project. Never prints keys.
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const ref=process.argv[2];
if(!ref || !/^[a-z]{20}$/.test(ref))throw new Error('Supply the selected Supabase project reference.');
const result=spawnSync('supabase',['projects','api-keys','--project-ref',ref,'--reveal','--output','json'],{encoding:'utf8',maxBuffer:1024*1024});
if(result.status!==0){console.error('Supabase credential configuration failed; no secret values displayed.');process.exit(1);}
let keys;
try{const body=JSON.parse(result.stdout);keys=Array.isArray(body)?body:body.api_keys || body.keys;}catch{console.error('Unexpected Supabase response; credential output withheld.');process.exit(1);}
const key=keys?.find(k=>k.type==='secret' && k.api_key)?.api_key || keys?.find(k=>k.name==='service_role' && k.api_key)?.api_key;
if(!key || key.includes('...') || key.includes('***'))throw new Error('No usable server key returned.');
let env=readFileSync('.env','utf8');
for(const [name,value] of [['SUPABASE_URL',`https://${ref}.supabase.co`],['SUPABASE_SERVICE_ROLE_KEY',key]]){const re=new RegExp(`^${name}=.*$`,'m');env=re.test(env)?env.replace(re,()=>`${name}=${value}`):env+`${name}=${value}\n`;}
writeFileSync('.env',env,{mode:0o600});
console.log('Supabase server credentials installed in ignored .env; no values displayed.');
