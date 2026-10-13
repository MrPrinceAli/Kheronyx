import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
const env=Object.fromEntries(readFileSync('.env','utf8').split('\n').filter(l=>l.includes('=')).map(l=>{const i=l.indexOf('=');return [l.slice(0,i),l.slice(i+1)];}));
const secrets=['AI_API_KEY','VIRUSTOTAL_API_KEY','ACCESS_PASSWORD','ACCESS_PASSWORD_HASH','SESSION_SECRET','CRON_SECRET','SUPABASE_SERVICE_ROLE_KEY'].map(k=>env[k]).filter(Boolean);
const files=execFileSync('git',['diff','--cached','--name-only','--diff-filter=ACM'],{encoding:'utf8'}).trim().split('\n').filter(Boolean);
for(const file of files){const content=execFileSync('git',['show',`:${file}`],{encoding:'utf8',maxBuffer:20*1024*1024});if(secrets.some(value=>content.includes(value))){console.error('A local credential appears in staged files. Commit stopped.');process.exit(1);}}
console.log(`Secret check passed for ${files.length} staged files; ignored .env values excluded.`);
