import { readFileSync } from 'node:fs';
import { randomBytes, scryptSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const env=Object.fromEntries(readFileSync('.env','utf8').split('\n').filter(l=>l.trim() && !l.startsWith('#') && l.includes('=')).map(l=>{const i=l.indexOf('=');return [l.slice(0,i).trim(),l.slice(i+1).trim()];}));
if(env.ACCESS_PASSWORD){const salt=randomBytes(16).toString('hex');env.ACCESS_PASSWORD_HASH=`${salt}:${scryptSync(env.ACCESS_PASSWORD,salt,64).toString('hex')}`;}
if(!env.ACCESS_PASSWORD_HASH || !env.SESSION_SECRET)throw new Error('Configure password and session secret in .env first.');
for(const key of ['AI_BASE_URL','AI_API_KEY','AI_MODEL','AI_FALLBACK_MODEL','ACCESS_PASSWORD_HASH','SESSION_SECRET','CRON_SECRET','SUPABASE_URL','SUPABASE_SERVICE_ROLE_KEY','SUPABASE_BUCKET']) {
  if(!env[key])continue;
  const result=spawnSync('vercel',['env','add',key,'production,preview','--sensitive','--yes','--force'],{input:env[key],encoding:'utf8'});
  if(result.status!==0){console.error(`Unable to configure ${key}; check Vercel login and project link.`);process.exit(1);}
  console.log(`Configured ${key} (value hidden).`);
}
console.log('Environment synchronized. Redeploy to apply changes.');
