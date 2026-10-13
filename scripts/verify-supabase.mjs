import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import { createClient } from '@supabase/supabase-js';
import WebSocket from 'ws';
const env=Object.fromEntries(readFileSync('.env','utf8').split('\n').filter(l=>l.includes('=') && !l.startsWith('#')).map(l=>{const i=l.indexOf('=');return [l.slice(0,i),l.slice(i+1)];}));
const supabase=createClient(env.SUPABASE_URL,env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false,autoRefreshToken:false},realtime:{transport:WebSocket}});
const bucket=env.SUPABASE_BUCKET,path=`${'0'.repeat(32)}/${randomUUID()}.jpg`,input=readFileSync('tests/fixtures/one-pixel.jpg');
try {
  const {data:signed,error:signError}=await supabase.storage.from(bucket).createSignedUploadUrl(path);assert.equal(signError,null);
  const upload=await fetch(signed.signedUrl,{method:'PUT',headers:{'Content-Type':'application/octet-stream','x-upsert':'false'},body:input});assert.ok(upload.ok,`Signed upload failed: HTTP ${upload.status}`);
  const {data:info,error:infoError}=await supabase.storage.from(bucket).info(path);assert.equal(infoError,null);assert.equal(info.size || info.metadata?.size,input.length);
  const publicAccess=await fetch(`${env.SUPABASE_URL}/storage/v1/object/public/${bucket}/${path}`);assert.equal(publicAccess.ok,false);
  const {data:download,error:downloadError}=await supabase.storage.from(bucket).download(path);assert.equal(downloadError,null);assert.deepEqual(Buffer.from(await download.arrayBuffer()),input);
  const {error:historyError}=await supabase.from('kheronyx_reports').select('id').limit(1);assert.equal(historyError,null);
  const {data:limit,error:limitError}=await supabase.rpc('kheronyx_rate_limit',{p_key:`qa:${randomUUID()}`,p_limit:1,p_window_seconds:60});assert.equal(limitError,null);assert.equal(limit,true);
  console.log('Supabase verification passed: private signed upload, object metadata, anonymous public access denied, authenticated download, report table, rate limiting.');
}finally{const {error}=await supabase.storage.from(bucket).remove([path]);assert.equal(error,null);console.log('Temporary verification upload removed.');}
