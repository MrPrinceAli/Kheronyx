import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { assess } from "../lib/ai";
import type { Artifact } from "../lib/types";

const artifact:Artifact={filename:"test.jpg",kind:"jpg",size:100,sha256:"a".repeat(64),metadata:{dimensions:{width:1,height:1}},strings:[],urls:[],indicators:[],limitations:["Static analysis only"],incomplete:false};
const assessment={risk:"low",confidence:"medium",summary:"Temuan terbatas pada struktur file.",findings:[],recommendations:["Verifikasi sumber file."],limitations:["Bukan jaminan aman."]};
const valid=()=>Response.json({choices:[{finish_reason:"stop",message:{content:JSON.stringify(assessment)}}]});
type Recorded={model:string;[key:string]:unknown};
async function scenario(t:TestContext,responses:(Response|Error)[],run:(requests:Recorded[])=>Promise<void>,fallback="gpt-6.1-sol") {
  const before={key:process.env.AI_API_KEY,model:process.env.AI_MODEL,fallback:process.env.AI_FALLBACK_MODEL};
  process.env.AI_API_KEY="unit-test-fake-key";process.env.AI_MODEL="gpt-6-astra";process.env.AI_FALLBACK_MODEL=fallback;
  const requests:Recorded[]=[];
  t.mock.method(globalThis,"fetch",async(_url:unknown,init?:RequestInit)=>{
    requests.push(JSON.parse(String(init?.body)));assert.ok(init?.signal instanceof AbortSignal);
    const next=responses.shift();if(next instanceof Error)throw next;assert.ok(next,"No unexpected extra requests allowed");return next;
  });
  try {await run(requests);}finally{for(const [key,value] of [["AI_API_KEY",before.key],["AI_MODEL",before.model],["AI_FALLBACK_MODEL",before.fallback]]){if(value===undefined)delete process.env[key!];else process.env[key!]=value;}t.mock.restoreAll();}
}
test("primary returns a valid report without calling backup and uses supported reasoning parameters",async t=>{
  await scenario(t,[valid()],async calls=>{const result=await assess(artifact);assert.equal(result.model,"gpt-6-astra");assert.equal(calls.length,1);assert.equal(calls[0].temperature,undefined);assert.equal(calls[0].max_tokens,undefined);assert.equal(calls[0].reasoning_effort,"medium");assert.equal(calls[0].max_completion_tokens,8000);});
});
test("provider failure switches once to backup and records actual selected model",async t=>{
  await scenario(t,[new Response("down",{status:503}),valid()],async calls=>{const result=await assess(artifact);assert.equal(result.model,"gpt-6.1-sol");assert.deepEqual(calls.map(c=>c.model),["gpt-6-astra","gpt-6.1-sol"]);});
});
test("timeout switches to backup instead of losing the analysis",async t=>{
  await scenario(t,[new DOMException("Timed out","TimeoutError"),valid()],async calls=>{assert.equal((await assess(artifact)).model,"gpt-6.1-sol");assert.equal(calls.length,2);});
});
test("invalid JSON and truncated output require a new valid report from the backup",async t=>{
  for(const first of [Response.json({choices:[{message:{content:"not valid JSON"}}]}),Response.json({choices:[{finish_reason:"length",message:{content:JSON.stringify(assessment)}}]})]) {
    await scenario(t,[first,valid()],async calls=>{assert.equal((await assess(artifact)).model,"gpt-6.1-sol");assert.equal(calls.length,2);});
  }
});
test("invalid credentials and exhausted account balance do not issue backup requests",async t=>{
  for(const status of [401,402])await scenario(t,[new Response("denied",{status})],async calls=>{await assert.rejects(assess(artifact));assert.equal(calls.length,1);});
});
test("explicit model refusal is returned as an error without trying to bypass it",async t=>{
  await scenario(t,[Response.json({choices:[{finish_reason:"stop",message:{content:null,refusal:"Cannot assess"}}]})],async calls=>{await assert.rejects(assess(artifact),/tidak memberikan penilaian/);assert.equal(calls.length,1);});
});
test("two failed models return an error and never create an assessment",async t=>{
  await scenario(t,[new Response("down",{status:500}),new Response("down",{status:502})],async calls=>{await assert.rejects(assess(artifact),/Model utama dan cadangan/);assert.equal(calls.length,2);});
});
test("an unavailable model can fail over, while invalid shared parameters stop immediately",async t=>{
  await scenario(t,[Response.json({error:{code:"model_not_found"}},{status:400}),valid()],async calls=>{assert.equal((await assess(artifact)).model,"gpt-6.1-sol");assert.equal(calls.length,2);});
  await scenario(t,[Response.json({error:{code:"invalid_parameter"}},{status:400})],async calls=>{await assert.rejects(assess(artifact));assert.equal(calls.length,1);});
});
test("same or disabled backup does not accidentally double-charge a failed primary",async t=>{
  for(const fallback of ["gpt-6-astra",""])await scenario(t,[new Response("down",{status:503})],async calls=>{await assert.rejects(assess(artifact));assert.equal(calls.length,1);},fallback);
});
test("a valid interpretation of incomplete extraction stays unknown without unnecessary fallback",async t=>{
  await scenario(t,[valid()],async calls=>{const result=await assess({...artifact,incomplete:true});assert.equal(result.assessment.risk,"unknown");assert.equal(result.assessment.confidence,"low");assert.equal(result.model,"gpt-6-astra");assert.equal(calls.length,1);});
});
test("a comma-separated backup chain is tried in order until one model answers",async t=>{
  await scenario(t,[new Response("down",{status:503}),new DOMException("Timed out","TimeoutError"),valid()],async calls=>{
    const result=await assess(artifact);assert.equal(result.model,"gemini-3.8-flash");
    assert.deepEqual(calls.map(c=>c.model),["gpt-6-astra","gpt-6-sol","gemini-3.8-flash"]);
    assert.equal(calls[2].temperature,0.1);assert.equal(calls[2].reasoning_effort,undefined);
  },"gpt-6-sol, gemini-3.8-flash ,gpt-6.1-sol");
});
