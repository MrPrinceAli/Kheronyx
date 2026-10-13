"use client";

import { useEffect, useRef } from "react";
import styles from "./access-transition.module.css";

export type SmokePhase = "cover" | "covered" | "reveal";
export type SmokeOrigin = { left: number; top: number; width: number; height: number };

// Rendered at reduced resolution and upscaled by CSS: smoke is soft by nature, and this keeps the
// shader cheap enough for integrated GPUs and phones.
const RESOLUTION = .5;

const VERTEX = `attribute vec2 a;void main(){gl_Position=vec4(a,0.,1.);}`;

// Domain-warped fractal noise (fbm of fbm) gives billowing, tendril-edged smoke instead of round puffs.
// uCover grows the smoke outward from behind the eye, leaving a soft hole around it that closes last;
// uReveal tears the smoke apart into wisps, clearing from the eye outward.
const FRAGMENT = `precision highp float;
uniform vec2 uRes;uniform vec2 uOrigin;uniform vec2 uEye;uniform float uTime;uniform float uCover;uniform float uReveal;
float hash(vec2 p){p=fract(p*vec2(123.34,456.21));p+=dot(p,p+45.32);return fract(p.x*p.y);}
float noise(vec2 p){vec2 i=floor(p),f=fract(p);vec2 u=f*f*(3.-2.*f);
  return mix(mix(hash(i),hash(i+vec2(1.,0.)),u.x),mix(hash(i+vec2(0.,1.)),hash(i+vec2(1.,1.)),u.x),u.y);}
float fbm(vec2 p){float v=0.,a=.5;mat2 m=mat2(1.6,1.2,-1.2,1.6);for(int i=0;i<5;i++){v+=a*noise(p);p=m*p;a*=.5;}return v;}
void main(){
  vec2 frag=vec2(gl_FragCoord.x,uRes.y-gl_FragCoord.y);
  float scale=min(uRes.x,uRes.y);
  vec2 p=(frag-uOrigin)/scale;
  float t=uTime*.06;
  vec2 drift=p*1.55+vec2(0.,t*1.4);
  vec2 q=vec2(fbm(drift+vec2(0.,t)),fbm(drift+vec2(5.2,1.3)-t));
  vec2 r=vec2(fbm(drift+2.5*q+vec2(1.7,9.2)+t*.7),fbm(drift+2.5*q+vec2(8.3,2.8)-t*.5));
  float n=fbm(drift+2.6*r);
  float d=length(p*vec2(1.,1.18));
  float reach=length(max(uOrigin,uRes-uOrigin))/scale+.6;
  float front=uCover*reach;
  float edge=d-(n-.5)*.75-(r.x-.5)*.45;
  float cover=1.-smoothstep(front-.38,front,edge);
  float body=smoothstep(.15,.9,n*.75+r.y*.45);
  float smoke=max(cover*mix(.84,1.,body),smoothstep(.8,.98,uCover));
  vec2 e=(frag-uOrigin)/uEye;
  float close=smoothstep(.45,.97,uCover);
  float holeRadius=mix(.95,.0,close);
  // Wisps from both warp layers chew the hole's edge so it never reads as an oval.
  float ragged=length(e)+(n-.5)*1.5+(r.x-.5)*.9+(q.y-.5)*.6;
  float hole=(1.-smoothstep(holeRadius*.35,holeRadius+.25,ragged))*(1.-close);
  // The gloom dims the whole page, the eye included, so the hole never reads as a bright halo;
  // inside the hole a thin veil of the smoke itself stays visible.
  float gloom=min(uCover*1.6,1.)*.42;
  float alpha=max(smoke*(1.-hole*.7),gloom);
  // Reveal: broad, slow-moving holes tear the smoke apart from the eye outward while it thins overall.
  float vr=fbm(p*1.1+r*1.3+vec2(t*.8,-t))*.85+d*.32;
  float sweep=uReveal*1.8-.45;
  alpha*=1.-smoothstep(vr-.28,vr+.08,sweep);
  alpha*=1.-pow(uReveal,1.6)*.55;
  alpha*=1.-smoothstep(.9,1.,uReveal);
  float light=clamp(smoothstep(.38,.88,n)*.75+smoothstep(.5,.92,r.x)*.35,0.,1.);
  vec3 col=mix(vec3(.014,.018,.024),vec3(.17,.185,.2),light*.42);
  alpha=clamp(alpha,0.,1.);
  gl_FragColor=vec4(col*alpha,alpha);
}`;

const ease = (x: number) => x < .5 ? 4*x*x*x : 1 - Math.pow(-2*x + 2, 3)/2;

export function SmokeCanvas({phase, origin, coverMs, revealMs}:{phase:SmokePhase;origin:SmokeOrigin;coverMs:number;revealMs:number}) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const phaseRef = useRef(phase);
  const revealStart = useRef(0);

  useEffect(() => {
    phaseRef.current = phase;
    if (phase === "reveal") revealStart.current = performance.now();
  }, [phase]);

  useEffect(() => {
    const element = canvas.current; if (!element) return;
    const gl = element.getContext("webgl", {premultipliedAlpha: true, antialias: false, alpha: true});
    if (!gl || gl.isContextLost()) { element.dataset.fallback = "true"; return; }
    delete element.dataset.fallback;
    const compile = (type: number, source: string) => { const shader = gl.createShader(type)!; gl.shaderSource(shader, source); gl.compileShader(shader); return shader; };
    const program = gl.createProgram()!;
    gl.attachShader(program, compile(gl.VERTEX_SHADER, VERTEX));
    gl.attachShader(program, compile(gl.FRAGMENT_SHADER, FRAGMENT));
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) { element.dataset.fallback = "true"; return; }
    gl.useProgram(program);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1,3,-1,-1,3]), gl.STATIC_DRAW);
    const position = gl.getAttribLocation(program, "a");
    gl.enableVertexAttribArray(position); gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);
    const uniform = (name: string) => gl.getUniformLocation(program, name);
    const [uRes, uOrigin, uEye, uTime, uCover, uReveal] = ["uRes","uOrigin","uEye","uTime","uCover","uReveal"].map(uniform);

    const start = performance.now(); let frame = 0;
    const draw = (now: number) => {
      const width = Math.max(1, Math.round(innerWidth*RESOLUTION)), height = Math.max(1, Math.round(innerHeight*RESOLUTION));
      if (element.width !== width || element.height !== height) { element.width = width; element.height = height; gl.viewport(0, 0, width, height); }
      const current = phaseRef.current;
      const cover = current === "cover" ? ease(Math.min((now-start)/coverMs, 1)) : 1;
      const reveal = current === "reveal" ? Math.min((now-revealStart.current)/revealMs, 1) : 0;
      gl.uniform2f(uRes, width, height);
      gl.uniform2f(uOrigin, (origin.left+origin.width/2)*RESOLUTION, (origin.top+origin.height/2)*RESOLUTION);
      gl.uniform2f(uEye, origin.width/2*RESOLUTION, origin.height/2*RESOLUTION);
      gl.uniform1f(uTime, (now-start)/1000);
      gl.uniform1f(uCover, cover);
      gl.uniform1f(uReveal, reveal);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      frame = requestAnimationFrame(draw);
    };
    frame = requestAnimationFrame(draw);
    // No loseContext() here: React may re-run this effect on the same canvas, which would get the dead context back.
    return () => { cancelAnimationFrame(frame); gl.deleteProgram(program); };
  }, [origin, coverMs, revealMs]);

  return <canvas ref={canvas} className={styles.smoke} data-access-transition={phase} aria-hidden="true"/>;
}
