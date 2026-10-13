"use client";

import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import styles from "./access-transition.module.css";

type EyeOrigin = { left: number; top: number; width: number; height: number };
type Phase = "idle" | "cover" | "covered" | "reveal";
const TransitionContext = createContext<((origin?: EyeOrigin) => Promise<void>) | null>(null);
const COVER_MS = 1400;
const REVEAL_MS = 1300;
// Puffs fan out from behind the eye on a golden-angle spiral; far puffs leave later and clear last.
const PUFFS = Array.from({length:14},(_,i)=>{
  const angle=i*2.39996, distance=5+(i%6)*10;
  return {
    "--dx":`${(Math.cos(angle)*distance).toFixed(2)}vmax`,
    "--dy":`${(Math.sin(angle)*distance*.8).toFixed(2)}vmax`,
    "--scale":(1+(i%4)*.3).toFixed(2),
    "--spin":`${(i%2?1:-1)*(16+i*4)}deg`,
    "--delay":`${Math.round(distance*5)}ms`,
    "--clear":`${Math.round(distance*7)}ms`,
    "--churn":`${16+(i%5)*3}s`,
  } as CSSProperties;
});

function Smoke() {
  const id=useId().replace(/:/g,"");
  return <div className={styles.smoke} aria-hidden="true">
    <svg className={styles.defs} width="0" height="0">
      <defs>
        <radialGradient id={`${id}-body`}><stop stopColor="#05070a"/><stop offset=".5" stopColor="#05070a" stopOpacity=".96"/><stop offset=".8" stopColor="#05070a" stopOpacity=".5"/><stop offset="1" stopColor="#05070a" stopOpacity="0"/></radialGradient>
        <radialGradient id={`${id}-wisp`}><stop stopColor="#fff"/><stop offset="1" stopColor="#fff" stopOpacity="0"/></radialGradient>
        {[3,11,23].map((seed,i)=><g key={seed}>
          <filter id={`${id}-billow${i}`} x="-15%" y="-15%" width="130%" height="130%" colorInterpolationFilters="sRGB"><feTurbulence type="fractalNoise" baseFrequency=".011" numOctaves="3" seed={seed}/><feDisplacementMap in="SourceGraphic" scale="78" xChannelSelector="R" yChannelSelector="B"/></filter>
          <filter id={`${id}-curl${i}`} x="0" y="0" width="100%" height="100%" colorInterpolationFilters="sRGB"><feTurbulence type="fractalNoise" baseFrequency=".017" numOctaves="3" seed={seed+5}/><feColorMatrix values="0 0 0 0 .5 0 0 0 0 .52 0 0 0 0 .55 1.8 0 0 0 -.78"/><feComposite in2="SourceGraphic" operator="in"/></filter>
        </g>)}
      </defs>
    </svg>
    <div className={styles.shroud}/>
    {PUFFS.map((style,i)=><div key={i} className={styles.puff} style={style}>
      <svg viewBox="0 0 400 400"><circle cx="200" cy="200" r="150" fill={`url(#${id}-body)`} filter={`url(#${id}-billow${i%3})`}/><circle cx="200" cy="200" r="125" fill={`url(#${id}-wisp)`} filter={`url(#${id}-curl${i%3})`} opacity=".12"/></svg>
    </div>)}
  </div>;
}

export function AccessTransition({children}:{children:ReactNode}) {
  const router = useRouter();
  const pathname = usePathname();
  const [phase, setPhase] = useState<Phase>("idle");
  const [origin, setOrigin] = useState<EyeOrigin>();
  const flight = useRef<{resolve:()=>void;reject:(error:Error)=>void} | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const deadline = useRef<ReturnType<typeof setTimeout> | null>(null);

  const finish = useCallback((error?: Error) => {
    if (timer.current) clearTimeout(timer.current);
    if (deadline.current) clearTimeout(deadline.current);
    timer.current = deadline.current = null;
    setPhase("idle");
    const current = flight.current; flight.current = null;
    if (error) current?.reject(error); else current?.resolve();
  }, []);

  const enter = useCallback((source?: EyeOrigin) => {
    if (flight.current) return Promise.resolve();
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      router.push("/dashboard"); router.refresh(); return Promise.resolve();
    }
    setOrigin(source || {left:innerWidth/2-160,top:innerHeight/2-80,width:320,height:160});
    setPhase("cover");
    return new Promise<void>((resolve,reject) => {
      flight.current = {resolve,reject};
      timer.current = setTimeout(() => {
        setPhase("covered");
        try { router.push("/dashboard"); router.refresh(); }
        catch { finish(new Error("Dashboard belum dapat dibuka. Coba lagi.")); return; }
        deadline.current = setTimeout(() => finish(new Error("Dashboard belum merespons. Coba masuk kembali.")), 12000);
      }, COVER_MS);
    });
  }, [router, finish]);

  useEffect(() => {
    if (pathname !== "/dashboard" || phase !== "covered") return;
    if (deadline.current) clearTimeout(deadline.current);
    // The persistent smoke stays opaque until the new route has committed and painted.
    let frame = requestAnimationFrame(() => {
      frame = requestAnimationFrame(() => {
        setPhase("reveal");
        timer.current = setTimeout(() => finish(), REVEAL_MS);
      });
    });
    return () => cancelAnimationFrame(frame);
  }, [pathname, phase, finish]);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
    if (deadline.current) clearTimeout(deadline.current);
  }, []);

  const active = phase !== "idle";
  const geometry = origin ? {
    "--eye-x": `${origin.left+origin.width/2}px`,
    "--eye-y": `${origin.top+origin.height/2}px`,
  } as CSSProperties : undefined;

  return <TransitionContext.Provider value={enter}>
    <div className={styles.content} data-access-transition={phase} inert={active}>{children}</div>
    {active && <div className={styles.scene} data-access-transition={phase} style={geometry} role="status" aria-live="polite">
      <span className="visually-hidden">Opening your workspace…</span>
      <Smoke/>
    </div>}
  </TransitionContext.Provider>;
}

export function useAccessTransition() {
  const transition = useContext(TransitionContext);
  if (!transition) throw new Error("Access transition provider is missing.");
  return transition;
}
