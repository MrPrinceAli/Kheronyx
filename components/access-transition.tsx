"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import styles from "./access-transition.module.css";
import { SmokeCanvas } from "./smoke-canvas";

type EyeOrigin = { left: number; top: number; width: number; height: number };
type Phase = "idle" | "cover" | "covered" | "reveal";
const TransitionContext = createContext<((origin?: EyeOrigin) => Promise<void>) | null>(null);
// Slow, gloomy pacing: the smoke takes the page first and swallows the eye last.
const COVER_MS = 6000;
const REVEAL_MS = 3100;
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

  return <TransitionContext.Provider value={enter}>
    <div className={styles.content} data-access-transition={phase} inert={active}>{children}</div>
    {phase !== "idle" && origin && <div className={styles.scene} role="status" aria-live="polite">
      <span className="visually-hidden">Opening your workspace…</span>
      <SmokeCanvas phase={phase} origin={origin} coverMs={COVER_MS} revealMs={REVEAL_MS}/>
    </div>}
  </TransitionContext.Provider>;
}

export function useAccessTransition() {
  const transition = useContext(TransitionContext);
  if (!transition) throw new Error("Access transition provider is missing.");
  return transition;
}
