"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import styles from "./access-transition.module.css";
import { SmokeCanvas } from "./smoke-canvas";
import { TypedHandle } from "./typed-handle";

type EyeOrigin = { left: number; top: number; width: number; height: number };
// Entering: cover → covered (route swap) → reveal. Leaving: leave → away (route swap) → arrive.
type Phase = "idle" | "cover" | "covered" | "reveal" | "leave" | "away" | "arrive";
type Transitions = { enter: (origin?: EyeOrigin) => Promise<void>; leave: () => Promise<void> };
const TransitionContext = createContext<Transitions | null>(null);
// Slow, gloomy pacing: the smoke takes the page first and swallows the eye last.
const COVER_MS = 6000;
const REVEAL_MS = 3100;
// The smoke is near-opaque from about here on, so "Please Wait..." can appear.
const WAIT_AT_MS = 4000;
// Logout is a quick slide back to the landing page.
const LEAVE_MS = 420;
const ARRIVE_MS = 560;

export function AccessTransition({children}:{children:ReactNode}) {
  const router = useRouter();
  const pathname = usePathname();
  const [phase, setPhase] = useState<Phase>("idle");
  const [origin, setOrigin] = useState<EyeOrigin>();
  const [startedAt, setStartedAt] = useState(0);
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

  // Plays the outro phase, swaps the route while hidden, and lets the pathname effect below play the intro.
  const travel = useCallback((to: string, outro: Phase, hidden: Phase, outroMs: number, failure: string) => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      router.push(to); router.refresh(); return Promise.resolve();
    }
    setPhase(outro);
    return new Promise<void>((resolve,reject) => {
      flight.current = {resolve,reject};
      timer.current = setTimeout(() => {
        setPhase(hidden);
        try { router.push(to); router.refresh(); }
        catch { finish(new Error(failure)); return; }
        deadline.current = setTimeout(() => finish(new Error(failure)), 12000);
      }, outroMs);
    });
  }, [router, finish]);

  const enter = useCallback((source?: EyeOrigin) => {
    if (flight.current) return Promise.resolve();
    setOrigin(source || {left:innerWidth/2-160,top:innerHeight/2-80,width:320,height:160});
    setStartedAt(performance.now());
    return travel("/dashboard", "cover", "covered", COVER_MS, "Dashboard belum merespons. Coba masuk kembali.");
  }, [travel]);

  const leave = useCallback(() => {
    if (flight.current) return Promise.resolve();
    return travel("/", "leave", "away", LEAVE_MS, "Halaman awal belum merespons. Muat ulang halaman.");
  }, [travel]);

  useEffect(() => {
    const next = phase === "covered" && pathname === "/dashboard" ? {phase: "reveal" as const, ms: REVEAL_MS}
      : phase === "away" && pathname === "/" ? {phase: "arrive" as const, ms: ARRIVE_MS} : null;
    if (!next) return;
    if (deadline.current) clearTimeout(deadline.current);
    // Stay hidden until the new route has committed and painted.
    let frame = requestAnimationFrame(() => {
      frame = requestAnimationFrame(() => {
        setPhase(next.phase);
        timer.current = setTimeout(() => finish(), next.ms);
      });
    });
    return () => cancelAnimationFrame(frame);
  }, [pathname, phase, finish]);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
    if (deadline.current) clearTimeout(deadline.current);
  }, []);

  const active = phase !== "idle";
  const smoke = phase === "cover" || phase === "covered" || phase === "reveal" ? phase : null;

  return <TransitionContext.Provider value={{enter, leave}}>
    <div className={styles.content} data-access-transition={phase} inert={active}>{children}</div>
    {smoke && origin && <>
      <div className={styles.scene} role="status" aria-live="polite">
        <span className="visually-hidden">Opening your workspace…</span>
        <SmokeCanvas layer="back" phase={smoke} origin={origin} startedAt={startedAt} coverMs={COVER_MS} revealMs={REVEAL_MS}/>
      </div>
      {/* The front layer only exists to swallow the landing eye. Once the page is fully dark the eye is gone,
          and keeping it would leave a darker, eye-shaped patch while the smoke clears. */}
      {smoke === "cover" && <SmokeCanvas layer="front" phase={smoke} origin={origin} startedAt={startedAt} coverMs={COVER_MS} revealMs={REVEAL_MS}/>}
      {/* Fades in once the smoke has swallowed the page; typing starts as it appears. */}
      <div className={styles.wait} data-access-transition={smoke}><TypedHandle text="Please Wait..." startDelay={WAIT_AT_MS} hold={2400} pace={.5}/></div>
    </>}
  </TransitionContext.Provider>;
}

function useTransitions() {
  const transitions = useContext(TransitionContext);
  if (!transitions) throw new Error("Access transition provider is missing.");
  return transitions;
}

export function useAccessTransition() { return useTransitions().enter; }
export function useLeaveTransition() { return useTransitions().leave; }
