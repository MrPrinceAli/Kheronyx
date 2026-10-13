"use client";

import { useEffect, useState } from "react";
import styles from "./typed-handle.module.css";

const GLYPHS = "!<>-_/\\[]{}=+*^?#$%01";

// Types the handle like a terminal: each character scrambles through glyphs before it locks in,
// holds with a blinking cursor, backspaces, then loops.
// `pace` scales every delay (below 1 types faster).
export function TypedHandle({text="./Viclatess",startDelay=700,hold=6500,pace=1}:{text?:string;startDelay?:number;hold?:number;pace?:number}) {
  const [typed,setTyped] = useState({length:0,glyph:""});

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) { setTyped({length:text.length,glyph:""}); return; }
    let timer: ReturnType<typeof setTimeout>;
    let length = 0, scramble = 0, erasing = false;
    const glyph = () => GLYPHS[Math.floor(Math.random()*GLYPHS.length)];
    const tick = () => {
      if (erasing) {
        length--; setTyped({length,glyph:""});
        if (length === 0) { erasing = false; timer = setTimeout(tick, 650*pace); } else timer = setTimeout(tick, 38*pace);
        return;
      }
      if (length === text.length) { erasing = true; timer = setTimeout(tick, hold); return; }
      if (scramble < 3) { scramble++; setTyped({length,glyph:glyph()}); timer = setTimeout(tick, 32*pace); return; }
      scramble = 0; length++; setTyped({length,glyph:""});
      timer = setTimeout(tick, (60+Math.random()*110)*pace);
    };
    timer = setTimeout(tick, startDelay);
    return () => clearTimeout(timer);
  }, [text, startDelay, hold, pace]);

  return <span className={styles.handle}>
    <span className="visually-hidden">{text}</span>
    <span className={styles.ghost} aria-hidden="true">{text}</span>
    <span className={styles.typed} aria-hidden="true">{text.slice(0,typed.length)}{typed.glyph && <span className={styles.glyph}>{typed.glyph}</span>}<span className={styles.cursor}/></span>
  </span>;
}
