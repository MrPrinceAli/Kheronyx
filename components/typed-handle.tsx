"use client";

import { useEffect, useState } from "react";
import styles from "./typed-handle.module.css";

const GLYPHS = "!<>-_/\\[]{}=+*^?#$%01";

// Types the handle like a terminal: each character scrambles through glyphs before it locks in,
// holds with a blinking cursor, backspaces, then loops.
export function TypedHandle({text="./Viclatess"}:{text?:string}) {
  const [typed,setTyped] = useState({length:0,glyph:""});

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) { setTyped({length:text.length,glyph:""}); return; }
    let timer: ReturnType<typeof setTimeout>;
    let length = 0, scramble = 0, erasing = false;
    const glyph = () => GLYPHS[Math.floor(Math.random()*GLYPHS.length)];
    const tick = () => {
      if (erasing) {
        length--; setTyped({length,glyph:""});
        if (length === 0) { erasing = false; timer = setTimeout(tick, 650); } else timer = setTimeout(tick, 38);
        return;
      }
      if (length === text.length) { erasing = true; timer = setTimeout(tick, 6500); return; }
      if (scramble < 3) { scramble++; setTyped({length,glyph:glyph()}); timer = setTimeout(tick, 32); return; }
      scramble = 0; length++; setTyped({length,glyph:""});
      timer = setTimeout(tick, 60+Math.random()*110);
    };
    timer = setTimeout(tick, 700);
    return () => clearTimeout(timer);
  }, [text]);

  return <span className={styles.handle}>
    <span className="visually-hidden">{text}</span>
    <span className={styles.ghost} aria-hidden="true">{text}</span>
    <span className={styles.typed} aria-hidden="true">{text.slice(0,typed.length)}{typed.glyph && <span className={styles.glyph}>{typed.glyph}</span>}<span className={styles.cursor}/></span>
  </span>;
}
