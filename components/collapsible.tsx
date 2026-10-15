import type { ReactNode } from "react";
import styles from "./collapsible.module.css";

// Smooth expand/collapse without measuring heights: the wrapper animates grid rows 0fr -> 1fr. Content stays mounted
// (hidden from assistive tech and focus while closed) so the transition can play both ways.
export function Collapsible({open, children}: {open: boolean; children: ReactNode}) {
  return <div className={`${styles.collapse} ${open ? styles.open : ""}`} aria-hidden={!open} inert={!open}>
    <div className={styles.inner}>{children}</div>
  </div>;
}

// Chevron that turns 180° with the same easing.
export const chevronClass = (open: boolean) => `${styles.chevron} ${open ? styles.turned : ""}`;
