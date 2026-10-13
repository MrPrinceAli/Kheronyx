import styles from "./engine-status.module.css";

export function EngineStatus({connected}:{connected:boolean}) {
  return <span className={`${styles.status} ${connected?styles.connected:styles.offline}`} aria-label={connected?"GPT-6 Astra connected":"GPT-6 Astra awaiting connection"}>
    <span className={styles.signal} aria-hidden="true"><i/><i/><i/><i/><i/></span>
    <span>{connected?"Connected":"Offline"}</span>
  </span>;
}
