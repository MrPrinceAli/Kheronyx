import styles from "./engine-status.module.css";

export function EngineStatus({connected,name}:{connected:boolean;name:string}) {
  return <span className={`${styles.status} ${connected?styles.connected:styles.offline}`} aria-label={connected?`${name} connected`:`${name} awaiting connection`}>
    <span className={styles.signal} aria-hidden="true"><i/><i/><i/><i/><i/></span>
    <span>{connected?"Connected":"Offline"}</span>
  </span>;
}
