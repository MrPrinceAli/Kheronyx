import { useId } from "react";
import styles from "./eye.module.css";
export function Eye({className="",animated=false}:{className?:string;animated?:boolean}) {
  const id=useId().replace(/:/g,"");
  const opening="M48 161C204 100 386 104 551 163C458 196 376 216 297 213C209 213 125 192 48 161Z";
  const fibers=Array.from({length:64},(_,i)=>{
    const angle=i*Math.PI/32,inner=29+(i%5)*3,outer=69+(i%7)*2;
    const point=(radius:number,theta:number)=>`${(300+Math.cos(theta)*radius).toFixed(3)} ${(162+Math.sin(theta)*radius).toFixed(3)}`;
    return <path key={i} d={`M${point(inner,angle)}L${point(outer,angle+.016)}`} stroke={i%3===0?"#969b9e":"#565d60"} strokeWidth={i%4===0?1.3:.6} opacity={i%3===0?.34:.22}/>;
  });
  return <svg className={`eye ${styles.eye} ${className} ${animated?styles.animated:""}`} viewBox="0 0 600 300" fill="none" aria-hidden="true">
    <defs>
      <radialGradient id={`${id}-iris`}><stop stopColor="#030405"/><stop offset=".5" stopColor="#0a0e10"/><stop offset=".76" stopColor="#232a2e"/><stop offset=".93" stopColor="#0b1013"/><stop offset="1" stopColor="#020405"/></radialGradient>
      <linearGradient id={`${id}-sclera`} x1="300" y1="110" x2="300" y2="222" gradientUnits="userSpaceOnUse"><stop stopColor="#434b51"/><stop offset=".48" stopColor="#b4babe"/><stop offset=".76" stopColor="#ced2d3"/><stop offset="1" stopColor="#5b656b"/></linearGradient>
      <linearGradient id={`${id}-shadow`} x1="300" y1="104" x2="300" y2="174" gradientUnits="userSpaceOnUse"><stop stopColor="#020305"/><stop offset=".72" stopColor="#020305" stopOpacity=".65"/><stop offset="1" stopColor="#020305" stopOpacity="0"/></linearGradient>
      <linearGradient id={`${id}-beam`}><stop stopColor="white" stopOpacity="0"/><stop offset=".34" stopColor="white" stopOpacity=".7"/><stop offset=".5" stopColor="white"/><stop offset=".68" stopColor="white" stopOpacity=".7"/><stop offset="1" stopColor="white" stopOpacity="0"/></linearGradient>
      <clipPath id={`${id}-clip`}><path d={opening}/></clipPath>
    </defs>
    <path d="M17 161C165 74 401 66 583 162C462 224 373 243 294 235C199 237 111 207 17 161Z" fill="#080a0c"/>
    <path d={opening} fill={`url(#${id}-sclera)`}/>
    <g clipPath={`url(#${id}-clip)`}>
      <g className={styles.gaze}>
        <circle cx="300" cy="162" r="84" fill={`url(#${id}-iris)`}/>
        <circle cx="300" cy="162" r="79" stroke="#010203" strokeWidth="5"/>
        <circle cx="300" cy="162" r="72" stroke="#768085" strokeWidth=".8" strokeOpacity=".25"/>
        {fibers}
        <circle cx="300" cy="162" r="48" stroke="#414b51" strokeWidth="1" strokeDasharray="1 3" opacity=".45"/>
        <path d="M300 108C280 130 280 190 300 216C320 191 320 131 300 108Z" fill="#000"/>
        <path d="M300 120L298 201" stroke="#2d3439" strokeWidth=".6"/>
        <path d="M330 141L338 139L335 150" stroke="#c7ced1" strokeWidth="1.3" strokeOpacity=".45"/>
        <g className="eye-reticle" stroke="#9ca5aa" strokeWidth=".75" opacity=".38"><path d="M256 141V132H265M335 132H344V141M344 184V193H335M265 193H256V184"/><path d="M300 126V134M300 192V200M254 162H263M337 162H346"/></g>
      </g>
      <path d="M25 105H580V175C456 151 381 146 300 144C212 138 120 149 25 178Z" fill={`url(#${id}-shadow)`}/>
      <g className={styles.beam}><rect x="30" y="112" width="550" height="1.4" fill={`url(#${id}-beam)`}/><rect x="30" y="113.4" width="550" height="9" fill="white" opacity=".045"/><path d="M278 110H289M311 110H322" stroke="white" strokeWidth=".7" opacity=".7"/></g>
      <g className={styles.shutter}><rect x="25" y="105" width="560" height="127" fill="#080a0c"/></g>
    </g>
    <path d="M17 161C165 74 401 66 583 162L551 169C393 105 204 99 48 169Z" fill="#050608"/>
    <path d="M54 178C157 223 231 237 298 231C387 238 474 211 550 179" stroke="#444d53" strokeWidth="1.2"/>
    <path d="M42 198L100 216M501 211L563 184" stroke="#788189" strokeWidth=".7" opacity=".4"/>
  </svg>;
}
