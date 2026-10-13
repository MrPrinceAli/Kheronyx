import { useId } from "react";
export function Eye({className="",animated=false}:{className?:string;animated?:boolean}) {
  const id=useId().replace(/:/g,"");
  return <svg className={`eye ${className} ${animated?"eye-animated":""}`} viewBox="0 0 600 300" fill="none" aria-hidden="true">
    <defs>
      <radialGradient id={`${id}-iris`}><stop stopColor="#080a0c"/><stop offset=".55" stopColor="#1c2228"/><stop offset=".8" stopColor="#080a0c"/><stop offset="1" stopColor="#51575c"/></radialGradient>
      <linearGradient id={`${id}-lid`} x1="300" y1="62" x2="300" y2="245" gradientUnits="userSpaceOnUse"><stop stopColor="#080b0e"/><stop offset=".6" stopColor="#151a1e"/><stop offset="1" stopColor="#737a7f"/></linearGradient>
      <linearGradient id={`${id}-beam`}><stop stopColor="white" stopOpacity="0"/><stop offset=".5" stopColor="white" stopOpacity=".8"/><stop offset="1" stopColor="white" stopOpacity="0"/></linearGradient>
      <clipPath id={`${id}-clip`}><path d="M50 151C132 83 206 62 300 62C394 62 468 83 550 151C465 213 391 237 300 237C209 237 135 213 50 151Z"/></clipPath>
    </defs>
    <path d="M36 152C131 66 207 47 300 47C395 47 469 66 564 152C468 226 391 254 300 254C207 254 132 226 36 152Z" fill={`url(#${id}-lid)`}/>
    <path d="M52 151C136 94 207 73 300 73C393 73 464 94 548 151C465 196 390 220 300 220C210 220 135 196 52 151Z" fill="#e9eced"/>
    <g clipPath={`url(#${id}-clip)`}>
      <circle cx="300" cy="148" r="88" fill={`url(#${id}-iris)`}/>
      <circle cx="300" cy="148" r="78" stroke="#8b9295" strokeOpacity=".24" strokeWidth=".8"/>
      <circle cx="300" cy="148" r="68" stroke="#adb2b4" strokeOpacity=".15" strokeWidth="1.5" strokeDasharray="2 4"/>
      <circle cx="300" cy="148" r="55" stroke="#a7acad" strokeOpacity=".12" strokeWidth="10" strokeDasharray="1 5"/>
      <circle cx="300" cy="148" r="34" fill="#020304"/>
      <circle cx="283" cy="124" r="9" fill="#e2e6e7" opacity=".65"/>
      <circle cx="305" cy="109" r="3" fill="#e2e6e7" opacity=".45"/>
      <g className="scan-beam"><rect x="45" y="45" width="510" height="4" fill={`url(#${id}-beam)`}/><rect x="45" y="49" width="510" height="24" fill="white" opacity=".035"/></g>
    </g>
    <path d="M36 152C137 65 211 50 300 50C389 50 463 65 564 152" stroke="#080a0d" strokeWidth="10" strokeLinecap="round"/>
    <path d="M68 169C155 230 223 247 300 247C377 247 445 230 532 169" stroke="#a5abad" strokeOpacity=".24" strokeWidth="2"/>
  </svg>;
}
