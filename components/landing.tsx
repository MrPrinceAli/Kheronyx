"use client";
import { useEffect, useRef, useState } from "react";
import { AppWindow, ArrowRight, Eye as EyeIcon, EyeOff, FileImage, FileText, HardDrive, Image as ImageIcon, Loader2, LockKeyhole, ScanLine, ShieldCheck } from "lucide-react";
import { Eye } from "./eye";
import { useAccessTransition } from "./access-transition";
import { TypedHandle } from "./typed-handle";
import styles from "./landing.module.css";

function AndroidIcon({size=13}:{size?:number}) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m7 5-2-3m12 3 2-3M4 12a8 8 0 0 1 16 0v6H4zM8 18v4m8-4v4M1 12v5m22-5v5"/><path d="M8 9h.01M16 9h.01" strokeWidth="2.5"/></svg>;
}

const fileFormats = [
  {extension:"pdf",Icon:FileText},
  {extension:"apk",Icon:AndroidIcon},
  {extension:"exe",Icon:AppWindow},
  {extension:"png",Icon:FileImage},
  {extension:"jpg",Icon:ImageIcon},
];

// Text attribution only: third-party logos need their owners' permission.
const intelSources=[["VirusTotal","https://www.virustotal.com"],["abuse.ch","https://abuse.ch"],["RDAP","https://about.rdap.org"]] as const;
export function Landing() {
  const [open,setOpen]=useState(false),[password,setPassword]=useState(""),[visible,setVisible]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState("");
  const input=useRef<HTMLInputElement>(null);const emblem=useRef<HTMLDivElement>(null);const enterDashboard=useAccessTransition();
  useEffect(()=>{if(open)input.current?.focus({preventScroll:true});},[open]);
  async function login(e:React.FormEvent) {
    e.preventDefault();if(busy)return;setBusy(true);setError("");
    try{const response=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password})});const body=await response.json();if(!response.ok)throw new Error(body.error);input.current?.blur();const source=emblem.current?.querySelector(".hero-eye")?.getBoundingClientRect();await enterDashboard(source);}catch(e){setError(e instanceof Error?e.message:"Koneksi terputus. Coba lagi.");setBusy(false);}
  }
  return <div className={`landing ${styles.page} ${open?styles.loginOpen:""}`}>
    <header className="landing-header"><a href="/" className="wordmark"><span className="brand-symbol"><Eye/></span>KHERONYX<span className="brand-version">/ 01</span></a><span className="private-label"><LockKeyhole size={12}/> PRIVATE ACCESS</span></header>
    <main className="landing-main">
      <div ref={emblem} className="hero-emblem"><div className="eye-aura"/><div className="target-corner top-left"/><div className="target-corner top-right"/><div className="target-corner bottom-left"/><div className="target-corner bottom-right"/>
        <span className="emblem-meta">KX · FILE INTELLIGENCE</span><Eye className="hero-eye" animated/><span className="emblem-coordinate">01 / OBSERVE</span>
      </div>
      <div className="hero-copy">
        <div className="eyebrow hero-features">
          <span className="hero-feature"><ScanLine size={12} strokeWidth={1.5} aria-hidden="true"/>STATIC INTELLIGENCE</span>
          <span className="hero-feature-divider" aria-hidden="true">·</span>
          <span className="hero-feature hero-feature-ai"><img className="hero-feature-logo" src="/openai.svg" width={12} height={12} alt="" aria-hidden="true"/>GPT-6 Sol Assisted</span>
        </div>
        <h1>Kheronyx<span className="title-dot">.</span></h1>
        <p className="hero-tagline">Revealing the hidden depth.</p>
        <p className="builder">build by <TypedHandle/></p>
      </div>
      <div className="login-area"><button className={`button button-dark login-toggle ${open?"is-open":""}`} onClick={()=>setOpen(!open)} aria-expanded={open} aria-controls="login-form"><LockKeyhole size={16}/>Login<ArrowRight size={16}/></button>
        <div className={styles.loginReveal} aria-hidden={!open} inert={!open}><div className={styles.loginRevealInner}>
          <form id="login-form" className="login-form" onSubmit={login}><div className={`password-field ${error?"field-error":""}`}><input id="password" ref={input} type={visible?"text":"password"} aria-label="Password" autoComplete="current-password" placeholder="Masukkan password" value={password} onChange={e=>setPassword(e.target.value)} maxLength={256} required/><button type="button" className="icon-button" onClick={()=>setVisible(!visible)} aria-label={visible?"Sembunyikan password":"Tampilkan password"}>{visible?<EyeOff size={16}/>:<EyeIcon size={16}/>}</button></div>{error&&<p className="form-error" role="alert">{error}</p>}<button className="button button-dark" disabled={busy || !password}>{busy?<Loader2 size={16} className="spin"/>:<ArrowRight size={16}/>} {busy?"Memeriksa akses…":"Masuk ke dashboard"}</button><span className="login-caption"><ShieldCheck size={12}/>Private Access</span></form>
        </div></div>
      </div>
    </main>
    <footer className="landing-footer"><span className="footer-note"><ScanLine size={14}/> ONE FILE. A CLOSER LOOK.</span><div className="format-row">{fileFormats.map(({extension,Icon})=><span className="format-tag" key={extension}><Icon size={13} aria-hidden="true"/>.{extension}</span>)}<span className="format-tag format-soon"><HardDrive size={13} aria-hidden="true"/>.dmg <span>coming soon</span></span></div><div className="footer-credits"><span className="footer-intel">THREAT INTEL{intelSources.map(([name,href],i)=><span key={name}>{i?" · ":" "}<a href={href} target="_blank" rel="noopener noreferrer">{name}</a></span>)}</span><span className="footer-copyright">© 2026 Kheronyx</span></div></footer>
  </div>;
}
