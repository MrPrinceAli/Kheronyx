"use client";
import { useEffect, useRef, useState } from "react";
import { ArrowRight, Eye as EyeIcon, EyeOff, Loader2, LockKeyhole, ScanLine, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { Eye } from "./eye";
export function Landing() {
  const [open,setOpen]=useState(false),[password,setPassword]=useState(""),[visible,setVisible]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState("");
  const input=useRef<HTMLInputElement>(null);const router=useRouter();
  useEffect(()=>{if(open)input.current?.focus();},[open]);
  async function login(e:React.FormEvent) {
    e.preventDefault();if(busy)return;setBusy(true);setError("");
    try{const response=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password})});const body=await response.json();if(!response.ok)throw new Error(body.error);router.push("/dashboard");router.refresh();}catch(e){setError(e instanceof Error?e.message:"Koneksi terputus. Coba lagi.");setBusy(false);}
  }
  return <div className="landing">
    <header className="landing-header"><a href="/" className="wordmark"><span className="brand-symbol"><Eye/></span>KHERONYX<span className="brand-version">/ 01</span></a><span className="private-label"><LockKeyhole size={12}/> PRIVATE ACCESS</span></header>
    <main className="landing-main">
      <div className="hero-emblem"><div className="eye-aura"/><div className="target-corner top-left"/><div className="target-corner top-right"/><div className="target-corner bottom-left"/><div className="target-corner bottom-right"/>
        <span className="emblem-meta">KX · FILE INTELLIGENCE</span><Eye className="hero-eye" animated/><span className="emblem-coordinate">01 / OBSERVE</span>
      </div>
      <div className="hero-copy">
        <div className="eyebrow hero-features">
          <span className="hero-feature"><ScanLine size={12} strokeWidth={1.5} aria-hidden="true"/>STATIC INTELLIGENCE</span>
          <span className="hero-feature-divider" aria-hidden="true">·</span>
          <span className="hero-feature hero-feature-ai"><img className="hero-feature-logo" src="/openai.svg" width={12} height={12} alt="" aria-hidden="true"/>GPT-6 Astra Assisted</span>
        </div>
        <h1>Kheronyx<span className="title-dot">.</span></h1>
        <p className="hero-tagline">See beneath the surface.</p>
        <p className="builder">build by <span>./Viclatess</span></p>
      </div>
      <div className="login-area"><button className={`button button-dark login-toggle ${open?"is-open":""}`} onClick={()=>setOpen(!open)} aria-expanded={open} aria-controls="login-form"><LockKeyhole size={16}/>Login<ArrowRight size={16}/></button>
        {open && <form id="login-form" className="login-form" onSubmit={login}><label htmlFor="password">Password akses</label><div className={`password-field ${error?"field-error":""}`}><input id="password" ref={input} type={visible?"text":"password"} autoComplete="current-password" placeholder="Masukkan password" value={password} onChange={e=>setPassword(e.target.value)} maxLength={256} required/><button type="button" className="icon-button" onClick={()=>setVisible(!visible)} aria-label={visible?"Sembunyikan password":"Tampilkan password"}>{visible?<EyeOff size={16}/>:<EyeIcon size={16}/>}</button></div>{error&&<p className="form-error" role="alert">{error}</p>}<button className="button button-dark" disabled={busy || !password}>{busy?<Loader2 size={16} className="spin"/>:<ArrowRight size={16}/>} {busy?"Memeriksa akses…":"Masuk ke dashboard"}</button><span className="login-caption"><ShieldCheck size={12}/>Akses privat. Tanpa akun tambahan.</span></form>}
      </div>
    </main>
    <footer className="landing-footer"><span className="footer-note"><ScanLine size={14}/> ONE FILE. A CLOSER LOOK.</span><div className="format-row">{["PDF","APK","EXE","PNG","JPG"].map(type=><span className="format-tag" key={type}>.{type.toLowerCase()}</span>)}<span className="format-tag format-soon">.dmg <span>coming soon</span></span></div><span className="footer-copyright">© 2026 Kheronyx</span></footer>
  </div>;
}
