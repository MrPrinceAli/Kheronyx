import type { Metadata } from "next";
import { AccessTransition } from "@/components/access-transition";
import "./globals.css";
export const metadata:Metadata={title:"Kheronyx — See beneath the surface",description:"Analisis statis berbantuan AI untuk PDF, APK, EXE, PNG, dan JPG. Kenali isi file dan pahami risikonya sebelum dibuka.",icons:{icon:"/icon.svg"}};
export default function RootLayout({children}:{children:React.ReactNode}) {return <html lang="id"><body><AccessTransition>{children}</AccessTransition></body></html>;}
