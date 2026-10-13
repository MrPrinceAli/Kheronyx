import { redirect } from "next/navigation";
import { sessionId } from "@/lib/auth";
import { aiConfigured } from "@/lib/ai";
import { storageConfigured } from "@/lib/db";
import { Dashboard } from "@/components/dashboard";
export const dynamic="force-dynamic";
export default async function Page(){if(!await sessionId())redirect("/");return <Dashboard config={{aiReady:aiConfigured(),storageReady:storageConfigured(),maxBytes:(storageConfigured()?40:4)*1024*1024,model:process.env.AI_MODEL || "Auto"}}/>;}
