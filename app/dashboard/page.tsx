import { redirect } from "next/navigation";
import { sessionId } from "@/lib/auth";
import { aiConfigured, modelConfig } from "@/lib/ai";
import { storageConfigured } from "@/lib/db";
import { virusTotalConfigured } from "@/lib/virustotal";
import { uploadMode } from "@/lib/blob";
import { sizeLimits } from "@/lib/limits";
import { Dashboard } from "@/components/dashboard";
export const dynamic="force-dynamic";
export default async function Page(){if(!await sessionId())redirect("/");return <Dashboard config={{aiReady:aiConfigured(),storageReady:storageConfigured(),virusTotalReady:virusTotalConfigured(),upload:uploadMode(),limits:sizeLimits(uploadMode()),...modelConfig()}}/>;}
