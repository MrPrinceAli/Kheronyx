import type { FileKind } from "./types";

export type UploadMode = "blob" | "supabase" | "direct";
export const MB = 1024 * 1024;
// Per-format analysis ceilings. Large APKs are mostly assets and native libraries; only the
// manifest and the first DEX files are ever inflated, so memory stays bounded.
export const KIND_LIMITS: Record<FileKind, number> = { apk: 250 * MB, exe: 250 * MB, pdf: 50 * MB, png: 250 * MB, jpg: 250 * MB };
// Supabase Free caps objects at 50 MB (bucket set to 40 MB); direct form posts hit Vercel's 4.5 MB body limit.
const MODE_CAPS: Record<UploadMode, number> = { blob: Infinity, supabase: 40 * MB, direct: 4 * MB };
// Files above this size count against the monthly large-file quota that protects the Hobby Blob transfer allowance.
export const LARGE_FILE_BYTES = 50 * MB;

export function sizeLimits(mode: UploadMode): Record<FileKind, number> {
  return Object.fromEntries(Object.entries(KIND_LIMITS).map(([kind, limit]) => [kind, Math.min(limit, MODE_CAPS[mode])])) as Record<FileKind, number>;
}

export const formatMB = (bytes: number) => `${Math.round(bytes / MB)} MB`;
