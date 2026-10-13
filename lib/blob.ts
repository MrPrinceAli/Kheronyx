import { BlobNotFoundError, del, get, head, list } from "@vercel/blob";
import { storageConfigured } from "./db";
import type { UploadMode } from "./limits";

export function blobConfigured() { return Boolean(process.env.BLOB_READ_WRITE_TOKEN); }
export function uploadMode(): UploadMode { return blobConfigured() ? "blob" : storageConfigured() ? "supabase" : "direct"; }
export function quarantinePath(session: string, path: unknown): path is string {
  return typeof path === "string" && new RegExp(`^${session}/[a-f0-9-]{36}\\.(pdf|apk|exe|png|jpg)$`).test(path);
}

// Streams a private quarantine blob straight into one buffer of the declared size, so a 250 MB APK
// is held in memory once instead of being copied through Blob and ArrayBuffer.
export async function readBlob(pathname: string, maxBytes: number) {
  // get() streams without a content-length (size reads as 0), so the stored size comes from head().
  const meta = await head(pathname).catch(error => { if (error instanceof BlobNotFoundError) return null; throw error; });
  if (!meta) throw new Error("File tidak ditemukan. Upload ulang.");
  const size = meta.size;
  if (size < 1 || size > maxBytes) throw new Error(`File melebihi batas ${Math.round(maxBytes / 1024 / 1024)} MB untuk format ini.`);
  const result = await get(pathname, { access: "private", useCache: false });
  if (!result || result.statusCode !== 200) throw new Error("File tidak ditemukan. Upload ulang.");
  const buffer = Buffer.allocUnsafe(size); const reader = result.stream.getReader(); let offset = 0;
  try {
    for (;;) {
      const {done, value} = await reader.read(); if (done) break;
      if (offset + value.length > size) throw new Error("Ukuran file berubah saat diunduh. Upload ulang.");
      buffer.set(value, offset); offset += value.length;
    }
  } finally { reader.releaseLock(); }
  if (offset !== size) throw new Error("File belum terunduh lengkap. Upload ulang.");
  return buffer;
}

export async function removeBlob(pathname: string) { await del(pathname); }

export async function cleanupBlobs(cutoff: number) {
  let cursor: string | undefined, deleted = 0;
  do {
    const page = await list({ limit: 1000, cursor });
    const stale = page.blobs.filter(blob => new Date(blob.uploadedAt).getTime() < cutoff).map(blob => blob.pathname);
    if (stale.length) { await del(stale); deleted += stale.length; }
    cursor = page.hasMore ? page.cursor : undefined;
  } while (cursor);
  return deleted;
}
