/**
 * Client-side validation for uploaded RoE documents (Phase 1.2 security
 * requirements). The server repeats these checks in Phase 3 — client-side
 * validation is for UX only and is never trusted on its own.
 */
export const MAX_ROE_BYTES = 500 * 1024;
const ALLOWED_EXT = /\.(md|markdown|txt)$/i;
const ALLOWED_MIME = new Set(['', 'text/plain', 'text/markdown', 'text/x-markdown']);

export type RoeFileResult = { ok: true; text: string } | { ok: false; error: string };

export async function validateRoeFile(file: File): Promise<RoeFileResult> {
  if (!ALLOWED_EXT.test(file.name)) return { ok: false, error: 'Only .md and .txt files are accepted.' };
  if (!ALLOWED_MIME.has(file.type)) return { ok: false, error: `Unexpected file type "${file.type}".` };
  if (file.size === 0) return { ok: false, error: 'File is empty.' };
  if (file.size > MAX_ROE_BYTES) return { ok: false, error: `File exceeds the 500 KB limit (${(file.size / 1024).toFixed(0)} KB).` };

  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.includes(0)) return { ok: false, error: 'Binary content (null bytes) detected.' };

  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return { ok: true, text };
  } catch {
    return { ok: false, error: 'File is not valid UTF-8 text.' };
  }
}
