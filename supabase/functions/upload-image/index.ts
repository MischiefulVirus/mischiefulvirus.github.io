import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const RATE_LIMIT_PEPPER = Deno.env.get("RATE_LIMIT_PEPPER") ?? "";
const DISCORD_WEBHOOK_URL = Deno.env.get("DISCORD_WEBHOOK_URL") ?? "";
const ALLOWED_ORIGINS = new Set(["https://01.nya.je", "https://mischiefulvirus.github.io"]);
const MAX_BYTES = 5 * 1024 * 1024;

function cors(origin: string | null) {
  const allowed = origin && ALLOWED_ORIGINS.has(origin) ? origin : "https://01.nya.je";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}
function reply(body: unknown, status: number, headers: Record<string,string>) {
  return new Response(JSON.stringify(body), { status, headers: { ...headers, "Content-Type": "application/json" } });
}
function validImage(bytes: Uint8Array, mime: string) {
  const starts = (...sig: number[]) => sig.every((v, i) => bytes[i] === v);
  if (mime === "image/jpeg") return starts(0xff,0xd8,0xff);
  if (mime === "image/png") return starts(0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a);
  if (mime === "image/webp") return bytes.length >= 12 && String.fromCharCode(...bytes.slice(0,4)) === "RIFF" && String.fromCharCode(...bytes.slice(8,12)) === "WEBP";
  return false;
}
function cleanName(name: string) {
  const base = name.split(/[\\/]/).pop() ?? "image";
  return base.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 100) || "image";
}
async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2,"0")).join("");
}
serve(async (req) => {
  const origin = req.headers.get("origin");
  const headers = cors(origin);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers });
  if (req.method !== "POST") return reply({ error: "method not allowed" }, 405, headers);
  if (origin && !ALLOWED_ORIGINS.has(origin)) return reply({ error: "origin not allowed" }, 403, headers);
  if (!req.headers.get("apikey")) return reply({ error: "missing API key" }, 401, headers);
  if (!SUPABASE_URL || !SERVICE_KEY || !RATE_LIMIT_PEPPER) return reply({ error: "server configuration incomplete" }, 500, headers);

  let file: File;
  try {
    const form = await req.formData();
    const candidate = form.get("file");
    if (!(candidate instanceof File)) return reply({ error: "missing image file" }, 400, headers);
    file = candidate;
  } catch {
    return reply({ error: "invalid multipart upload" }, 400, headers);
  }
  if (file.size < 1 || file.size > MAX_BYTES) return reply({ error: "image must be between 1 byte and 5 MB" }, 413, headers);
  const mime = file.type.toLowerCase();
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (!validImage(bytes, mime)) return reply({ error: "file must be a valid JPEG, PNG, or WebP image" }, 415, headers);

  const forwarded = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const ip = req.headers.get("cf-connecting-ip") || forwarded || "unknown";
  const ipHash = await sha256(RATE_LIMIT_PEPPER + ":" + ip);
  const restHeaders = { "apikey": SERVICE_KEY, "Authorization": "Bearer " + SERVICE_KEY, "Content-Type": "application/json" };

  const claim = await fetch(SUPABASE_URL + "/rest/v1/rpc/claim_gallery_upload_slot", {
    method: "POST", headers: restHeaders, body: JSON.stringify({ p_ip_hash: ipHash })
  });
  if (!claim.ok) return reply({ error: "rate limit service unavailable" }, 503, headers);
  const claimData = await claim.json().catch(() => false);
  const allowed = claimData === true || (Array.isArray(claimData) && claimData[0] === true) ||
    (typeof claimData === "object" && claimData !== null && (claimData.allowed === true || claimData.claim_gallery_upload_slot === true));
  if (!allowed) return reply({ error: "one upload per minute; please wait before trying again" }, 429, headers);

  const originalName = cleanName(file.name || "image");
  const extension = mime === "image/jpeg" ? "jpg" : mime.split("/")[1];
  const objectPath = crypto.randomUUID() + "." + extension;
  const storage = await fetch(SUPABASE_URL + "/storage/v1/object/gallery/" + objectPath, {
    method: "POST",
    headers: { ...restHeaders, "Content-Type": mime, "x-upsert": "false" },
    body: bytes
  });
  if (!storage.ok) {
    const detail = await storage.text().catch(() => "");
    return reply({ error: "storage upload failed", detail: detail.slice(0,300) }, 502, headers);
  }

  const inserted = await fetch(SUPABASE_URL + "/rest/v1/gallery_images", {
    method: "POST",
    headers: { ...restHeaders, "Prefer": "return=representation" },
    body: JSON.stringify({ object_path: objectPath, original_name: originalName, mime_type: mime, size_bytes: file.size })
  });
  if (!inserted.ok) {
    await fetch(SUPABASE_URL + "/storage/v1/object/gallery/" + objectPath, { method: "DELETE", headers: restHeaders }).catch(() => {});
    const detail = await inserted.text().catch(() => "");
    return reply({ error: "could not save gallery metadata", detail: detail.slice(0,300) }, 502, headers);
  }

  if (DISCORD_WEBHOOK_URL) {
    fetch(DISCORD_WEBHOOK_URL, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: "new gallery image: **" + originalName + "** (" + mime + ", " + file.size + " bytes)" })
    }).catch(() => {});
  }
  return reply({ success: true, object_path: objectPath }, 201, headers);
});