import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const RATE_LIMIT_PEPPER = Deno.env.get("RATE_LIMIT_PEPPER") ?? "";
const DISCORD_WEBHOOK_URL = Deno.env.get("DISCORD_WEBHOOK_URL") ?? "";
const ADMIN_PASSWORD = Deno.env.get("GALLERY_ADMIN_PASSWORD") ?? "";
const ADMIN_SESSION_SECRET = Deno.env.get("GALLERY_ADMIN_SESSION_SECRET") ?? "";
const ALLOWED_ORIGINS = new Set(["https://01.nya.je", "https://mischiefulvirus.github.io"]);
const IMAGE_MAX_BYTES = 5 * 1024 * 1024;
const VIDEO_MAX_BYTES = 10 * 1024 * 1024;
const encoder = new TextEncoder();

function cors(origin: string | null) {
  const allowed = origin && ALLOWED_ORIGINS.has(origin) ? origin : "https://01.nya.je";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info, x-gallery-admin-token",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}
function reply(body: unknown, status: number, headers: Record<string,string>) {
  return new Response(JSON.stringify(body), { status, headers: { ...headers, "Content-Type": "application/json" } });
}
function validMedia(bytes: Uint8Array, mime: string) {
  const starts = (...sig: number[]) => sig.every((v, i) => bytes[i] === v);
  if (mime === "image/jpeg") return starts(0xff,0xd8,0xff);
  if (mime === "image/png") return starts(0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a);
  if (mime === "image/webp") return bytes.length >= 12 && String.fromCharCode(...bytes.slice(0,4)) === "RIFF" && String.fromCharCode(...bytes.slice(8,12)) === "WEBP";
  if (mime === "image/gif") {
    const signature = String.fromCharCode(...bytes.slice(0,6));
    return bytes.length >= 6 && (signature === "GIF87a" || signature === "GIF89a");
  }
  if (mime === "video/mp4" || mime === "video/quicktime") {
    return bytes.length >= 12 && String.fromCharCode(...bytes.slice(4,8)) === "ftyp";
  }
  if (mime === "video/webm") return bytes.length >= 4 && starts(0x1a,0x45,0xdf,0xa3);
  if (mime === "video/ogg") return bytes.length >= 4 && String.fromCharCode(...bytes.slice(0,4)) === "OggS";
  return false;
}
function mediaExtension(mime: string) {
  const extensions: Record<string,string> = {
    "image/jpeg":"jpg", "image/png":"png", "image/webp":"webp", "image/gif":"gif",
    "video/mp4":"mp4", "video/webm":"webm", "video/ogg":"ogv", "video/quicktime":"mov"
  };
  return extensions[mime] || "bin";
}
const adjectives = ["ashen","astral","cryptic","distant","dreaming","faded","forgotten","hollow","lucid","midnight","mythic","silent","velvet","vivid","withered"];
const nouns = ["angel","archive","comet","echo","ghost","hunter","orchid","phantom","raven","signal","specter","wanderer","wraith","zero"];
function randomInt(max: number) {
  const bytes = new Uint32Array(1);
  crypto.getRandomValues(bytes);
  return bytes[0] % max;
}
async function ensureVisitor(visitorId: string) {
  if (!RATE_LIMIT_PEPPER) throw new Error("visitor identity is not configured");
  if (!/^[0-9a-f-]{36}$/i.test(visitorId)) throw new Error("invalid visitor identity");
  const visitorHash = await sha256(RATE_LIMIT_PEPPER + ":gallery-visitor:" + visitorId);
  const endpoint = SUPABASE_URL + "/rest/v1/gallery_visitors";
  const lookup = await fetch(endpoint + "?visitor_hash=eq." + visitorHash + "&select=display_name", { headers: restHeaders() });
  if (!lookup.ok) throw new Error("could not look up visitor identity");
  const existing = await lookup.json().catch(() => []);
  if (Array.isArray(existing) && existing[0]?.display_name) {
    await fetch(endpoint + "?visitor_hash=eq." + visitorHash, {
      method: "PATCH", headers: { ...restHeaders(), "Prefer":"return=minimal" },
      body: JSON.stringify({ last_seen_at: new Date().toISOString() })
    });
    return { visitorHash, displayName: String(existing[0].display_name) };
  }
  for (let attempt = 0; attempt < 12; attempt++) {
    const displayName = adjectives[randomInt(adjectives.length)] + "-" +
      nouns[randomInt(nouns.length)] + "-" + (randomInt(9000) + 1000);
    const inserted = await fetch(endpoint, {
      method: "POST", headers: { ...restHeaders(), "Prefer":"return=representation" },
      body: JSON.stringify({ visitor_hash: visitorHash, display_name: displayName })
    });
    if (inserted.ok) return { visitorHash, displayName };
    if (inserted.status === 409) {
      const retryLookup = await fetch(endpoint + "?visitor_hash=eq." + visitorHash + "&select=display_name", { headers: restHeaders() });
      const rows = await retryLookup.json().catch(() => []);
      if (Array.isArray(rows) && rows[0]?.display_name) return { visitorHash, displayName: String(rows[0].display_name) };
      continue;
    }
    throw new Error("could not create visitor identity");
  }
  throw new Error("could not assign a unique display name");
}
async function validImageId(id: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id);
}
function cleanName(name: string) {
  const base = name.split(/[\\/]/).pop() ?? "image";
  return base.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 100) || "image";
}
async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2,"0")).join("");
}
function b64url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
}
function fromB64url(value: string) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}
async function sessionKey() {
  return await crypto.subtle.importKey(
    "raw", encoder.encode(ADMIN_SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
  );
}
async function createAdminToken() {
  const payload = encoder.encode(JSON.stringify({ role: "gallery-admin", exp: Date.now() + 60 * 60 * 1000 }));
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", await sessionKey(), payload));
  return b64url(payload) + "." + b64url(signature);
}
async function validAdminToken(token: string) {
  try {
    const parts = token.split(".");
    if (parts.length !== 2) return false;
    const payload = fromB64url(parts[0]);
    const signature = fromB64url(parts[1]);
    const valid = await crypto.subtle.verify("HMAC", await sessionKey(), signature, payload);
    if (!valid) return false;
    const claims = JSON.parse(new TextDecoder().decode(payload));
    return claims.role === "gallery-admin" && Number.isFinite(claims.exp) && claims.exp > Date.now();
  } catch {
    return false;
  }
}
async function passwordMatches(candidate: string) {
  const [a, b] = await Promise.all([sha256(candidate), sha256(ADMIN_PASSWORD)]);
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
const restHeaders = () => ({
  "apikey": SERVICE_KEY,
  "Authorization": "Bearer " + SERVICE_KEY,
  "Content-Type": "application/json"
});

serve(async (req) => {
  const origin = req.headers.get("origin");
  const headers = cors(origin);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers });
  if (req.method !== "POST") return reply({ error: "method not allowed" }, 405, headers);
  if (origin && !ALLOWED_ORIGINS.has(origin)) return reply({ error: "origin not allowed" }, 403, headers);
  if (!req.headers.get("apikey")) return reply({ error: "missing API key" }, 401, headers);
  if (!SUPABASE_URL || !SERVICE_KEY) return reply({ error: "server configuration incomplete" }, 500, headers);

  if (req.headers.get("content-type")?.includes("application/json")) {
    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return reply({ error: "invalid JSON request" }, 400, headers);
    }

    if (body.action === "login") {
      if (!ADMIN_PASSWORD || ADMIN_SESSION_SECRET.length < 32) {
        return reply({ error: "admin login is not configured" }, 503, headers);
      }
      const password = typeof body.password === "string" ? body.password : "";
      if (password && password.length <= 256 && await passwordMatches(password)) {
        return reply({ success: true, token: await createAdminToken(), expires_in: 3600 }, 200, headers);
      }
      const loginIp = req.headers.get("cf-connecting-ip") ||
        req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
      const loginIpHash = await sha256(ADMIN_SESSION_SECRET + ":admin-login:" + loginIp);
      const loginLimit = await fetch(SUPABASE_URL + "/rest/v1/rpc/claim_gallery_admin_login_slot", {
        method: "POST", headers: restHeaders(),
        body: JSON.stringify({ p_ip_hash: loginIpHash })
      });
      if (!loginLimit.ok) return reply({ error: "admin login protection is unavailable" }, 503, headers);
      const loginAllowed = await loginLimit.json().catch(() => false);
      if (!(loginAllowed === true || (Array.isArray(loginAllowed) && loginAllowed[0] === true))) {
        return reply({ error: "too many login attempts; wait 15 minutes and try again" }, 429, headers);
      }
      return reply({ error: "incorrect password" }, 401, headers);
    }

    if (body.action === "admin-list") {
      if (!ADMIN_SESSION_SECRET || typeof body.token !== "string" || !(await validAdminToken(body.token))) {
        return reply({ error: "admin session expired; log in again" }, 401, headers);
      }
      const listing = await fetch(SUPABASE_URL + "/rest/v1/gallery_images?select=id,object_path,original_name,mime_type,size_bytes,created_at,uploader_name&order=created_at.desc&limit=100", {
        headers: restHeaders()
      });
      if (!listing.ok) return reply({ error: "could not load moderation queue" }, 502, headers);
      return reply({ success: true, images: await listing.json().catch(() => []) }, 200, headers);
    }

    if (body.action === "react") {
      const visitorId = typeof body.visitor_id === "string" ? body.visitor_id : "";
      const imageId = typeof body.image_id === "string" ? body.image_id : "";
      const reaction = body.reaction;
      if (!validImageId(imageId) || !["upvote","downvote","sob"].includes(String(reaction))) {
        return reply({ error: "invalid reaction request" }, 400, headers);
      }
      let visitor;
      try { visitor = await ensureVisitor(visitorId); }
      catch (error) { return reply({ error: error instanceof Error ? error.message : "visitor identity failed" }, 400, headers); }
      const base = SUPABASE_URL + "/rest/v1/";
      if (reaction === "sob") {
        const response = await fetch(base + "gallery_sobs?on_conflict=image_id,visitor_hash", {
          method: "POST", headers: { ...restHeaders(), "Prefer":"resolution=ignore-duplicates,return=minimal" },
          body: JSON.stringify({ image_id: imageId, visitor_hash: visitor.visitorHash })
        });
        if (!response.ok) return reply({ error: "could not save sob reaction" }, 502, headers);
        return reply({ success: true, display_name: visitor.displayName }, 200, headers);
      }
      const vote = reaction === "upvote" ? 1 : -1;
      const existingResponse = await fetch(base + "gallery_votes?image_id=eq." + imageId + "&visitor_hash=eq." + visitor.visitorHash + "&select=vote", { headers: restHeaders() });
      if (!existingResponse.ok) return reply({ error: "could not check existing vote" }, 502, headers);
      const existingRows = await existingResponse.json().catch(() => []);
      if (Array.isArray(existingRows) && existingRows[0]?.vote === vote) {
        const removed = await fetch(base + "gallery_votes?image_id=eq." + imageId + "&visitor_hash=eq." + visitor.visitorHash, {
          method: "DELETE", headers: { ...restHeaders(), "Prefer":"return=minimal" }
        });
        if (!removed.ok) return reply({ error: "could not remove vote" }, 502, headers);
        return reply({ success: true, vote: 0, display_name: visitor.displayName }, 200, headers);
      }
      const saved = await fetch(base + "gallery_votes?on_conflict=image_id,visitor_hash", {
        method: "POST", headers: { ...restHeaders(), "Prefer":"resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify({ image_id: imageId, visitor_hash: visitor.visitorHash, vote, updated_at: new Date().toISOString() })
      });
      if (!saved.ok) return reply({ error: "could not save vote" }, 502, headers);
      return reply({ success: true, vote, display_name: visitor.displayName }, 200, headers);
    }

    if (body.action === "delete") {
      if (!ADMIN_SESSION_SECRET || typeof body.token !== "string" || !(await validAdminToken(body.token))) {
        return reply({ error: "admin session expired; log in again" }, 401, headers);
      }
      const id = typeof body.id === "string" ? body.id : "";
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
        return reply({ error: "invalid image id" }, 400, headers);
      }
      const authHeaders = restHeaders();
      const lookup = await fetch(SUPABASE_URL + "/rest/v1/gallery_images?id=eq." + encodeURIComponent(id) + "&select=object_path", {
        headers: authHeaders
      });
      if (!lookup.ok) return reply({ error: "could not find gallery image" }, 502, headers);
      const rows = await lookup.json().catch(() => []);
      if (!Array.isArray(rows) || rows.length === 0) return reply({ error: "image not found" }, 404, headers);
      const objectPath = String(rows[0].object_path || "");
      if (!objectPath || objectPath.includes("..")) return reply({ error: "invalid stored image path" }, 500, headers);

      const encodedPath = objectPath.split("/").map(encodeURIComponent).join("/");
      const removedObject = await fetch(SUPABASE_URL + "/storage/v1/object/gallery/" + encodedPath, {
        method: "DELETE", headers: {
          "apikey": SERVICE_KEY,
          "Authorization": "Bearer " + SERVICE_KEY
        }
      });
      if (!removedObject.ok) {
        const detail = await removedObject.text().catch(() => "");
        return reply({ error: "could not delete stored image", detail: detail.slice(0, 200) }, 502, headers);
      }
      const removedRow = await fetch(SUPABASE_URL + "/rest/v1/gallery_images?id=eq." + encodeURIComponent(id), {
        method: "DELETE", headers: { ...authHeaders, "Prefer": "return=minimal" }
      });
      if (!removedRow.ok) return reply({ error: "image file deleted, but its gallery record could not be removed" }, 502, headers);
      return reply({ success: true }, 200, headers);
    }
    return reply({ error: "unknown action" }, 400, headers);
  }

  if (!RATE_LIMIT_PEPPER) return reply({ error: "upload rate limiting is not configured" }, 500, headers);
  let file: File;
  let visitorId = "";
  try {
    const form = await req.formData();
    const candidate = form.get("file");
    if (!(candidate instanceof File)) return reply({ error: "missing media file" }, 400, headers);
    file = candidate;
    visitorId = typeof form.get("visitor_id") === "string" ? String(form.get("visitor_id")) : "";
  } catch {
    return reply({ error: "invalid multipart upload" }, 400, headers);
  }
  const maxBytes = mime.startsWith("video/") ? VIDEO_MAX_BYTES : IMAGE_MAX_BYTES;
  if (file.size < 1 || file.size > maxBytes) return reply({ error: mime.startsWith("video/") ? "video files must be between 1 byte and 10 MB" : "image files must be between 1 byte and 5 MB" }, 413, headers);
  const mime = file.type.toLowerCase();
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (!validMedia(bytes, mime)) return reply({ error: "file must be a valid JPEG, PNG, WebP, GIF, MP4, WebM, Ogg, or QuickTime video" }, 415, headers);

  const forwarded = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const ip = req.headers.get("cf-connecting-ip") || forwarded || "unknown";
  const authHeaders = restHeaders();
  const adminToken = req.headers.get("x-gallery-admin-token") || "";
  const isAdmin = Boolean(ADMIN_SESSION_SECRET) && await validAdminToken(adminToken);

  if (!isAdmin) {
    const ipHash = await sha256(RATE_LIMIT_PEPPER + ":" + ip);
    const claim = await fetch(SUPABASE_URL + "/rest/v1/rpc/claim_gallery_upload_slot", {
      method: "POST", headers: authHeaders, body: JSON.stringify({ p_ip_hash: ipHash })
    });
    if (!claim.ok) return reply({ error: "rate limit service unavailable" }, 503, headers);
    const claimData = await claim.json().catch(() => false);
    const allowed = claimData === true || (Array.isArray(claimData) && claimData[0] === true) ||
      (typeof claimData === "object" && claimData !== null && (claimData.allowed === true || claimData.claim_gallery_upload_slot === true));
    if (!allowed) return reply({ error: "one upload per minute; please wait before trying again" }, 429, headers);
  }

  let visitor;
  try { visitor = await ensureVisitor(visitorId); }
  catch (error) { return reply({ error: error instanceof Error ? error.message : "visitor identity failed" }, 400, headers); }

  const originalName = cleanName(file.name || "upload");
  const extension = mediaExtension(mime);
  const objectPath = crypto.randomUUID() + "." + extension;
  const storage = await fetch(SUPABASE_URL + "/storage/v1/object/gallery/" + objectPath, {
    method: "POST",
    headers: { ...authHeaders, "Content-Type": mime, "x-upsert": "false" },
    body: bytes
  });
  if (!storage.ok) {
    const detail = await storage.text().catch(() => "");
    return reply({ error: "storage upload failed", detail: detail.slice(0,300) }, 502, headers);
  }

  const inserted = await fetch(SUPABASE_URL + "/rest/v1/gallery_images", {
    method: "POST",
    headers: { ...authHeaders, "Prefer": "return=representation" },
    body: JSON.stringify({
      object_path: objectPath, original_name: originalName, mime_type: mime,
      size_bytes: file.size, uploader_hash: visitor.visitorHash, uploader_name: visitor.displayName
    })
  });
  if (!inserted.ok) {
    await fetch(SUPABASE_URL + "/storage/v1/object/gallery/" + objectPath, { method: "DELETE", headers: authHeaders }).catch(() => {});
    const detail = await inserted.text().catch(() => "");
    return reply({ error: "could not save gallery metadata", detail: detail.slice(0,300) }, 502, headers);
  }

  const insertedRows = await inserted.json().catch(() => []);
  const imageId = Array.isArray(insertedRows) && insertedRows[0]?.id ? String(insertedRows[0].id) : "";
  if (DISCORD_WEBHOOK_URL) {
    const galleryLink = "https://01.nya.je/gallery/" + (imageId ? "?image=" + encodeURIComponent(imageId) : "");
    const publicMediaUrl = SUPABASE_URL + "/storage/v1/object/public/gallery/" +
      objectPath.split("/").map(encodeURIComponent).join("/");
    fetch(DISCORD_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content: "new gallery submission • [view in gallery](" + galleryLink + ")",
        embeds: [{
          title: "new gallery submission",
          url: galleryLink,
          description: originalName + " • " + mime + " • " + file.size + " bytes • by " + visitor.displayName,
          ...(mime.startsWith("image/") ? { image: { url: publicMediaUrl } } : { thumbnail: { url: "https://01.nya.je/favicon.ico" } })
        }]
      })
    }).catch(() => {});
  }
  return reply({ success: true, id: imageId, object_path: objectPath, uploader_name: visitor.displayName }, 201, headers);
});
