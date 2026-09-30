import dns from "node:dns/promises";
import net from "node:net";
import { NextResponse } from "next/server";

export const runtime = "nodejs";
const MAX_REDIRECTS = 4;
const REQUEST_TIMEOUT = 9000;
const SECURITY_HEADERS = [
  ["content-security-policy", "Content-Security-Policy", "Controls which scripts, styles, and other resources the page may load.", "It reduces the damage an injected script could do in a browser."],
  ["strict-transport-security", "Strict-Transport-Security", "Tells browsers to keep using HTTPS for this website.", "It helps prevent downgrade attacks that try to force an unsafe connection."],
  ["x-content-type-options", "X-Content-Type-Options", "Stops browsers from guessing a file's type in unsafe ways.", "It helps prevent files from being interpreted as something more dangerous."],
  ["x-frame-options", "X-Frame-Options", "Controls whether another site can embed this page in a frame. CSP frame-ancestors can provide similar framing protection when this header is absent.", "It helps reduce deceptive clickjacking attacks, although some sites use CSP frame-ancestors instead."],
  ["referrer-policy", "Referrer-Policy", "Controls how much page address information is shared with other sites.", "It helps limit accidental exposure of sensitive URL details."],
];
function isPrivateIp(host) {
  const value = host.replace(/^\[|\]$/g, "").toLowerCase();
  const family = net.isIP(value);
  if (family === 4) {
    const octets = value.split(".").map(Number);
    const [a, b] = octets;
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 0 || b === 168)) ||
      (a === 198 && b >= 18 && b <= 19);
  }
  if (family === 6) {
    // Covers loopback, unspecified, IPv4-mapped private addresses, ULA, and link-local IPv6.
    return value === "::" || value === "::1" || value.startsWith("::ffff:") ||
      /^(fc|fd)[0-9a-f]{2}:/.test(value) || /^fe[89ab][0-9a-f]:/.test(value);
  }
  return false;
}
async function assertPublicTarget(url) {
  if (!/^https?:$/.test(url.protocol)) throw new Error("For safety, LinkLens only checks public HTTP or HTTPS websites.");
  if (url.username || url.password || !url.hostname || !url.hostname.includes(".") || url.hostname === "localhost" || url.hostname.endsWith(".localhost") || isPrivateIp(url.hostname)) {
    if (!url.hostname.includes(".") && url.hostname !== "localhost" && !isPrivateIp(url.hostname)) throw new Error("Enter a valid website address, such as https://example.com.");
    throw new Error("For safety, LinkLens cannot check localhost or private network addresses.");
  }
  const records = await dns.lookup(url.hostname, { all: true, verbatim: true });
  if (!records.length || records.some(({ address }) => isPrivateIp(address))) throw new Error("For safety, LinkLens cannot check a website that resolves to a private network address.");
}
function inspectUrl(url) { const hostname = url.hostname; const labels = hostname.split("."); return { hostname, rawIp: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":"), longHostname: hostname.length > 50, excessiveSubdomains: labels.length > 4, suspiciousCharacters: /[^a-z0-9.-]/i.test(hostname) || hostname.includes("--") }; }
function rootDomain(hostname) { const labels = hostname.toLowerCase().split(".").filter(Boolean); return labels.slice(-2).join("."); }
function classifyRedirects(initialUrl, finalUrl, redirects) { const sameRoot = rootDomain(initialUrl.hostname) === rootDomain(finalUrl.hostname); const ordinary = redirects <= 1 && sameRoot; const reason = redirects === 0 ? "No redirect was needed. The website responded directly at the address you entered." : ordinary ? "This is a normal redirect, such as sending the address to HTTPS or www." : redirects > 1 ? "Several redirects were followed. Check that the chain is expected before continuing." : "The address changed to a different hostname or domain. Check that this destination is expected."; return { state: ordinary ? "normal" : "attention", ordinary, reason }; }
function scoreResult({ https, headers, urlFlags }) { let score = 100; if (!https) score -= 25; score -= Object.values(headers).filter((header) => !header.present).length * 8; if (urlFlags.rawIp) score -= 20; if (urlFlags.longHostname) score -= 10; if (urlFlags.excessiveSubdomains) score -= 8; if (urlFlags.suspiciousCharacters) score -= 12; return Math.max(0, Math.min(100, score)); }
export async function POST(request) { try { const body = await request.json(); const input = String(body?.url || "").trim(); if (!input) throw new Error("Enter a website address to analyze."); if (input.length > 2048) throw new Error("That website address is too long to check."); const initialUrl = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`); await assertPublicTarget(initialUrl); let currentUrl = initialUrl; let response; let redirects = 0; for (let attempt = 0; attempt <= MAX_REDIRECTS; attempt += 1) { await assertPublicTarget(currentUrl); response = await fetch(currentUrl, { redirect: "manual", signal: AbortSignal.timeout(REQUEST_TIMEOUT), headers: { "User-Agent": "LinkLens safe website check" } }); if (![301, 302, 303, 307, 308].includes(response.status)) break; const location = response.headers.get("location"); if (!location) break; if (attempt === MAX_REDIRECTS) throw new Error("This website redirected too many times to check safely."); currentUrl = new URL(location, currentUrl); redirects += 1; } const headers = Object.fromEntries(SECURITY_HEADERS.map(([key, name, explanation, why]) => [key, { name, present: Boolean(response.headers.get(name)), explanation, why }])); const urlFlags = inspectUrl(currentUrl); const redirectAssessment = classifyRedirects(initialUrl, currentUrl, redirects); const score = scoreResult({ https: currentUrl.protocol === "https:", headers, urlFlags }); return NextResponse.json({ inputUrl: initialUrl.toString(), finalUrl: currentUrl.toString(), redirects, redirectAssessment, statusCode: response.status, https: currentUrl.protocol === "https:", headers, urlFlags, score, status: score >= 80 ? "Stronger Signals" : score >= 55 ? "Mixed Signals" : "Fewer Signals" }); } catch (error) { const known = ["For safety", "Enter a website", "redirected too many", "too long"].some((text) => error?.message?.includes(text)); const message = known ? error.message : error?.name === "TimeoutError" ? "The website took too long to respond. Try again or check the address." : "We could not reach that website. It may be unavailable or blocking safe checks."; return NextResponse.json({ error: message }, { status: 400 }); } }
