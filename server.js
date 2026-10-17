"use strict";

require("dotenv").config();
const dns = require("node:dns").promises;
const https = require("node:https");
const net = require("node:net");
const ipaddr = require("ipaddr.js");
const crypto = require("node:crypto");
const express = require("express");
const cors = require("cors");
const manifest = require("./plugin.json");

const NETWORK = "eip155:84532"; // Base Sepolia
const FACILITATOR_DEFAULT = "https://x402.org/facilitator";
const MAX_CONFIG_BYTES = 1024 * 1024;

class TargetValidationError extends Error {
  constructor(message, code = "invalid_target") { super(message); this.name = "TargetValidationError"; this.code = code; }
}

class VendorFailure extends Error {
  constructor(code, message, status) { super(message); this.name = "VendorFailure"; this.code = code; this.status = status; }
}

function isPublicIpv4(address) {
  if (net.isIP(address) !== 4) return false;
  try { return ipaddr.parse(address).range() === "unicast"; }
  catch { return false; }
}

function hasExpectedValue(body, expectedKey) {
  if (body === null || body === undefined) return false;
  if (expectedKey) {
    let current = body;
    for (const part of expectedKey.split(".")) {
      if (!current || typeof current !== "object" || !Object.prototype.hasOwnProperty.call(current, part)) return false;
      current = current[part];
    }
    return current !== null && current !== undefined && current !== "";
  }
  if (typeof body === "string") return body.trim().length > 0;
  if (Array.isArray(body)) return body.length > 0;
  if (typeof body !== "object") return true;
  if (body.status === "error") return false;
  if (Object.prototype.hasOwnProperty.call(body, "data")) return body.data !== null && body.data !== undefined && body.data !== "";
  return Object.values(body).some(value => value !== null && value !== undefined && value !== "");
}

function validateRequestBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new TargetValidationError("Request body must be a JSON object");
  if (typeof body.target_url !== "string" || !body.target_url.trim()) throw new TargetValidationError("target_url must be a non-empty string");
  if (body.expected_key !== undefined && (typeof body.expected_key !== "string" || !body.expected_key.trim() || body.expected_key.length > 256)) {
    throw new TargetValidationError("expected_key must be a non-empty string of at most 256 characters");
  }
  if (body.payload !== undefined && (!body.payload || typeof body.payload !== "object" || Array.isArray(body.payload))) {
    throw new TargetValidationError("payload must be a JSON object");
  }
}

function mockVendor(path) {
  if (path === "/mock-vendor/good") return { status: 200, body: { status: "success", data: "High quality market analysis report verified by Aegis AI." } };
  if (path === "/mock-vendor/bad") return { status: 500, body: { status: "error", data: null } };
  if (path === "/mock-vendor/not-found") return { status: 404, body: { error: "not found" } };
  if (path === "/mock-vendor/empty") return { status: 200, body: null, failure: "empty_body" };
  if (path === "/mock-vendor/invalid-json") return { status: 200, body: null, failure: "invalid_json" };
  if (path === "/mock-vendor/timeout") return { status: 200, body: null, failure: "timeout" };
  if (path === "/mock-vendor/missing-data") return { status: 200, body: { status: "success", result: "report without data" } };
  if (path === "/mock-vendor/redirect") return { status: 302, body: null, failure: "redirect_blocked" };
  return null;
}

async function prepareTarget(targetValue, { mode, allowlist, req, resolver = dns.lookup, enableMocks = false }) {
  if (typeof targetValue !== "string" || !targetValue.trim()) throw new TargetValidationError("target_url must be a non-empty string");
  if (targetValue.startsWith("/")) {
    if (mode !== "demo" || !enableMocks || !mockVendor(targetValue.split("?")[0])) {
      throw new TargetValidationError("Relative targets are available only for enabled demo mock routes");
    }
    return { kind: "mock", path: targetValue.split("?")[0] };
  }

  let url;
  try { url = new URL(targetValue); }
  catch { throw new TargetValidationError("target_url must be a valid absolute HTTPS URL"); }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || (url.port && url.port !== "443")) {
    throw new TargetValidationError("Vendor URL must use HTTPS on port 443 and contain no credentials or fragment");
  }
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (net.isIP(hostname) === 6) throw new TargetValidationError("IPv6 vendor destinations are disabled; configure a public IPv4 hostname");
  if (!allowlist.has(hostname)) throw new TargetValidationError("Vendor hostname is not present in VENDOR_ALLOWLIST");

  let records;
  try {
    records = net.isIP(hostname) === 4
      ? [{ address: hostname, family: 4 }]
      : await resolver(hostname, { all: true, verbatim: true });
  } catch {
    throw new TargetValidationError("Vendor hostname could not be resolved", "dns_failure");
  }
  if (!records.length || records.some(record => record.family !== 4 || !isPublicIpv4(record.address))) {
    throw new TargetValidationError("Vendor hostname resolves to a non-public or unsupported address", "private_destination");
  }
  // Pin the validated address into the HTTPS socket lookup to prevent a DNS
  // rebinding change between validation and connect. TLS still verifies host.
  return { kind: "https", url, address: records[0].address };
}

function performPinnedHttpsRequest(target, payload, { timeoutMs, maxResponseBytes }) {
  return new Promise((resolve, reject) => {
    let request;
    const deadline = setTimeout(() => request?.destroy(new VendorFailure("timeout", "Vendor request timed out")), timeoutMs);
    const body = Buffer.from(JSON.stringify(payload || {}));
    request = https.request(target.url, {
      method: "POST",
      agent: false,
      maxHeaderSize: 16 * 1024,
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        "accept-encoding": "identity",
        "content-length": body.length
      },
      lookup: (_hostname, _options, callback) => callback(null, target.address, 4),
      servername: target.url.hostname
    }, response => {
      const chunks = [];
      let size = 0;
      response.on("data", chunk => {
        size += chunk.length;
        if (size > maxResponseBytes) {
          response.destroy(new VendorFailure("response_too_large", "Vendor response exceeded the configured size limit"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("error", error => reject(error));
      response.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        if (response.statusCode >= 300 && response.statusCode < 400) return reject(new VendorFailure("redirect_blocked", "Vendor redirects are not followed", response.statusCode));
        if (response.statusCode !== 200) return reject(new VendorFailure("vendor_http_error", "Vendor returned a non-success status", response.statusCode));
        if (!raw.trim()) return reject(new VendorFailure("empty_body", "Vendor returned an empty body", response.statusCode));
        const contentType = String(response.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
        if (!(contentType === "application/json" || /^application\/[a-z0-9.+-]+\+json$/.test(contentType))) {
          return reject(new VendorFailure("invalid_content_type", "Vendor did not return JSON", response.statusCode));
        }
        try { resolve({ status: response.statusCode, body: JSON.parse(raw) }); }
        catch { reject(new VendorFailure("invalid_json", "Vendor returned malformed JSON", response.statusCode)); }
      });
    });
    request.setTimeout(timeoutMs, () => request.destroy(new VendorFailure("timeout", "Vendor request timed out")));
    request.on("error", error => {
      clearTimeout(deadline);
      if (error instanceof VendorFailure) reject(error);
      else reject(new VendorFailure("network_error", "Vendor could not be reached"));
    });
    request.on("close", () => clearTimeout(deadline));
    request.end(body);
  });
}

async function requestVendor(target, payload, config) {
  if (target.kind === "mock") {
    const result = mockVendor(target.path);
    if (result.failure) throw new VendorFailure(result.failure, `Mock vendor ${result.failure.replaceAll("_", " ")}`, result.status);
    if (result.status !== 200) throw new VendorFailure("vendor_http_error", "Vendor returned a non-success status", result.status);
    return result.body;
  }
  const result = config.vendorRequest
    ? await config.vendorRequest(target, payload)
    : await performPinnedHttpsRequest(target, payload, config);
  if (result.status !== 200) throw new VendorFailure(result.status >= 300 && result.status < 400 ? "redirect_blocked" : "vendor_http_error", "Vendor returned a non-success status", result.status);
  return result.body;
}

function buildX402({ payToAddress, facilitatorUrl = FACILITATOR_DEFAULT, price = "$0.10", facilitatorTimeoutMs = 90_000, facilitator, syncFacilitatorOnStart = true }) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(payToAddress || "") || /^0x0{40}$/i.test(payToAddress || "")) {
    throw new Error("PAY_TO_ADDRESS must be a valid EVM address before PAYMENT_MODE=x402 can start");
  }
  let facilitatorOrigin;
  try { facilitatorOrigin = new URL(facilitatorUrl); }
  catch { throw new Error("FACILITATOR_URL must be a valid HTTPS URL"); }
  if (facilitatorOrigin.protocol !== "https:" || facilitatorOrigin.username || facilitatorOrigin.password) {
    throw new Error("FACILITATOR_URL must use HTTPS and contain no credentials");
  }
  const normalizedPrice = String(price).startsWith("$") ? String(price) : `$${price}`;
  if (!/^\$(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(normalizedPrice) || Number(normalizedPrice.slice(1)) <= 0) {
    throw new Error("PAYMENT_PRICE_USDC must be a positive decimal USD amount");
  }
  if (!Number.isSafeInteger(Number(facilitatorTimeoutMs)) || Number(facilitatorTimeoutMs) < 1 || Number(facilitatorTimeoutMs) > 120_000) {
    throw new Error("FACILITATOR_TIMEOUT_MS must be an integer from 1 to 120000 milliseconds");
  }
  const { HTTPFacilitatorClient } = require("@x402/core/server");
  const { paymentMiddleware, x402ResourceServer } = require("@x402/express");
  const { ExactEvmScheme } = require("@x402/evm/exact/server");
  const { declareDiscoveryExtension } = require("@x402/extensions/bazaar");
  const client = facilitator || new HTTPFacilitatorClient({ url: facilitatorUrl, timeoutMs: Number(facilitatorTimeoutMs) });
  const resourceServer = new x402ResourceServer(client).register(NETWORK, new ExactEvmScheme());
  const settlementGuard = createSettlementGuard();
  resourceServer.onBeforeSettle(context => settlementGuard.beforeSettle(context));
  resourceServer.onAfterSettle(context => settlementGuard.afterSettle(context));
  resourceServer.onSettleFailure(context => settlementGuard.onFailure(context));
  const inputSchema = {
    type: "object",
    properties: {
      target_url: { type: "string", description: "HTTPS vendor URL on VENDOR_ALLOWLIST" },
      expected_key: { type: "string", description: "Optional dotted JSON key path that must exist and be non-empty" },
      payload: { type: "object", description: "JSON body forwarded to the vendor" }
    },
    required: ["target_url"], additionalProperties: false
  };
  const routes = {
    "POST /v1/inspect-and-pay": {
      accepts: [{ scheme: "exact", price: normalizedPrice, network: NETWORK, payTo: payToAddress, maxTimeoutSeconds: 120 }],
      description: "Inspect an allowlisted vendor response. Base Sepolia USDC is settled only after a valid response; failed inspection returns before settlement.",
      mimeType: "application/json",
      serviceName: "Aegis AI",
      tags: ["api", "inspection", "proxy"],
      extensions: declareDiscoveryExtension({
        method: "POST", bodyType: "json", input: { target_url: "https://vendor.example/api", expected_key: "data", payload: {} }, inputSchema,
        output: { example: { data: "Inspected vendor output" }, schema: { type: "object", additionalProperties: true } }
      })
    }
  };
  return paymentMiddleware(routes, resourceServer, undefined, undefined, syncFacilitatorOnStart);
}

function createRateLimiter({ limit = 60, windowMs = 60_000, trustProxy = false } = {}) {
  const buckets = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const key = trustProxy ? req.ip : (req.socket.remoteAddress || "unknown");
    let bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) bucket = { count: 0, resetAt: now + windowMs };
    bucket.count++;
    buckets.set(key, bucket);
    if (buckets.size > 5000) {
      for (const [ip, entry] of buckets) if (entry.resetAt <= now) buckets.delete(ip);
    }
    res.set("RateLimit-Limit", String(limit));
    res.set("RateLimit-Remaining", String(Math.max(0, limit - bucket.count)));
    if (bucket.count > limit) {
      res.set("Retry-After", String(Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))));
      return res.status(429).json({ error: "Too many requests" });
    }
    next();
  };
}

function createPaymentDeduplicator({ ttlMs = 120_000, maxEntries = 2000 } = {}) {
  const completed = new Map();
  const pending = new Map();
  return {
    async run(paymentId, requestFingerprint, operation) {
      if (!paymentId) return operation();
      const now = Date.now();
      for (const [key, value] of completed) if (value.expiresAt <= now) completed.delete(key);
      const previous = completed.get(paymentId) || pending.get(paymentId);
      if (previous) {
        if (previous.fingerprint !== requestFingerprint) return { status: 409, body: { error: "Payment authorization was already used for a different request" } };
        return previous.response || previous.promise;
      }
      const entry = { fingerprint: requestFingerprint };
      entry.promise = Promise.resolve().then(operation).then(response => {
        completed.set(paymentId, { fingerprint: requestFingerprint, response, expiresAt: Date.now() + ttlMs });
        while (completed.size > maxEntries) completed.delete(completed.keys().next().value);
        return response;
      }).finally(() => pending.delete(paymentId));
      pending.set(paymentId, entry);
      return entry.promise;
    }
  };
}

function createSettlementGuard({ ttlMs = 120_000, maxEntries = 2000 } = {}) {
  const completed = new Map();
  const pending = new Map();
  function keyFor(context) {
    return crypto.createHash("sha256").update(JSON.stringify({
      paymentPayload: context.paymentPayload,
      requirements: context.requirements
    })).digest("hex");
  }
  function resolve(key, result) {
    const entry = pending.get(key);
    if (entry) {
      pending.delete(key);
      entry.resolve(result);
    }
  }
  return {
    async beforeSettle(context) {
      const now = Date.now();
      for (const [key, entry] of completed) if (entry.expiresAt <= now) completed.delete(key);
      const key = keyFor(context);
      const previous = completed.get(key);
      if (previous) return { skip: true, result: previous.result };
      const active = pending.get(key);
      if (active) return { skip: true, result: await active.promise };
      let complete;
      const promise = new Promise(resolvePromise => { complete = resolvePromise; });
      pending.set(key, { promise, resolve: complete });
      return undefined;
    },
    afterSettle(context) {
      const key = keyFor(context);
      if (context.result.success) {
        completed.set(key, { result: context.result, expiresAt: Date.now() + ttlMs });
        while (completed.size > maxEntries) completed.delete(completed.keys().next().value);
      }
      resolve(key, context.result);
    },
    onFailure(context) {
      const key = keyFor(context);
      const error = context.error || {};
      const result = {
        success: false,
        errorReason: error.errorReason || "settlement_failed",
        errorMessage: error.errorMessage || "Settlement could not be confirmed",
        transaction: error.transaction || "",
        network: context.requirements.network
      };
      // Do not cache failures: the facilitator may later reconcile an
      // indeterminate settlement when the client safely retries.
      resolve(key, result);
      return undefined;
    }
  };
}

function createApp(options = {}) {
  const mode = options.mode || process.env.PAYMENT_MODE || "demo";
  if (!new Set(["demo", "x402"]).has(mode)) throw new Error("PAYMENT_MODE must be either demo or x402");
  const allowlist = new Set((options.allowlist ?? process.env.VENDOR_ALLOWLIST ?? "").split(",").map(value => value.trim().toLowerCase().replace(/\.$/, "")).filter(Boolean));
  const timeoutMs = Number(options.timeoutMs ?? process.env.REQUEST_TIMEOUT_MS ?? 10000);
  const maxResponseBytes = Number(options.maxResponseBytes ?? process.env.MAX_VENDOR_RESPONSE_BYTES ?? 1_048_576);
  const maxBodyBytes = Number(options.maxBodyBytes ?? process.env.MAX_BODY_BYTES ?? 65_536);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30_000) throw new Error("REQUEST_TIMEOUT_MS must be 100 to 30000 milliseconds");
  if (!Number.isInteger(maxResponseBytes) || maxResponseBytes < 1024 || maxResponseBytes > 10_485_760) throw new Error("MAX_VENDOR_RESPONSE_BYTES must be 1024 to 10485760");
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes < 1024 || maxBodyBytes > 1_048_576) throw new Error("MAX_BODY_BYTES must be 1024 to 1048576");
  const enableMocks = options.enableMocks ?? mode === "demo";
  const trustProxy = options.trustProxy ?? process.env.TRUST_PROXY === "1";
  const paymentDeduplicator = createPaymentDeduplicator(options.deduplication);
  const app = express();
  app.disable("x-powered-by");
  if (trustProxy) app.set("trust proxy", 1);
  app.use(cors());
  app.use(express.json({ limit: maxBodyBytes, strict: true }));

  app.get("/", (_req, res) => res.json({ name: "Aegis AI", mode, status: "ready" }));
  app.get("/.well-known/paybox.json", (_req, res) => res.json({ ...manifest, payment_mode: mode }));

  if (enableMocks && mode === "demo") {
    app.post("/mock-vendor/good", (_req, res) => res.json(mockVendor("/mock-vendor/good").body));
    app.post("/mock-vendor/bad", (_req, res) => res.status(500).json(mockVendor("/mock-vendor/bad").body));
    app.post("/mock-vendor/not-found", (_req, res) => res.status(404).json({ error: "not found" }));
    app.post("/mock-vendor/empty", (_req, res) => res.status(200).end());
    app.post("/mock-vendor/invalid-json", (_req, res) => res.type("application/json").status(200).send("{"));
    app.post("/mock-vendor/timeout", (_req, res) => setTimeout(() => { if (!res.headersSent) res.json({ data: "late" }); }, timeoutMs * 2));
    app.post("/mock-vendor/missing-data", (_req, res) => res.json(mockVendor("/mock-vendor/missing-data").body));
    app.post("/mock-vendor/redirect", (_req, res) => res.redirect(302, "http://127.0.0.1/"));
  }

  app.use("/v1/inspect-and-pay", createRateLimiter(options.rateLimit));
  if (mode === "x402") {
    const x402Middleware = options.x402Middleware || buildX402({
      payToAddress: options.payToAddress ?? process.env.PAY_TO_ADDRESS,
      facilitatorUrl: options.facilitatorUrl || process.env.FACILITATOR_URL || FACILITATOR_DEFAULT,
      price: options.price || process.env.PAYMENT_PRICE_USDC || "$0.10",
      facilitatorTimeoutMs: options.facilitatorTimeoutMs ?? process.env.FACILITATOR_TIMEOUT_MS ?? 90_000,
      facilitator: options.facilitator,
      syncFacilitatorOnStart: options.syncFacilitatorOnStart ?? true
    });
    app.use(x402Middleware);
  }

  app.post("/v1/inspect-and-pay", async (req, res) => {
    try { validateRequestBody(req.body); }
    catch (error) { return res.status(400).json({ error: error.message }); }
    if (mode === "demo") {
      const signature = req.get("payment-signature");
      const authorization = req.get("authorization");
      if (!(signature && signature.trim()) && !(authorization && /^x402\s+\S+/i.test(authorization))) {
        const challenge = { mode: "demo", state: "required", message: "Demo payment header required; no funds will move." };
        return res.status(402).set("PAYMENT-REQUIRED", JSON.stringify(challenge)).json({ error: "Demo payment required", payment: challenge });
      }
    }

    let target;
    try {
      target = await prepareTarget(req.body.target_url, {
        mode, allowlist, req, resolver: options.resolver || dns.lookup, enableMocks,
      });
    } catch (error) {
      return res.status(400).json({ error: error.message, code: error.code || "invalid_target" });
    }

    const inspect = async () => {
      try {
        const vendorBody = await requestVendor(target, req.body.payload, { timeoutMs, maxResponseBytes, vendorRequest: options.vendorRequest });
        if (!hasExpectedValue(vendorBody, req.body.expected_key)) {
          return { status: 422, body: {
            error: "Vendor response failed inspection",
            reason: req.body.expected_key ? "expected_key_missing" : "missing_or_empty_data",
            payment: mode === "demo" ? { state: "demo_only", settlement: "not_performed" } : { state: "not_settled", reason: "inspection_failed" }
          } };
        }
        return { status: 200, body: vendorBody };
      } catch (error) {
        return { status: 422, body: {
          error: "Vendor response failed inspection",
          reason: error.code || "vendor_failure",
          ...(Number.isInteger(error.status) ? { vendor_status: error.status } : {}),
          payment: mode === "demo" ? { state: "demo_only", settlement: "not_performed" } : { state: "not_settled", reason: "inspection_failed" }
        } };
      }
    };
    let result;
    if (mode === "x402") {
      const authorization = req.get("payment-signature") || req.get("x-payment") || "";
      const paymentId = crypto.createHash("sha256").update(authorization).digest("hex");
      const fingerprint = crypto.createHash("sha256").update(JSON.stringify({ target_url: req.body.target_url, expected_key: req.body.expected_key, payload: req.body.payload })).digest("hex");
      result = await paymentDeduplicator.run(paymentId, fingerprint, inspect);
    } else result = await inspect();
    if (result.status !== 200) return res.status(result.status).json(result.body);
    if (mode === "demo") {
      res.set("PAYMENT-RESPONSE", JSON.stringify({ mode: "demo", state: "not_settled" }));
    }
    return res.status(200).json(result.body);
  });

  app.use((error, _req, res, _next) => {
    if (error instanceof SyntaxError && "body" in error) return res.status(400).json({ error: "Invalid JSON body" });
    if (error && error.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
    console.error("Request error:", error && error.message ? error.message : "unknown error");
    return res.status(500).json({ error: "Internal server error" });
  });
  return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  const app = createApp();
  app.listen(port, () => console.log(`Aegis AI (${process.env.PAYMENT_MODE || "demo"}) listening on port ${port}`));
}

module.exports = {
  createApp, buildX402, prepareTarget, performPinnedHttpsRequest,
  hasExpectedValue, isPublicIpv4, validateRequestBody,
  createPaymentDeduplicator, createSettlementGuard, TargetValidationError, VendorFailure, NETWORK
};
