"use strict";

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const manifest = require("./plugin.json");

const app = express();
const port = Number(process.env.PORT || 3000);
const timeoutMs = Math.min(Math.max(Number(process.env.REQUEST_TIMEOUT_MS || 10000), 1000), 30000);
const payTo = process.env.PAY_TO_ADDRESS || "0x0000000000000000000000000000000000000000";
const allowlist = new Set((process.env.VENDOR_ALLOWLIST || "").split(",").map(x => x.trim().toLowerCase()).filter(Boolean));

app.disable("x-powered-by");
app.use(cors());
app.use(express.json({ limit: process.env.MAX_BODY_BYTES || "64kb" }));

app.get("/.well-known/paybox.json", (_req, res) => res.json(manifest));

app.post("/mock-vendor/good", (_req, res) => res.json({
  status: "success",
  data: "High quality market analysis report verified by Aegis AI."
}));

app.post("/mock-vendor/bad", (_req, res) => res.status(500).json({
  status: "error",
  data: null
}));

function hasPaymentHeader(req) {
  const signature = req.get("payment-signature");
  const authorization = req.get("authorization");
  return Boolean((signature && signature.trim()) || (authorization && /^x402\s+\S+/i.test(authorization)));
}

function paymentRequired(res) {
  const instructions = {
    scheme: "exact",
    network: "base-sepolia",
    amount: "100000",
    asset: "USDC",
    payTo,
    description: "Aegis AI inspection proxy request"
  };
  return res.status(402)
    .set("PAYMENT-REQUIRED", JSON.stringify(instructions))
    .json({ error: "Payment required", payment: instructions });
}

// Presence is not proof of payment. Production use must verify the signed
// payment and settle/refund through an x402 facilitator before reporting it.
async function verifyPayment(req) {
  if (process.env.PAYMENT_MODE === "facilitator") {
    if (!process.env.FACILITATOR_URL) throw new Error("FACILITATOR_URL is required in facilitator mode");
    // Intentionally fail closed until a provider-specific verify/settle adapter
    // is implemented. Never treat a client-supplied header as settled funds.
    throw new Error("No facilitator adapter configured; refusing unverified payment");
  }
  return hasPaymentHeader(req); // Demo-only simulation.
}

function isPrivateIpv4(host) {
  const parts = host.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  return parts[0] === 10 || parts[0] === 127 || parts[0] === 0 ||
    (parts[0] === 169 && parts[1] === 254) || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) || (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127);
}

function resolveTarget(value, req) {
  if (typeof value !== "string" || !value.trim()) throw new Error("target_url must be a non-empty string");
  let url;
  try { url = new URL(value, `${req.protocol}://${req.get("host")}`); }
  catch { throw new Error("target_url is not a valid URL"); }
  const sameOrigin = url.origin === `${req.protocol}://${req.get("host")}`;
  if (sameOrigin) {
    if (!url.pathname.startsWith("/mock-vendor/")) throw new Error("Only mock-vendor same-origin paths are allowed");
    return url.toString();
  }
  if (url.protocol !== "https:" || url.username || url.password) throw new Error("Vendor URL must be HTTPS and contain no credentials");
  const host = url.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || isPrivateIpv4(host) || host.includes(":")) {
    throw new Error("Private or local vendor addresses are not allowed");
  }
  if (!allowlist.has(host)) throw new Error("Vendor hostname is not present in VENDOR_ALLOWLIST");
  return url.toString();
}

function hasExpectedValue(data, key) {
  if (data === null || data === undefined || data === "") return false;
  if (!key) {
    if (typeof data === "string") return data.trim().length > 0;
    if (typeof data !== "object") return true;
    if (!Object.prototype.hasOwnProperty.call(data, "data")) return false;
    if (data.status === "error") return false;
    return data.data !== null && data.data !== undefined && data.data !== "";
  }
  return Boolean(data && typeof data === "object" && Object.prototype.hasOwnProperty.call(data, key) &&
    data[key] !== null && data[key] !== undefined && data[key] !== "");
}

app.post("/v1/inspect-and-pay", async (req, res) => {
  if (!hasPaymentHeader(req)) return paymentRequired(res);
  let paymentAccepted;
  try { paymentAccepted = await verifyPayment(req); }
  catch (err) {
    return res.status(503).json({ error: "Payment could not be verified", detail: err.message });
  }
  if (!paymentAccepted) return paymentRequired(res);

  const { target_url: targetUrl, expected_key: expectedKey, payload } = req.body || {};
  let target;
  try { target = resolveTarget(targetUrl, req); }
  catch (err) { return res.status(400).json({ error: err.message }); }
  if (expectedKey !== undefined && (typeof expectedKey !== "string" || !expectedKey.trim())) {
    return res.status(400).json({ error: "expected_key must be a non-empty string" });
  }
  if (payload !== undefined && (payload === null || typeof payload !== "object")) {
    return res.status(400).json({ error: "payload must be an object or array" });
  }

  try {
    const vendor = await axios.post(target, payload || {}, {
      timeout: timeoutMs,
      maxRedirects: 0,
      validateStatus: () => true,
      headers: { "content-type": "application/json", accept: "application/json" }
    });
    const cleanData = vendor.data;
    const passed = vendor.status === 200 && hasExpectedValue(cleanData, expectedKey);
    if (!passed) {
      return res.status(422).json({
        error: "Vendor failed inspection; escrow refund requested.",
        vendor_status: vendor.status,
        escrow: process.env.PAYMENT_MODE === "demo" ? "simulated_refund" : "refund_pending"
      });
    }
    return res.status(200)
      .set("PAYMENT-RESPONSE", JSON.stringify({ status: "demo-accepted", escrow: "not_settled" }))
      .json(cleanData);
  } catch (err) {
    return res.status(422).json({
      error: "Vendor request failed inspection; escrow refund requested.",
      detail: err.code === "ECONNABORTED" ? "Vendor request timed out" : "Vendor could not be reached",
      escrow: "simulated_refund"
    });
  }
});

app.use((err, _req, res, _next) => {
  if (err instanceof SyntaxError && "body" in err) return res.status(400).json({ error: "Invalid JSON body" });
  console.error("Request error:", err.message);
  return res.status(500).json({ error: "Internal server error" });
});

app.listen(port, () => console.log(`Aegis AI demo listening on http://localhost:${port}`));
