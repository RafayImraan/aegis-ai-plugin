"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createApp, prepareTarget, createPaymentDeduplicator, NETWORK } = require("../server");

async function withServer(app, fn) {
  const server = app.listen(0, "127.0.0.1");
  await new Promise(resolve => server.once("listening", resolve));
  const address = server.address();
  try { await fn(`http://127.0.0.1:${address.port}`); }
  finally { await new Promise(resolve => server.close(resolve)); }
}

function demoApp(options = {}) {
  return createApp({ mode: "demo", enableMocks: true, rateLimit: { limit: 100 }, ...options });
}

function testnetFacilitator(overrides = {}) {
  return {
    getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: "exact", network: NETWORK }], extensions: [], signers: {} }),
    verify: async () => ({ isValid: false, invalidReason: "test_invalid_payment" }),
    settle: async () => ({ success: false, errorReason: "test_not_settled", transaction: "", network: NETWORK }),
    ...overrides
  };
}

async function post(base, body, headers = {}) {
  return fetch(`${base}/v1/inspect-and-pay`, {
    method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body)
  });
}

function signedMockHeaders(response) {
  const required = JSON.parse(Buffer.from(response.headers.get("payment-required"), "base64").toString("utf8"));
  const accepted = required.accepts.find(option => option.network === NETWORK && option.scheme === "exact");
  const paymentPayload = {
    x402Version: 2,
    resource: required.resource,
    accepted,
    payload: {
      signature: `0x${"1".repeat(130)}`,
      authorization: {
        from: "0x0000000000000000000000000000000000000002",
        to: accepted.payTo,
        value: accepted.amount,
        validAfter: "0",
        validBefore: String(Math.floor(Date.now() / 1000) + 60),
        nonce: `0x${"0".repeat(64)}`
      }
    }
  };
  return { "payment-signature": Buffer.from(JSON.stringify(paymentPayload)).toString("base64") };
}

test("manifest discovery returns project metadata and explicit mode", async () => {
  await withServer(demoApp(), async base => {
    const response = await fetch(`${base}/.well-known/paybox.json`);
    const manifest = await response.json();
    assert.equal(response.status, 200);
    assert.equal(manifest.payment_mode, "demo");
    assert.equal(manifest.capabilities[0].payment.network, NETWORK);
  });
});

test("unpaid demo call returns 402 and explicitly says it is a demo challenge", async () => {
  await withServer(demoApp(), async base => {
    const response = await post(base, { target_url: "/mock-vendor/good" });
    const body = await response.json();
    assert.equal(response.status, 402);
    assert.equal(body.payment.state, "required");
    assert.equal(body.payment.mode, "demo");
  });
});

test("demo header cannot be mistaken for real settlement", async () => {
  await withServer(demoApp(), async base => {
    const response = await post(base, { target_url: "/mock-vendor/good", expected_key: "data" }, { "payment-signature": "anything" });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.match(body.data, /market analysis report/);
    assert.equal(JSON.parse(response.headers.get("payment-response")).state, "not_settled");
  });
});

test("failed vendor status, 404, empty body, malformed JSON, timeout, redirect, and missing keys fail inspection", async t => {
  const cases = [
    ["/mock-vendor/bad", "vendor_http_error", 500],
    ["/mock-vendor/not-found", "vendor_http_error", 404],
    ["/mock-vendor/empty", "empty_body"],
    ["/mock-vendor/invalid-json", "invalid_json"],
    ["/mock-vendor/timeout", "timeout"],
    ["/mock-vendor/redirect", "redirect_blocked"]
  ];
  await withServer(demoApp(), async base => {
    for (const [target_url, reason, vendor_status] of cases) {
      await t.test(target_url, async () => {
        const response = await post(base, { target_url }, { authorization: "x402 demo" });
        const body = await response.json();
        assert.equal(response.status, 422);
        assert.equal(body.reason, reason);
        if (vendor_status) assert.equal(body.vendor_status, vendor_status);
        assert.equal(body.payment.settlement, "not_performed");
        assert.doesNotMatch(JSON.stringify(body), /refund(ed)?/i);
      });
    }
  });
});

test("expected_key is validated against the response and supports dotted paths", async () => {
  await withServer(demoApp({ allowlist: "vendor.example", resolver: async () => [{ address: "93.184.216.34", family: 4 }], vendorRequest: async () => ({ status: 200, body: { result: { answer: "42" } } }) }), async base => {
    const pass = await post(base, { target_url: "https://vendor.example/api", expected_key: "result.answer" }, { "payment-signature": "demo" });
    assert.equal(pass.status, 200);
    const miss = await post(base, { target_url: "https://vendor.example/api", expected_key: "result.missing" }, { "payment-signature": "demo" });
    assert.equal(miss.status, 422);
    assert.equal((await miss.json()).reason, "expected_key_missing");
  });
});

test("invalid request body and malformed JSON receive safe client errors", async () => {
  await withServer(demoApp(), async base => {
    const wrong = await post(base, { target_url: "/mock-vendor/good", payload: "not-an-object" }, { "payment-signature": "demo" });
    assert.equal(wrong.status, 400);
    const malformed = await fetch(`${base}/v1/inspect-and-pay`, { method: "POST", headers: { "content-type": "application/json" }, body: "{" });
    assert.equal(malformed.status, 400);
    assert.doesNotMatch(await malformed.text(), /SyntaxError|stack|node_modules/i);
  });
});

test("SSRF destinations are rejected, including private IPv4, IPv6, and mixed DNS answers", async () => {
  const options = { mode: "x402", allowlist: new Set(["127.0.0.1", "vendor.example", "[::1]"]), enableMocks: false };
  await assert.rejects(prepareTarget("https://127.0.0.1/admin", options), /non-public/);
  await assert.rejects(prepareTarget("https://[::1]/admin", options), /IPv6/);
  await assert.rejects(prepareTarget("https://vendor.example/api", {
    ...options, resolver: async () => [
      { address: "93.184.216.34", family: 4 },
      { address: "169.254.169.254", family: 4 }
    ]
  }), /non-public/);
});

test("validated DNS result is pinned and redirect responses are not followed", async () => {
  const target = await prepareTarget("https://vendor.example/api", {
    mode: "x402", allowlist: new Set(["vendor.example"]), resolver: async () => [{ address: "93.184.216.34", family: 4 }]
  });
  assert.equal(target.address, "93.184.216.34");
  await withServer(demoApp({
    allowlist: "vendor.example",
    resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    vendorRequest: async () => ({ status: 302, body: null })
  }), async base => {
    const response = await post(base, { target_url: "https://vendor.example/api" }, { "payment-signature": "demo" });
    assert.equal(response.status, 422);
    assert.equal((await response.json()).reason, "redirect_blocked");
  });
});

test("mock vendor endpoints are absent in x402 mode and pay-to cannot default to a fake address", async () => {
  assert.throws(() => createApp({ mode: "x402", payToAddress: "0x0000000000000000000000000000000000000000" }), /valid EVM address/);
  assert.throws(() => createApp({
    mode: "x402", payToAddress: "0x0000000000000000000000000000000000000001",
    facilitator: testnetFacilitator(), facilitatorTimeoutMs: 120001
  }), /FACILITATOR_TIMEOUT_MS/);
  const app = createApp({ mode: "x402", payToAddress: "0x0000000000000000000000000000000000000001", enableMocks: false, facilitator: testnetFacilitator() });
  await withServer(app, async base => {
    const response = await fetch(`${base}/mock-vendor/good`, { method: "POST" });
    assert.equal(response.status, 404);
  });
});

test("official x402 middleware rejects malformed payment authorization before calling a vendor", async () => {
  let vendorCalls = 0;
  const app = createApp({
    mode: "x402",
    payToAddress: "0x0000000000000000000000000000000000000001",
    facilitator: testnetFacilitator(),
    enableMocks: false,
    allowlist: "vendor.example",
    resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    vendorRequest: async () => { vendorCalls++; return { status: 200, body: { data: "should not run" } }; }
  });
  await withServer(app, async base => {
    const response = await post(base, { target_url: "https://vendor.example/api", expected_key: "data" }, { "payment-signature": "not-a-valid-x402-payload" });
    assert.equal(response.status, 402);
    assert.equal(vendorCalls, 0);
  });
});

test("official SDK flow verifies first, inspects the vendor, then settles only after inspection passes", async () => {
  const events = [];
  const facilitator = testnetFacilitator({
    verify: async () => { events.push("verify"); return { isValid: true, payer: "0x0000000000000000000000000000000000000002" }; },
    settle: async () => { events.push("settle"); return { success: true, payer: "0x0000000000000000000000000000000000000002", transaction: `0x${"a".repeat(64)}`, network: NETWORK }; }
  });
  const app = createApp({
    mode: "x402", payToAddress: "0x0000000000000000000000000000000000000001", facilitator,
    allowlist: "vendor.example", resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    vendorRequest: async () => { events.push("vendor"); return { status: 200, body: { data: "verified report" } }; }
  });
  await withServer(app, async base => {
    const initial = await post(base, { target_url: "https://vendor.example/api", expected_key: "data" });
    assert.equal(initial.status, 402);
    const headers = signedMockHeaders(initial);
    const paid = await post(base, { target_url: "https://vendor.example/api", expected_key: "data" }, headers);
    assert.equal(paid.status, 200);
    assert.deepEqual(await paid.json(), { data: "verified report" });
    assert.deepEqual(events, ["verify", "vendor", "settle"]);
    assert.ok(paid.headers.get("payment-response"), "official middleware returns settlement evidence");
  });
});

test("official SDK flow does not settle when vendor inspection fails", async () => {
  let settlements = 0;
  const facilitator = testnetFacilitator({
    verify: async () => ({ isValid: true, payer: "0x0000000000000000000000000000000000000002" }),
    settle: async () => { settlements++; return { success: true, transaction: `0x${"b".repeat(64)}`, network: NETWORK }; }
  });
  const app = createApp({
    mode: "x402", payToAddress: "0x0000000000000000000000000000000000000001", facilitator,
    allowlist: "vendor.example", resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    vendorRequest: async () => ({ status: 500, body: { error: "vendor failed" } })
  });
  await withServer(app, async base => {
    const initial = await post(base, { target_url: "https://vendor.example/api" });
    const headers = signedMockHeaders(initial);
    const failed = await post(base, { target_url: "https://vendor.example/api" }, headers);
    assert.equal(failed.status, 422);
    assert.equal((await failed.json()).payment.state, "not_settled");
    assert.equal(settlements, 0);
  });
});

test("official SDK retries a settlement_pending result once and withholds vendor output if still pending", async () => {
  let settlements = 0;
  const facilitator = testnetFacilitator({
    verify: async () => ({ isValid: true }),
    settle: async () => {
      settlements++;
      return { success: false, errorReason: "settlement_pending", transaction: `0x${"c".repeat(64)}`, network: NETWORK };
    }
  });
  const app = createApp({
    mode: "x402", payToAddress: "0x0000000000000000000000000000000000000001", facilitator,
    allowlist: "vendor.example", resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    vendorRequest: async () => ({ status: 200, body: { data: "must not be disclosed before confirmed settlement" } })
  });
  await withServer(app, async base => {
    const initial = await post(base, { target_url: "https://vendor.example/api" });
    const headers = signedMockHeaders(initial);
    const response = await post(base, { target_url: "https://vendor.example/api" }, headers);
    assert.equal(response.status, 402);
    assert.equal(settlements, 2, "the SDK makes one bounded retry for settlement_pending");
    assert.doesNotMatch(await response.text(), /must not be disclosed/);
  });
});

test("concurrent retries of one authorization call the vendor and settlement only once", async () => {
  let vendorCalls = 0;
  let settlements = 0;
  const facilitator = testnetFacilitator({
    verify: async () => ({ isValid: true }),
    settle: async () => {
      settlements++;
      await new Promise(resolve => setTimeout(resolve, 20));
      return { success: true, transaction: `0x${"d".repeat(64)}`, network: NETWORK };
    }
  });
  const app = createApp({
    mode: "x402", payToAddress: "0x0000000000000000000000000000000000000001", facilitator,
    allowlist: "vendor.example", resolver: async () => [{ address: "93.184.216.34", family: 4 }],
    vendorRequest: async () => {
      vendorCalls++;
      await new Promise(resolve => setTimeout(resolve, 10));
      return { status: 200, body: { data: "single execution" } };
    }
  });
  await withServer(app, async base => {
    const body = { target_url: "https://vendor.example/api", expected_key: "data" };
    const initial = await post(base, body);
    const headers = signedMockHeaders(initial);
    const [first, retry] = await Promise.all([post(base, body, headers), post(base, body, headers)]);
    assert.equal(first.status, 200);
    assert.equal(retry.status, 200);
    assert.equal(vendorCalls, 1);
    assert.equal(settlements, 1);
  });
});

test("request rate limit returns 429 after the configured request count", async () => {
  await withServer(demoApp({ rateLimit: { limit: 1, windowMs: 60_000 } }), async base => {
    const body = { target_url: "/mock-vendor/good" };
    assert.equal((await post(base, body)).status, 402);
    const limited = await post(base, body);
    assert.equal(limited.status, 429);
  });
});

test("same payment authorization and body deduplicates work; conflicting reuse is rejected", async () => {
  const deduplicator = createPaymentDeduplicator();
  let calls = 0;
  const work = () => new Promise(resolve => setTimeout(() => { calls++; resolve({ status: 200, body: { data: "once" } }); }, 5));
  const [first, second] = await Promise.all([deduplicator.run("payment-hash", "body-hash", work), deduplicator.run("payment-hash", "body-hash", work)]);
  assert.deepEqual(first, second);
  assert.equal(calls, 1);
  const conflict = await deduplicator.run("payment-hash", "different-body", work);
  assert.equal(conflict.status, 409);
  assert.equal(calls, 1);
});

test("Base Sepolia testnet exact x402 challenge is emitted by the official middleware", async () => {
  const app = createApp({ mode: "x402", payToAddress: "0x0000000000000000000000000000000000000001", facilitator: testnetFacilitator() });
  await withServer(app, async base => {
    const response = await post(base, { target_url: "https://vendor.example/api" });
    assert.equal(response.status, 402);
    const header = response.headers.get("payment-required");
    assert.ok(header);
    const challenge = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    assert.equal(challenge.x402Version, 2);
    assert.ok(challenge.accepts.some(option => option.scheme === "exact" && option.network === NETWORK && option.payTo === "0x0000000000000000000000000000000000000001"));
    assert.match(challenge.accepts.find(option => option.network === NETWORK).amount, /^100000$/);
  });
});
