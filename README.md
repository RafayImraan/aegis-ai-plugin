# Aegis AI

A small Express demo of an x402-style inspection proxy for PayBox agents. It requests a payment header, forwards an allowed vendor request, checks the response, and returns the inspected data or a 422 failure.

## Setup

```sh
npm install
cp .env.example .env
npm start
```

On Windows PowerShell, use `Copy-Item .env.example .env` instead of `cp`. The server listens on port 3000 by default.

## Manual test (Windows PowerShell)

Start the server in one terminal with `npm start`, then run these commands in a second PowerShell terminal.

### A. Discover the plugin manifest

```powershell
Invoke-RestMethod http://localhost:3000/.well-known/paybox.json
```

Expected: JSON describing the Aegis AI capability.

### B. Send a request without a payment header

```powershell
$body = @{ target_url = "/mock-vendor/good"; expected_key = "data" } | ConvertTo-Json

try {
  Invoke-RestMethod http://localhost:3000/v1/inspect-and-pay `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
} catch {
  $_.ErrorDetails.Message
}
```

Expected: HTTP 402 and payment instructions. PowerShell reports non-2xx responses as exceptions, so the `catch` prints the response body.

### C. Simulate payment and inspect a successful vendor response

```powershell
$body = @{ target_url = "/mock-vendor/good"; expected_key = "data" } | ConvertTo-Json

Invoke-RestMethod http://localhost:3000/v1/inspect-and-pay `
  -Method Post `
  -Headers @{ "payment-signature" = "demo" } `
  -ContentType "application/json" `
  -Body $body
```

Expected: HTTP 200 and the mock market analysis report. The header value `demo` only simulates payment acceptance; this does not release escrow or move funds.

### D. Simulate payment and inspect a failed vendor response

```powershell
$body = @{ target_url = "/mock-vendor/bad"; expected_key = "data" } | ConvertTo-Json

try {
  Invoke-RestMethod http://localhost:3000/v1/inspect-and-pay `
    -Method Post `
    -Headers @{ "authorization" = "x402 demo" } `
    -ContentType "application/json" `
    -Body $body
} catch {
  $_.ErrorDetails.Message
}
```

Expected: HTTP 422 with `vendor_status: 500` and `escrow: "simulated_refund"`. This reports the demo failure path; no real refund is issued.

The mock targets must be relative paths such as `/mock-vendor/good`. Remote targets require HTTPS and a hostname listed in `VENDOR_ALLOWLIST`. Redirects are disabled, request size and time are bounded, and local/private targets are rejected.

## Payment and escrow boundary

This MVP does **not** implement real escrow, x402 signature verification, settlement, or refunds. In default `PAYMENT_MODE=demo`, a non-empty `PAYMENT-SIGNATURE` or `authorization: x402 ...` header is merely treated as a simulated payment signal. Success says `demo-accepted` and `not_settled`; failure says a simulated refund was requested. No funds move. The `PAYMENT-REQUIRED` details are a demo challenge and must be aligned to the chosen x402 facilitator/wallet protocol before marketplace use.

Before handling real payments, implement a provider-specific facilitator adapter that verifies the signed payment, settles only after inspection passes, and issues or coordinates a refund on failure. The server deliberately fails closed in `PAYMENT_MODE=facilitator` until that adapter exists. Protect facilitator credentials, define replay/idempotency handling, and use a dedicated payment address. Do not present this demo as production-ready custody or escrow software.
