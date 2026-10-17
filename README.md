# Aegis AI

Aegis AI is an HTTP proxy that inspects a vendor response before returning it to an AI agent. The demo shows the PayBox discovery manifest, a payment challenge, a successful vendor response, and a rejected vendor response.

## Run locally

Requires Node.js 18 or newer.

```bash
npm install
```

Create a local environment file and start the server:

```powershell
Copy-Item .env.example .env
npm start
```

The server listens on `http://localhost:3000` in demo mode.

## Demo walkthrough

Use a second terminal while the server is running.

### Discover the plugin

```bash
curl -i http://localhost:3000/.well-known/paybox.json
```

The endpoint returns the Aegis AI manifest and the `inspect_and_pay` capability.

### Request without a payment header

```bash
curl -i -X POST http://localhost:3000/v1/inspect-and-pay \
  -H "Content-Type: application/json" \
  -d '{"target_url":"/mock-vendor/good","expected_key":"data"}'
```

The demo returns `402 Payment Required` with a demo challenge.

### Inspect a successful vendor response

```bash
curl -i -X POST http://localhost:3000/v1/inspect-and-pay \
  -H "Content-Type: application/json" \
  -H "PAYMENT-SIGNATURE: demo" \
  -d '{"target_url":"/mock-vendor/good","expected_key":"data"}'
```

The good mock vendor returns JSON containing `data`; Aegis returns the inspected response with status `200`.

### Reject a failed vendor response

```bash
curl -i -X POST http://localhost:3000/v1/inspect-and-pay \
  -H "Content-Type: application/json" \
  -H "PAYMENT-SIGNATURE: demo" \
  -d '{"target_url":"/mock-vendor/bad","expected_key":"data"}'
```

The bad mock vendor returns an error. Aegis rejects it with status `422` and does not settle payment.

## Payment behavior

The walkthrough uses demo mode. The `PAYMENT-SIGNATURE: demo` header is a demonstration signal only: no payment is verified, no funds move, and no refund is issued. Aegis demonstrates conditional settlement behavior; it does not hold funds in escrow.
