# `xconnect-controller-edge` (Cloudflare Worker — Phase 3)

TypeScript + Hono + Cloudflare **Hyperdrive (PostgreSQL)** + Web Crypto (`Ed25519` / `JWKS`) edge implementation of `xconnect-controller`.

## Local Development & Contract Verification

```bash
npm ci
npm run typecheck
npm test
```

## Contract Parity Requirement
Any changes to canonical `SignedConfig` / `GatewaySignedConfig` signing bytes, `Ed25519` signature generation, or `PolicyArtifact` SHA-256 digests **must** pass the shared vectors in `../../contracts/xconnect-overlay-v1/golden-vectors.json`.

## Cloudflare Hyperdrive Deployment

```bash
# 1. Create Hyperdrive config pointing to the shared PostgreSQL instance
npx wrangler hyperdrive create xconnect-overlay-pg --connection-string="postgres://..."

# 2. Replace `id = "REPLACE_WITH_HYPERDRIVE_ID"` in wrangler.toml, then set secrets:
npx wrangler secret put XCONNECT_OVERLAY_SIGNING_PRIVATE_KEY
npx wrangler secret put JWT_ACCESS_SECRET

# 3. Deploy edge worker
npm run deploy
```
