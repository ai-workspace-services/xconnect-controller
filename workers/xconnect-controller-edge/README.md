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

## Automated Post-Merge CI/CD Deployment (Vault KV)

On every push/merge to `main` (and `workflow_dispatch`), the final `deploy-worker` job in `../../.github/workflows/ci.yml` runs after `test`, `worker-ts`, and `container` pass:

1. Authenticates to `https://vault.svc.plus` via GitHub OIDC (`role: github-actions-xconnect-controller-prod`) and reads:
   - Vault KV path: `prod/serverless/cloudflare` (`kv/data/prod/serverless/cloudflare`)
   - Keys: `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`
2. Resolves `CLOUDFLARE_HYPERDRIVE_ID` (from repository variable `CLOUDFLARE_HYPERDRIVE_ID` or an existing `xconnect-overlay-pg` / `xconnect-controller-pg` Hyperdrive config) via `scripts/render-wrangler-config.mjs`.
3. Runs `npx wrangler deploy --config wrangler.deploy.toml` and verifies `/healthz` returns `runtime: "cloudflare-worker"`.
