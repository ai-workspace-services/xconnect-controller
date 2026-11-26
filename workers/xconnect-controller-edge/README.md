# `xconnect-controller-edge` (Cloudflare Worker — Phase 3)

TypeScript + Hono + Cloudflare **Hyperdrive (PostgreSQL)** + Web Crypto (`Ed25519` / `JWKS`) edge implementation of `xconnect-controller`.

## Contract Parity Requirement
Any changes to canonical `SignedConfig` / `GatewaySignedConfig` signing bytes, `Ed25519` signature generation, or `PolicyArtifact` SHA-256 digests **must** pass the shared vectors in `../../contracts/xconnect-overlay-v1/golden-vectors.json`.
