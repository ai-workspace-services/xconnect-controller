# xconnect-controller

Independent XConnect Overlay / Agent-Server control-plane service split from `ai-workspace-services/accounts`.

## Architecture
- **Go Self-Hosted (`cmd/xconnect-controller`)**: Standalone Go service for K3s / self-hosted deployments with persistent Ed25519 key-ring signing (`current` + `previous`), in-process immutable `(network_id, generation)` policy cache, expired session pruning, and offline JWKS JWT verification (`ACCOUNTS_JWKS_URL`).
- **Cloudflare Worker (`workers/xconnect-controller-edge`)**: Phase 3 TypeScript + Hono edge controller backed by Cloudflare Hyperdrive + shared PostgreSQL and Web Crypto `Ed25519`.
- **Shared Contracts (`contracts/xconnect-overlay-v1/`)**: Cross-language OpenAPI spec + deterministic Golden Test Vectors ensuring byte-for-byte equivalence between Go and TypeScript runtimes.
