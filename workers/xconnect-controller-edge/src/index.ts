import { Hono } from "hono";
import {
  authenticateAgentServerUser,
  handleGetAgentStatus,
  handleGetSubscription,
  handleListAgentNodes,
  handleListAgentUsers,
  handleSyncConfig,
  handleUsersEventsSSEFallback,
  type AgentServerDeps,
} from "./agent_server.ts";
import {
  buildSigningKeysList,
  computeETag,
  etagMatches,
  loadSigningContext,
  type SigningContext,
} from "./crypto.ts";
import {
  OverlayError,
  ackEnrollment,
  exchangeJoinToken,
  getEnrollmentSignedConfig,
  getGatewaySignedConfig,
  getPolicyArtifact,
  listUserGateways,
  mintDeviceSession,
  pingDatabase,
  serviceOptionsFromEnv,
  withPgClient,
} from "./db.ts";
import {
  GATEWAY_SIGNED_CONFIG_V2_MEDIA_TYPE,
  POLICY_MEDIA_TYPE,
  SIGNED_CONFIG_V2_MEDIA_TYPE,
  type DeviceSessionRequest,
  type ExchangeRequest,
  type SignedConfigAckRequest,
  type WorkerEnv,
} from "./types.ts";

function parseSchemeToken(header: string | undefined, scheme: string): string | null {
  if (!header) return null;
  const prefix = `${scheme} `;
  if (!header.startsWith(prefix)) return null;
  const val = header.slice(prefix.length).trim();
  return val ? val : null;
}

async function requireSigningContext(env: WorkerEnv): Promise<SigningContext> {
  return loadSigningContext(env);
}

export function createApp(deps: AgentServerDeps = {}) {
  const app = new Hono<{ Bindings: WorkerEnv }>();
  const agentDeps: AgentServerDeps = {
    withClient: deps.withClient ?? withPgClient,
    cacheStore: deps.cacheStore,
    staticEd25519Keys: deps.staticEd25519Keys,
    now: deps.now,
  };

  app.onError((err, c) => {
    if (err instanceof OverlayError) {
      return c.json({ error: err.code, message: err.message }, err.status as 400);
    }
    return c.json({ error: "overlay_internal_error", message: "Internal Server Error" }, 500);
  });

  app.get("/healthz", (c) => c.json({ status: "ok", runtime: "cloudflare-worker" }));

  app.get("/readyz", async (c) => {
    try {
      await withPgClient(c.env, (client) => pingDatabase(client));
      return c.json({ status: "ready", database: "ok", runtime: "cloudflare-worker" });
    } catch {
      return c.json({ status: "not_ready", database: "unavailable" }, 503);
    }
  });

  app.post("/api/overlay/v1/device/session", async (c) => {
    const credential = parseSchemeToken(c.req.header("Authorization"), "Device");
    if (!credential) {
      throw new OverlayError(401, "invalid_token", "Unauthorized");
    }
    const body = await c.req.json<DeviceSessionRequest>().catch(() => {
      throw new OverlayError(400, "invalid_request", "Bad Request");
    });
    const signingCtx = await requireSigningContext(c.env);
    const opts = serviceOptionsFromEnv(c.env);
    const resp = await withPgClient(c.env, (client) =>
      mintDeviceSession(client, signingCtx, opts, credential, body),
    );
    c.header("Cache-Control", "no-store");
    return c.json(resp, 200);
  });

  app.get("/api/overlay/v1/enrollment/signed-config", async (c) => {
    const token = parseSchemeToken(c.req.header("Authorization"), "Bearer");
    if (!token) {
      throw new OverlayError(401, "invalid_token", "Unauthorized");
    }
    const v2 = (c.req.header("Accept") ?? "").includes(SIGNED_CONFIG_V2_MEDIA_TYPE);
    const signingCtx = await requireSigningContext(c.env);
    const opts = serviceOptionsFromEnv(c.env);
    const { config, etag } = await withPgClient(c.env, (client) =>
      getEnrollmentSignedConfig(
        client,
        signingCtx,
        opts,
        token,
        c.req.query("device_id") ?? "",
        c.req.query("network_id") ?? "",
        v2,
      ),
    );

    c.header("Cache-Control", "private, no-store");
    c.header("ETag", etag);
    if (config.schema_version === 2) {
      c.header("Vary", "Accept");
    }
    if (etagMatches(c.req.header("If-None-Match"), etag)) {
      return c.body(null, 304);
    }
    const mediaType =
      config.schema_version === 2 ? SIGNED_CONFIG_V2_MEDIA_TYPE : "application/json";
    return c.body(JSON.stringify(config), 200, { "Content-Type": mediaType });
  });

  app.get("/api/overlay/v1/gateway/signed-config", async (c) => {
    const token = parseSchemeToken(c.req.header("Authorization"), "Bearer");
    if (!token) {
      throw new OverlayError(401, "invalid_token", "Unauthorized");
    }
    const v2 = (c.req.header("Accept") ?? "").includes(GATEWAY_SIGNED_CONFIG_V2_MEDIA_TYPE);
    const signingCtx = await requireSigningContext(c.env);
    const opts = serviceOptionsFromEnv(c.env);
    const { config, etag } = await withPgClient(c.env, (client) =>
      getGatewaySignedConfig(client, signingCtx, opts, token, v2),
    );

    c.header("Cache-Control", "private, no-store");
    c.header("Vary", "Accept");
    c.header("ETag", etag);
    if (etagMatches(c.req.header("If-None-Match"), etag)) {
      return c.body(null, 304);
    }
    const mediaType =
      config.schema_version >= 2 ? GATEWAY_SIGNED_CONFIG_V2_MEDIA_TYPE : "application/json";
    return c.body(JSON.stringify(config), 200, { "Content-Type": mediaType });
  });

  app.post("/api/overlay/v1/enrollment/signed-config/:generation/ack", async (c) => {
    const token = parseSchemeToken(c.req.header("Authorization"), "Bearer");
    if (!token) {
      throw new OverlayError(401, "invalid_token", "Unauthorized");
    }
    const gen = Number.parseInt(c.req.param("generation"), 10);
    if (!Number.isFinite(gen) || gen <= 0) {
      throw new OverlayError(400, "invalid_request", "Bad Request");
    }
    const body = await c.req.json<SignedConfigAckRequest>().catch(() => {
      throw new OverlayError(400, "invalid_request", "Bad Request");
    });
    const resp = await withPgClient(c.env, (client) => ackEnrollment(client, token, gen, body));
    c.header("Cache-Control", "no-store");
    return c.json(resp, 200);
  });

  app.get("/api/overlay/v1/enrollment/policy-artifacts/:generation/:digest", async (c) => {
    const token = parseSchemeToken(c.req.header("Authorization"), "Bearer");
    if (!token) {
      throw new OverlayError(401, "invalid_token", "Unauthorized");
    }
    const gen = Number.parseInt(c.req.param("generation"), 10);
    const digest = (c.req.param("digest") ?? "").trim();
    if (!Number.isFinite(gen) || gen <= 0 || !digest) {
      throw new OverlayError(400, "invalid_request", "Bad Request");
    }
    const raw = await withPgClient(c.env, (client) => getPolicyArtifact(client, token, gen, digest));
    const etag = `"${digest}"`;
    c.header("Cache-Control", "private, no-store");
    c.header("ETag", etag);
    if (etagMatches(c.req.header("If-None-Match"), etag)) {
      return c.body(null, 304);
    }
    return c.body(raw, 200, { "Content-Type": POLICY_MEDIA_TYPE });
  });

  app.post("/api/overlay/v1/join-tokens/exchange", async (c) => {
    const body = await c.req.json<ExchangeRequest>().catch(() => {
      throw new OverlayError(400, "invalid_request", "Bad Request");
    });
    const signingCtx = await requireSigningContext(c.env);
    const opts = serviceOptionsFromEnv(c.env);
    const resp = await withPgClient(c.env, (client) =>
      exchangeJoinToken(client, signingCtx, opts, body),
    );
    c.header("Cache-Control", "no-store");
    return c.json(resp, 200);
  });

  app.get("/api/overlay/v1/signing-keys", async (c) => {
    await authenticateAgentServerUser(c, agentDeps);
    const signingCtx = await requireSigningContext(c.env);
    const payload = JSON.stringify({ keys: buildSigningKeysList(signingCtx) });
    const etag = await computeETag(payload);
    c.header("Cache-Control", "private, max-age=300");
    c.header("Vary", "Authorization");
    c.header("ETag", etag);
    if (etagMatches(c.req.header("If-None-Match"), etag)) {
      return c.body(null, 304);
    }
    return c.body(payload, 200, { "Content-Type": "application/json" });
  });

  app.get("/api/overlay/v1/gateways", async (c) => {
    const userId = await authenticateAgentServerUser(c, agentDeps);
    const gateways = await agentDeps.withClient!(c.env, (client) => listUserGateways(client as never, userId));
    c.header("Cache-Control", "no-store");
    return c.json({ gateways }, 200);
  });

  app.get("/api/agent-server/v1/status", (c) => handleGetAgentStatus(c, agentDeps));
  app.get("/api/agent-server/v1/users", (c) => handleListAgentUsers(c, agentDeps));
  app.get("/api/agent-server/v1/users/events", (c) => handleUsersEventsSSEFallback(c));
  app.get("/api/agent-server/v1/nodes", (c) => handleListAgentNodes(c, agentDeps));
  app.get("/api/agent-server/v1/subscription", (c) => handleGetSubscription(c, agentDeps));
  app.get("/api/agent/nodes", (c) => handleListAgentNodes(c, agentDeps));
  app.get("/api/auth/sync/subscription", (c) => handleGetSubscription(c, agentDeps));
  app.get("/api/auth/sync/subscription/:format", (c) => handleGetSubscription(c, agentDeps));
  app.get("/api/auth/sync/config", (c) => handleSyncConfig(c, agentDeps));

  return app;
}

const app = createApp();
export default app;
