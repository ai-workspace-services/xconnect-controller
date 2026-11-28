import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  type EdgeCacheStore,
  type PgQueryExecutor,
} from "../src/agent_server.ts";
import { encodeBase64Url, importEd25519PrivateKey, importEd25519PublicKey } from "../src/crypto.ts";
import { createApp } from "../src/index.ts";
import type { WorkerEnv } from "../src/types.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const goldenPath = resolve(__dirname, "../../../contracts/xconnect-overlay-v1/golden-vectors.json");
const golden = JSON.parse(readFileSync(goldenPath, "utf8")) as {
  key_id: string;
  seed_base64: string;
  public_key_base64: string;
};

interface MockDBState {
  users: Record<string, unknown>[];
  agents: Record<string, unknown>[];
  healthSnapshots: Record<string, unknown>[];
  billingProfiles: Record<string, unknown>[];
  quotaStates: Record<string, unknown>[];
  blacklist: Record<string, unknown>[];
  teams: Record<string, unknown>[];
  memberships: Record<string, unknown>[];
  enrollments: Record<string, unknown>[];
  queries: string[];
}

function createMockPg(state: MockDBState): PgQueryExecutor {
  return {
    async query<T = Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
      state.queries.push(sql);
      if (/^\s*(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)/i.test(sql)) {
        throw new Error(`read-only worker attempted write SQL: ${sql}`);
      }
      if (sql.includes("FROM users")) {
        if (sql.includes("WHERE uuid::text = $1")) {
          const id = String(params[0] ?? "");
          return { rows: state.users.filter((u) => u.id === id) as T[] };
        }
        return { rows: state.users as T[] };
      }
      if (sql.includes("FROM agents")) {
        return { rows: state.agents as T[] };
      }
      if (sql.includes("FROM node_health_snapshots")) {
        return { rows: state.healthSnapshots as T[] };
      }
      if (sql.includes("FROM account_billing_profiles")) {
        return { rows: state.billingProfiles as T[] };
      }
      if (sql.includes("FROM account_quota_states")) {
        if (sql.includes("suspend_state = 'suspended'")) {
          return {
            rows: state.quotaStates.filter(
              (q) => q.suspend_state === "suspended" || q.proxy_access_state === "paused",
            ) as T[],
          };
        }
        return { rows: state.quotaStates as T[] };
      }
      if (sql.includes("FROM email_blacklist")) {
        return { rows: state.blacklist as T[] };
      }
      if (sql.includes("FROM network_teams")) {
        return { rows: state.teams as T[] };
      }
      if (sql.includes("FROM network_team_members")) {
        return { rows: state.memberships as T[] };
      }
      if (sql.includes("FROM team_agent_enrollments")) {
        return { rows: state.enrollments as T[] };
      }
      return { rows: [] };
    },
  };
}

class MemoryEdgeCache implements EdgeCacheStore {
  private readonly store = new Map<string, Response>();
  public hits = 0;
  public puts = 0;

  async match(request: Request | string): Promise<Response | undefined> {
    const key = typeof request === "string" ? request : request.url;
    const hit = this.store.get(key);
    if (!hit) return undefined;
    this.hits++;
    return hit.clone();
  }

  async put(request: Request | string, response: Response): Promise<void> {
    const key = typeof request === "string" ? request : request.url;
    this.puts++;
    this.store.set(key, response.clone());
  }
}

async function makeEdDSAUserJWT(userId: string, email: string, roles: string[]): Promise<{
  token: string;
  staticKeys: Map<string, CryptoKey>;
}> {
  const imported = await importEd25519PrivateKey(golden.seed_base64);
  const pubKey = await importEd25519PublicKey(golden.public_key_base64);
  const encodeJSON = (v: unknown) => encodeBase64Url(new TextEncoder().encode(JSON.stringify(v)));
  const nowSec = Math.floor(Date.now() / 1000);
  const input = `${encodeJSON({ alg: "EdDSA", typ: "JWT", kid: golden.key_id })}.${encodeJSON({
    user_id: userId,
    email,
    roles,
    exp: nowSec + 3600,
  })}`;
  const sig = await crypto.subtle.sign("Ed25519", imported.signingKey, new TextEncoder().encode(input));
  return {
    token: `${input}.${encodeBase64Url(new Uint8Array(sig))}`,
    staticKeys: new Map([[golden.key_id, pubKey]]),
  };
}

test("Worker Form B: /api/agent-server/v1/users/events returns 501 with X-XConnect-Fallback: origin-go", async () => {
  const app = createApp();
  const env = { HYPERDRIVE: { connectionString: "" } } as unknown as WorkerEnv;
  const resp = await app.request("/api/agent-server/v1/users/events", {}, env);
  assert.equal(resp.status, 501);
  assert.equal(resp.headers.get("X-XConnect-Fallback"), "origin-go");
  const body = (await resp.json()) as { error: string; fallback: string; message: string };
  assert.equal(body.error, "sse_requires_origin_go");
  assert.equal(body.fallback, "origin-go");
  assert.ok(body.message.length > 0);
});

test("Worker Form B: status, users, nodes, and subscription use Cache API, ETag/304, JWKS, and read-only Hyperdrive PG", async () => {
  const now = new Date("2026-11-27T08:00:00Z");
  const state: MockDBState = {
    users: [
      {
        id: "u-pro-1",
        name: "alice",
        email: "alice@example.test",
        role: "user",
        groups: ["segment:quota:plus-20gb"],
        email_verified: true,
        email_verified_at: now.toISOString(),
        active: true,
        proxy_uuid: "a55a9f3a-5d63-4b99-9c3a-9dfeb6d57da2",
        created_at: now.toISOString(),
        updated_at: now.toISOString(),
      },
      {
        id: "u-free-1",
        name: "freeuser",
        email: "free@example.test",
        role: "user",
        groups: ["segment:quota:free-3gb"],
        email_verified: true,
        active: true,
        proxy_uuid: "bbbbbbbb-5d63-4b99-9c3a-9dfeb6d57da2",
        created_at: now.toISOString(),
        updated_at: now.toISOString(),
      },
      {
        id: "u-root",
        name: "root",
        email: "root@example.test",
        role: "root",
        groups: [],
        email_verified: true,
        active: true,
        proxy_uuid: "cccccccc-5d63-4b99-9c3a-9dfeb6d57da2",
        created_at: now.toISOString(),
        updated_at: now.toISOString(),
      },
    ],
    agents: [
      {
        id: "jp-xconnect-01.svc.plus",
        name: "JP-Free",
        groups: ["resource:free"],
        healthy: true,
        last_heartbeat: now.toISOString(),
        clients_count: 2,
        sync_revision: "rev-1",
        updated_at: now.toISOString(),
      },
    ],
    healthSnapshots: [
      {
        node_id: "jp-xconnect-01.svc.plus",
        region: "jp",
        line_code: "cn2",
        pricing_group: "free",
        stats_enabled: true,
        xray_revision: "v1",
        healthy: true,
        sampled_at: now.toISOString(),
      },
      {
        node_id: "jp-xconnect-02.svc.plus",
        region: "jp",
        line_code: "ec2",
        pricing_group: "pro",
        stats_enabled: true,
        xray_revision: "v2",
        healthy: true,
        sampled_at: now.toISOString(),
      },
    ],
    billingProfiles: [{ account_uuid: "u-pro-1", package_name: "pro", included_quota_bytes: 0, high_speed_quota_bytes: 0 }],
    quotaStates: [],
    blacklist: [],
    teams: [],
    memberships: [],
    enrollments: [],
    queries: [],
  };

  const cache = new MemoryEdgeCache();
  const { token: userJWT, staticKeys } = await makeEdDSAUserJWT("u-pro-1", "alice@example.test", ["user"]);
  const { token: rootJWT } = await makeEdDSAUserJWT("u-root", "root@example.test", ["root"]);
  const mockPg = createMockPg(state);

  const app = createApp({
    withClient: async (_env, fn) => fn(mockPg as never),
    cacheStore: cache,
    staticEd25519Keys: staticKeys,
    now: () => now,
  });

  const env = {
    HYPERDRIVE: { connectionString: "postgres://mock" },
    INTERNAL_SERVICE_TOKEN: "internal-edge-secret",
    XCONNECT_AGENT_CREDENTIALS_JSON: JSON.stringify([
      { id: "jp-xconnect-01.svc.plus", name: "JP Free", token: "agent-free-tok", groups: ["resource:free"] },
      { id: "jp-xconnect-02.svc.plus", name: "JP Pro", token: "agent-pro-tok", groups: ["resource:pro"] },
    ]),
    XCONNECT_AGENT_USERS_CACHE_TTL: "15s",
  } as unknown as WorkerEnv;

  // 1. GET /api/agent-server/v1/users: unauth -> 401, auth -> 200 + Cache API MISS -> HIT -> ETag 304
  const unauthUsers = await app.request("/api/agent-server/v1/users", {}, env);
  assert.equal(unauthUsers.status, 401);

  const usersResp1 = await app.request(
    "/api/agent-server/v1/users",
    { headers: { Authorization: "Bearer agent-free-tok" } },
    env,
  );
  assert.equal(usersResp1.status, 200);
  assert.equal(usersResp1.headers.get("X-Cache"), "MISS");
  const etagUsers = usersResp1.headers.get("ETag");
  assert.ok(etagUsers);
  const usersJson = (await usersResp1.json()) as { total: number; routingPolicy: { pool: string } };
  assert.equal(usersJson.total, 3);
  assert.equal(usersJson.routingPolicy.pool, "Media-Pool");

  const queriesAfterMiss = state.queries.length;
  const usersResp2 = await app.request(
    "/api/agent-server/v1/users",
    { headers: { Authorization: "Bearer agent-free-tok" } },
    env,
  );
  assert.equal(usersResp2.status, 200);
  assert.equal(usersResp2.headers.get("X-Cache"), "HIT");
  assert.equal(state.queries.length, queriesAfterMiss, "Cache HIT must not hit Hyperdrive PG");

  const users304 = await app.request(
    "/api/agent-server/v1/users",
    { headers: { Authorization: "Bearer agent-free-tok", "If-None-Match": etagUsers! } },
    env,
  );
  assert.equal(users304.status, 304);

  // 2. GET /api/agent-server/v1/status: non-admin user -> 403, root JWT -> 200, internal token -> 200 + 304
  const statusUser = await app.request(
    "/api/agent-server/v1/status",
    { headers: { Authorization: `Bearer ${userJWT}` } },
    env,
  );
  assert.equal(statusUser.status, 403);

  const statusRoot = await app.request(
    "/api/agent-server/v1/status",
    { headers: { Authorization: `Bearer ${rootJWT}` } },
    env,
  );
  assert.equal(statusRoot.status, 200);
  const statusETag = statusRoot.headers.get("ETag");
  assert.ok(statusETag);
  const statusBody = (await statusRoot.json()) as { agents: { id: string }[] };
  assert.equal(statusBody.agents.length, 2);

  const statusInternal304 = await app.request(
    "/api/agent-server/v1/status",
    { headers: { "X-Internal-Service-Token": "internal-edge-secret", "If-None-Match": statusETag! } },
    env,
  );
  assert.equal(statusInternal304.status, 304);

  // 3. GET /api/agent-server/v1/nodes & GET /api/agent/nodes + ETag 304
  for (const path of ["/api/agent-server/v1/nodes", "/api/agent/nodes"]) {
    const resp = await app.request(path, { headers: { Authorization: `Bearer ${userJWT}` } }, env);
    assert.equal(resp.status, 200);
    const etag = resp.headers.get("ETag");
    assert.ok(etag);
    const nodes = (await resp.json()) as { address: string }[];
    assert.equal(nodes.length, 2);

    const resp304 = await app.request(
      path,
      { headers: { Authorization: `Bearer ${userJWT}`, "If-None-Match": etag! } },
      env,
    );
    assert.equal(resp304.status, 304);
  }

  // 4. GET /api/auth/sync/subscription & /api/auth/sync/subscription/:format & /api/auth/sync/config
  const clashResp = await app.request(
    `/api/auth/sync/subscription?token=${encodeURIComponent(userJWT)}`,
    {},
    env,
  );
  assert.equal(clashResp.status, 200);
  assert.ok((clashResp.headers.get("Content-Type") ?? "").includes("text/yaml"));
  const clashBody = await clashResp.text();
  assert.ok(clashBody.includes("proxies:"));
  assert.ok(clashBody.includes("Pro-EC2-Pool"));

  const singboxResp = await app.request(
    "/api/auth/sync/subscription/singbox",
    { headers: { Authorization: `Bearer ${userJWT}` } },
    env,
  );
  assert.equal(singboxResp.status, 200);
  const sbJson = (await singboxResp.json()) as { outbounds: unknown[] };
  assert.ok(sbJson.outbounds.length >= 4);

  const syncResp = await app.request(
    "/api/auth/sync/config?since_version=0",
    { headers: { Authorization: `Bearer ${userJWT}` } },
    env,
  );
  assert.equal(syncResp.status, 200);
  const syncJson = (await syncResp.json()) as { changed: boolean; routes: unknown[]; nodes: unknown[] };
  assert.equal(syncJson.changed, true);
  assert.equal(syncJson.routes.length, 4);
  assert.equal(syncJson.nodes.length, 2);
});

test("Worker Form B: whitelist-free user accesses Media-Pool resource:plus nodes and stays excluded from Pro/Custom", async () => {
  const now = new Date("2026-11-28T01:00:00Z");
  const wlUserId = "edfd5179-f9e7-40ba-89d0-d8a957b6cd7a";
  const state: MockDBState = {
    users: [
      {
        id: wlUserId,
        name: "Nora",
        email: "624220860@qq.com",
        role: "user",
        groups: ["segment:whitelist:free", "User"],
        email_verified: true,
        active: true,
        proxy_uuid: "aaaaaaaa-5d63-4b99-9c3a-9dfeb6d57da2",
        created_at: now.toISOString(),
        updated_at: now.toISOString(),
      },
      {
        id: "u-free-regular",
        name: "regular-free",
        email: "free@example.test",
        role: "user",
        groups: ["segment:quota:free-3gb", "User"],
        email_verified: true,
        active: true,
        proxy_uuid: "bbbbbbbb-5d63-4b99-9c3a-9dfeb6d57da2",
        created_at: now.toISOString(),
        updated_at: now.toISOString(),
      },
    ],
    agents: [
      {
        id: "jp-xconnect-01.svc.plus",
        name: "jp-xconnect-01.svc.plus",
        groups: ["internal", "resource:plus"],
        healthy: true,
        last_heartbeat: now.toISOString(),
        clients_count: 16,
        sync_revision: "rev-plus",
        updated_at: now.toISOString(),
      },
      {
        id: "us-xconnect.svc.plus",
        name: "us-xconnect.svc.plus",
        groups: ["internal", "resource:custom", "custom:allow-free"],
        healthy: true,
        last_heartbeat: now.toISOString(),
        clients_count: 2,
        sync_revision: "rev-custom",
        updated_at: now.toISOString(),
      },
      {
        id: "jp-xconnect-pro-01.svc.plus",
        name: "jp-xconnect-pro-01.svc.plus",
        groups: ["internal", "resource:pro"],
        healthy: true,
        last_heartbeat: now.toISOString(),
        clients_count: 5,
        sync_revision: "rev-pro",
        updated_at: now.toISOString(),
      },
    ],
    healthSnapshots: [
      { node_id: "jp-xconnect-01.svc.plus", region: "jp", pricing_group: "plus", healthy: true, sampled_at: now.toISOString() },
      { node_id: "us-xconnect.svc.plus", region: "us", pricing_group: "custom", healthy: true, sampled_at: now.toISOString() },
      { node_id: "jp-xconnect-pro-01.svc.plus", region: "jp", pricing_group: "pro", healthy: true, sampled_at: now.toISOString() },
    ],
    billingProfiles: [
      {
        account_uuid: wlUserId,
        package_name: "whitelist",
        included_quota_bytes: 5 * 1024 ** 3,
        high_speed_quota_bytes: 0,
      },
    ],
    quotaStates: [
      {
        account_uuid: wlUserId,
        remaining_included_quota: 5 * 1024 ** 3,
        remaining_high_speed_quota: 0,
        arrears: false,
        throttle_state: "normal",
        suspend_state: "active",
        proxy_access_state: "active",
      },
    ],
    blacklist: [],
    teams: [],
    memberships: [],
    enrollments: [],
    queries: [],
  };

  const { token: wlJWT, staticKeys } = await makeEdDSAUserJWT(wlUserId, "624220860@qq.com", ["user"]);
  const { token: freeJWT } = await makeEdDSAUserJWT("u-free-regular", "free@example.test", ["user"]);
  const mockPg = createMockPg(state);

  const app = createApp({
    withClient: async (_env, fn) => fn(mockPg as never),
    staticEd25519Keys: staticKeys,
    now: () => now,
  });

  const env = {
    HYPERDRIVE: { connectionString: "postgres://mock" },
    XCONNECT_AGENT_CREDENTIALS_JSON: JSON.stringify([
      { id: "jp-xconnect-01.svc.plus", name: "JP Plus", token: "agent-plus-tok", groups: ["resource:plus"] },
      { id: "us-xconnect.svc.plus", name: "US Custom", token: "agent-custom-tok", nodeId: "us-custom-01", groups: ["resource:custom", "custom:allow-free"], allowedEmails: ["vip@example.test"] },
    ]),
  } as unknown as WorkerEnv;

  const wlNodesResp = await app.request("/api/agent-server/v1/nodes", { headers: { Authorization: `Bearer ${wlJWT}` } }, env);
  assert.equal(wlNodesResp.status, 200);
  const wlNodes = (await wlNodesResp.json()) as { address: string; open_to_users: boolean; routing_pool: string }[];
  assert.equal(wlNodes.length, 1);
  assert.equal(wlNodes[0].address, "jp-xconnect-01.svc.plus");
  assert.equal(wlNodes[0].open_to_users, true);
  assert.equal(wlNodes[0].routing_pool, "Media-Pool");

  const freeNodesResp = await app.request("/api/agent-server/v1/nodes", { headers: { Authorization: `Bearer ${freeJWT}` } }, env);
  assert.equal(freeNodesResp.status, 200);
  const freeNodes = (await freeNodesResp.json()) as unknown[];
  assert.equal(freeNodes.length, 0);

  const plusUsersResp = await app.request(
    "/api/agent-server/v1/users",
    { headers: { Authorization: "Bearer agent-plus-tok" } },
    env,
  );
  assert.equal(plusUsersResp.status, 200);
  const plusUsers = (await plusUsersResp.json()) as { clients: { Email: string }[] };
  assert.deepEqual(
    plusUsers.clients.map((c) => c.Email),
    ["624220860@qq.com"],
  );
});
