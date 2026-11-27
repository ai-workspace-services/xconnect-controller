import type { Context } from "hono";
import { computeETag, decodeBase64Flexible, etagMatches, sha256Hex } from "./crypto.ts";
import { OverlayError } from "./db.ts";
import { extractUserId, verifyJWT } from "./jwks.ts";
import type {
  AgentClient,
  AgentCredential,
  AgentIdentity,
  AgentStatusEntry,
  ClientListResponse,
  RouteRule,
  RoutingPolicy,
  UserScope,
  VlessNode,
  WorkerEnv,
} from "./types.ts";

export interface PgQueryExecutor {
  query<T = Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: T[] }>;
}

export interface EdgeCacheStore {
  match(request: Request | string): Promise<Response | undefined>;
  put(request: Request | string, response: Response): Promise<void>;
}

export interface AgentServerDeps {
  withClient?: <T>(env: WorkerEnv, fn: (client: PgQueryExecutor) => Promise<T>) => Promise<T>;
  cacheStore?: EdgeCacheStore;
  staticEd25519Keys?: Map<string, CryptoKey>;
  now?: () => Date;
}

const DEFAULT_AGENT_USERS_TTL_SEC = 15;
const DEFAULT_STATUS_TTL_SEC = 5;
const DEFAULT_NODES_TTL_SEC = 5;
const REGIONAL_HEARTBEAT_TTL_MS = 5 * 60_000;

const ROUTING_POOL_MEDIA = "Media-Pool";
const ROUTING_POOL_PRO = "Pro-EC2-Pool";
const ROUTING_POOL_CUSTOM = "Custom-Dedicated";
const TIER_DIRECT = "DIRECT";
const POLICY_VERSION = 1;
const POLICY_REVISION = "2026-11-19.1";

const DEFAULT_FLOW = "xtls-rprx-vision";
const PUBLIC_EMAIL_UNION_POLICY = "public-union-v1";
const UNION_EMAIL_PREFIX = "node-email-union:";
const MANAGED_TEAM_MARKER = "enrollment:team";
const AGENT_FREE_GRANT_PREFIX = "agent:free-grant:";
const EMAIL_OPTIONAL_REG_GROUP = "account:registration:email-optional";

const MONTHLY_FREE_GROUP = "segment:quota:free-3gb";
const MONTHLY_FREE_5GB_ALIAS = "segment:quota:free-5gb";
const MONTHLY_PLUS_GROUP = "segment:quota:plus-20gb";
const MONTHLY_UNLIMITED_GROUP = "segment:quota:unlimited-beta";
const WHITELIST_FREE_GROUP = "segment:whitelist:free";
const ONE_TIME_TRIAL_GROUP = "segment:trial:once-5gb";
const SUB_UNLIMITED_OVERRIDE = "segment:subscription:unlimited";
const SUB_LISTED_GROUP = "segment:subscription:listed";

const TEAM_ID_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const PUBLIC_CLASSES = new Set(["shared", "free", "plus", "pro"]);

const DIRECT_XRAY_DOMAINS = ["geosite:cn"];
const DIRECT_XRAY_IPS = ["geoip:cn"];
const DIRECT_CLASH_RULES = [
  "GEOIP,private,DIRECT,no-resolve",
  "GEOSITE,cn,DIRECT",
  "GEOIP,cn,DIRECT,no-resolve",
];

const MEDIA_XRAY_DOMAINS = [
  "geosite:youtube",
  "geosite:netflix",
  "geosite:disney",
  "geosite:tiktok",
  "geosite:twitch",
  "geosite:spotify",
  "geosite:bilibili",
  "domain:speedtest.net",
  "domain:fast.com",
  "domain:steamcontent.com",
  "domain:icloud-content.com",
  "domain:mega.nz",
];
const MEDIA_CLASH_RULES = [
  "GEOSITE,youtube,Media-Pool",
  "GEOSITE,netflix,Media-Pool",
  "GEOSITE,disney,Media-Pool",
  "GEOSITE,tiktok,Media-Pool",
  "GEOSITE,twitch,Media-Pool",
  "GEOSITE,spotify,Media-Pool",
  "GEOSITE,bilibili,Media-Pool",
  "DOMAIN-SUFFIX,speedtest.net,Media-Pool",
  "DOMAIN-SUFFIX,fast.com,Media-Pool",
  "DOMAIN-SUFFIX,steamcontent.com,Media-Pool",
  "DOMAIN-SUFFIX,icloud-content.com,Media-Pool",
  "DOMAIN-SUFFIX,mega.nz,Media-Pool",
];

const PRO_XRAY_DOMAINS = [
  "geosite:openai",
  "geosite:anthropic",
  "domain:claude.ai",
  "domain:cursor.sh",
  "domain:cursor.com",
  "geosite:github",
  "geosite:google",
  "geosite:cloudflare",
];
const PRO_CLASH_RULES = [
  "GEOSITE,openai,Pro-EC2-Pool",
  "GEOSITE,anthropic,Pro-EC2-Pool",
  "DOMAIN-SUFFIX,claude.ai,Pro-EC2-Pool",
  "DOMAIN-SUFFIX,cursor.sh,Pro-EC2-Pool",
  "DOMAIN-SUFFIX,cursor.com,Pro-EC2-Pool",
  "GEOSITE,github,Pro-EC2-Pool",
  "GEOSITE,google,Pro-EC2-Pool",
  "GEOSITE,cloudflare,Pro-EC2-Pool",
];
const FALLBACK_CLASH_RULES = ["MATCH,Media-Pool"];

interface UserRow {
  id: string;
  name: string;
  email: string;
  role: string;
  groups: string[];
  emailVerified: boolean;
  active: boolean;
  proxyUuid: string;
  proxyUuidExpiresAt: Date | null;
  subscriptionValidFrom: Date | null;
  subscriptionValidUntil: Date | null;
  archivedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

interface NetworkTeamRow {
  id: string;
  name: string;
  member_limit: number;
  valid_from: Date | string;
  valid_until: Date | string;
  active: boolean;
}

interface NetworkMembership {
  userId: string;
  teamId: string;
  dedicatedOnly: boolean;
  configured: boolean;
}

interface NetworkAccess {
  accountId: string;
  configured: boolean;
  mode: "personal" | "dedicated";
  teamId?: string;
  team?: NetworkTeamRow;
  allowed: boolean;
}

interface BillingProfile {
  accountUuid: string;
  packageName: string;
  includedQuotaBytes: number;
  highSpeedQuotaBytes: number;
}

interface QuotaState {
  accountUuid: string;
  remainingIncludedQuota: number;
  remainingHighSpeedQuota: number;
  suspendState: string;
  proxyAccessState: string;
}

interface TeamAgentEnrollment {
  agentId: string;
  suggestedTeamId: string;
  assignedTeamId: string;
  status: string;
  updatedAt: Date;
}

interface NodeSnapshot {
  id: string;
  nodeId: string;
  name: string;
  groups: string[];
  allowedEmails?: string[];
  healthy: boolean;
  message: string;
  users: number;
  syncRevision: string;
  updatedAt: Date;
  running: boolean;
  clients: number;
  lastSync?: Date;
  region: string;
  entryPoint: string;
  openToUsers?: boolean;
  routingPool?: string;
  subPoolTags?: string[];
}

interface RegionalPool {
  private?: boolean;
  code: string;
  entry: string;
  displayName?: string;
  resourceClass?: string;
  teamId?: string;
  routingPool?: string;
  mediaOnProAction?: string;
  publicResource: boolean;
  subPoolTags?: string[];
  poolCount: number;
  openToUsers: boolean;
  closedReasons: string[];
}

interface SubscriptionNode {
  id: string;
  name: string;
  region?: string;
  address: string;
  port: number;
  uuid: string;
  flow?: string;
  transport?: string;
  path?: string;
  mode?: string;
  security?: string;
  serverName?: string;
  fingerprint?: string;
  alpn?: string[];
  resourceClass?: string;
  routingPool?: string;
  pricingGroup?: string;
  subPoolTags?: string[];
  vlessUri?: string;
}

function parseDurationSeconds(raw: string | undefined, fallbackSeconds: number): number {
  const val = (raw ?? "").trim().toLowerCase();
  if (!val) return fallbackSeconds;
  if (val === "0" || val === "0s") return 0;
  if (/^\d+$/.test(val)) return Number.parseInt(val, 10);
  const m = val.match(/^(\d+)(s|m|h)$/);
  if (!m) return fallbackSeconds;
  const n = Number.parseInt(m[1], 10);
  switch (m[2]) {
    case "s":
      return n;
    case "m":
      return n * 60;
    case "h":
      return n * 3600;
    default:
      return fallbackSeconds;
  }
}

function parseBoolEnv(raw: string | undefined): boolean {
  const val = (raw ?? "").trim().toLowerCase();
  return val === "1" || val === "true" || val === "yes" || val === "on";
}

function parseBearer(header: string | undefined): string | null {
  if (!header) return null;
  if (!header.startsWith("Bearer ")) return null;
  const token = header.slice(7).trim();
  return token || null;
}

function parseCookie(cookieHeader: string | undefined, name: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const k = part.slice(0, idx).trim();
    if (k === name) {
      const v = part.slice(idx + 1).trim();
      return v || null;
    }
  }
  return null;
}

function extractInternalToken(c: Context<{ Bindings: WorkerEnv }>): string | null {
  const h1 = (c.req.header("X-Internal-Service-Token") ?? "").trim();
  if (h1) return h1;
  const h2 = (c.req.header("X-Service-Token") ?? "").trim();
  if (h2) return h2;
  return parseBearer(c.req.header("Authorization"));
}

function constantTimeStringEqual(a: string, b: string): boolean {
  if (a.length !== b.length || a.length === 0) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function resolveCacheStore(deps: AgentServerDeps): EdgeCacheStore | undefined {
  if (deps.cacheStore) return deps.cacheStore;
  const g = globalThis as unknown as { caches?: { default?: EdgeCacheStore } };
  return g.caches?.default;
}

async function respondWithEdgeCache(
  c: Context<{ Bindings: WorkerEnv }>,
  opts: {
    cacheStore?: EdgeCacheStore;
    cacheKeyUrl: string;
    ttlSeconds: number;
    contentType: string;
    responseCacheControl: string;
    compute: () => Promise<{ body: string; etag?: string }>;
  },
): Promise<Response> {
  const cacheReq = new Request(opts.cacheKeyUrl, { method: "GET" });
  if (opts.cacheStore && opts.ttlSeconds > 0) {
    const hit = await opts.cacheStore.match(cacheReq);
    if (hit) {
      const etag = hit.headers.get("ETag") ?? (await computeETag(await hit.clone().text()));
      c.header("ETag", etag);
      c.header("Cache-Control", opts.responseCacheControl);
      c.header("X-Cache", "HIT");
      if (etagMatches(c.req.header("If-None-Match"), etag)) {
        return c.body(null, 304);
      }
      const body = await hit.text();
      return c.body(body, 200, { "Content-Type": opts.contentType });
    }
  }

  const computed = await opts.compute();
  const etag = computed.etag || (await computeETag(computed.body));

  if (opts.cacheStore && opts.ttlSeconds > 0) {
    const toStore = new Response(computed.body, {
      status: 200,
      headers: {
        "Content-Type": opts.contentType,
        "Cache-Control": `public, max-age=${opts.ttlSeconds}`,
        ETag: etag,
      },
    });
    const putPromise = opts.cacheStore.put(cacheReq, toStore);
    let waitUntil: ((p: Promise<unknown>) => void) | undefined;
    try {
      const execCtx = (c as unknown as { executionCtx?: { waitUntil?: (p: Promise<unknown>) => void } })
        .executionCtx;
      waitUntil = execCtx?.waitUntil?.bind(execCtx);
    } catch {
      waitUntil = undefined;
    }
    if (waitUntil) {
      waitUntil(putPromise);
    } else {
      await putPromise;
    }
  }

  c.header("ETag", etag);
  c.header("Cache-Control", opts.responseCacheControl);
  c.header("X-Cache", "MISS");
  if (etagMatches(c.req.header("If-None-Match"), etag)) {
    return c.body(null, 304);
  }
  return c.body(computed.body, 200, { "Content-Type": opts.contentType });
}

function loadAgentCredentials(env: WorkerEnv): AgentCredential[] {
  const raw = (env.XCONNECT_AGENT_CREDENTIALS_JSON ?? env.AGENT_CREDENTIALS_JSON ?? "").trim();
  const creds: AgentCredential[] = [];
  if (raw) {
    const parsed = JSON.parse(raw) as AgentCredential[] | { credentials?: AgentCredential[] };
    const list = Array.isArray(parsed) ? parsed : (parsed.credentials ?? []);
    for (const item of list) {
      if (item && item.id?.trim() && item.token?.trim()) {
        creds.push({
          id: item.id.trim(),
          nodeId: item.nodeId?.trim() || undefined,
          name: item.name?.trim() || undefined,
          token: item.token.trim(),
          groups: (item.groups ?? []).map((g) => g.trim()).filter(Boolean),
          allowedEmails: item.allowedEmails?.map((e) => e.trim()).filter(Boolean),
        });
      }
    }
  }
  const internalToken = (env.INTERNAL_SERVICE_TOKEN ?? "").trim();
  if (creds.length === 0 && internalToken) {
    creds.push({
      id: "*",
      name: "Internal Agents (Shared Token)",
      token: internalToken,
      groups: ["internal"],
    });
  }
  return creds;
}

async function authenticateAgentCredential(
  env: WorkerEnv,
  token: string,
): Promise<AgentIdentity | null> {
  const creds = loadAgentCredentials(env);
  if (creds.length === 0 || !token) return null;
  const presentedDigest = await sha256Hex(token.trim());
  for (const cred of creds) {
    const expectedDigest = await sha256Hex(cred.token.trim());
    if (constantTimeStringEqual(presentedDigest, expectedDigest)) {
      return {
        id: cred.id,
        nodeId: cred.nodeId,
        name: cred.name,
        groups: cred.groups ?? [],
        allowedEmails: cred.allowedEmails,
      };
    }
  }
  return null;
}

function isUndefinedTableError(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const code = (err as { code?: string }).code;
  const msg = (err as { message?: string }).message ?? "";
  return code === "42P01" || msg.includes("does not exist");
}

async function safeQuery<T = Record<string, unknown>>(
  client: PgQueryExecutor,
  sql: string,
  params: unknown[] = [],
): Promise<T[]> {
  try {
    const res = await client.query<T>(sql, params);
    return res.rows ?? [];
  } catch (err) {
    if (isUndefinedTableError(err)) {
      return [];
    }
    throw err;
  }
}

function parseJsonStringArray(raw: unknown): string[] {
  if (Array.isArray(raw)) {
    return raw.map((v) => String(v));
  }
  if (typeof raw === "string" && raw.trim()) {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.map((v) => String(v)) : [];
    } catch {
      return [];
    }
  }
  return [];
}

function parseDateOrNull(raw: unknown): Date | null {
  if (!raw) return null;
  if (raw instanceof Date) return Number.isNaN(raw.getTime()) ? null : raw;
  const d = new Date(String(raw));
  return Number.isNaN(d.getTime()) ? null : d;
}

function mapUserRow(r: Record<string, unknown>): UserRow {
  const emailVerifiedAt = parseDateOrNull(r.email_verified_at);
  const emailVerified = Boolean(r.email_verified) || emailVerifiedAt !== null;
  return {
    id: String(r.id ?? "").trim(),
    name: String(r.name ?? "").trim(),
    email: String(r.email ?? "").trim(),
    role: String(r.role ?? "user").trim(),
    groups: parseJsonStringArray(r.groups),
    emailVerified,
    active: r.active === undefined ? true : Boolean(r.active),
    proxyUuid: String(r.proxy_uuid ?? "").trim(),
    proxyUuidExpiresAt: parseDateOrNull(r.proxy_uuid_expires_at),
    subscriptionValidFrom: parseDateOrNull(r.subscription_valid_from),
    subscriptionValidUntil: parseDateOrNull(r.subscription_valid_until),
    archivedAt: parseDateOrNull(r.archived_at),
    createdAt: parseDateOrNull(r.created_at) ?? new Date(0),
    updatedAt: parseDateOrNull(r.updated_at) ?? new Date(0),
  };
}

async function listUsers(client: PgQueryExecutor): Promise<UserRow[]> {
  const rows = await safeQuery<Record<string, unknown>>(
    client,
    `SELECT uuid::text AS id,
            COALESCE(username, '') AS name,
            COALESCE(email, '') AS email,
            COALESCE(role, 'user') AS role,
            COALESCE(groups, '[]'::jsonb) AS groups,
            email_verified,
            email_verified_at,
            active,
            COALESCE(proxy_uuid::text, '') AS proxy_uuid,
            proxy_uuid_expires_at,
            subscription_valid_from,
            subscription_valid_until,
            archived_at,
            created_at,
            updated_at
     FROM users
     ORDER BY created_at ASC`,
  );
  return rows.map(mapUserRow);
}

async function getUserById(client: PgQueryExecutor, userId: string): Promise<UserRow | null> {
  const rows = await safeQuery<Record<string, unknown>>(
    client,
    `SELECT uuid::text AS id,
            COALESCE(username, '') AS name,
            COALESCE(email, '') AS email,
            COALESCE(role, 'user') AS role,
            COALESCE(groups, '[]'::jsonb) AS groups,
            email_verified,
            email_verified_at,
            active,
            COALESCE(proxy_uuid::text, '') AS proxy_uuid,
            proxy_uuid_expires_at,
            subscription_valid_from,
            subscription_valid_until,
            archived_at,
            created_at,
            updated_at
     FROM users
     WHERE uuid::text = $1
     LIMIT 1`,
    [userId.trim()],
  );
  return rows[0] ? mapUserRow(rows[0]) : null;
}

async function listBlockedUserIds(client: PgQueryExecutor): Promise<Set<string>> {
  const rows = await safeQuery<{ account_uuid: string }>(
    client,
    `SELECT account_uuid::text AS account_uuid
     FROM account_quota_states
     WHERE suspend_state = 'suspended' OR proxy_access_state = 'paused'`,
  );
  return new Set(rows.map((r) => String(r.account_uuid).trim()).filter(Boolean));
}

async function listBlacklistedEmails(client: PgQueryExecutor): Promise<Set<string>> {
  const rows = await safeQuery<{ email: string }>(client, `SELECT email FROM email_blacklist`);
  return new Set(rows.map((r) => String(r.email ?? "").trim().toLowerCase()).filter(Boolean));
}

async function listNetworkTeams(client: PgQueryExecutor): Promise<NetworkTeamRow[]> {
  return safeQuery<NetworkTeamRow>(
    client,
    `SELECT id, name, member_limit, valid_from, valid_until, active FROM network_teams ORDER BY id`,
  );
}

async function listNetworkMemberships(client: PgQueryExecutor): Promise<Map<string, NetworkMembership>> {
  const rows = await safeQuery<{ user_id: string; team_id: string; dedicated_only: boolean }>(
    client,
    `SELECT user_uuid::text AS user_id, COALESCE(team_id, '') AS team_id, dedicated_only FROM network_team_members`,
  );
  const map = new Map<string, NetworkMembership>();
  for (const r of rows) {
    map.set(String(r.user_id).trim(), {
      userId: String(r.user_id).trim(),
      teamId: String(r.team_id ?? "").trim(),
      dedicatedOnly: Boolean(r.dedicated_only),
      configured: true,
    });
  }
  return map;
}

async function listBillingProfiles(client: PgQueryExecutor): Promise<Map<string, BillingProfile>> {
  const rows = await safeQuery<Record<string, unknown>>(
    client,
    `SELECT account_uuid::text AS account_uuid, package_name, included_quota_bytes, high_speed_quota_bytes
     FROM account_billing_profiles`,
  );
  const map = new Map<string, BillingProfile>();
  for (const r of rows) {
    const id = String(r.account_uuid ?? "").trim();
    map.set(id, {
      accountUuid: id,
      packageName: String(r.package_name ?? "").trim().toLowerCase(),
      includedQuotaBytes: Number(r.included_quota_bytes ?? 0),
      highSpeedQuotaBytes: Number(r.high_speed_quota_bytes ?? 0),
    });
  }
  return map;
}

async function listQuotaStates(client: PgQueryExecutor): Promise<Map<string, QuotaState>> {
  const rows = await safeQuery<Record<string, unknown>>(
    client,
    `SELECT account_uuid::text AS account_uuid,
            remaining_included_quota,
            remaining_high_speed_quota,
            suspend_state,
            proxy_access_state
     FROM account_quota_states`,
  );
  const map = new Map<string, QuotaState>();
  for (const r of rows) {
    const id = String(r.account_uuid ?? "").trim();
    map.set(id, {
      accountUuid: id,
      remainingIncludedQuota: Number(r.remaining_included_quota ?? 0),
      remainingHighSpeedQuota: Number(r.remaining_high_speed_quota ?? 0),
      suspendState: String(r.suspend_state ?? "").trim(),
      proxyAccessState: String(r.proxy_access_state ?? "").trim(),
    });
  }
  return map;
}

async function listTeamAgentEnrollments(client: PgQueryExecutor): Promise<Map<string, TeamAgentEnrollment>> {
  const rows = await safeQuery<Record<string, unknown>>(
    client,
    `SELECT agent_id, suggested_team_id, assigned_team_id, status, updated_at
     FROM team_agent_enrollments
     ORDER BY agent_id`,
  );
  const map = new Map<string, TeamAgentEnrollment>();
  for (const r of rows) {
    const id = String(r.agent_id ?? "").trim();
    map.set(id, {
      agentId: id,
      suggestedTeamId: String(r.suggested_team_id ?? "").trim(),
      assignedTeamId: String(r.assigned_team_id ?? "").trim(),
      status: String(r.status ?? "").trim(),
      updatedAt: parseDateOrNull(r.updated_at) ?? new Date(0),
    });
  }
  return map;
}

async function loadNodeSnapshotsFromDB(
  client: PgQueryExecutor,
  env: WorkerEnv,
): Promise<NodeSnapshot[]> {
  const creds = loadAgentCredentials(env);
  const byId = new Map<string, NodeSnapshot>();

  for (const cred of creds) {
    if (cred.id !== "*") {
      byId.set(cred.id, {
        id: cred.id,
        nodeId: cred.nodeId ?? "",
        name: cred.name ?? cred.id,
        groups: cred.groups ?? [],
        allowedEmails: cred.allowedEmails,
        healthy: false,
        message: "",
        users: 0,
        syncRevision: "",
        updatedAt: new Date(0),
        running: false,
        clients: 0,
        region: "",
        entryPoint: regionalEntryHost(cred.id),
      });
    }
  }

  const agents = await safeQuery<Record<string, unknown>>(
    client,
    `SELECT id, name, groups, healthy, last_heartbeat, clients_count, sync_revision, updated_at
     FROM agents
     ORDER BY id ASC`,
  );
  for (const a of agents) {
    const id = String(a.id ?? "").trim();
    if (!id) continue;
    const hb = parseDateOrNull(a.last_heartbeat);
    const updated = hb ?? parseDateOrNull(a.updated_at) ?? new Date(0);
    const existing = byId.get(id);
    const groups = parseJsonStringArray(a.groups);
    byId.set(id, {
      id,
      nodeId: existing?.nodeId ?? "",
      name: String(a.name ?? existing?.name ?? id).trim(),
      groups: groups.length > 0 ? groups : (existing?.groups ?? []),
      allowedEmails: existing?.allowedEmails,
      healthy: Boolean(a.healthy),
      message: "",
      users: Number(a.clients_count ?? 0),
      syncRevision: String(a.sync_revision ?? "").trim(),
      updatedAt: updated,
      running: Boolean(a.healthy),
      clients: Number(a.clients_count ?? 0),
      lastSync: hb ?? undefined,
      region: existing?.region ?? "",
      entryPoint: existing?.entryPoint || regionalEntryHost(id),
    });
  }

  const snapshots = await safeQuery<Record<string, unknown>>(
    client,
    `SELECT node_id, region, line_code, pricing_group, stats_enabled, xray_revision, healthy, sampled_at
     FROM node_health_snapshots
     ORDER BY node_id ASC`,
  );
  for (const n of snapshots) {
    const nodeId = String(n.node_id ?? "").trim();
    if (!nodeId) continue;
    const sampledAt = parseDateOrNull(n.sampled_at) ?? new Date(0);
    const existing = byId.get(nodeId);
    const pg = String(n.pricing_group ?? "").trim().toLowerCase();
    const defaultGroups = PUBLIC_CLASSES.has(pg) ? [`resource:${pg}`] : [];
    if (!existing) {
      byId.set(nodeId, {
        id: nodeId,
        nodeId,
        name: nodeId,
        groups: defaultGroups,
        healthy: Boolean(n.healthy),
        message: "",
        users: 0,
        syncRevision: "",
        updatedAt: sampledAt,
        running: Boolean(n.healthy),
        clients: 0,
        lastSync: sampledAt,
        region: String(n.region ?? "").trim().toLowerCase(),
        entryPoint: regionalEntryHost(nodeId),
      });
    } else {
      if (!existing.region && n.region) {
        existing.region = String(n.region).trim().toLowerCase();
      }
      if (!existing.entryPoint) {
        existing.entryPoint = regionalEntryHost(existing.id);
      }
      if (sampledAt.getTime() > existing.updatedAt.getTime()) {
        existing.updatedAt = sampledAt;
        existing.healthy = Boolean(n.healthy);
        existing.running = Boolean(n.healthy);
      }
    }
  }

  const enrollments = await listTeamAgentEnrollments(client);
  const result: NodeSnapshot[] = [];
  for (const snap of byId.values()) {
    const enr = enrollments.get(snap.id);
    if (enr) {
      snap.groups = enrollmentGroups(enr);
    }
    if (enr || snap.groups.includes(MANAGED_TEAM_MARKER)) {
      const ready =
        Boolean(enr) &&
        enr!.status === "approved" &&
        snap.healthy &&
        snap.running &&
        snap.lastSync !== undefined &&
        snap.lastSync.getTime() > enr!.updatedAt.getTime() &&
        snap.syncRevision.startsWith(`${enrollmentRevision(enr!)}-`);
      if (!ready) {
        snap.openToUsers = false;
        snap.groups = [MANAGED_TEAM_MARKER, "access:dedicated-only"];
      }
    }
    result.push(snap);
  }
  result.sort((a, b) => a.id.localeCompare(b.id));
  return result;
}

function accountAccessVerified(user: UserRow): boolean {
  return user.emailVerified || user.groups.includes(EMAIL_OPTIONAL_REG_GROUP);
}

function normalizeMonthlyQuotaGroup(group: string): string {
  const t = group.trim();
  if (t === MONTHLY_FREE_GROUP || t === MONTHLY_FREE_5GB_ALIAS) return MONTHLY_FREE_GROUP;
  if (t === MONTHLY_PLUS_GROUP || t === MONTHLY_UNLIMITED_GROUP) return t;
  return "";
}

function monthlyQuotaGroup(user: UserRow): string {
  for (const known of [MONTHLY_UNLIMITED_GROUP, MONTHLY_PLUS_GROUP, MONTHLY_FREE_GROUP]) {
    if (user.groups.some((g) => normalizeMonthlyQuotaGroup(g) === known)) return known;
  }
  return "";
}

function isOneTimeTrialMember(user: UserRow): boolean {
  return user.groups.some((g) => g.trim() === ONE_TIME_TRIAL_GROUP);
}

function isWhitelistFreeMember(user: UserRow): boolean {
  return user.groups.some((g) => g.trim() === WHITELIST_FREE_GROUP);
}

function hasSubscriptionUnlimitedOverride(user: UserRow, now: Date): boolean {
  if (!user.active || user.archivedAt) return false;
  if (user.subscriptionValidFrom && now.getTime() < user.subscriptionValidFrom.getTime()) return false;
  if (user.subscriptionValidUntil) {
    const end = user.subscriptionValidUntil;
    const expiry = Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), end.getUTCDate() + 1);
    if (now.getTime() >= expiry) return false;
  }
  const hasOverride = user.groups.includes(SUB_UNLIMITED_OVERRIDE);
  const hasListed = user.groups.includes(SUB_LISTED_GROUP);
  const hasRecurring = user.groups.some((g) =>
    ["segment:monthly", "segment:yearly", "segment:subscription:monthly", "segment:subscription:yearly"].includes(g),
  );
  return hasListed && hasOverride && hasRecurring && monthlyQuotaGroup(user) === MONTHLY_PLUS_GROUP;
}

function isMonthlyQuotaLimitMember(user: UserRow, now: Date): boolean {
  if (hasSubscriptionUnlimitedOverride(user, now)) return false;
  if (isWhitelistFreeMember(user) || isOneTimeTrialMember(user)) return true;
  const g = monthlyQuotaGroup(user);
  return g === MONTHLY_FREE_GROUP || g === MONTHLY_PLUS_GROUP;
}

function isCustomDedicatedUser(user: UserRow, packageName: string): boolean {
  if (packageName.trim().toLowerCase() === "custom") return true;
  const markers = new Set([
    "resource:custom",
    "segment:custom",
    "access:custom",
    "access:custom-dedicated",
    "pool:custom-dedicated",
  ]);
  return user.groups.some((g) => markers.has(g.trim().toLowerCase()));
}

function hasMediaPassthroughEntitlement(user: UserRow, packageName: string): boolean {
  const pkg = packageName.trim().toLowerCase();
  if (pkg === "media-passthrough" || pkg === "unlimited" || pkg === "unlimited-beta") return true;
  const markers = new Set([
    "media:passthrough",
    "segment:media-passthrough",
    "pool:media-passthrough",
    "segment:quota:unlimited",
  ]);
  return user.groups.some((g) => markers.has(g.trim().toLowerCase()));
}

function effectiveAgentResourceClass(access: NetworkAccess, user: UserRow, packageName: string): string {
  if (access.mode === "dedicated") return "team";
  if (isCustomDedicatedUser(user, packageName)) return "custom";
  if (isOneTimeTrialMember(user) || packageName.trim().toLowerCase() === "trial") return "pro";
  const group = monthlyQuotaGroup(user);
  if (
    packageName.trim().toLowerCase() === "pro" &&
    (group === MONTHLY_PLUS_GROUP || group === MONTHLY_UNLIMITED_GROUP)
  ) {
    return "pro";
  }
  if (group === MONTHLY_PLUS_GROUP || group === MONTHLY_UNLIMITED_GROUP) return "plus";
  return "free";
}

function agentNetworkScope(groups: string[]): { team: string; valid: boolean } {
  let team = "";
  let dedicated = false;
  for (const raw of groups) {
    const g = raw.trim();
    const lower = g.toLowerCase();
    if (
      lower.startsWith("team-admin:") ||
      (lower.startsWith("team:") && !g.startsWith("team:")) ||
      (lower === "access:dedicated-only" && g !== lower)
    ) {
      return { team: "", valid: false };
    }
    if (g === "access:dedicated-only") dedicated = true;
    if (g.startsWith("team:")) {
      const id = g.slice(5);
      if (!TEAM_ID_RE.test(id) || (team && team !== id)) {
        return { team: "", valid: false };
      }
      team = id;
    }
  }
  return { team, valid: !dedicated || team !== "" };
}

function networkScopeAllows(access: NetworkAccess, groups: string[]): boolean {
  const { team, valid } = agentNetworkScope(groups);
  if (!valid || !access.allowed) return false;
  if (access.mode === "dedicated") {
    return Boolean(access.teamId) && team === access.teamId;
  }
  return team === "";
}

function publicUnionEmails(groups: string[]): string[] {
  const set = new Set<string>();
  for (const g of groups) {
    if (g.startsWith(UNION_EMAIL_PREFIX)) {
      const e = g.slice(UNION_EMAIL_PREFIX.length).trim().toLowerCase();
      if (e && e.includes("@") && !e.includes("*") && !e.includes("?")) {
        set.add(e);
      }
    }
  }
  return [...set].sort();
}

function hasPublicUnionPolicy(groups: string[]): boolean {
  return groups.includes(`node-email-policy:${PUBLIC_EMAIL_UNION_POLICY}`);
}

async function agentResourceScope(groups: string[]): Promise<{ scope: UserScope; valid: boolean }> {
  const scope: UserScope = { resourceClass: "shared" };
  if (hasPublicUnionPolicy(groups)) {
    const emails = publicUnionEmails(groups);
    scope.emailPolicy = PUBLIC_EMAIL_UNION_POLICY;
    scope.emailDigest = await sha256Hex(emails.join("\n"));
  }
  if (groups.includes("custom:allow-free")) {
    scope.customAllowFree = true;
  }
  const { team, valid } = agentNetworkScope(groups);
  if (!valid) return { scope: { resourceClass: "" }, valid: false };
  let seen = "";
  let hasConfigurePublic = false;
  if (team) {
    scope.resourceClass = "team";
    scope.teamId = team;
    seen = "team";
  }
  for (const raw of groups) {
    const g = raw.trim();
    if (g === "agent:configure-public") {
      hasConfigurePublic = true;
      continue;
    }
    if (!g.startsWith("resource:")) continue;
    const cls = g.slice("resource:".length);
    if (!["shared", "free", "plus", "pro", "custom"].includes(cls)) {
      return { scope: { resourceClass: "" }, valid: false };
    }
    if (seen && seen !== cls) {
      return { scope: { resourceClass: "" }, valid: false };
    }
    seen = cls;
    scope.resourceClass = cls;
  }
  if (hasConfigurePublic && scope.resourceClass === "custom") {
    return { scope: { resourceClass: "" }, valid: false };
  }
  if (scope.resourceClass === "team" && seen !== "team") {
    return { scope: { resourceClass: "" }, valid: false };
  }
  if (scope.resourceClass !== "team" && scope.teamId) {
    return { scope: { resourceClass: "" }, valid: false };
  }
  return { scope, valid: true };
}

function publicAgentResourceClassAllows(poolClass: string, userClass: string): boolean {
  if (poolClass === "shared" && userClass === "custom") return true;
  const rank: Record<string, number> = { free: 1, plus: 2, pro: 3 };
  const userRank = rank[userClass];
  if (!userRank) return false;
  if (poolClass === "shared") return true;
  const poolRank = rank[poolClass];
  return Boolean(poolRank) && userRank >= poolRank;
}

function agentResourceScopeAllowsUser(
  scope: UserScope,
  access: NetworkAccess,
  user: UserRow,
  packageName: string,
): boolean {
  if (scope.resourceClass === "team") {
    return access.mode === "dedicated" && access.teamId === scope.teamId;
  }
  if (access.mode === "dedicated") return false;
  const cls = effectiveAgentResourceClass(access, user, packageName);
  if (scope.resourceClass === "custom") {
    if (isOneTimeTrialMember(user) || packageName.trim().toLowerCase() === "trial") return false;
    return cls === "custom" || cls === "plus" || cls === "pro" || (Boolean(scope.customAllowFree) && cls === "free");
  }
  return publicAgentResourceClassAllows(scope.resourceClass, cls);
}

function accessFromMembership(
  member: NetworkMembership | undefined,
  teams: NetworkTeamRow[],
  now: Date,
): NetworkAccess {
  if (!member || (!member.dedicatedOnly && !member.teamId)) {
    return {
      accountId: member?.userId ?? "",
      configured: Boolean(member?.configured),
      mode: "personal",
      allowed: true,
    };
  }
  const team = teams.find((t) => t.id === member.teamId);
  let allowed = false;
  if (team) {
    const validFrom = new Date(team.valid_from).getTime();
    const validUntil = new Date(team.valid_until).getTime();
    allowed = Boolean(team.active) && now.getTime() >= validFrom && now.getTime() < validUntil;
  }
  return {
    accountId: member.userId,
    configured: Boolean(member.configured),
    mode: "dedicated",
    teamId: member.teamId || undefined,
    team,
    allowed,
  };
}

function enrollmentGroups(e: TeamAgentEnrollment): string[] {
  if (e.status === "approved") {
    return [MANAGED_TEAM_MARKER, `team:${e.assignedTeamId}`];
  }
  return [MANAGED_TEAM_MARKER, "access:dedicated-only"];
}

function formatRFC3339NanoUTC(d: Date): string {
  return d.toISOString();
}

function enrollmentRevision(e: TeamAgentEnrollment): string {
  // Deterministic enrollment revision prefix
  return `enrollment-${e.agentId}-${e.status}-${e.assignedTeamId}-${formatRFC3339NanoUTC(e.updatedAt)}`;
}

function poolForResourceClass(resourceClass: string): string {
  switch (resourceClass.trim().toLowerCase()) {
    case "pro":
      return ROUTING_POOL_PRO;
    case "custom":
    case "team":
      return ROUTING_POOL_CUSTOM;
    default:
      return ROUTING_POOL_MEDIA;
  }
}

function routingPolicyForScope(scope: UserScope): RoutingPolicy {
  const pool = poolForResourceClass(scope.resourceClass);
  const pricingGroups =
    pool === ROUTING_POOL_PRO
      ? ["pro"]
      : pool === ROUTING_POOL_CUSTOM
        ? ["custom", "team"]
        : ["free", "shared", "plus"];
  const subPoolTags =
    pool === ROUTING_POOL_MEDIA ? ["media:video", "media:shopping", "media:ai-app"] : undefined;
  return {
    version: POLICY_VERSION,
    revision: POLICY_REVISION,
    pool,
    publicResource: pool !== ROUTING_POOL_CUSTOM,
    mediaOnProAction: "allow",
    ...(pool === ROUTING_POOL_MEDIA ? { fallbackDefault: true } : {}),
    ...(pool !== ROUTING_POOL_PRO ? { unlimited: true } : {}),
    pricingGroups,
    ...(subPoolTags ? { subPoolTags } : {}),
    directDomains: [...DIRECT_XRAY_DOMAINS],
    directIps: [...DIRECT_XRAY_IPS],
    mediaDomains: [...MEDIA_XRAY_DOMAINS],
    proWhitelistDomains: [...PRO_XRAY_DOMAINS],
  };
}

function regionalEntryHost(raw: string): string {
  let value = raw.trim();
  if (!value) return "";
  if (!value.includes("://")) value = `https://${value}`;
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return "";
  }
  if (u.username || u.password || (u.protocol !== "http:" && u.protocol !== "https:")) {
    return "";
  }
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host === "*" || !host.includes(".") || /^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    return "";
  }
  for (const label of host.split(".")) {
    if (!label || label.startsWith("-") || label.endsWith("-") || !/^[a-z0-9-]+$/.test(label)) {
      return "";
    }
  }
  return host;
}

function inferRegionFromHost(host: string): string {
  let prefix = host.trim();
  const dotIdx = prefix.indexOf(".");
  if (dotIdx > 0) prefix = prefix.slice(0, dotIdx);
  const dashIdx = prefix.indexOf("-");
  if (dashIdx > 0) prefix = prefix.slice(0, dashIdx);
  prefix = prefix.toLowerCase().trim();
  return prefix.length === 2 ? prefix : "";
}

function activeFreeGrantExpiresAt(user: UserRow, nodeId: string, now: Date): Date | null {
  if (!nodeId || !user.active || user.archivedAt) return null;
  const prefix = `${AGENT_FREE_GRANT_PREFIX}${nodeId}:`;
  let matched: { status: string; expiresAt: Date } | null = null;
  for (const g of user.groups) {
    const trimmed = g.trim();
    if (!trimmed.startsWith(prefix)) continue;
    const encoded = trimmed.slice(prefix.length);
    if (!encoded) return null;
    try {
      const jsonStr = new TextDecoder().decode(decodeBase64Flexible(encoded));
      const obj = JSON.parse(jsonStr) as {
        nodeId?: string;
        accountId?: string;
        status?: string;
        expiresAt?: string;
      };
      if (obj.nodeId !== nodeId) return null;
      if (obj.accountId && obj.accountId !== user.id) return null;
      if (obj.status !== "active" && obj.status !== "revoked") return null;
      const exp = parseDateOrNull(obj.expiresAt);
      if (!exp) return null;
      matched = { status: obj.status, expiresAt: exp };
    } catch {
      return null;
    }
  }
  if (!matched || matched.status !== "active" || now.getTime() >= matched.expiresAt.getTime()) {
    return null;
  }
  return matched.expiresAt;
}

function isQuotaExhausted(
  user: UserRow,
  billing: BillingProfile | undefined,
  quota: QuotaState | undefined,
  access: NetworkAccess,
  highSpeed: boolean,
  now: Date,
): boolean {
  if (isCustomDedicatedUser(user, "") || hasMediaPassthroughEntitlement(user, "")) return false;
  if (access.mode === "dedicated" && access.allowed) return false;
  if (!isMonthlyQuotaLimitMember(user, now)) return false;
  if (!billing) return false;
  if (isCustomDedicatedUser(user, billing.packageName) || hasMediaPassthroughEntitlement(user, billing.packageName)) {
    return false;
  }
  const limit = highSpeed ? billing.highSpeedQuotaBytes : billing.includedQuotaBytes;
  if (limit <= 0) return false;
  const remaining = highSpeed
    ? (quota?.remainingHighSpeedQuota ?? 0)
    : (quota?.remainingIncludedQuota ?? 0);
  return remaining <= 0;
}

function resolveDisplayGroups(groups: string[]): string[] {
  return groups.filter((g) => !g.startsWith(UNION_EMAIL_PREFIX) && !g.startsWith("node-email-policy:"));
}

function resolveNodeName(host: string): string {
  const first = host.trim().split(".", 2)[0]?.toLowerCase() ?? "";
  switch (first) {
    case "jp-xconnect":
      return "JP-Connect";
    case "hk-xconnect":
      return "HK-Connect";
    case "ph-xconnect":
      return "PH-Connect";
    case "us-xconnect":
      return "US-Connect";
    default:
      return host.trim().toLowerCase() || "unknown-node";
  }
}

function buildThreeTierRoutes(hasMedia: boolean, hasPro: boolean, hasCustom: boolean): RouteRule[] {
  const fallbackTarget = hasMedia ? ROUTING_POOL_MEDIA : hasCustom ? ROUTING_POOL_CUSTOM : TIER_DIRECT;
  const proTarget = hasPro ? ROUTING_POOL_PRO : fallbackTarget;
  const rewrite = (rules: string[], from: string, to: string) =>
    rules.map((rule) => {
      if (from === to) return rule;
      const parts = rule.split(",");
      if (parts.length >= 2 && parts[parts.length - 1] === from) {
        parts[parts.length - 1] = to;
      } else if (parts.length >= 3 && parts[parts.length - 2] === from) {
        parts[parts.length - 2] = to;
      }
      return parts.join(",");
    });

  return [
    {
      priority: 1,
      name: "direct_cn_private",
      target: TIER_DIRECT,
      effective_target: TIER_DIRECT,
      domains: [...DIRECT_XRAY_DOMAINS],
      ips: ["geoip:private", ...DIRECT_XRAY_IPS],
      clash_rules: [...DIRECT_CLASH_RULES],
    },
    {
      priority: 2,
      name: "media_pool_priority",
      target: ROUTING_POOL_MEDIA,
      effective_target: fallbackTarget,
      media_on_pro_action: "allow",
      domains: [...MEDIA_XRAY_DOMAINS],
      clash_rules: rewrite(MEDIA_CLASH_RULES, ROUTING_POOL_MEDIA, fallbackTarget),
    },
    {
      priority: 3,
      name: "pro_ec2_whitelist",
      target: ROUTING_POOL_PRO,
      effective_target: proTarget,
      media_on_pro_action: "allow",
      domains: [...PRO_XRAY_DOMAINS],
      clash_rules: rewrite(PRO_CLASH_RULES, ROUTING_POOL_PRO, proTarget),
    },
    {
      priority: 4,
      name: "global_fallback",
      target: ROUTING_POOL_MEDIA,
      effective_target: fallbackTarget,
      clash_rules: rewrite(FALLBACK_CLASH_RULES, ROUTING_POOL_MEDIA, fallbackTarget),
    },
  ];
}

function buildVLESSURI(node: SubscriptionNode): string {
  if (node.vlessUri?.trim()) return node.vlessUri.trim();
  const port = node.port > 0 ? node.port : 443;
  const transport = (node.transport ?? "xhttp").trim().toLowerCase() || "xhttp";
  const sni = node.serverName?.trim() || node.address.trim();
  const fp = node.fingerprint?.trim() || "chrome";
  const tag = node.name.trim() || node.address.trim();
  if (transport === "tcp") {
    const flow = node.flow?.trim() || DEFAULT_FLOW;
    return `vless://${node.uuid.trim()}@${node.address.trim()}:${port}?encryption=none&type=tcp&security=tls&sni=${encodeURIComponent(sni)}&fp=${encodeURIComponent(fp)}&flow=${encodeURIComponent(flow)}#${encodeURIComponent(tag)}`;
  }
  const path = node.path?.trim() || "/split";
  const mode = node.mode?.trim() || "auto";
  return `vless://${node.uuid.trim()}@${node.address.trim()}:${port}?encryption=none&type=xhttp&security=tls&host=${encodeURIComponent(node.address.trim())}&path=${encodeURIComponent(path)}&mode=${encodeURIComponent(mode)}&sni=${encodeURIComponent(sni)}&fp=${encodeURIComponent(fp)}&alpn=h2%2Chttp%2F1.1%2Ch3#${encodeURIComponent(tag)}`;
}

function yamlStr(value: string): string {
  if (
    value === "" ||
    /[:#{}[\],&*?|<>=!%@`'"\n\r]/.test(value) ||
    value.startsWith("-") ||
    value.startsWith(" ") ||
    value.endsWith(" ") ||
    /^(true|false|null|yes|no|on|off|\d+(\.\d+)?)$/i.test(value)
  ) {
    return JSON.stringify(value);
  }
  return value;
}

function renderClashYAML(
  all: SubscriptionNode[],
  media: SubscriptionNode[],
  pro: SubscriptionNode[],
  custom: SubscriptionNode[],
): string {
  const lines: string[] = [
    "port: 7890",
    "socks-port: 7891",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
  ];
  if (all.length === 0) {
    lines.push("proxies: []");
  } else {
    lines.push("proxies:");
    for (const node of all) {
      lines.push(`  - name: ${yamlStr(node.name)}`);
      lines.push("    type: vless");
      lines.push(`    server: ${yamlStr(node.address)}`);
      lines.push(`    port: ${node.port}`);
      lines.push(`    uuid: ${yamlStr(node.uuid)}`);
      lines.push("    tls: true");
      lines.push(`    servername: ${yamlStr(node.serverName ?? node.address)}`);
      lines.push(`    client-fingerprint: ${yamlStr(node.fingerprint ?? "chrome")}`);
      lines.push("    udp: true");
      lines.push("    skip-cert-verify: false");
      if ((node.transport ?? "xhttp").toLowerCase() === "tcp") {
        lines.push("    network: tcp");
        if (node.flow) lines.push(`    flow: ${yamlStr(node.flow)}`);
      } else {
        lines.push("    network: xhttp");
        lines.push("    xhttp-opts:");
        lines.push(`      path: ${yamlStr(node.path || "/split")}`);
        lines.push(`      mode: ${yamlStr(node.mode || "auto")}`);
      }
    }
  }

  const groups: Array<{ name: string; type: string; url?: string; interval?: number; proxies: string[] }> = [];
  if (media.length > 0) {
    groups.push({
      name: ROUTING_POOL_MEDIA,
      type: "url-test",
      url: "https://cp.cloudflare.com/generate_204",
      interval: 300,
      proxies: media.map((n) => n.name),
    });
  }
  if (pro.length > 0) {
    groups.push({
      name: ROUTING_POOL_PRO,
      type: "url-test",
      url: "https://cp.cloudflare.com/generate_204",
      interval: 180,
      proxies: pro.map((n) => n.name),
    });
  }
  if (custom.length > 0) {
    groups.push({
      name: ROUTING_POOL_CUSTOM,
      type: "select",
      proxies: custom.map((n) => n.name),
    });
  }
  if (groups.length > 1) {
    groups.unshift({
      name: "XConnect",
      type: "select",
      proxies: [...groups.map((g) => g.name), TIER_DIRECT],
    });
  }

  if (groups.length === 0) {
    lines.push("proxy-groups: []");
  } else {
    lines.push("proxy-groups:");
    for (const g of groups) {
      lines.push(`  - name: ${yamlStr(g.name)}`);
      lines.push(`    type: ${yamlStr(g.type)}`);
      if (g.url) lines.push(`    url: ${yamlStr(g.url)}`);
      if (g.interval) lines.push(`    interval: ${g.interval}`);
      lines.push("    proxies:");
      for (const p of g.proxies) {
        lines.push(`      - ${yamlStr(p)}`);
      }
    }
  }

  const routes = buildThreeTierRoutes(media.length > 0, pro.length > 0, custom.length > 0);
  lines.push("rules:");
  for (const tier of routes) {
    for (const r of tier.clash_rules ?? []) {
      lines.push(`  - ${yamlStr(r)}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

function renderSubscriptionPayload(
  rawFormat: string,
  input: {
    userId: string;
    userEmail: string;
    allowCustom: boolean;
    allowPro: boolean;
    nodes: SubscriptionNode[];
    now: Date;
  },
): { body: string; contentType: string } {
  const fmtRaw = rawFormat.trim().toLowerCase();
  let fmt: "clash" | "singbox" | "xray" | "one" | "vless";
  if (!fmtRaw || ["clash", "mihomo", "clash-meta", "clash.meta", "yaml"].includes(fmtRaw)) {
    fmt = "clash";
  } else if (["singbox", "sing-box"].includes(fmtRaw)) {
    fmt = "singbox";
  } else if (["xray", "xray-json", "xrayjson", "v2ray"].includes(fmtRaw)) {
    fmt = "xray";
  } else if (["one", "xconnect-one"].includes(fmtRaw)) {
    fmt = "one";
  } else if (["vless", "uri", "raw"].includes(fmtRaw)) {
    fmt = "vless";
  } else {
    throw new OverlayError(400, "unsupported_subscription_format", `unsupported subscription format: ${rawFormat}`);
  }

  const all: SubscriptionNode[] = [];
  const media: SubscriptionNode[] = [];
  const pro: SubscriptionNode[] = [];
  const custom: SubscriptionNode[] = [];
  const nameCounts = new Map<string, number>();

  for (const orig of input.nodes) {
    const pool =
      orig.routingPool &&
      [ROUTING_POOL_MEDIA, ROUTING_POOL_PRO, ROUTING_POOL_CUSTOM].includes(orig.routingPool)
        ? orig.routingPool
        : poolForResourceClass(orig.resourceClass ?? "");
    if (pool === ROUTING_POOL_CUSTOM && !input.allowCustom) continue;
    if (pool === ROUTING_POOL_PRO && !input.allowPro) continue;
    const node: SubscriptionNode = {
      ...orig,
      routingPool: pool,
      port: orig.port > 0 ? orig.port : 443,
      transport: orig.transport || "xhttp",
      security: orig.security || "tls",
      serverName: orig.serverName || orig.address,
      fingerprint: orig.fingerprint || "chrome",
      name: orig.name || orig.address,
    };
    const count = (nameCounts.get(node.name) ?? 0) + 1;
    nameCounts.set(node.name, count);
    if (count > 1) node.name = `${node.name}-${count}`;
    node.vlessUri = buildVLESSURI(node);

    all.push(node);
    if (pool === ROUTING_POOL_PRO) pro.push(node);
    else if (pool === ROUTING_POOL_CUSTOM) custom.push(node);
    else media.push(node);
  }

  if (fmt === "clash") {
    return {
      body: renderClashYAML(all, media, pro, custom),
      contentType: "text/yaml; charset=utf-8",
    };
  }
  if (fmt === "vless") {
    const body = all.length > 0 ? `${all.map((n) => buildVLESSURI(n)).join("\n")}\n` : "";
    return { body, contentType: "text/plain; charset=utf-8" };
  }
  if (fmt === "one") {
    const pools: Record<string, unknown> = {};
    if (media.length > 0) {
      pools[ROUTING_POOL_MEDIA] = {
        public_resource: true,
        media_on_pro_action: "allow",
        fallback_default: true,
        pricing_groups: ["free", "shared", "plus"],
        sub_pool_tags: ["media:video", "media:shopping", "media:ai-app"],
        nodes: media,
      };
    }
    if (pro.length > 0) {
      pools[ROUTING_POOL_PRO] = {
        public_resource: true,
        media_on_pro_action: "allow",
        fallback_default: false,
        pricing_groups: ["pro"],
        nodes: pro,
      };
    }
    if (input.allowCustom && custom.length > 0) {
      pools[ROUTING_POOL_CUSTOM] = {
        public_resource: false,
        media_on_pro_action: "allow",
        fallback_default: false,
        pricing_groups: ["custom", "team"],
        nodes: custom,
      };
    }
    const payload = {
      schema_version: 1,
      format: "one",
      generated_at: input.now.toISOString(),
      policy_revision: POLICY_REVISION,
      pools,
      nodes: all,
      routes: buildThreeTierRoutes(media.length > 0, pro.length > 0, input.allowCustom && custom.length > 0),
      vless_uris: all.map((n) => buildVLESSURI(n)),
    };
    return {
      body: JSON.stringify(payload, null, 2),
      contentType: "application/json; charset=utf-8",
    };
  }
  if (fmt === "singbox") {
    const outbounds: Record<string, unknown>[] = [];
    for (const node of all) {
      const ob: Record<string, unknown> = {
        type: "vless",
        tag: node.name,
        server: node.address,
        server_port: node.port,
        uuid: node.uuid,
        tls: {
          enabled: true,
          server_name: node.serverName,
          utls: { enabled: true, fingerprint: node.fingerprint },
        },
      };
      if ((node.transport ?? "xhttp") === "tcp") {
        if (node.flow) ob.flow = node.flow;
      } else {
        ob.transport = {
          type: "xhttp",
          host: node.address,
          path: node.path || "/split",
          mode: node.mode || "auto",
        };
      }
      outbounds.push(ob);
    }
    if (media.length > 0) {
      outbounds.push({
        type: "urltest",
        tag: ROUTING_POOL_MEDIA,
        outbounds: media.map((n) => n.name),
        url: "https://cp.cloudflare.com/generate_204",
        interval: "5m",
      });
    }
    if (pro.length > 0) {
      outbounds.push({
        type: "urltest",
        tag: ROUTING_POOL_PRO,
        outbounds: pro.map((n) => n.name),
        url: "https://cp.cloudflare.com/generate_204",
        interval: "3m",
      });
    }
    if (custom.length > 0) {
      outbounds.push({
        type: "selector",
        tag: ROUTING_POOL_CUSTOM,
        outbounds: custom.map((n) => n.name),
      });
    }
    outbounds.push({ type: "direct", tag: "direct" }, { type: "block", tag: "block" });
    const fallback = media.length > 0 ? ROUTING_POOL_MEDIA : custom.length > 0 ? ROUTING_POOL_CUSTOM : "direct";
    const proTarget = pro.length > 0 ? ROUTING_POOL_PRO : fallback;
    const doc = {
      log: { level: "info" },
      inbounds: [{ type: "mixed", tag: "mixed-in", listen: "127.0.0.1", listen_port: 7890 }],
      outbounds,
      route: {
        auto_detect_interface: true,
        rules: [
          { ip_is_private: true, outbound: "direct" },
          { geosite: ["cn"], outbound: "direct" },
          { geoip: ["cn"], outbound: "direct" },
          {
            geosite: ["youtube", "netflix", "disney", "tiktok", "twitch", "spotify", "bilibili"],
            domain_suffix: ["speedtest.net", "fast.com", "steamcontent.com", "icloud-content.com", "mega.nz"],
            outbound: fallback,
          },
          {
            geosite: ["openai", "anthropic", "github", "google", "cloudflare"],
            domain_suffix: ["claude.ai", "cursor.sh", "cursor.com"],
            outbound: proTarget,
          },
        ],
        final: fallback,
      },
    };
    return {
      body: JSON.stringify(doc, null, 2),
      contentType: "application/json; charset=utf-8",
    };
  }

  // fmt === "xray"
  const outbounds: Record<string, unknown>[] = [];
  const balancers: Record<string, unknown>[] = [];
  const pushOutbound = (prefix: string, idx: number, node: SubscriptionNode) => {
    const user: Record<string, unknown> = { id: node.uuid, encryption: "none" };
    const stream: Record<string, unknown> = {
      network: (node.transport ?? "xhttp") === "tcp" ? "tcp" : "xhttp",
      security: "tls",
      tlsSettings: { serverName: node.serverName, fingerprint: node.fingerprint },
    };
    if ((node.transport ?? "xhttp") === "tcp") {
      if (node.flow) user.flow = node.flow;
    } else {
      stream.xhttpSettings = {
        host: node.address,
        path: node.path || "/split",
        mode: node.mode || "auto",
      };
    }
    outbounds.push({
      tag: `${prefix}-${idx + 1}`,
      protocol: "vless",
      settings: { vnext: [{ address: node.address, port: node.port, users: [user] }] },
      streamSettings: stream,
    });
  };
  media.forEach((n, i) => pushOutbound("media", i, n));
  pro.forEach((n, i) => pushOutbound("pro", i, n));
  custom.forEach((n, i) => pushOutbound("custom", i, n));
  if (media.length > 0) balancers.push({ tag: ROUTING_POOL_MEDIA, selector: ["media-"] });
  if (pro.length > 0) balancers.push({ tag: ROUTING_POOL_PRO, selector: ["pro-"] });
  if (custom.length > 0) balancers.push({ tag: ROUTING_POOL_CUSTOM, selector: ["custom-"] });
  outbounds.push({ tag: "direct", protocol: "freedom" }, { tag: "block", protocol: "blackhole" });

  const fallback = media.length > 0 ? ROUTING_POOL_MEDIA : custom.length > 0 ? ROUTING_POOL_CUSTOM : TIER_DIRECT;
  const poolRule = (base: Record<string, unknown>, target: string) =>
    target === TIER_DIRECT ? { ...base, outboundTag: "direct" } : { ...base, balancerTag: target };
  const doc = {
    log: { loglevel: "warning" },
    inbounds: [
      { listen: "127.0.0.1", port: 1080, protocol: "socks", settings: { udp: true } },
      { listen: "127.0.0.1", port: 1081, protocol: "http" },
    ],
    outbounds,
    routing: {
      domainStrategy: "IPIfNonMatch",
      rules: [
        { type: "field", ip: ["geoip:private"], outboundTag: "direct" },
        { type: "field", domain: DIRECT_XRAY_DOMAINS, outboundTag: "direct" },
        { type: "field", ip: DIRECT_XRAY_IPS, outboundTag: "direct" },
        poolRule({ type: "field", domain: MEDIA_XRAY_DOMAINS }, fallback),
        poolRule({ type: "field", domain: PRO_XRAY_DOMAINS }, pro.length > 0 ? ROUTING_POOL_PRO : fallback),
        poolRule({ type: "field", network: "tcp,udp" }, fallback),
      ],
      ...(balancers.length > 0 ? { balancers } : {}),
    },
  };
  return {
    body: JSON.stringify(doc, null, 2),
    contentType: "application/json; charset=utf-8",
  };
}

function buildRegionalPoolsForUser(
  snapshots: NodeSnapshot[],
  access: NetworkAccess,
  user: UserRow,
  packageName: string,
  now: Date,
): RegionalPool[] {
  const wantClass = effectiveAgentResourceClass(access, user, packageName);
  const wantTeam = (access.teamId ?? "").trim();
  const customAllowed = wantClass === "custom" || (access.mode !== "dedicated" && isCustomDedicatedUser(user, packageName));

  const groups = new Map<
    string,
    { pool: RegionalPool; ids: Set<string>; reasons: Set<string> }
  >();

  for (const snap of snapshots) {
    const { team: teamId } = agentNetworkScope(snap.groups);
    const { team: _t, valid: scopeValid } = agentNetworkScope(snap.groups);
    let resourceClass = "";
    if (teamId) {
      resourceClass = "team";
    } else {
      for (const g of snap.groups) {
        if (g.startsWith("resource:")) {
          resourceClass = g.slice("resource:".length);
        }
      }
      if (!resourceClass && snap.groups.length > 0 && scopeValid) {
        resourceClass = "shared";
      }
    }
    if (!resourceClass || !scopeValid) continue;

    const customEmails = snap.allowedEmails ?? [];
    const tempFreeAllowed =
      resourceClass === "custom" &&
      access.mode !== "dedicated" &&
      wantClass === "free" &&
      Boolean(snap.nodeId) &&
      customEmails.length > 0 &&
      activeFreeGrantExpiresAt(user, snap.nodeId, now) !== null;
    if (
      resourceClass === "custom" &&
      customEmails.length > 0 &&
      !customEmails.some((e) => e.toLowerCase() === user.email.toLowerCase()) &&
      !tempFreeAllowed
    ) {
      continue;
    }
    if (snap.updatedAt.getTime() === 0 || !networkScopeAllows(access, snap.groups)) {
      continue;
    }
    const entry = regionalEntryHost(snap.entryPoint || snap.id);
    const region = (snap.region || (entry ? inferRegionFromHost(entry) : "")).toLowerCase();
    if (!region || !entry) continue;

    const isTrial = isOneTimeTrialMember(user) || packageName.trim().toLowerCase() === "trial";
    const isCustomPool =
      resourceClass === "custom" ||
      (snap.routingPool ?? "").toLowerCase() === ROUTING_POOL_CUSTOM.toLowerCase();
    let classAllowed = false;
    if (resourceClass === "team") {
      classAllowed = wantClass === "team" && Boolean(wantTeam) && teamId === wantTeam;
    } else if (isCustomPool) {
      if (!isTrial && resourceClass === "custom") {
        classAllowed =
          customEmails.length > 0
            ? customAllowed ||
              wantClass === "plus" ||
              wantClass === "pro" ||
              (snap.groups.includes("custom:allow-free") && wantClass === "free") ||
              tempFreeAllowed
            : customAllowed;
      }
    } else {
      const publicOverride =
        PUBLIC_CLASSES.has(resourceClass) &&
        access.mode !== "dedicated" &&
        publicUnionEmails(snap.groups).includes(user.email.toLowerCase());
      classAllowed = publicAgentResourceClassAllows(resourceClass, wantClass) || publicOverride;
    }
    if (!classAllowed) continue;

    const key = `${region}\x00${entry}\x00${resourceClass}\x00${teamId}`;
    let agg = groups.get(key);
    if (!agg) {
      const routingPool = isCustomPool ? ROUTING_POOL_CUSTOM : poolForResourceClass(resourceClass);
      agg = {
        pool: {
          ...(resourceClass === "custom" && customEmails.length > 0 ? { private: true } : {}),
          code: region,
          entry,
          ...(snap.name ? { displayName: snap.name } : {}),
          resourceClass,
          ...(teamId ? { teamId } : {}),
          routingPool,
          mediaOnProAction: "allow",
          publicResource: routingPool !== ROUTING_POOL_CUSTOM,
          ...(routingPool === ROUTING_POOL_MEDIA
            ? { subPoolTags: ["media:video", "media:shopping", "media:ai-app"] }
            : {}),
          poolCount: 0,
          openToUsers: false,
          closedReasons: [],
        },
        ids: new Set<string>(),
        reasons: new Set<string>(),
      };
      groups.set(key, agg);
    }
    agg.ids.add(snap.id);
    const fresh =
      snap.updatedAt.getTime() <= now.getTime() &&
      now.getTime() - snap.updatedAt.getTime() <= REGIONAL_HEARTBEAT_TTL_MS;
    const open = snap.openToUsers !== false;
    agg.pool.openToUsers = agg.pool.openToUsers || (open && fresh && snap.healthy && snap.running);
    if (!open) agg.reasons.add("explicit_disabled");
    if (!fresh) agg.reasons.add("stale");
    if (!snap.healthy) agg.reasons.add("unhealthy");
    if (!snap.running) agg.reasons.add("xray_not_running");
  }

  const out: RegionalPool[] = [];
  for (const agg of groups.values()) {
    agg.pool.poolCount = agg.ids.size;
    if (!agg.pool.openToUsers) {
      for (const r of ["explicit_disabled", "stale", "unhealthy", "xray_not_running"]) {
        if (agg.reasons.has(r)) agg.pool.closedReasons.push(r);
      }
    }
    out.push(agg.pool);
  }
  out.sort((a, b) => (a.code === b.code ? a.entry.localeCompare(b.entry) : a.code.localeCompare(b.code)));
  return out;
}

async function resolveUserNodesData(
  client: PgQueryExecutor,
  env: WorkerEnv,
  userId: string,
  now: Date,
): Promise<{
  user: UserRow;
  access: NetworkAccess;
  packageName: string;
  resourceClass: string;
  highSpeedExhausted: boolean;
  vpsExhausted: boolean;
  dualGateEnabled: boolean;
  vlessNodes: VlessNode[];
  subNodes: SubscriptionNode[];
  pools: RegionalPool[];
}> {
  const user = await getUserById(client, userId);
  if (!user) {
    throw new OverlayError(401, "user_not_found", "user not found");
  }
  const [blockedIds, blacklistedEmails, teams, memberships, billingProfiles, quotaStates, snapshots] =
    await Promise.all([
      listBlockedUserIds(client),
      listBlacklistedEmails(client),
      listNetworkTeams(client),
      listNetworkMemberships(client),
      listBillingProfiles(client),
      listQuotaStates(client),
      loadNodeSnapshotsFromDB(client, env),
    ]);

  if (blockedIds.has(user.id) || blacklistedEmails.has(user.email.toLowerCase())) {
    throw new OverlayError(403, "proxy_access_blocked", "proxy access is blocked");
  }

  const billing = billingProfiles.get(user.id);
  const quota = quotaStates.get(user.id);
  const membership = memberships.get(user.id);
  const access = accessFromMembership(membership, teams, now);
  if (!user.active || user.archivedAt || !accountAccessVerified(user) || blockedIds.has(user.id)) {
    access.allowed = false;
  }

  const dualGateEnabled = parseBoolEnv(env.DUAL_BUCKET_PRO_GATE_ENABLED);
  const vpsExhausted = isQuotaExhausted(user, billing, quota, access, false, now);
  const hasHighSpeed =
    !isOneTimeTrialMember(user) &&
    Boolean(billing && billing.highSpeedQuotaBytes > 0) &&
    !isCustomDedicatedUser(user, billing?.packageName ?? "") &&
    !hasMediaPassthroughEntitlement(user, billing?.packageName ?? "");
  const hsExhausted = isOneTimeTrialMember(user)
    ? vpsExhausted
    : hasHighSpeed
      ? isQuotaExhausted(user, billing, quota, access, true, now)
      : false;
  const fullyExhausted = isOneTimeTrialMember(user)
    ? vpsExhausted
    : dualGateEnabled
      ? vpsExhausted && (!hasHighSpeed || hsExhausted)
      : vpsExhausted;

  if (fullyExhausted) {
    throw new OverlayError(403, "quota_exhausted", "natural-month quota exhausted");
  }
  if (!user.active || user.archivedAt) {
    throw new OverlayError(403, "account_paused", "account is paused");
  }
  if (!user.proxyUuid) {
    throw new OverlayError(503, "proxy_uuid_unavailable", "proxy UUID is not provisioned for this account");
  }
  if (user.proxyUuidExpiresAt && now.getTime() > user.proxyUuidExpiresAt.getTime()) {
    throw new OverlayError(403, "proxy_uuid_expired", "proxy access has expired, please renew");
  }
  if (!access.allowed) {
    throw new OverlayError(403, "team_access_inactive", "team access is inactive");
  }

  const packageName = billing?.packageName ?? "";
  const resourceClass = effectiveAgentResourceClass(access, user, packageName);
  const pools = buildRegionalPoolsForUser(snapshots, access, user, packageName, now);

  const xhttpMode = (env.XRAY_XHTTP_MODE ?? "").trim() || "auto";
  const xhttpPort = Number.parseInt((env.XRAY_XHTTP_PORT ?? "").trim() || "443", 10) || 443;
  const tcpPort = Number.parseInt((env.XRAY_TCP_PORT ?? "").trim() || "1443", 10) || 1443;
  const xhttpPathBase = (env.XRAY_XHTTP_PATH ?? "").trim() || "/split";
  const xhttpPath = `/${xhttpPathBase.replace(/^\/+/, "")}`;

  const vlessNodes: VlessNode[] = [];
  const subNodes: SubscriptionNode[] = [];
  for (const pool of pools) {
    if (!pool.openToUsers) continue;
    const nodeClass = pool.resourceClass === "free" ? "free" : resourceClass;
    const pricingGroup = pool.resourceClass || nodeClass;
    const routingPool = pool.routingPool || poolForResourceClass(pricingGroup);
    if (dualGateEnabled) {
      if (routingPool === ROUTING_POOL_PRO && hsExhausted) continue;
      if (routingPool === ROUTING_POOL_MEDIA && vpsExhausted) continue;
    }
    const host = pool.entry;
    const nodeName = pool.displayName || pool.code;
    const vlessXhttp = `vless://${user.proxyUuid}@${host}:443?encryption=none&type=xhttp&security=tls&host=${host}&path=${encodeURIComponent(xhttpPath)}&mode=${encodeURIComponent(xhttpMode)}&sni=${host}&fp=chrome&alpn=h2%2Chttp%2F1.1%2Ch3#${encodeURIComponent(nodeName)}`;
    const vlessTcp = `vless://${user.proxyUuid}@${host}:1443?encryption=none&type=tcp&security=tls&sni=${host}&fp=chrome&flow=${DEFAULT_FLOW}#${encodeURIComponent(nodeName)}`;

    vlessNodes.push({
      ...(pool.private ? { private: true } : {}),
      name: nodeName,
      region: pool.code,
      pool_count: pool.poolCount,
      open_to_users: true,
      address: host,
      port: xhttpPort,
      users: [user.proxyUuid],
      transport: "xhttp",
      path: xhttpPath,
      mode: xhttpMode,
      security: "tls",
      flow: DEFAULT_FLOW,
      resource_class: nodeClass,
      routing_pool: routingPool,
      pricing_group: pricingGroup,
      ...(pool.subPoolTags ? { sub_pool_tags: pool.subPoolTags } : {}),
      server_name: host,
      xhttp_port: xhttpPort,
      tcp_port: tcpPort,
      uri_scheme_xhttp: vlessXhttp,
      uri_scheme_tcp: vlessTcp,
      ...(dualGateEnabled && hsExhausted ? { highSpeedQuotaExhausted: true } : {}),
    });
    subNodes.push({
      id: host,
      name: nodeName,
      region: pool.code,
      address: host,
      port: xhttpPort,
      uuid: user.proxyUuid,
      flow: DEFAULT_FLOW,
      transport: "xhttp",
      path: xhttpPath,
      mode: xhttpMode,
      security: "tls",
      serverName: host,
      fingerprint: "chrome",
      resourceClass: pricingGroup,
      routingPool,
      pricingGroup,
      subPoolTags: pool.subPoolTags,
      vlessUri: vlessXhttp,
    });
  }

  if (access.mode === "dedicated" && vlessNodes.length === 0) {
    throw new OverlayError(503, "team_nodes_unavailable", "dedicated team nodes are unavailable");
  }

  return {
    user,
    access,
    packageName,
    resourceClass,
    highSpeedExhausted: dualGateEnabled && hsExhausted,
    vpsExhausted,
    dualGateEnabled,
    vlessNodes,
    subNodes,
    pools,
  };
}

async function authenticateJWTAllowQuery(
  c: Context<{ Bindings: WorkerEnv }>,
  deps: AgentServerDeps,
): Promise<string> {
  const token =
    parseBearer(c.req.header("Authorization")) ||
    parseCookie(c.req.header("Cookie"), "xc_session") ||
    (c.req.query("token") ?? "").trim() ||
    null;
  if (!token) {
    throw new OverlayError(401, "unauthorized", "user authentication required");
  }
  try {
    const claims = await verifyJWT(token, {
      jwksUrl: (c.env.ACCOUNTS_JWKS_URL ?? "").trim() || undefined,
      hs256Secret: (c.env.JWT_ACCESS_SECRET ?? "").trim() || undefined,
      staticEd25519Keys: deps.staticEd25519Keys,
      nowSeconds: deps.now ? Math.floor(deps.now().getTime() / 1000) : undefined,
    });
    const userId = extractUserId(claims);
    if (!userId || userId === "system") {
      throw new OverlayError(401, "unauthorized", "user authentication required");
    }
    return userId;
  } catch (err) {
    if (err instanceof OverlayError) throw err;
    throw new OverlayError(401, "unauthorized", "invalid or expired token");
  }
}

export async function handleGetAgentStatus(
  c: Context<{ Bindings: WorkerEnv }>,
  deps: AgentServerDeps,
): Promise<Response> {
  const withClient = deps.withClient;
  if (!withClient) throw new Error("withClient dependency required");
  const cacheStore = resolveCacheStore(deps);

  let isInternal = false;
  let agentIdentity: AgentIdentity | null = null;
  let jwtUserId: string | null = null;

  const expectedInternal = (c.env.INTERNAL_SERVICE_TOKEN ?? "").trim();
  const internalCandidate = extractInternalToken(c);
  if (expectedInternal && internalCandidate && constantTimeStringEqual(internalCandidate, expectedInternal)) {
    isInternal = true;
  }

  if (!isInternal) {
    const token =
      parseBearer(c.req.header("Authorization")) ||
      parseCookie(c.req.header("Cookie"), "xc_session");
    if (!token) {
      return c.json({ error: "missing_token" }, 401);
    }
    agentIdentity = await authenticateAgentCredential(c.env, token);
    if (!agentIdentity) {
      try {
        const claims = await verifyJWT(token, {
          jwksUrl: (c.env.ACCOUNTS_JWKS_URL ?? "").trim() || undefined,
          hs256Secret: (c.env.JWT_ACCESS_SECRET ?? "").trim() || undefined,
          staticEd25519Keys: deps.staticEd25519Keys,
          nowSeconds: deps.now ? Math.floor(deps.now().getTime() / 1000) : undefined,
        });
        const uid = extractUserId(claims);
        if (uid && uid !== "system") {
          jwtUserId = uid;
        }
      } catch {
        return c.json({ error: "invalid_token" }, 401);
      }
      if (!jwtUserId) {
        return c.json({ error: "invalid_token" }, 401);
      }
    }
  }

  const scopeKey = isInternal
    ? "internal"
    : agentIdentity
      ? `agent:${agentIdentity.id}:${agentIdentity.nodeId ?? ""}`
      : `user:${jwtUserId}`;
  const cacheKeyUrl = `https://cache.xconnect.internal/api/agent-server/v1/status?scope=${encodeURIComponent(scopeKey)}`;
  const ttlSec = parseDurationSeconds(c.env.XCONNECT_AGENT_STATUS_CACHE_TTL, DEFAULT_STATUS_TTL_SEC);

  // Validate JWT user role before serving cache if JWT-authenticated
  if (jwtUserId) {
    const userCheck = await withClient(c.env, (client) => getUserById(client, jwtUserId!));
    if (userCheck) {
      if (!userCheck.active || userCheck.archivedAt) {
        return c.json({ error: "account_suspended" }, 403);
      }
      if (!["root", "superadmin", "admin", "operator"].includes(userCheck.role.toLowerCase())) {
        return c.json({ error: "forbidden", message: "administrator or agent authentication required" }, 403);
      }
    }
  }

  return respondWithEdgeCache(c, {
    cacheStore,
    cacheKeyUrl,
    ttlSeconds: ttlSec,
    contentType: "application/json; charset=utf-8",
    responseCacheControl: "private, no-store",
    compute: async () => {
      const entries = await withClient(c.env, async (client) => {
        let snapshots = await loadNodeSnapshotsFromDB(client, c.env);
        if (agentIdentity) {
          const { scope, valid } = await agentResourceScope(agentIdentity.groups);
          if (!valid) {
            throw new OverlayError(403, "agent_scope_invalid", "invalid agent scope");
          }
          const isWildcard =
            agentIdentity.id === "*" &&
            !agentIdentity.groups.includes(MANAGED_TEAM_MARKER) &&
            !scope.teamId;
          if (!isWildcard) {
            snapshots = snapshots.filter((snap) => {
              if (agentIdentity!.nodeId) {
                return snap.id === agentIdentity!.id || snap.nodeId === agentIdentity!.nodeId;
              }
              if (scope.teamId) {
                const ns = agentNetworkScope(snap.groups);
                return ns.valid && ns.team === scope.teamId;
              }
              return snap.id === agentIdentity!.id;
            });
          }
        } else if (jwtUserId) {
          const user = await getUserById(client, jwtUserId);
          if (!user) throw new OverlayError(401, "user_not_found", "user not found");
          if (!["root", "superadmin"].includes(user.role.toLowerCase())) {
            const [teams, memberships, billingProfiles] = await Promise.all([
              listNetworkTeams(client),
              listNetworkMemberships(client),
              listBillingProfiles(client),
            ]);
            const access = accessFromMembership(memberships.get(user.id), teams, deps.now ? deps.now() : new Date());
            const pkg = billingProfiles.get(user.id)?.packageName ?? "";
            const filtered: NodeSnapshot[] = [];
            for (const snap of snapshots) {
              if (!networkScopeAllows(access, snap.groups)) continue;
              const { scope, valid } = await agentResourceScope(snap.groups);
              if (valid && agentResourceScopeAllowsUser(scope, access, user, pkg)) {
                filtered.push(snap);
              }
            }
            snapshots = filtered;
          }
        }

        const out: AgentStatusEntry[] = snapshots.map((snap) => ({
          id: snap.id,
          ...(snap.name ? { name: snap.name } : {}),
          ...(resolveDisplayGroups(snap.groups).length > 0
            ? { groups: resolveDisplayGroups(snap.groups) }
            : {}),
          healthy: snap.healthy,
          ...(snap.message ? { message: snap.message } : {}),
          users: snap.users,
          ...(snap.syncRevision ? { syncRevision: snap.syncRevision } : {}),
          updatedAt: snap.updatedAt.toISOString(),
          xray: {
            running: snap.running,
            clients: snap.clients,
            ...(snap.lastSync ? { lastSync: snap.lastSync.toISOString() } : {}),
          },
        }));
        return out;
      });
      return { body: JSON.stringify({ agents: entries }) };
    },
  });
}

export async function handleListAgentUsers(
  c: Context<{ Bindings: WorkerEnv }>,
  deps: AgentServerDeps,
): Promise<Response> {
  const withClient = deps.withClient;
  if (!withClient) throw new Error("withClient dependency required");
  const cacheStore = resolveCacheStore(deps);

  const token = parseBearer(c.req.header("Authorization"));
  if (!token) {
    return c.json({ error: "missing_token" }, 401);
  }
  const cred = await authenticateAgentCredential(c.env, token);
  if (!cred) {
    return c.json({ error: "invalid_token" }, 401);
  }

  const requestedAgentId =
    (c.req.header("X-Agent-ID") ?? "").trim() || (c.req.query("agentId") ?? "").trim();
  const reqClass = (c.req.header("X-Agent-Resource-Class") ?? "").trim();
  const reqTeam = (c.req.header("X-Agent-Team-ID") ?? "").trim();
  const reqAllowFree = (c.req.header("X-Agent-Custom-Allow-Free") ?? "").trim();
  const reqEmailPolicy = (c.req.header("X-Agent-Email-Policy") ?? "").trim();
  const reqAllowedEmails = (c.req.header("X-Agent-Allowed-Emails") ?? "").trim();

  if (reqAllowFree && reqAllowFree !== "true" && reqAllowFree !== "false") {
    return c.json({ error: "agent_scope_invalid", message: "custom allow free must be true or false" }, 400);
  }

  let effectiveGroups = [...cred.groups];
  let effectiveId = cred.id;
  let effectiveAllowedEmails = cred.allowedEmails;

  if (cred.nodeId) {
    if (requestedAgentId && requestedAgentId !== cred.id) {
      return c.json({ error: "agent_scope_mismatch", message: "node credential cannot select another agent" }, 403);
    }
    const { scope, valid } = await agentResourceScope(cred.groups);
    if (!valid) return c.json({ error: "agent_scope_invalid" }, 403);
    if (reqClass && reqClass !== scope.resourceClass) {
      return c.json({ error: "agent_scope_mismatch" }, 403);
    }
    if (reqTeam && reqTeam !== (scope.teamId ?? "")) {
      return c.json({ error: "agent_scope_mismatch" }, 403);
    }
    if (reqAllowFree === "true" && !scope.customAllowFree) {
      return c.json({ error: "agent_scope_mismatch" }, 403);
    }
    if (scope.resourceClass === "custom") {
      if (!cred.allowedEmails || cred.allowedEmails.length === 0) {
        return c.json({ error: "agent_scope_invalid" }, 403);
      }
      effectiveAllowedEmails = cred.allowedEmails;
    }
  } else {
    if (requestedAgentId && requestedAgentId !== cred.id) {
      const { team, valid } = agentNetworkScope(cred.groups);
      if (!valid || team) {
        return c.json({ error: "agent_scope_mismatch" }, 403);
      }
      effectiveId = requestedAgentId;
    }
    if (reqClass || reqTeam) {
      if (!["shared", "free", "plus", "pro", "custom", "team"].includes(reqClass)) {
        return c.json({ error: "agent_scope_invalid" }, 400);
      }
      if ((reqClass !== "team" && reqTeam) || (reqClass === "team" && !reqTeam)) {
        return c.json({ error: "agent_scope_invalid" }, 400);
      }
      const { scope: cs, valid: cv } = await agentResourceScope(cred.groups);
      if (!cv) return c.json({ error: "agent_scope_invalid" }, 403);
      const isPublicManager =
        cred.groups.includes("agent:configure-public") ||
        (cred.groups.includes("internal") && cred.id === "*" && cs.resourceClass === "shared");
      if (reqClass === "custom" && cred.groups.includes("agent:configure-public")) {
        return c.json({ error: "agent_scope_mismatch" }, 403);
      }
      if (isPublicManager && cs.resourceClass !== "team" && cs.resourceClass !== "custom" && reqClass !== "team") {
        effectiveGroups = effectiveGroups.filter((g) => !g.startsWith("resource:"));
        effectiveGroups.push(`resource:${reqClass}`);
      } else if (cs.resourceClass !== reqClass || (cs.teamId ?? "") !== reqTeam) {
        return c.json({ error: "agent_scope_mismatch" }, 403);
      }
    }
    if (reqEmailPolicy || reqAllowedEmails) {
      const { scope } = await agentResourceScope(effectiveGroups);
      if (scope.resourceClass === "team") {
        return c.json({ error: "agent_email_policy_invalid" }, 400);
      }
      if (scope.resourceClass !== "custom") {
        if (!PUBLIC_CLASSES.has(scope.resourceClass) || reqEmailPolicy !== PUBLIC_EMAIL_UNION_POLICY) {
          return c.json({ error: "agent_email_policy_invalid" }, 400);
        }
        try {
          const emails = JSON.parse(reqAllowedEmails) as string[];
          if (!Array.isArray(emails)) throw new Error("not array");
          effectiveGroups = effectiveGroups.filter(
            (g) => !g.startsWith(UNION_EMAIL_PREFIX) && !g.startsWith("node-email-policy:"),
          );
          for (const e of emails) {
            effectiveGroups.push(`${UNION_EMAIL_PREFIX}${String(e).trim().toLowerCase()}`);
          }
          effectiveGroups.push(`node-email-policy:${PUBLIC_EMAIL_UNION_POLICY}`);
        } catch {
          return c.json({ error: "agent_email_policy_invalid" }, 400);
        }
      }
    }
  }

  const { scope, valid } = await agentResourceScope(effectiveGroups);
  if (!valid) {
    return c.json({ error: "agent_scope_invalid" }, 403);
  }

  const allowedEmailsKey = effectiveAllowedEmails
    ? JSON.stringify(effectiveAllowedEmails)
    : reqAllowedEmails;
  const cacheIdentity = await sha256Hex(
    `${effectiveId}\x00${cred.nodeId ?? ""}\x00${effectiveGroups.join(",")}\x00${allowedEmailsKey}`,
  );
  const cacheKeyUrl = `https://cache.xconnect.internal/api/agent-server/v1/users?key=${cacheIdentity}`;
  const ttlSec = parseDurationSeconds(c.env.XCONNECT_AGENT_USERS_CACHE_TTL, DEFAULT_AGENT_USERS_TTL_SEC);

  return respondWithEdgeCache(c, {
    cacheStore,
    cacheKeyUrl,
    ttlSeconds: ttlSec,
    contentType: "application/json; charset=utf-8",
    responseCacheControl: "no-store",
    compute: async () => {
      const now = deps.now ? deps.now() : new Date();
      const resp = await withClient(c.env, async (client) => {
        const [users, blockedIds, blacklistedEmails, teams, memberships, billingProfiles, quotaStates] =
          await Promise.all([
            listUsers(client),
            listBlockedUserIds(client),
            listBlacklistedEmails(client),
            listNetworkTeams(client),
            listNetworkMemberships(client),
            listBillingProfiles(client),
            listQuotaStates(client),
          ]);

        const routingPolicy = routingPolicyForScope(scope);
        const dualGateEnabled = parseBoolEnv(c.env.DUAL_BUCKET_PRO_GATE_ENABLED);
        const clients: AgentClient[] = [];

        for (const u of users) {
          if (!u.active || u.archivedAt) continue;
          const access = accessFromMembership(memberships.get(u.id), teams, now);
          if (!networkScopeAllows(access, effectiveGroups)) continue;
          const billing = billingProfiles.get(u.id);
          const pkg = billing?.packageName ?? "";
          const publicOverride =
            PUBLIC_CLASSES.has(scope.resourceClass) &&
            access.mode !== "dedicated" &&
            publicUnionEmails(effectiveGroups).includes(u.email.toLowerCase());
          if (!agentResourceScopeAllowsUser(scope, access, u, pkg) && !publicOverride) continue;
          if (blockedIds.has(u.id) || blacklistedEmails.has(u.email.toLowerCase())) continue;

          if (scope.resourceClass !== "custom" && scope.resourceClass !== "team") {
            const quota = quotaStates.get(u.id);
            const highSpeed =
              !isOneTimeTrialMember(u) && dualGateEnabled && scope.resourceClass === "pro";
            if (isQuotaExhausted(u, billing, quota, access, highSpeed, now)) continue;
          }
          if (!accountAccessVerified(u) || !u.proxyUuid) continue;
          clients.push({
            ID: u.proxyUuid,
            Email: u.email.toLowerCase(),
            Flow: DEFAULT_FLOW,
          });
        }

        clients.sort((a, b) => a.ID.localeCompare(b.ID));

        let finalClients = clients;
        if (scope.resourceClass === "custom") {
          let allowedList: string[] = [];
          try {
            const parsed = JSON.parse(allowedEmailsKey);
            if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > 256) {
              throw new OverlayError(400, "custom_emails_required", "custom_emails_required");
            }
            allowedList = parsed.map((e) => String(e).trim().toLowerCase());
          } catch (err) {
            if (err instanceof OverlayError) throw err;
            throw new OverlayError(400, "custom_emails_required", "custom_emails_required");
          }
          const staticIds = new Set<string>();
          finalClients = clients.filter((cl) => {
            if (allowedList.includes(cl.Email.toLowerCase())) {
              staticIds.add(cl.ID);
              return true;
            }
            return false;
          });
          if (cred.nodeId) {
            for (const u of users) {
              const exp = activeFreeGrantExpiresAt(u, cred.nodeId, now);
              if (!exp || !u.active || u.archivedAt) continue;
              if (blockedIds.has(u.id) || blacklistedEmails.has(u.email.toLowerCase())) continue;
              const access = accessFromMembership(memberships.get(u.id), teams, now);
              if (!networkScopeAllows(access, effectiveGroups) || access.mode === "dedicated") continue;
              const billing = billingProfiles.get(u.id);
              const pkg = billing?.packageName ?? "";
              if (effectiveAgentResourceClass(access, u, pkg) !== "free") continue;
              const quota = quotaStates.get(u.id);
              if (isQuotaExhausted(u, billing, quota, access, false, now)) continue;
              if (!accountAccessVerified(u) || !u.proxyUuid || staticIds.has(u.proxyUuid)) continue;
              finalClients.push({
                ID: u.proxyUuid,
                Email: u.email.toLowerCase(),
                Flow: DEFAULT_FLOW,
                expiresAt: exp.toISOString(),
              });
            }
            finalClients.sort((a, b) => a.ID.localeCompare(b.ID));
          }
        }

        const revision = await sha256Hex(
          JSON.stringify({ scope, routingPolicy, clients: finalClients }),
        );
        const payload: ClientListResponse = {
          agentId: effectiveId,
          ...(cred.nodeId ? { nodeId: cred.nodeId } : {}),
          scope,
          routingPolicy,
          clients: finalClients,
          total: finalClients.length,
          revision,
          generatedAt: now.toISOString(),
        };
        return payload;
      });
      return {
        body: JSON.stringify(resp),
        etag: `"${resp.revision}"`,
      };
    },
  });
}

export function handleUsersEventsSSEFallback(c: Context<{ Bindings: WorkerEnv }>): Response {
  c.header("X-XConnect-Fallback", "origin-go");
  c.header("Cache-Control", "no-store");
  return c.json(
    {
      error: "sse_requires_origin_go",
      message: "SSE user event stream is served by Go origin; retry against origin-go",
      fallback: "origin-go",
    },
    501,
  );
}

export async function handleListAgentNodes(
  c: Context<{ Bindings: WorkerEnv }>,
  deps: AgentServerDeps,
): Promise<Response> {
  const withClient = deps.withClient;
  if (!withClient) throw new Error("withClient dependency required");
  const cacheStore = resolveCacheStore(deps);
  const userId = await authenticateJWTAllowQuery(c, deps);

  const ttlSec = parseDurationSeconds(c.env.XCONNECT_AGENT_NODES_CACHE_TTL, DEFAULT_NODES_TTL_SEC);
  const cacheKeyUrl = `https://cache.xconnect.internal/api/agent-server/v1/nodes?user=${encodeURIComponent(userId)}`;

  return respondWithEdgeCache(c, {
    cacheStore,
    cacheKeyUrl,
    ttlSeconds: ttlSec,
    contentType: "application/json; charset=utf-8",
    responseCacheControl: "private, no-store",
    compute: async () => {
      const now = deps.now ? deps.now() : new Date();
      const data = await withClient(c.env, (client) => resolveUserNodesData(client, c.env, userId, now));
      return { body: JSON.stringify(data.vlessNodes) };
    },
  });
}

export async function handleGetSubscription(
  c: Context<{ Bindings: WorkerEnv }>,
  deps: AgentServerDeps,
): Promise<Response> {
  const withClient = deps.withClient;
  if (!withClient) throw new Error("withClient dependency required");
  const cacheStore = resolveCacheStore(deps);
  const userId = await authenticateJWTAllowQuery(c, deps);

  const rawFormat = (c.req.param("format") ?? c.req.query("format") ?? "").trim();
  const fmtNorm = rawFormat.toLowerCase() || "clash";
  const ttlSec = parseDurationSeconds(c.env.XCONNECT_AGENT_NODES_CACHE_TTL, DEFAULT_NODES_TTL_SEC);
  const cacheKeyUrl = `https://cache.xconnect.internal/api/auth/sync/subscription?user=${encodeURIComponent(userId)}&format=${encodeURIComponent(fmtNorm)}`;

  // Validate format upfront before cache check so invalid formats always return 400.
  renderSubscriptionPayload(rawFormat, {
    userId,
    userEmail: "",
    allowCustom: false,
    allowPro: false,
    nodes: [],
    now: new Date(0),
  });

  const contentType =
    fmtNorm === "vless" || fmtNorm === "uri" || fmtNorm === "raw"
      ? "text/plain; charset=utf-8"
      : ["singbox", "sing-box", "xray", "xray-json", "xrayjson", "v2ray", "one", "xconnect-one"].includes(
            fmtNorm,
          )
        ? "application/json; charset=utf-8"
        : "text/yaml; charset=utf-8";

  return respondWithEdgeCache(c, {
    cacheStore,
    cacheKeyUrl,
    ttlSeconds: ttlSec,
    contentType,
    responseCacheControl: "private, no-store",
    compute: async () => {
      const now = deps.now ? deps.now() : new Date();
      const data = await withClient(c.env, (client) => resolveUserNodesData(client, c.env, userId, now));
      const isTrial =
        isOneTimeTrialMember(data.user) || data.packageName.trim().toLowerCase() === "trial";
      const allowCustom =
        !isTrial &&
        (data.resourceClass === "custom" ||
          data.resourceClass === "team" ||
          (data.access.mode !== "dedicated" && isCustomDedicatedUser(data.user, data.packageName)));
      const allowPro = data.resourceClass === "pro" && !data.highSpeedExhausted;
      const rendered = renderSubscriptionPayload(rawFormat, {
        userId: data.user.id,
        userEmail: data.user.email,
        allowCustom,
        allowPro,
        nodes: data.subNodes,
        now,
      });
      return { body: rendered.body };
    },
  });
}

export async function handleSyncConfig(
  c: Context<{ Bindings: WorkerEnv }>,
  deps: AgentServerDeps,
): Promise<Response> {
  const withClient = deps.withClient;
  if (!withClient) throw new Error("withClient dependency required");
  const cacheStore = resolveCacheStore(deps);
  const userId = await authenticateJWTAllowQuery(c, deps);

  const rawSince = (c.req.query("since_version") ?? "").trim();
  let sinceVersion = 0;
  if (rawSince) {
    if (!/^\d+$/.test(rawSince)) {
      return c.json(
        { error: "invalid_since_version", message: "since_version must be a non-negative integer" },
        400,
      );
    }
    sinceVersion = Number.parseInt(rawSince, 10);
  }

  const ttlSec = parseDurationSeconds(c.env.XCONNECT_AGENT_NODES_CACHE_TTL, DEFAULT_NODES_TTL_SEC);
  const cacheKeyUrl = `https://cache.xconnect.internal/api/auth/sync/config?user=${encodeURIComponent(userId)}&since=${sinceVersion}`;

  return respondWithEdgeCache(c, {
    cacheStore,
    cacheKeyUrl,
    ttlSeconds: ttlSec,
    contentType: "application/json; charset=utf-8",
    responseCacheControl: "private, no-store",
    compute: async () => {
      const now = deps.now ? deps.now() : new Date();
      const data = await withClient(c.env, (client) => resolveUserNodesData(client, c.env, userId, now));
      const u = data.user;
      const version =
        u.updatedAt.getTime() > 0
          ? Math.floor(u.updatedAt.getTime() / 1000)
          : u.createdAt.getTime() > 0
            ? Math.floor(u.createdAt.getTime() / 1000)
            : Math.floor(now.getTime() / 1000);
      const updatedAt = u.updatedAt.getTime() > 0 ? u.updatedAt : now;
      const changed =
        sinceVersion < version || data.access.configured || data.access.mode === "dedicated";

      let hasMedia = false;
      let hasPro = false;
      let hasCustom = false;
      for (const pool of data.pools) {
        if (!pool.openToUsers) continue;
        if (pool.routingPool === ROUTING_POOL_PRO) hasPro = true;
        else if (pool.routingPool === ROUTING_POOL_CUSTOM) hasCustom = true;
        else hasMedia = true;
      }
      if (!hasMedia && !hasPro && !hasCustom) {
        if (data.resourceClass === "pro") {
          hasPro = !data.dualGateEnabled || !data.highSpeedExhausted;
          hasMedia = !data.dualGateEnabled || !data.vpsExhausted;
        } else if (data.resourceClass === "custom" || data.resourceClass === "team") {
          hasCustom = true;
        } else {
          hasMedia = true;
        }
      }

      const routes = buildThreeTierRoutes(hasMedia, hasPro, hasCustom);
      const profiles: unknown[] = [];
      const nodes: unknown[] = [];
      if (changed) {
        for (const sub of data.subNodes) {
          const nodeName = sub.name || resolveNodeName(sub.address);
          profiles.push({
            id: sub.id,
            remark: nodeName,
            display_name: nodeName,
            host: sub.address,
            address: sub.address,
            port: 443,
            uuid: sub.uuid,
            flow: "",
            transport: "xhttp",
            security: "tls",
            source: "server",
            country_code: sub.region ?? "",
            resource_class: data.resourceClass,
            routing_pool: sub.routingPool ?? ROUTING_POOL_MEDIA,
            pricing_group: sub.pricingGroup ?? data.resourceClass,
            vless_uri: sub.vlessUri ?? "",
          });
          nodes.push({
            id: sub.id,
            name: nodeName,
            display_name: nodeName,
            remark: nodeName,
            host: sub.address,
            protocol: "vless",
            transport: "xhttp",
            security: "tls",
            address: sub.address,
            port: 443,
            server_name: sub.address,
            uuid: sub.uuid,
            flow: "",
            source: "server",
            country_code: sub.region ?? "",
            resource_class: data.resourceClass,
            routing_pool: sub.routingPool ?? ROUTING_POOL_MEDIA,
            pricing_group: sub.pricingGroup ?? data.resourceClass,
            updated_at: updatedAt.toISOString(),
            vless_uri: sub.vlessUri ?? "",
            uri_scheme_xhttp: sub.vlessUri ?? "",
          });
        }
      }

      const payload = {
        network_access: {
          ...(data.access.accountId ? { accountId: data.access.accountId } : {}),
          mode: data.access.mode,
          ...(data.access.teamId ? { teamId: data.access.teamId } : {}),
          ...(data.access.team ? { team: data.access.team } : {}),
          allowed: data.access.allowed,
        },
        schema_version: 1,
        changed,
        version,
        updated_at: updatedAt.toISOString(),
        profiles,
        nodes,
        rendered_json: "",
        routes,
        dns: { mode: "secure_tunnel", servers: [] },
        meta: { digest: "", warnings: [] },
        digest: "",
        warnings: [],
      };
      return { body: JSON.stringify(payload) };
    },
  });
}
