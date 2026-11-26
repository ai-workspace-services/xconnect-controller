import { Client } from "pg";
import {
  buildSigningKeysList,
  canonicalPolicyJSON,
  clientPolicyArtifact,
  clientSigningBytes,
  computeETag,
  configID,
  defaultPolicyArtifact,
  formatRFC3339Seconds,
  gatewaySigningBytes,
  newId,
  newOpaqueToken,
  randomHex,
  sha256Hex,
  signEd25519,
  validOpaque,
  type SigningContext,
} from "./crypto.ts";
import {
  DEFAULT_CONNECTION_MODE,
  DEFAULT_GATEWAY_LISTEN_SOCKET,
  DEFAULT_TRANSPORT_MODE,
  DEFAULT_TRANSPORT_PATH,
  GATEWAY_FRONTEND_CADDY_UNIX_H2C,
  GATEWAY_FRONTEND_DIRECT_TLS,
  POLICY_MEDIA_TYPE,
  ROLE_GATEWAY,
  ROLE_ONE,
  TRANSPORT_VLESS_XHTTP,
  type Device,
  type DeviceSessionRequest,
  type DeviceSessionResponse,
  type ExchangeRequest,
  type ExchangeResponse,
  type GatewayPeer,
  type GatewaySignedConfig,
  type Network,
  type PolicyArtifact,
  type SignedConfig,
  type SignedConfigAckRequest,
  type SignedConfigAckResponse,
  type UserGatewaySummary,
  type WorkerEnv,
} from "./types.ts";

export class OverlayError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export const ErrInvalidInput = () => new OverlayError(400, "invalid_request", "Bad Request");
export const ErrInvalidToken = () => new OverlayError(401, "invalid_token", "Unauthorized");
export const ErrInviteConstraint = () =>
  new OverlayError(403, "invite_constraint_mismatch", "Forbidden");
export const ErrForbidden = () => new OverlayError(403, "resource_access_denied", "Forbidden");
export const ErrNotFound = () => new OverlayError(404, "resource_not_found", "Not Found");
export const ErrDeviceConflict = () => new OverlayError(409, "resource_conflict", "Conflict");
export const ErrGenerationConflict = () =>
  new OverlayError(409, "resource_conflict", "Conflict");

const DEVICE_ID_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const ALLOWED_PLATFORMS = new Set(["linux", "darwin", "windows", "ios", "android"]);

interface NetworkRow {
  id: string;
  display_name: string;
  cidr: string;
  gateway_id: string;
  gateway_wireguard_key: string;
  gateway_wireguard_address: string;
  gateway_endpoint_host: string;
  gateway_endpoint_port: number;
  transport_server_name: string;
  transport_port: number;
  transport_auth_id: string;
  transport_kind: string;
  transport_path: string;
  transport_mode: string;
  transport_host: string;
  gateway_frontend: string;
  gateway_listen_socket: string;
  connection_mode: string;
  owner_user_id: string;
  policy_json?: string;
  config_generation: string | number;
  created_at: Date | string;
  updated_at: Date | string;
}

interface DeviceRow {
  id: string;
  user_uuid: string;
  user_id: string;
  network_id: string;
  role: string;
  name: string;
  platform: string;
  hostname: string;
  wireguard_public_key: string;
  wireguard_address: string;
  status: string;
  last_seen_at: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string;
}

interface CredentialRow {
  id: string;
  device_id: string;
  credential_id: string;
  token_hash: string;
  issued_at: Date | string;
  expires_at: Date | string;
  revoked_at: Date | string | null;
}

interface EnrollmentRow {
  id: string;
  device_id: string;
  token_hash: string;
  issued_at: Date | string;
  expires_at: Date | string;
  consumed_at: Date | string | null;
}

interface InviteRow {
  id: string;
  network_id: string;
  token_hash: string;
  device_id: string | null;
  platform: string | null;
  role: string;
  expires_at: Date | string;
  remaining_uses: number;
  consumed_at: Date | string | null;
}

export interface ServiceOptions {
  localProxyPort: number;
  enrollmentTTLMs: number;
  credentialTTLMs: number;
  signedConfigTTLMs: number;
  defaultGatewayFrontend: string;
  defaultGatewayListenSocket: string;
}

export function serviceOptionsFromEnv(env: WorkerEnv): ServiceOptions {
  let localProxyPort = 51830;
  if (env.XCONNECT_OVERLAY_LOCAL_PROXY_PORT?.trim()) {
    const parsed = Number.parseInt(env.XCONNECT_OVERLAY_LOCAL_PROXY_PORT.trim(), 10);
    if (Number.isFinite(parsed) && parsed >= 1024 && parsed <= 65535) {
      localProxyPort = parsed;
    }
  }
  return {
    localProxyPort,
    enrollmentTTLMs: 15 * 60_000,
    credentialTTLMs: 365 * 24 * 3600_000,
    signedConfigTTLMs: 10 * 60_000,
    defaultGatewayFrontend:
      (env.XCONNECT_GATEWAY_XRAY_FRONTEND ?? "").trim() || GATEWAY_FRONTEND_DIRECT_TLS,
    defaultGatewayListenSocket:
      (env.XCONNECT_GATEWAY_XRAY_LISTEN_SOCKET ?? "").trim() || DEFAULT_GATEWAY_LISTEN_SOCKET,
  };
}

export async function withPgClient<T>(
  env: WorkerEnv,
  fn: (client: Client) => Promise<T>,
): Promise<T> {
  const conn = env.HYPERDRIVE?.connectionString;
  if (!conn) {
    throw new Error("HYPERDRIVE binding is not configured");
  }
  const client = new Client({ connectionString: conn });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

function parseIPv4(ip: string): number {
  const parts = ip.split(".").map((n) => Number.parseInt(n, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    throw ErrInvalidInput();
  }
  return (((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0);
}

function formatIPv4(num: number): string {
  return [
    (num >>> 24) & 0xff,
    (num >>> 16) & 0xff,
    (num >>> 8) & 0xff,
    num & 0xff,
  ].join(".");
}

function parseCIDR(cidr: string): { base: number; mask: number; size: number } {
  const [ipStr, prefixStr] = cidr.trim().split("/");
  const prefix = Number.parseInt(prefixStr ?? "", 10);
  if (!ipStr || Number.isNaN(prefix) || prefix < 8 || prefix > 30) {
    throw ErrInvalidInput();
  }
  const ip = parseIPv4(ipStr);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const base = (ip & mask) >>> 0;
  const size = 2 ** (32 - prefix);
  return { base, mask, size };
}

function defaultGatewayAddress(network: NetworkRow): string {
  const configured = (network.gateway_wireguard_address ?? "").trim();
  if (configured) return configured;
  const { base } = parseCIDR(network.cidr);
  return `${formatIPv4((base + 1) >>> 0)}/32`;
}

async function allocateAddress(client: Client, network: NetworkRow): Promise<string> {
  const { base, size } = parseCIDR(network.cidr);
  let gatewayAddr = (base + 1) >>> 0;
  const configured = (network.gateway_wireguard_address ?? "").trim();
  if (configured) {
    const [ipPart] = configured.split("/");
    gatewayAddr = parseIPv4(ipPart);
  }
  const existing = await client.query<{ wireguard_address: string }>(
    `SELECT wireguard_address FROM overlay_devices WHERE network_id = $1`,
    [network.id],
  );
  const used = new Set(existing.rows.map((r) => r.wireguard_address));
  for (let offset = 1; offset < size - 1; offset++) {
    const candidate = (base + offset) >>> 0;
    if (candidate === gatewayAddr) continue;
    const addr = `${formatIPv4(candidate)}/32`;
    if (!used.has(addr)) {
      return addr;
    }
  }
  throw new OverlayError(500, "overlay_internal_error", "overlay network address pool exhausted");
}

function resolveTransport(network: NetworkRow) {
  return {
    kind: (network.transport_kind ?? "").trim() || TRANSPORT_VLESS_XHTTP,
    path: (network.transport_path ?? "").trim() || DEFAULT_TRANSPORT_PATH,
    mode: (network.transport_mode ?? "").trim() || DEFAULT_TRANSPORT_MODE,
    host: (network.transport_host ?? "").trim() || undefined,
  };
}

function resolveGatewayFrontend(network: NetworkRow, opts: ServiceOptions): { frontend: string; socket?: string } {
  const frontend =
    (network.gateway_frontend ?? "").trim() || opts.defaultGatewayFrontend || GATEWAY_FRONTEND_DIRECT_TLS;
  if (frontend !== GATEWAY_FRONTEND_DIRECT_TLS && frontend !== GATEWAY_FRONTEND_CADDY_UNIX_H2C) {
    throw ErrInvalidInput();
  }
  if (frontend === GATEWAY_FRONTEND_DIRECT_TLS) {
    return { frontend };
  }
  const socket = (network.gateway_listen_socket ?? "").trim() || opts.defaultGatewayListenSocket;
  return { frontend, socket };
}

function toNetwork(row: NetworkRow): Network {
  const mode = (row.connection_mode ?? "").trim() || DEFAULT_CONNECTION_MODE;
  const out: Network = {
    id: row.id,
    display_name: row.display_name,
    cidr: row.cidr,
    gateway_id: row.gateway_id,
    gateway_wireguard_public_key: row.gateway_wireguard_key,
    gateway_endpoint_host: row.gateway_endpoint_host,
    gateway_endpoint_port: Number(row.gateway_endpoint_port),
    transport_server_name: row.transport_server_name,
    transport_port: Number(row.transport_port),
    transport_auth_id: row.transport_auth_id,
    transport_kind: row.transport_kind,
  } as Network;
  if (row.transport_path) out.transport_path = row.transport_path;
  if (row.transport_mode) out.transport_mode = row.transport_mode;
  if (row.transport_host) out.transport_host = row.transport_host;
  if (row.gateway_frontend) out.gateway_frontend = row.gateway_frontend;
  if (row.gateway_listen_socket) out.gateway_listen_socket = row.gateway_listen_socket;
  out.connection_mode = mode;
  out.config_generation = Number(row.config_generation);
  out.created_at = formatRFC3339Seconds(row.created_at);
  out.updated_at = formatRFC3339Seconds(row.updated_at);
  return out;
}

function toDevice(row: DeviceRow): Device {
  const out: Device = {
    id: row.id,
    network_id: row.network_id,
    name: row.name,
    platform: row.platform,
    hostname: row.hostname,
    wireguard_public_key: row.wireguard_public_key,
    wireguard_address: row.wireguard_address,
  };
  if (row.user_id) out.user_id = row.user_id;
  if (row.role === ROLE_GATEWAY) out.role = ROLE_GATEWAY;
  out.created_at = formatRFC3339Seconds(row.created_at);
  out.updated_at = formatRFC3339Seconds(row.updated_at);
  if (row.last_seen_at) out.last_seen_at = formatRFC3339Seconds(row.last_seen_at);
  return out;
}

function parsePolicyArtifact(network: NetworkRow): PolicyArtifact {
  const gen = Number(network.config_generation) || 1;
  const raw = (network.policy_json ?? "").trim();
  if (!raw) {
    return defaultPolicyArtifact(network.id, gen);
  }
  const parsed = JSON.parse(raw) as PolicyArtifact;
  if (parsed.network_id !== network.id || Number(parsed.revision) !== gen) {
    throw ErrGenerationConflict();
  }
  return parsed;
}

async function loadActiveEnrollment(
  client: Client,
  rawToken: string,
  now: Date,
): Promise<{ enrollment: EnrollmentRow; device: DeviceRow; network: NetworkRow }> {
  const tokenHash = await sha256Hex(rawToken);
  const enrRes = await client.query<EnrollmentRow>(
    `SELECT id, device_id, token_hash, issued_at, expires_at, consumed_at
     FROM overlay_enrollment_sessions WHERE token_hash = $1 LIMIT 1`,
    [tokenHash],
  );
  const enrollment = enrRes.rows[0];
  if (
    !enrollment ||
    enrollment.consumed_at !== null ||
    new Date(enrollment.expires_at).getTime() <= now.getTime()
  ) {
    throw ErrInvalidToken();
  }

  const devRes = await client.query<DeviceRow>(
    `SELECT * FROM overlay_devices WHERE id = $1 LIMIT 1`,
    [enrollment.device_id],
  );
  const device = devRes.rows[0];
  if (!device) {
    throw ErrInvalidToken();
  }

  const netRes = await client.query<NetworkRow>(
    `SELECT * FROM overlay_networks WHERE id = $1 LIMIT 1`,
    [device.network_id],
  );
  const network = netRes.rows[0];
  if (!network) {
    throw ErrNotFound();
  }
  return { enrollment, device, network };
}

async function advanceNetworkGenerationTx(client: Client, network: NetworkRow): Promise<number> {
  const currentGen = Number(network.config_generation) || 1;
  const nextGen = currentGen + 1;
  let nextPolicyJSON = network.policy_json ?? "";
  if (nextPolicyJSON.trim()) {
    const policy = JSON.parse(nextPolicyJSON) as PolicyArtifact;
    if (policy.network_id !== network.id || Number(policy.revision) !== currentGen) {
      throw ErrGenerationConflict();
    }
    policy.revision = nextGen;
    nextPolicyJSON = JSON.stringify(policy);
  }
  const res = await client.query(
    `UPDATE overlay_networks
     SET config_generation = $1, policy_json = $2, updated_at = NOW()
     WHERE id = $3 AND config_generation = $4`,
    [nextGen, nextPolicyJSON, network.id, currentGen],
  );
  if (res.rowCount !== 1) {
    throw ErrGenerationConflict();
  }
  network.config_generation = nextGen;
  network.policy_json = nextPolicyJSON;
  return nextGen;
}

export async function pingDatabase(client: Client): Promise<void> {
  await client.query("SELECT 1");
}

export async function mintDeviceSession(
  client: Client,
  signingCtx: SigningContext,
  opts: ServiceOptions,
  rawCredential: string,
  req: DeviceSessionRequest,
  now = new Date(),
): Promise<DeviceSessionResponse> {
  const nonce = (req.client_nonce ?? "").trim();
  if (!nonce || nonce.length > 128) {
    throw ErrInvalidInput();
  }
  const credHash = await sha256Hex(rawCredential);
  const credRes = await client.query<CredentialRow>(
    `SELECT * FROM overlay_device_credentials WHERE token_hash = $1 LIMIT 1`,
    [credHash],
  );
  const cred = credRes.rows[0];
  if (
    !cred ||
    cred.revoked_at !== null ||
    new Date(cred.expires_at).getTime() <= now.getTime()
  ) {
    throw ErrInvalidToken();
  }

  const devRes = await client.query<DeviceRow>(
    `SELECT * FROM overlay_devices WHERE id = $1 LIMIT 1`,
    [cred.device_id],
  );
  const device = devRes.rows[0];
  if (!device || device.status !== "active") {
    throw ErrInvalidToken();
  }

  const netRes = await client.query<NetworkRow>(
    `SELECT id FROM overlay_networks WHERE id = $1 LIMIT 1`,
    [device.network_id],
  );
  const network = netRes.rows[0];
  if (!network) {
    throw ErrNotFound();
  }

  const enrollmentSecret = newOpaqueToken("xenr_");
  const enrollmentHash = await sha256Hex(enrollmentSecret);
  const issuedAt = new Date(Math.floor(now.getTime() / 1000) * 1000);
  const expiresAt = new Date(issuedAt.getTime() + opts.enrollmentTTLMs);

  await client.query(
    `INSERT INTO overlay_enrollment_sessions (id, device_id, token_hash, issued_at, expires_at, created_at)
     VALUES ($1, $2, $3, $4, $5, $4)`,
    [newId("enr"), device.id, enrollmentHash, issuedAt.toISOString(), expiresAt.toISOString()],
  );

  return {
    client_nonce: nonce,
    enrollment_token: enrollmentSecret,
    token_type: "Bearer",
    issued_at: formatRFC3339Seconds(issuedAt),
    expires_at: formatRFC3339Seconds(expiresAt),
    scope: ["overlay:config:read", "overlay:config:ack"],
    device_id: device.id,
    network_id: network.id,
    signing_keys: buildSigningKeysList(signingCtx, issuedAt),
  };
}

export async function getEnrollmentSignedConfig(
  client: Client,
  signingCtx: SigningContext,
  opts: ServiceOptions,
  rawToken: string,
  deviceIdQuery: string,
  networkIdQuery: string,
  v2: boolean,
  now = new Date(),
): Promise<{ config: SignedConfig; etag: string }> {
  const { device, network } = await loadActiveEnrollment(client, rawToken, now);
  if (deviceIdQuery.trim() !== device.id || (networkIdQuery && networkIdQuery !== network.id)) {
    throw ErrForbidden();
  }
  const generation = Number(network.config_generation) || 1;
  const issuedAt = new Date(Math.floor(now.getTime() / 1000) * 1000);
  const expiresAt = new Date(issuedAt.getTime() + opts.signedConfigTTLMs);
  const cfgId = await configID(network.id, device.id, generation);
  const t = resolveTransport(network);

  const unsigned: Omit<SignedConfig, "signature"> = {
    schema_version: v2 ? 2 : 1,
    config_id: cfgId,
    network_id: network.id,
    device_id: device.id,
    generation,
    issued_at: formatRFC3339Seconds(issuedAt),
    expires_at: formatRFC3339Seconds(expiresAt),
    proxy_core: "xray",
    transport: {
      kind: t.kind,
      loopback: { host: "127.0.0.1", port: opts.localProxyPort },
      remote: {
        host: network.gateway_endpoint_host,
        port: Number(network.transport_port),
        server_name: network.transport_server_name,
      },
      auth_id: network.transport_auth_id,
      ...(t.path ? { path: t.path } : {}),
      ...(t.mode ? { mode: t.mode } : {}),
      ...(t.host ? { host: t.host } : {}),
    },
    wireguard: {
      interface_name: "xconone0",
      addresses: [device.wireguard_address],
      mtu: 1420,
      peers: [
        {
          gateway_id: network.gateway_id,
          public_key: network.gateway_wireguard_key,
          allowed_ips: [network.cidr],
          endpoint: { host: "127.0.0.1", port: opts.localProxyPort },
          persistent_keepalive_seconds: 12,
        },
      ],
    },
  };

  if (v2) {
    const gwPolicy = parsePolicyArtifact(network);
    const clientPolicy = canonicalPolicyJSON(clientPolicyArtifact(gwPolicy));
    const digest = await sha256Hex(clientPolicy);
    unsigned.policy = {
      generation,
      digest,
      path: `/api/overlay/v1/enrollment/policy-artifacts/${generation}/${digest}`,
      media_type: POLICY_MEDIA_TYPE,
    };
  }

  const bytes = clientSigningBytes(unsigned);
  const sigValue = await signEd25519(signingCtx.signingKey, bytes);
  const fullConfig: SignedConfig = {
    ...unsigned,
    signature: { algorithm: "Ed25519", key_id: signingCtx.keyId, value: sigValue },
  };
  const etag = await computeETag(JSON.stringify(fullConfig));
  return { config: fullConfig, etag };
}

export async function getGatewaySignedConfig(
  client: Client,
  signingCtx: SigningContext,
  opts: ServiceOptions,
  rawToken: string,
  v2: boolean,
  now = new Date(),
): Promise<{ config: GatewaySignedConfig; etag: string }> {
  const { device, network } = await loadActiveEnrollment(client, rawToken, now);
  if (device.status !== "active" || device.role !== ROLE_GATEWAY || device.id !== network.gateway_id) {
    throw ErrForbidden();
  }

  const peersRes = await client.query<DeviceRow>(
    `SELECT id, role, wireguard_public_key, wireguard_address
     FROM overlay_devices
     WHERE network_id = $1 AND status = 'active'
     ORDER BY id ASC`,
    [network.id],
  );
  const peers: GatewayPeer[] = peersRes.rows
    .filter((d) => d.role === ROLE_ONE)
    .map((d) => ({
      device_id: d.id,
      wireguard_public_key: d.wireguard_public_key,
      wireguard_address: d.wireguard_address,
      allowed_ips: d.wireguard_address,
    }));

  const generation = Number(network.config_generation) || 1;
  const issuedAt = new Date(Math.floor(now.getTime() / 1000) * 1000);
  const expiresAt = new Date(issuedAt.getTime() + opts.signedConfigTTLMs);
  const cfgId = await configID(network.id, network.gateway_id, generation);
  const t = resolveTransport(network);
  const { frontend, socket } = resolveGatewayFrontend(network, opts);
  const connectionMode = (network.connection_mode ?? "").trim() || DEFAULT_CONNECTION_MODE;

  const unsigned: Omit<GatewaySignedConfig, "signature"> = {
    schema_version: v2 ? 2 : 1,
    role: ROLE_GATEWAY,
    config_id: cfgId,
    network_id: network.id,
    gateway_id: network.gateway_id,
    generation,
    issued_at: formatRFC3339Seconds(issuedAt),
    expires_at: formatRFC3339Seconds(expiresAt),
    connection_mode: connectionMode,
    interface_name: "xconzero0",
    address: defaultGatewayAddress(network),
    listen_port: Number(network.gateway_endpoint_port),
    mtu: 1420,
    peers,
    transport: {
      kind: t.kind,
      server_name: network.transport_server_name,
      port: Number(network.transport_port),
      auth_id: network.transport_auth_id,
      ...(t.path ? { path: t.path } : {}),
      ...(t.mode ? { mode: t.mode } : {}),
      ...(t.host ? { host: t.host } : {}),
      ...(frontend ? { frontend } : {}),
      ...(socket ? { listen_socket: socket } : {}),
    },
  };

  if (v2) {
    unsigned.policy = parsePolicyArtifact(network);
  }

  const bytes = gatewaySigningBytes(unsigned);
  const sigValue = await signEd25519(signingCtx.signingKey, bytes);
  const fullConfig: GatewaySignedConfig = {
    ...unsigned,
    signature: { algorithm: "Ed25519", key_id: signingCtx.keyId, value: sigValue },
  };
  const etag = await computeETag(JSON.stringify(fullConfig));
  return { config: fullConfig, etag };
}

export async function ackEnrollment(
  client: Client,
  rawToken: string,
  generation: number,
  req: SignedConfigAckRequest,
  now = new Date(),
): Promise<SignedConfigAckResponse> {
  const { device, network } = await loadActiveEnrollment(client, rawToken, now);
  const expectedCfgId = await configID(network.id, device.id, generation);
  if (req.device_id !== device.id || req.config_id !== expectedCfgId || !req.applied_at) {
    throw ErrForbidden();
  }
  const currentGen = Number(network.config_generation) || 1;
  if (generation !== currentGen) {
    throw ErrGenerationConflict();
  }

  const existing = await client.query<{
    device_id: string;
    config_id: string;
    generation: string | number;
    applied_at: Date | string;
    received_at: Date | string;
  }>(
    `SELECT device_id, config_id, generation, applied_at, received_at
     FROM overlay_signed_config_acks
     WHERE device_id = $1 AND generation = $2 LIMIT 1`,
    [device.id, generation],
  );
  const nowStr = formatRFC3339Seconds(now);

  if (existing.rows[0]) {
    const row = existing.rows[0];
    if (row.config_id !== req.config_id || row.device_id !== req.device_id) {
      throw ErrGenerationConflict();
    }
    await client.query(`UPDATE overlay_devices SET last_seen_at = $1, updated_at = $1 WHERE id = $2`, [
      nowStr,
      device.id,
    ]);
    return {
      acked: true,
      duplicate: true,
      ack: {
        device_id: row.device_id,
        config_id: row.config_id,
        generation: Number(row.generation),
        applied_at: formatRFC3339Seconds(row.applied_at),
        received_at: formatRFC3339Seconds(row.received_at),
      },
    };
  }

  const appliedStr = formatRFC3339Seconds(req.applied_at);
  await client.query(
    `INSERT INTO overlay_signed_config_acks (id, device_id, network_id, generation, config_id, applied_at, received_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [crypto.randomUUID(), device.id, network.id, generation, req.config_id, appliedStr, nowStr],
  );
  await client.query(`UPDATE overlay_devices SET last_seen_at = $1, updated_at = $1 WHERE id = $2`, [
    nowStr,
    device.id,
  ]);
  return {
    acked: true,
    duplicate: false,
    ack: {
      device_id: device.id,
      config_id: req.config_id,
      generation,
      applied_at: appliedStr,
      received_at: nowStr,
    },
  };
}

export async function getPolicyArtifact(
  client: Client,
  rawToken: string,
  generation: number,
  digest: string,
  now = new Date(),
): Promise<string> {
  const { device, network } = await loadActiveEnrollment(client, rawToken, now);
  if (generation !== (Number(network.config_generation) || 1) || device.status !== "active") {
    throw ErrForbidden();
  }
  const gwPolicy = parsePolicyArtifact(network);
  const raw = canonicalPolicyJSON(clientPolicyArtifact(gwPolicy));
  const actualDigest = await sha256Hex(raw);
  if (actualDigest !== digest.trim()) {
    throw ErrNotFound();
  }
  return raw;
}

export async function exchangeJoinToken(
  client: Client,
  signingCtx: SigningContext,
  opts: ServiceOptions,
  req: ExchangeRequest,
  now = new Date(),
): Promise<ExchangeResponse> {
  const role = req.role || ROLE_ONE;
  if (
    !validOpaque(req.join_token, "xjt_") ||
    !DEVICE_ID_RE.test(req.device_id) ||
    !ALLOWED_PLATFORMS.has(req.platform) ||
    (role !== ROLE_ONE && role !== ROLE_GATEWAY) ||
    (req.name && req.name.length > 255) ||
    (req.hostname && req.hostname.length > 255)
  ) {
    throw ErrInvalidInput();
  }

  const tokenHash = await sha256Hex(req.join_token);
  const nowISO = formatRFC3339Seconds(now);
  const credRawID = randomHex(16);
  const credentialID = `xdcid_${credRawID}`;
  const credentialSecret = `xdc_${credRawID}.${newOpaqueToken("")}`;
  const enrollmentSecret = newOpaqueToken("xenr_");
  const credHash = await sha256Hex(credentialSecret);
  const enrollHash = await sha256Hex(enrollmentSecret);
  const credExpires = formatRFC3339Seconds(new Date(now.getTime() + opts.credentialTTLMs));
  const enrollExpires = formatRFC3339Seconds(new Date(now.getTime() + opts.enrollmentTTLMs));

  await client.query("BEGIN");
  try {
    const consumeRes = await client.query<InviteRow>(
      `UPDATE overlay_invites
       SET remaining_uses = 0, consumed_at = $1
       WHERE token_hash = $2 AND remaining_uses > 0 AND expires_at > $1 AND consumed_at IS NULL
       RETURNING *`,
      [nowISO, tokenHash],
    );
    const invite = consumeRes.rows[0];
    if (!invite) {
      throw ErrInvalidToken();
    }
    if (
      (invite.device_id && invite.device_id !== req.device_id) ||
      (invite.platform && invite.platform !== req.platform) ||
      (invite.role && invite.role !== role)
    ) {
      throw ErrInviteConstraint();
    }

    const netRes = await client.query<NetworkRow>(
      `SELECT * FROM overlay_networks WHERE id = $1 FOR UPDATE`,
      [invite.network_id],
    );
    const network = netRes.rows[0];
    if (!network) {
      throw ErrNotFound();
    }
    if (invite.role === ROLE_GATEWAY && req.wireguard_public_key !== network.gateway_wireguard_key) {
      throw ErrInvalidInput();
    }

    const existingRes = await client.query<DeviceRow>(
      `SELECT * FROM overlay_devices WHERE id = $1 AND network_id = $2 FOR UPDATE`,
      [req.device_id, invite.network_id],
    );
    let device: DeviceRow;

    if (existingRes.rows[0]) {
      const existing = existingRes.rows[0];
      if (invite.role === ROLE_GATEWAY) {
        if (
          existing.role !== ROLE_GATEWAY ||
          existing.status !== "active" ||
          existing.wireguard_public_key !== req.wireguard_public_key ||
          existing.id !== network.gateway_id
        ) {
          throw ErrDeviceConflict();
        }
        await client.query(
          `UPDATE overlay_device_credentials SET revoked_at = $1 WHERE device_id = $2 AND revoked_at IS NULL`,
          [nowISO, existing.id],
        );
        device = existing;
      } else {
        if (
          existing.role !== ROLE_ONE ||
          req.device_id === network.gateway_id ||
          req.wireguard_public_key === network.gateway_wireguard_key
        ) {
          throw ErrDeviceConflict();
        }
        const conflictRes = await client.query<{ cnt: string }>(
          `SELECT COUNT(*)::text AS cnt FROM overlay_devices
           WHERE network_id = $1 AND id <> $2 AND wireguard_public_key = $3`,
          [network.id, existing.id, req.wireguard_public_key],
        );
        if (Number.parseInt(conflictRes.rows[0]?.cnt ?? "0", 10) > 0) {
          throw ErrDeviceConflict();
        }
        const address = existing.wireguard_address.trim() || (await allocateAddress(client, network));
        const needsGenBump =
          existing.wireguard_public_key !== req.wireguard_public_key ||
          existing.status !== "active" ||
          existing.wireguard_address !== address;

        await client.query(
          `UPDATE overlay_device_credentials SET revoked_at = $1 WHERE device_id = $2 AND revoked_at IS NULL`,
          [nowISO, existing.id],
        );
        const updRes = await client.query<DeviceRow>(
          `UPDATE overlay_devices
           SET name = $1, platform = $2, hostname = $3, wireguard_public_key = $4,
               wireguard_address = $5, status = 'active', updated_at = $6
           WHERE id = $7 AND network_id = $8
           RETURNING *`,
          [
            req.name ?? existing.name,
            req.platform,
            req.hostname ?? existing.hostname,
            req.wireguard_public_key,
            address,
            nowISO,
            existing.id,
            network.id,
          ],
        );
        device = updRes.rows[0];
        if (needsGenBump) {
          await advanceNetworkGenerationTx(client, network);
        }
      }
    } else {
      const address =
        invite.role === ROLE_GATEWAY
          ? defaultGatewayAddress(network)
          : await allocateAddress(client, network);
      const insRes = await client.query<DeviceRow>(
        `INSERT INTO overlay_devices
         (id, user_uuid, user_id, network_id, role, name, platform, hostname,
          wireguard_public_key, wireguard_address, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active', $11, $11)
         RETURNING *`,
        [
          req.device_id,
          network.owner_user_id,
          network.owner_user_id,
          invite.network_id,
          invite.role,
          req.name ?? req.device_id,
          req.platform,
          req.hostname ?? req.device_id,
          req.wireguard_public_key,
          address,
          nowISO,
        ],
      );
      device = insRes.rows[0];
      await advanceNetworkGenerationTx(client, network);
    }

    await client.query(
      `INSERT INTO overlay_device_credentials
       (id, device_id, credential_id, token_hash, issued_at, expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $5)`,
      [newId("cred"), device.id, credentialID, credHash, nowISO, credExpires],
    );
    await client.query(
      `INSERT INTO overlay_enrollment_sessions
       (id, device_id, token_hash, issued_at, expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $4)`,
      [newId("enr"), device.id, enrollHash, nowISO, enrollExpires],
    );
    await client.query("COMMIT");

    return {
      enrollment_token: enrollmentSecret,
      token_type: "Bearer",
      expires_at: enrollExpires,
      scope: ["overlay:config:read", "overlay:config:ack", "overlay:device:revoke"],
      device_credential: {
        credential_id: credentialID,
        credential: credentialSecret,
        token_type: "Device",
        issued_at: nowISO,
        expires_at: credExpires,
        scope: ["overlay:session:mint", "overlay:credential:rotate", "overlay:device:revoke"],
      },
      device: toDevice(device),
      network: toNetwork(network),
      signing_keys: buildSigningKeysList(signingCtx, now),
    };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  }
}

export async function listUserGateways(
  client: Client,
  userId: string,
  now = new Date(),
): Promise<UserGatewaySummary[]> {
  const res = await client.query<{
    id: string;
    display_name: string;
    cidr: string;
    gateway_id: string;
    gateway_endpoint_host: string;
    gateway_endpoint_port: number;
    transport_server_name: string;
    transport_port: number;
    connection_mode: string;
    gw_last_seen_at: Date | string | null;
    tel_healthy: boolean | null;
    tel_updated_at: Date | string | null;
  }>(
    `SELECT n.id, n.display_name, n.cidr, n.gateway_id, n.gateway_endpoint_host,
            n.gateway_endpoint_port, n.transport_server_name, n.transport_port,
            n.connection_mode,
            d.last_seen_at AS gw_last_seen_at,
            t.healthy AS tel_healthy,
            t.updated_at AS tel_updated_at
     FROM overlay_networks n
     LEFT JOIN overlay_devices d
       ON d.network_id = n.id AND d.role = 'gateway' AND d.status = 'active'
     LEFT JOIN overlay_device_telemetry t
       ON t.network_id = n.id AND t.role = 'gateway'
     WHERE n.owner_user_id = $1
        OR n.id IN (SELECT network_id FROM overlay_devices WHERE user_id = $1 AND status = 'active')
        OR n.id IN (SELECT network_id FROM overlay_network_members WHERE user_id = $1)
     ORDER BY n.id ASC`,
    [userId],
  );

  const recentCutoff = now.getTime() - 5 * 60_000;
  return res.rows.map((row) => {
    let healthy = false;
    let lastSeenAt: string | undefined;
    if (row.gw_last_seen_at) {
      const ts = new Date(row.gw_last_seen_at);
      lastSeenAt = formatRFC3339Seconds(ts);
      if (ts.getTime() <= now.getTime() && ts.getTime() >= recentCutoff) {
        healthy = true;
      }
    }
    if (typeof row.tel_healthy === "boolean") {
      healthy = row.tel_healthy;
      if (!lastSeenAt && row.tel_updated_at) {
        lastSeenAt = formatRFC3339Seconds(row.tel_updated_at);
      }
    }
    const summary: UserGatewaySummary = {
      network_id: row.id,
      display_name: row.display_name,
      cidr: row.cidr,
      gateway_id: row.gateway_id,
      gateway_endpoint_host: row.gateway_endpoint_host,
      gateway_endpoint_port: Number(row.gateway_endpoint_port),
      transport_server_name: row.transport_server_name,
      transport_port: Number(row.transport_port),
      connection_mode: (row.connection_mode ?? "").trim() || DEFAULT_CONNECTION_MODE,
      runtime_healthy: healthy,
    };
    if (lastSeenAt) summary.last_seen_at = lastSeenAt;
    return summary;
  });
}
