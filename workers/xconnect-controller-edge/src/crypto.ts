import {
  DEFAULT_PROTECTED_FLOWS,
  POLICY_COMPILER_VERSION,
  type Endpoint,
  type GatewayPeer,
  type GatewaySignedConfig,
  type GatewayTransport,
  type MeshSpec,
  type PolicyArtifact,
  type PolicyReference,
  type PolicyRule,
  type RelaySpec,
  type SignedConfig,
  type SigningKey,
  type Transport,
  type WireGuard,
  type WireGuardPeer,
  type WorkerEnv,
} from "./types.ts";

// ASN.1 PKCS#8 header wrapping a 32-byte raw Ed25519 private seed:
// SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING <32 bytes> } }
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

export function formatRFC3339Seconds(input: Date | string): string {
  const date = typeof input === "string" ? new Date(input) : input;
  const truncated = new Date(Math.floor(date.getTime() / 1000) * 1000);
  return truncated.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function decodeBase64Flexible(raw: string): Uint8Array {
  const trimmed = raw.trim();
  const normalized = trimmed.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + "=".repeat(padLen);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

export function encodeBase64Std(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

export function encodeBase64Url(bytes: Uint8Array): string {
  return encodeBase64Std(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function computeETag(input: string | Uint8Array): Promise<string> {
  return `"${await sha256Hex(input)}"`;
}

export function etagMatches(ifNoneMatch: string | undefined, etag: string): boolean {
  const header = (ifNoneMatch ?? "").trim();
  const target = etag.trim();
  if (!header || !target) return false;
  return header.split(",").some((part) => {
    const candidate = part.trim();
    return candidate === "*" || candidate === target || candidate.replace(/^W\//, "") === target;
  });
}

export interface ImportedEd25519Key {
  signingKey: CryptoKey;
  publicKeyRaw: Uint8Array;
  publicKeyBase64: string;
}

export async function importEd25519PrivateKey(base64Key: string): Promise<ImportedEd25519Key> {
  const decoded = decodeBase64Flexible(base64Key);
  let seed: Uint8Array;
  let knownPub: Uint8Array | undefined;
  if (decoded.length === 32) {
    seed = decoded;
  } else if (decoded.length === 64) {
    // Go crypto/ed25519 PrivateKey is 64 bytes: 32-byte seed || 32-byte public key.
    seed = decoded.slice(0, 32);
    knownPub = decoded.slice(32, 64);
  } else {
    throw new Error(`invalid Ed25519 private key length: ${decoded.length}`);
  }

  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + 32);
  pkcs8.set(ED25519_PKCS8_PREFIX, 0);
  pkcs8.set(seed, ED25519_PKCS8_PREFIX.length);

  // Extractable is needed only if we need to export JWK `x` to derive publicKeyRaw.
  const extractable = !knownPub;
  const signingKey = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", extractable, ["sign"]);

  let publicKeyRaw: Uint8Array;
  if (knownPub) {
    publicKeyRaw = knownPub;
  } else {
    const jwk = (await crypto.subtle.exportKey("jwk", signingKey)) as JsonWebKey;
    if (!jwk.x) {
      throw new Error("failed to derive Ed25519 public key from private seed");
    }
    publicKeyRaw = decodeBase64Flexible(jwk.x);
  }

  return {
    signingKey,
    publicKeyRaw,
    publicKeyBase64: encodeBase64Std(publicKeyRaw),
  };
}

export async function importEd25519PublicKey(base64Key: string): Promise<CryptoKey> {
  const raw = decodeBase64Flexible(base64Key);
  if (raw.length !== 32) {
    throw new Error(`invalid Ed25519 public key length: ${raw.length}`);
  }
  return crypto.subtle.importKey("raw", raw, "Ed25519", false, ["verify"]);
}

export async function signEd25519(signingKey: CryptoKey, message: string | Uint8Array): Promise<string> {
  const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  const sig = await crypto.subtle.sign("Ed25519", signingKey, bytes);
  return encodeBase64Std(new Uint8Array(sig));
}

export async function verifyEd25519(
  publicKey: CryptoKey,
  message: string | Uint8Array,
  signatureBase64: string,
): Promise<boolean> {
  const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  const sig = decodeBase64Flexible(signatureBase64);
  if (sig.length !== 64) return false;
  return crypto.subtle.verify("Ed25519", publicKey, sig, bytes);
}

function canonicalEndpoint(e: Endpoint): Endpoint {
  return { host: e.host, port: e.port };
}

function canonicalTransport(t: Transport): Transport {
  const out: Transport = {
    kind: t.kind,
    loopback: canonicalEndpoint(t.loopback),
    remote: {
      host: t.remote.host,
      port: t.remote.port,
      server_name: t.remote.server_name,
    },
    auth_id: t.auth_id,
  };
  if (t.path) out.path = t.path;
  if (t.mode) out.mode = t.mode;
  if (t.host) out.host = t.host;
  return out;
}

function canonicalWireGuardPeer(p: WireGuardPeer): WireGuardPeer {
  const out: WireGuardPeer = {
    gateway_id: p.gateway_id,
    public_key: p.public_key,
    allowed_ips: [...p.allowed_ips],
    endpoint: canonicalEndpoint(p.endpoint),
  };
  if (p.persistent_keepalive_seconds) {
    out.persistent_keepalive_seconds = p.persistent_keepalive_seconds;
  }
  return out;
}

function canonicalWireGuard(w: WireGuard): WireGuard {
  return {
    interface_name: w.interface_name,
    addresses: [...w.addresses],
    mtu: w.mtu,
    peers: (w.peers ?? []).map(canonicalWireGuardPeer),
  };
}

function canonicalPolicyReference(p: PolicyReference): PolicyReference {
  return {
    generation: p.generation,
    digest: p.digest,
    path: p.path,
    media_type: p.media_type,
  };
}

function canonicalPolicyRule(r: PolicyRule): PolicyRule {
  return {
    id: r.id,
    ...(r.description ? { description: r.description } : {}),
    action: r.action,
    ...(r.source_devices && r.source_devices.length > 0
      ? { source_devices: [...r.source_devices] }
      : {}),
    ...(r.destination_devices && r.destination_devices.length > 0
      ? { destination_devices: [...r.destination_devices] }
      : {}),
    ...(r.protocols && r.protocols.length > 0 ? { protocols: [...r.protocols] } : {}),
    ...(r.ports && r.ports.length > 0 ? { ports: [...r.ports] } : {}),
    ...(r.priority ? { priority: r.priority } : {}),
  };
}

export function canonicalPolicyArtifact(p: PolicyArtifact): PolicyArtifact {
  return {
    schema_version: p.schema_version,
    compiler_version: p.compiler_version,
    network_id: p.network_id,
    revision: p.revision,
    default_action: p.default_action,
    ...(p.protected_flows && p.protected_flows.length > 0
      ? { protected_flows: [...p.protected_flows] }
      : {}),
    rules: (p.rules ?? []).map(canonicalPolicyRule),
  };
}

export function canonicalPolicyJSON(p: PolicyArtifact): string {
  return JSON.stringify(canonicalPolicyArtifact(p));
}

export function defaultPolicyArtifact(networkId: string, generation: number): PolicyArtifact {
  return {
    schema_version: 1,
    compiler_version: POLICY_COMPILER_VERSION,
    network_id: networkId,
    revision: generation,
    default_action: "deny",
    protected_flows: [...DEFAULT_PROTECTED_FLOWS],
    rules: [],
  };
}

export function clientPolicyArtifact(p: PolicyArtifact): PolicyArtifact {
  return defaultPolicyArtifact(p.network_id, p.revision);
}

export function clientSigningBytes(cfg: Omit<SignedConfig, "signature"> | SignedConfig): string {
  const base = {
    schema_version: cfg.schema_version,
    config_id: cfg.config_id,
    network_id: cfg.network_id,
    device_id: cfg.device_id,
    generation: cfg.generation,
    issued_at: formatRFC3339Seconds(cfg.issued_at),
    expires_at: formatRFC3339Seconds(cfg.expires_at),
    proxy_core: cfg.proxy_core,
    transport: canonicalTransport(cfg.transport),
    wireguard: canonicalWireGuard(cfg.wireguard),
  };
  if (cfg.schema_version === 1) {
    return JSON.stringify(base);
  }
  const v2: Record<string, unknown> = {
    ...base,
    policy: cfg.policy ? canonicalPolicyReference(cfg.policy) : null,
  };
  if (cfg.mesh) {
    v2.mesh = {
      peers: cfg.mesh.peers.map((p) => ({
        device_id: p.device_id,
        public_key: p.public_key,
        address: p.address,
      })),
    } satisfies MeshSpec;
  }
  return JSON.stringify(v2);
}

function canonicalGatewayPeer(p: GatewayPeer): GatewayPeer {
  return {
    device_id: p.device_id,
    wireguard_public_key: p.wireguard_public_key,
    wireguard_address: p.wireguard_address,
    allowed_ips: p.allowed_ips,
  };
}

function canonicalGatewayTransport(t: GatewayTransport): GatewayTransport {
  const out: GatewayTransport = {
    kind: t.kind,
    server_name: t.server_name,
    port: t.port,
    auth_id: t.auth_id,
  };
  if (t.path) out.path = t.path;
  if (t.mode) out.mode = t.mode;
  if (t.host) out.host = t.host;
  if (t.frontend) out.frontend = t.frontend;
  if (t.listen_socket) out.listen_socket = t.listen_socket;
  return out;
}

export function gatewaySigningBytes(cfg: Omit<GatewaySignedConfig, "signature"> | GatewaySignedConfig): string {
  const out: Record<string, unknown> = {
    schema_version: cfg.schema_version,
    role: cfg.role,
    config_id: cfg.config_id,
    network_id: cfg.network_id,
    gateway_id: cfg.gateway_id,
    generation: cfg.generation,
    issued_at: formatRFC3339Seconds(cfg.issued_at),
    expires_at: formatRFC3339Seconds(cfg.expires_at),
  };
  const mode = (cfg.connection_mode ?? "").trim();
  if (mode) {
    out.connection_mode = mode;
  }
  out.interface_name = cfg.interface_name;
  out.address = cfg.address;
  out.listen_port = cfg.listen_port;
  out.mtu = cfg.mtu;
  out.peers = (cfg.peers ?? []).map(canonicalGatewayPeer);
  out.transport = canonicalGatewayTransport(cfg.transport);
  if (cfg.mesh) {
    out.mesh = {
      peers: cfg.mesh.peers.map((p) => ({
        device_id: p.device_id,
        public_key: p.public_key,
        allowed_peers: [...p.allowed_peers],
      })),
    } satisfies RelaySpec;
  }
  if (cfg.schema_version !== 1 && cfg.policy) {
    out.policy = canonicalPolicyArtifact(cfg.policy);
  }
  return JSON.stringify(out);
}

export interface SigningContext {
  keyId: string;
  signingKey: CryptoKey;
  publicKeyBase64: string;
  previousKeyId?: string;
  previousPublicKeyBase64?: string;
  previousNotAfter?: Date;
}

export async function loadSigningContext(env: WorkerEnv): Promise<SigningContext> {
  const keyId = (env.XCONNECT_OVERLAY_SIGNING_KEY_ID ?? "").trim() || "zero-signing-current";
  const privateRaw = (env.XCONNECT_OVERLAY_SIGNING_PRIVATE_KEY ?? "").trim();
  if (!privateRaw) {
    throw new Error("XCONNECT_OVERLAY_SIGNING_PRIVATE_KEY is required");
  }
  const imported = await importEd25519PrivateKey(privateRaw);

  let previousKeyId = (env.XCONNECT_OVERLAY_PREVIOUS_SIGNING_KEY_ID ?? "").trim() || undefined;
  const previousPublicRaw = (env.XCONNECT_OVERLAY_PREVIOUS_SIGNING_PUBLIC_KEY ?? "").trim();
  let previousPublicKeyBase64: string | undefined;
  if (previousPublicRaw) {
    const pubBytes = decodeBase64Flexible(previousPublicRaw);
    if (pubBytes.length !== 32) {
      throw new Error("XCONNECT_OVERLAY_PREVIOUS_SIGNING_PUBLIC_KEY must be a 32-byte Ed25519 public key");
    }
    previousPublicKeyBase64 = encodeBase64Std(pubBytes);
    previousKeyId = previousKeyId ?? "zero-signing-previous";
  }

  let previousNotAfter: Date | undefined;
  const notAfterRaw = (env.XCONNECT_OVERLAY_PREVIOUS_SIGNING_NOT_AFTER ?? "").trim();
  if (notAfterRaw) {
    const parsed = new Date(notAfterRaw);
    if (Number.isNaN(parsed.getTime())) {
      throw new Error("XCONNECT_OVERLAY_PREVIOUS_SIGNING_NOT_AFTER must be RFC3339 timestamp");
    }
    previousNotAfter = parsed;
  }

  return {
    keyId,
    signingKey: imported.signingKey,
    publicKeyBase64: imported.publicKeyBase64,
    previousKeyId,
    previousPublicKeyBase64,
    previousNotAfter,
  };
}

export function buildSigningKeysList(ctx: SigningContext, now = new Date()): SigningKey[] {
  const notBefore = formatRFC3339Seconds(new Date(now.getTime() - 60_000));
  const keys: SigningKey[] = [
    {
      key_id: ctx.keyId,
      algorithm: "Ed25519",
      public_key: ctx.publicKeyBase64,
      status: "current",
      not_before: notBefore,
    },
  ];
  if (ctx.previousPublicKeyBase64 && ctx.previousPublicKeyBase64 !== ctx.publicKeyBase64) {
    const notAfterDate = ctx.previousNotAfter ?? new Date(now.getTime() + 24 * 3600_000);
    if (notAfterDate.getTime() > now.getTime()) {
      keys.push({
        key_id: ctx.previousKeyId ?? "zero-signing-previous",
        algorithm: "Ed25519",
        public_key: ctx.previousPublicKeyBase64,
        status: "previous",
        not_before: notBefore,
        not_after: formatRFC3339Seconds(notAfterDate),
      });
    }
  }
  return keys;
}

export async function configID(networkId: string, deviceId: string, generation: number): Promise<string> {
  const sum = await sha256Hex(`${networkId}\x00${deviceId}\x00${generation}`);
  return `cfg_${sum.slice(0, 32)}`;
}

export function newOpaqueToken(prefix: string): string {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return prefix + encodeBase64Url(buf);
}

export function randomHex(byteLength: number): string {
  const buf = new Uint8Array(byteLength);
  crypto.getRandomValues(buf);
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function newId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, "")}`;
}

export function validOpaque(value: string, prefix: string): boolean {
  if (!value || value !== value.trim() || !value.startsWith(prefix)) return false;
  try {
    return decodeBase64Flexible(value.slice(prefix.length)).length === 32;
  } catch {
    return false;
  }
}
