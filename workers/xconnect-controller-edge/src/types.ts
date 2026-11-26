export const ROLE_GATEWAY = "gateway";
export const ROLE_ONE = "one";

export const TRANSPORT_VLESS_XHTTP = "vless-xhttp";
export const DEFAULT_TRANSPORT_PATH = "/xconnect";
export const DEFAULT_TRANSPORT_MODE = "auto";
export const GATEWAY_FRONTEND_DIRECT_TLS = "direct-tls";
export const GATEWAY_FRONTEND_CADDY_UNIX_H2C = "caddy-unix-h2c";
export const DEFAULT_GATEWAY_LISTEN_SOCKET = "/run/xconnect-gateway/xray.sock";
export const DEFAULT_CONNECTION_MODE = "wg_vless_l3";

export const SIGNED_CONFIG_V2_MEDIA_TYPE = "application/vnd.xconnect.signed-config.v2+json";
export const GATEWAY_SIGNED_CONFIG_V2_MEDIA_TYPE = "application/vnd.xconnect.gateway-config.v2+json";
export const POLICY_MEDIA_TYPE = "application/vnd.xconnect.policy.v1+json";
export const POLICY_COMPILER_VERSION = "xconnect-acl-v1alpha1.1";

export const DEFAULT_PROTECTED_FLOWS = [
  "control:controller-session",
  "control:gateway-apply-result",
  "control:gateway-heartbeat",
  "control:gateway-policy-artifact",
  "control:gateway-snapshot",
] as const;

export interface Endpoint {
  host: string;
  port: number;
}

export interface RemoteEndpoint {
  host: string;
  port: number;
  server_name: string;
}

export interface Transport {
  kind: string;
  loopback: Endpoint;
  remote: RemoteEndpoint;
  auth_id: string;
  path?: string;
  mode?: string;
  host?: string;
}

export interface WireGuardPeer {
  gateway_id: string;
  public_key: string;
  allowed_ips: string[];
  endpoint: Endpoint;
  persistent_keepalive_seconds?: number;
}

export interface WireGuard {
  interface_name: string;
  addresses: string[];
  mtu: number;
  peers: WireGuardPeer[];
}

export interface PolicyReference {
  generation: number;
  digest: string;
  path: string;
  media_type: string;
}

export interface MeshPeer {
  device_id: string;
  public_key: string;
  address: string;
}

export interface MeshSpec {
  peers: MeshPeer[];
}

export interface Signature {
  algorithm: string;
  key_id: string;
  value: string;
}

export interface SignedConfig {
  schema_version: number;
  config_id: string;
  network_id: string;
  device_id: string;
  generation: number;
  issued_at: string;
  expires_at: string;
  proxy_core: string;
  transport: Transport;
  wireguard: WireGuard;
  policy?: PolicyReference;
  mesh?: MeshSpec;
  signature: Signature;
}

export interface GatewayPeer {
  device_id: string;
  wireguard_public_key: string;
  wireguard_address: string;
  allowed_ips: string;
}

export interface GatewayTransport {
  kind: string;
  server_name: string;
  port: number;
  auth_id: string;
  path?: string;
  mode?: string;
  host?: string;
  frontend?: string;
  listen_socket?: string;
}

export interface RelayPeer {
  device_id: string;
  public_key: string;
  allowed_peers: string[];
}

export interface RelaySpec {
  peers: RelayPeer[];
}

export interface PolicyRule {
  id: string;
  description?: string;
  action: "allow" | "deny";
  source_devices?: string[];
  destination_devices?: string[];
  protocols?: string[];
  ports?: number[];
  priority?: number;
}

export interface PolicyArtifact {
  schema_version: number;
  compiler_version: string;
  network_id: string;
  revision: number;
  default_action: "allow" | "deny";
  protected_flows?: string[];
  rules: PolicyRule[];
}

export interface GatewaySignedConfig {
  schema_version: number;
  role: string;
  config_id: string;
  network_id: string;
  gateway_id: string;
  generation: number;
  issued_at: string;
  expires_at: string;
  connection_mode?: string;
  interface_name: string;
  address: string;
  listen_port: number;
  mtu: number;
  peers: GatewayPeer[];
  transport: GatewayTransport;
  mesh?: RelaySpec;
  policy?: PolicyArtifact;
  signature: Signature;
}

export interface SigningKey {
  key_id: string;
  algorithm: string;
  public_key: string;
  status: "current" | "previous";
  not_before: string;
  not_after?: string;
}

export interface Network {
  id: string;
  display_name: string;
  cidr: string;
  gateway_id: string;
  gateway_wireguard_public_key: string;
  gateway_endpoint_host: string;
  gateway_endpoint_port: number;
  transport_server_name: string;
  transport_port: number;
  transport_auth_id: string;
  transport_kind: string;
  transport_path?: string;
  transport_mode?: string;
  transport_host?: string;
  gateway_frontend?: string;
  gateway_listen_socket?: string;
  connection_mode?: string;
  config_generation?: number;
  created_at: string;
  updated_at: string;
}

export interface Device {
  id: string;
  user_id?: string;
  network_id: string;
  role?: string;
  name: string;
  platform: string;
  hostname: string;
  wireguard_public_key: string;
  wireguard_address: string;
  created_at?: string;
  updated_at?: string;
  last_seen_at?: string;
}

export interface DeviceCredential {
  credential_id: string;
  credential: string;
  token_type: string;
  issued_at: string;
  expires_at: string;
  scope: string[];
}

export interface ExchangeRequest {
  join_token: string;
  device_id: string;
  name?: string;
  platform: string;
  hostname?: string;
  wireguard_public_key: string;
  role?: string;
}

export interface ExchangeResponse {
  enrollment_token: string;
  token_type: string;
  expires_at: string;
  scope: string[];
  device_credential: DeviceCredential;
  device: Device;
  network: Network;
  signing_keys: SigningKey[];
}

export interface DeviceSessionRequest {
  client_nonce: string;
}

export interface DeviceSessionResponse {
  client_nonce: string;
  enrollment_token: string;
  token_type: string;
  issued_at: string;
  expires_at: string;
  scope: string[];
  device_id: string;
  network_id: string;
  signing_keys: SigningKey[];
}

export interface SignedConfigAckRequest {
  device_id: string;
  config_id: string;
  generation?: number;
  applied_at: string;
}

export interface SignedConfigAck {
  device_id: string;
  config_id: string;
  generation: number;
  applied_at: string;
  received_at: string;
}

export interface SignedConfigAckResponse {
  acked: boolean;
  duplicate: boolean;
  ack: SignedConfigAck;
}

export interface UserGatewaySummary {
  network_id: string;
  display_name: string;
  cidr: string;
  gateway_id: string;
  gateway_endpoint_host: string;
  gateway_endpoint_port: number;
  transport_server_name: string;
  transport_port: number;
  connection_mode: string;
  runtime_healthy: boolean;
  last_seen_at?: string;
}

export interface WorkerEnv {
  HYPERDRIVE: Hyperdrive;
  ACCOUNTS_JWKS_URL?: string;
  JWT_ACCESS_SECRET?: string;
  XCONNECT_OVERLAY_REQUIRE_SIGNING_KEY?: string;
  XCONNECT_OVERLAY_SIGNING_KEY_ID?: string;
  XCONNECT_OVERLAY_SIGNING_PRIVATE_KEY?: string;
  XCONNECT_OVERLAY_PREVIOUS_SIGNING_KEY_ID?: string;
  XCONNECT_OVERLAY_PREVIOUS_SIGNING_PUBLIC_KEY?: string;
  XCONNECT_OVERLAY_PREVIOUS_SIGNING_NOT_AFTER?: string;
  XCONNECT_OVERLAY_LOCAL_PROXY_PORT?: string;
  XCONNECT_OVERLAY_MESH_NETWORKS?: string;
  XCONNECT_GATEWAY_XRAY_FRONTEND?: string;
  XCONNECT_GATEWAY_XRAY_LISTEN_SOCKET?: string;
}
