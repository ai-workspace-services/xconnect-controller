package agentproto

import "time"

// OverlayStatus is non-secret telemetry submitted by control agents.
type OverlayStatus struct {
	NetworkID    string        `json:"network_id"`
	DeviceID     string        `json:"device_id"`
	Role         string        `json:"role"`
	Capabilities []string      `json:"capabilities"`
	Healthy      bool          `json:"healthy"`
	UpdatedAt    time.Time     `json:"updated_at"`
	ExpiresAt    time.Time     `json:"expires_at"`
	Paths        []OverlayPath `json:"paths,omitempty"`
}

type OverlayPath struct {
	SentPackets     uint64 `json:"sent_packets"`
	ReceivedPackets uint64 `json:"received_packets"`
	DeviceID        string `json:"device_id"`
	Path            string `json:"path"`
	Endpoint        string `json:"endpoint,omitempty"`
	RTTMillis       int64  `json:"rtt_ms,omitempty"`
	Reason          string `json:"reason"`
}

type GatewayTelemetry struct {
	SchemaVersion       int                    `json:"schema_version"`
	NetworkID           string                 `json:"network_id"`
	GatewayID           string                 `json:"gateway_id"`
	EndpointHost        string                 `json:"endpoint_host,omitempty"`
	ConnectionMode      string                 `json:"connection_mode,omitempty"`
	AppliedConfigID     string                 `json:"applied_config_id,omitempty"`
	AppliedGeneration   uint64                 `json:"applied_generation,omitempty"`
	WireGuardRunning    bool                   `json:"wireguard_running"`
	XrayRunning         bool                   `json:"xray_running"`
	RelayRunning        bool                   `json:"relay_running"`
	RelayActiveSessions int                    `json:"relay_active_sessions,omitempty"`
	SampledAt           time.Time              `json:"sampled_at"`
	ExpiresAt           time.Time              `json:"expires_at"`
	Traffic             GatewayTrafficSummary  `json:"traffic"`
	Peers               []GatewayPeerTelemetry `json:"peers,omitempty"`
	TopApps             []GatewayAppTraffic    `json:"top_apps,omitempty"`
}

type GatewayTrafficSummary struct {
	RxBytesTotal    uint64 `json:"rx_bytes_total"`
	TxBytesTotal    uint64 `json:"tx_bytes_total"`
	InternetRxBytes uint64 `json:"internet_rx_bytes"`
	InternetTxBytes uint64 `json:"internet_tx_bytes"`
	PrivateRxBytes  uint64 `json:"private_rx_bytes"`
	PrivateTxBytes  uint64 `json:"private_tx_bytes"`
}

type GatewayPeerTelemetry struct {
	DeviceID          string     `json:"device_id"`
	WireGuardAddress  string     `json:"wireguard_address,omitempty"`
	Connected         bool       `json:"connected"`
	Path              string     `json:"path,omitempty"`
	Endpoint          string     `json:"endpoint,omitempty"`
	LatestHandshakeAt *time.Time `json:"latest_handshake_at,omitempty"`
	RxBytes           uint64     `json:"rx_bytes"`
	TxBytes           uint64     `json:"tx_bytes"`
	RTTMillis         int64      `json:"rtt_ms,omitempty"`
}

type GatewayAppTraffic struct {
	App         string `json:"app"`
	RxBytes     uint64 `json:"rx_bytes"`
	TxBytes     uint64 `json:"tx_bytes"`
	Connections int    `json:"connections"`
}
