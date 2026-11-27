package agentproto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/mail"
	"sort"
	"strings"
	"time"
)

const (
	// DefaultFlow is applied to VLESS TCP clients when no explicit flow is provided.
	DefaultFlow = "xtls-rprx-vision"

	// PublicEmailUnionPolicy identifies the explicit public-node email union extension.
	PublicEmailUnionPolicy = "public-union-v1"
)

// Client represents an authorized VLESS client returned to edge agents.
type Client struct {
	ID        string     `json:"ID"`
	Email     string     `json:"Email"`
	Flow      string     `json:"Flow"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// ClientListResponse represents the payload returned by GET /api/agent-server/v1/users.
type ClientListResponse struct {
	AgentID          string         `json:"agentId,omitempty"`
	NodeID           string         `json:"nodeId,omitempty"`
	EnrollmentStatus string         `json:"enrollmentStatus,omitempty"`
	Scope            *UserScope     `json:"scope,omitempty"`
	RoutingPolicy    *RoutingPolicy `json:"routingPolicy,omitempty"`
	Clients          []Client       `json:"clients"`
	Total            int            `json:"total"`
	GeneratedAt      time.Time      `json:"generatedAt"`
	Revision         string         `json:"revision,omitempty"`
}

// RoutingPolicy conveys the controller's authoritative pool and three-tier
// traffic-split policy to an edge agent for its authenticated scope.
type RoutingPolicy struct {
	Version             int      `json:"version"`
	Revision            string   `json:"revision"`
	Pool                string   `json:"pool"`
	PublicResource      bool     `json:"publicResource"`
	MediaOnProAction    string   `json:"mediaOnProAction"`
	FallbackDefault     bool     `json:"fallbackDefault,omitempty"`
	Unlimited           bool     `json:"unlimited,omitempty"`
	PricingGroups       []string `json:"pricingGroups,omitempty"`
	SubPoolTags         []string `json:"subPoolTags,omitempty"`
	DirectDomains       []string `json:"directDomains,omitempty"`
	DirectIPs           []string `json:"directIps,omitempty"`
	MediaDomains        []string `json:"mediaDomains,omitempty"`
	ProWhitelistDomains []string `json:"proWhitelistDomains,omitempty"`
}

// UserScope is derived from an enrolled credential or an administrator-approved
// node assignment. Node-supplied team suggestions never grant authorization.
type UserScope struct {
	EmailPolicy     string `json:"emailPolicy,omitempty"`
	EmailDigest     string `json:"emailDigest,omitempty"`
	CustomAllowFree bool   `json:"customAllowFree,omitempty"`
	ResourceClass   string `json:"resourceClass"`
	TeamID          string `json:"teamId,omitempty"`
}

// StatusReport captures the runtime state of an agent and the managed Xray instance.
type StatusReport struct {
	Overlay          *OverlayStatus    `json:"overlay,omitempty"`
	GatewayTelemetry *GatewayTelemetry `json:"gatewayTelemetry,omitempty"`
	AgentID          string            `json:"agentId"`
	Role             string            `json:"role,omitempty"`
	Healthy          bool              `json:"healthy"`
	Message          string            `json:"message,omitempty"`
	Users            int               `json:"users"`
	SyncRevision     string            `json:"syncRevision,omitempty"`
	Xray             XrayStatus        `json:"xray"`
}

// XrayStatus describes the synchronisation state of the managed Xray process.
type XrayStatus struct {
	CustomAllowFree bool       `json:"customAllowFree,omitempty"`
	AllowedEmails   []string   `json:"allowedEmails,omitempty"`
	Running         bool       `json:"running"`
	Clients         int        `json:"clients"`
	LastSync        *time.Time `json:"lastSync,omitempty"`
	ConfigHash      string     `json:"configHash,omitempty"`
	NodeID          string     `json:"nodeId,omitempty"`
	NetworkID       string     `json:"networkId,omitempty"`
	Region          string     `json:"region,omitempty"`
	Pool            string     `json:"pool,omitempty"`
	EntryPoint      string     `json:"entryPoint,omitempty"`
	OpenToUsers     *bool      `json:"openToUsers,omitempty"`
	LineCode        string     `json:"lineCode,omitempty"`
	PricingGroup    string     `json:"pricingGroup,omitempty"`
	RoutingPool     string     `json:"routingPool,omitempty"`
	SubPoolTags     []string   `json:"subPoolTags,omitempty"`
	StatsEnabled    bool       `json:"statsEnabled"`
	XrayRevision    string     `json:"xrayRevision,omitempty"`
}

// NormalizeNodeEmails validates, deduplicates, lowercases, and sorts node email lists.
func NormalizeNodeEmails(emails []string) ([]string, error) {
	if len(emails) > 256 {
		return nil, errors.New("node email list exceeds 256 entries")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(emails))
	for _, raw := range emails {
		email := strings.ToLower(strings.TrimSpace(raw))
		parsed, err := mail.ParseAddress(email)
		if err != nil || parsed.Address != email || strings.ContainsAny(email, "*?") {
			return nil, errors.New("invalid node email (wildcards and display names forbidden)")
		}
		if !seen[email] {
			seen[email] = true
			out = append(out, email)
		}
	}
	sort.Strings(out)
	return out, nil
}

// NodeEmailDigest computes the deterministic SHA-256 digest of a normalized email list.
func NodeEmailDigest(emails []string) string {
	sum := sha256.Sum256([]byte(strings.Join(emails, "\n")))
	return hex.EncodeToString(sum[:])
}

// PublicResourceClass reports whether class is one of the public discovery pools.
func PublicResourceClass(class string) bool {
	switch class {
	case "shared", "free", "plus", "pro":
		return true
	}
	return false
}
