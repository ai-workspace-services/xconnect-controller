package agentserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net/mail"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ai-workspace-services/xconnect-controller/internal/agentproto"
)

// Credential defines the authentication material assigned to a managed agent.
type Credential struct {
	NodeID        string   `yaml:"nodeId" json:"nodeId"`
	AllowedEmails []string `yaml:"allowedEmails" json:"allowedEmails"`
	ID            string   `yaml:"id" json:"id"`
	Name          string   `yaml:"name" json:"name"`
	Token         string   `yaml:"token" json:"token"`
	Groups        []string `yaml:"groups" json:"groups"`
}

// Config groups the credential set exposed through configuration.
type Config struct {
	Credentials []Credential `yaml:"credentials" json:"credentials"`
}

// Identity represents an authenticated agent instance.
type Identity struct {
	NodeID        string
	AllowedEmails []string
	ID            string
	Name          string
	Groups        []string
}

// StatusSnapshot captures the last reported status for an agent.
type StatusSnapshot struct {
	Agent     Identity
	Report    agentproto.StatusReport
	UpdatedAt time.Time
}

// AgentRecord mirrors the persistent agents table row from accounts.
type AgentRecord struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Groups        []string   `json:"groups"`
	Healthy       bool       `json:"healthy"`
	LastHeartbeat *time.Time `json:"lastHeartbeat,omitempty"`
	ClientsCount  int        `json:"clientsCount"`
	SyncRevision  string     `json:"syncRevision,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

// RegistryStore provides persistence operations used by Registry.
type RegistryStore interface {
	ListAgents(ctx context.Context) ([]*AgentRecord, error)
	UpsertAgent(ctx context.Context, agent *AgentRecord) error
}

// Registry manages agent credentials and status reports in-memory with optional DB backing.
type Registry struct {
	mu            sync.RWMutex
	credentials   map[[32]byte]Identity
	byID          map[string]Identity
	statuses      map[string]StatusSnapshot
	sandboxAgents map[string]bool
	store         RegistryStore
	logger        *slog.Logger
}

// LoadConfigFromEnv loads agent credentials from XCONNECT_AGENT_CREDENTIALS_JSON,
// AGENT_CREDENTIALS_JSON, XCONNECT_AGENT_CREDENTIALS_PATH, or falls back to
// INTERNAL_SERVICE_TOKEN as a wildcard credential.
func LoadConfigFromEnv() (Config, error) {
	rawJSON := strings.TrimSpace(os.Getenv("XCONNECT_AGENT_CREDENTIALS_JSON"))
	if rawJSON == "" {
		rawJSON = strings.TrimSpace(os.Getenv("AGENT_CREDENTIALS_JSON"))
	}
	if rawJSON != "" {
		var creds []Credential
		if strings.HasPrefix(rawJSON, "[") {
			if err := json.Unmarshal([]byte(rawJSON), &creds); err != nil {
				return Config{}, err
			}
			return Config{Credentials: creds}, nil
		}
		var cfg Config
		if err := json.Unmarshal([]byte(rawJSON), &cfg); err != nil {
			return Config{}, err
		}
		return cfg, nil
	}

	if path := strings.TrimSpace(os.Getenv("XCONNECT_AGENT_CREDENTIALS_PATH")); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, err
		}
		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, err
		}
		return cfg, nil
	}

	if token := strings.TrimSpace(os.Getenv("INTERNAL_SERVICE_TOKEN")); token != "" {
		return Config{
			Credentials: []Credential{{
				ID:     "*",
				Name:   "Internal Agents (Shared Token)",
				Token:  token,
				Groups: []string{"internal"},
			}},
		}, nil
	}

	return Config{}, nil
}

// NewRegistry constructs a registry from configuration, validating credentials
// and normalising their representation.
func NewRegistry(cfg Config) (*Registry, error) {
	r := &Registry{
		credentials:   make(map[[32]byte]Identity),
		byID:          make(map[string]Identity),
		statuses:      make(map[string]StatusSnapshot),
		sandboxAgents: make(map[string]bool),
		logger:        slog.Default().With("component", "agent-registry"),
	}

	nodes := make(map[string]bool)
	for _, cred := range cfg.Credentials {
		id := strings.TrimSpace(cred.ID)
		token := strings.TrimSpace(cred.Token)
		if id == "" {
			return nil, errors.New("agent credential id is required")
		}
		if token == "" {
			return nil, errors.New("agent credential token is required")
		}
		if _, exists := r.byID[id]; exists {
			return nil, errors.New("duplicate agent credential id: " + id)
		}

		nodeID := strings.TrimSpace(cred.NodeID)
		if nodeID != "" {
			if id == "*" || nodes[nodeID] {
				return nil, errors.New("node-bound credentials require a unique nodeId and dedicated id")
			}
			nodes[nodeID] = true
			scope := ""
			allowFree := false
			for _, group := range normalizeStrings(cred.Groups) {
				if group == "custom:allow-free" {
					allowFree = true
				}
				next := ""
				if strings.HasPrefix(group, "resource:") {
					next = strings.TrimPrefix(group, "resource:")
					switch next {
					case "shared", "free", "plus", "pro", "custom":
					default:
						return nil, errors.New("invalid node credential resource class")
					}
				}
				if strings.HasPrefix(group, "team:") && strings.TrimPrefix(group, "team:") != "" {
					next = "team"
				}
				if next != "" {
					if scope != "" && scope != next {
						return nil, errors.New("conflicting node credential scopes")
					}
					scope = next
				}
			}
			if scope == "" {
				return nil, errors.New("node credential requires an explicit resource or team scope")
			}
			if allowFree && scope != "custom" {
				return nil, errors.New("custom Free audience requires custom scope")
			}
			if (scope == "custom") != (len(cred.AllowedEmails) > 0) {
				return nil, errors.New("custom node credential requires an enrolled audience; other classes forbid it")
			}
			for _, email := range cred.AllowedEmails {
				parsed, err := mail.ParseAddress(email)
				if err != nil || parsed.Address != email {
					return nil, errors.New("invalid enrolled node audience email")
				}
			}
		}
		if len(cred.AllowedEmails) > 0 && nodeID == "" {
			return nil, errors.New("credential allowedEmails requires nodeId")
		}
		digest := sha256.Sum256([]byte(token))
		if _, exists := r.credentials[digest]; exists {
			return nil, errors.New("duplicate agent credential token")
		}

		identity := Identity{
			NodeID:        nodeID,
			AllowedEmails: append([]string(nil), cred.AllowedEmails...),
			ID:            id,
			Name:          strings.TrimSpace(cred.Name),
			Groups:        normalizeStrings(cred.Groups),
		}
		r.credentials[digest] = identity
		r.byID[id] = identity
	}

	return r, nil
}

// SetStore configures a persistence store for the registry.
func (r *Registry) SetStore(st RegistryStore) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.store = st
}

// SetLogger overrides the default logger.
func (r *Registry) SetLogger(logger *slog.Logger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if logger != nil {
		r.logger = logger
	}
}

// Authenticate validates the provided token and returns the associated agent identity.
func (r *Registry) Authenticate(token string) (*Identity, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, false
	}
	digest := sha256.Sum256([]byte(token))

	r.mu.RLock()
	identity, ok := r.credentials[digest]
	r.mu.RUnlock()
	if !ok {
		return nil, false
	}

	cp := identity
	return &cp, true
}

// EnrolledNode returns the configured credential identity for a canonical node ID.
func (r *Registry) EnrolledNode(nodeID string) (Identity, bool) {
	if nodeID == "" {
		return Identity{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, identity := range r.credentials {
		if identity.NodeID == nodeID {
			return identity, true
		}
	}
	return Identity{}, false
}

// ReportStatus records the status report for the provided agent identity.
func (r *Registry) ReportStatus(agent Identity, report agentproto.StatusReport) {
	r.mu.Lock()
	r.byID[agent.ID] = agent
	r.statuses[agent.ID] = StatusSnapshot{
		Agent:     agent,
		Report:    report,
		UpdatedAt: time.Now().UTC(),
	}
	st := r.store
	logger := r.logger
	r.mu.Unlock()

	if st != nil {
		go func(a Identity, rep agentproto.StatusReport) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			now := time.Now().UTC()
			dbAgent := &AgentRecord{
				ID:            a.ID,
				Name:          a.Name,
				Groups:        a.Groups,
				Healthy:       rep.Healthy,
				LastHeartbeat: &now,
				ClientsCount:  rep.Xray.Clients,
				SyncRevision:  rep.SyncRevision,
			}
			if err := st.UpsertAgent(ctx, dbAgent); err != nil && logger != nil {
				logger.Error("failed to persist agent status heartbeat", "agent", a.ID, "err", err)
			}
		}(agent, report)
	}
}

// RegisterAgent dynamically registers an agent with the given ID if it doesn't already exist.
func (r *Registry) RegisterAgent(agentID string, groups []string) Identity {
	r.mu.Lock()
	if identity, exists := r.byID[agentID]; exists {
		r.mu.Unlock()
		return identity
	}

	identity := Identity{
		ID:     agentID,
		Name:   agentID,
		Groups: append([]string(nil), groups...),
	}
	r.byID[agentID] = identity
	st := r.store
	logger := r.logger
	r.mu.Unlock()

	if st != nil {
		go func(id string, g []string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			dbAgent := &AgentRecord{
				ID:     id,
				Name:   id,
				Groups: g,
			}
			if err := st.UpsertAgent(ctx, dbAgent); err != nil && logger != nil {
				logger.Error("failed to persist dynamically registered agent", "agent", id, "err", err)
			}
		}(agentID, groups)
	}

	return identity
}

// Load populates the registry from the persistence store.
func (r *Registry) Load(ctx context.Context) error {
	r.mu.RLock()
	st := r.store
	r.mu.RUnlock()
	if st == nil {
		return nil
	}
	agents, err := st.ListAgents(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range agents {
		if _, exists := r.byID[a.ID]; !exists {
			identity := Identity{
				ID:     a.ID,
				Name:   a.Name,
				Groups: a.Groups,
			}
			r.byID[a.ID] = identity
			if a.LastHeartbeat != nil {
				r.statuses[a.ID] = StatusSnapshot{
					Agent: identity,
					Report: agentproto.StatusReport{
						AgentID:      a.ID,
						Healthy:      a.Healthy,
						Users:        a.ClientsCount,
						SyncRevision: a.SyncRevision,
						Xray: agentproto.XrayStatus{
							Clients: a.ClientsCount,
						},
					},
					UpdatedAt: *a.LastHeartbeat,
				}
			}
		}
	}
	return nil
}

// Statuses returns the latest status snapshot for all agents sorted by ID.
func (r *Registry) Statuses() []StatusSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshots := make([]StatusSnapshot, 0, len(r.byID))
	for id, identity := range r.byID {
		snapshot, ok := r.statuses[id]
		if !ok {
			snapshot = StatusSnapshot{Agent: identity}
		}
		snapshots = append(snapshots, snapshot)
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Agent.ID < snapshots[j].Agent.ID
	})

	return snapshots
}

// Agents returns the configured agent identities in a deterministic order.
func (r *Registry) Agents() []Identity {
	r.mu.RLock()
	defer r.mu.RUnlock()

	agents := make([]Identity, 0, len(r.byID))
	for _, identity := range r.byID {
		agents = append(agents, identity)
	}
	sort.Slice(agents, func(i, j int) bool {
		return agents[i].ID < agents[j].ID
	})
	return agents
}

// SetAgentGroups updates inventory atomically after persisted enrollment authority is resolved.
func (r *Registry) SetAgentGroups(id string, groups []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	identity, ok := r.byID[id]
	if !ok {
		return
	}
	identity.Groups = append([]string(nil), groups...)
	r.byID[id] = identity
	if snapshot, ok := r.statuses[id]; ok {
		snapshot.Agent = identity
		r.statuses[id] = snapshot
	}
}

func normalizeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
