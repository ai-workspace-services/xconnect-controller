package agentserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ai-workspace-services/xconnect-controller/internal/agentproto"
	"github.com/ai-workspace-services/xconnect-controller/internal/auth"
)

const (
	// DefaultAgentUsersCacheTTL is the default TTL for GET /api/agent-server/v1/users.
	DefaultAgentUsersCacheTTL = 15 * time.Second
	defaultEventPollInterval  = 5 * time.Second
	xconnectProxyIdentityDom  = "xconnect.proxy_identity_ref.v1"
)

var errCustomEmailsRequired = errors.New("invalid custom emails")

// ServiceConfig configures the agent-server and config-sync control plane.
type ServiceConfig struct {
	AgentUsersCacheTTL time.Duration
	EventPollInterval  time.Duration
	PublicURL          string
	RoutingPolicy      RoutingPolicyConfig
	Clock              func() time.Time
}

// ResolveAgentUsersCacheTTL reads XCONNECT_AGENT_USERS_CACHE_TTL (default 15s, "0" disables).
func ResolveAgentUsersCacheTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv("XCONNECT_AGENT_USERS_CACHE_TTL"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("ACCOUNTS_AGENT_USERS_CACHE_TTL"))
	}
	if raw == "" {
		return DefaultAgentUsersCacheTTL
	}
	if raw == "0" {
		return 0
	}
	if parsed, err := time.ParseDuration(raw); err == nil && parsed >= 0 {
		return parsed
	}
	if secs, err := strconv.Atoi(raw); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	return DefaultAgentUsersCacheTTL
}

// ServiceConfigFromEnv constructs ServiceConfig from environment variables.
func ServiceConfigFromEnv() ServiceConfig {
	policy, err := LoadRoutingPolicyOrDefault("")
	if err != nil {
		policy = DefaultRoutingPolicy()
	}
	return ServiceConfig{
		AgentUsersCacheTTL: ResolveAgentUsersCacheTTL(),
		EventPollInterval:  defaultEventPollInterval,
		PublicURL:          strings.TrimSpace(os.Getenv("PUBLIC_URL")),
		RoutingPolicy:      policy,
		Clock:              func() time.Time { return time.Now().UTC() },
	}
}

type cachedAgentUsersEntry struct {
	clients   []agentproto.Client
	policy    *agentproto.RoutingPolicy
	revision  string
	expiresAt time.Time
}

// Service implements Go Form A read-only agent-server, config sync, heartbeat, and identity endpoints.
type Service struct {
	store              Store
	registry           *Registry
	verifier           *auth.Verifier
	agentUsersCacheTTL time.Duration
	eventPollInterval  time.Duration
	publicURL          string
	routingPolicy      RoutingPolicyConfig
	clock              func() time.Time

	cacheMu         sync.Mutex
	agentUsersCache map[string]cachedAgentUsersEntry
}

// NewService constructs a Service.
func NewService(st Store, registry *Registry, verifier *auth.Verifier, cfg ServiceConfig) *Service {
	if cfg.EventPollInterval <= 0 {
		cfg.EventPollInterval = defaultEventPollInterval
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.RoutingPolicy.Version == 0 && len(cfg.RoutingPolicy.Pools) == 0 {
		cfg.RoutingPolicy = DefaultRoutingPolicy()
	}
	return &Service{
		store:              st,
		registry:           registry,
		verifier:           verifier,
		agentUsersCacheTTL: cfg.AgentUsersCacheTTL,
		eventPollInterval:  cfg.EventPollInterval,
		publicURL:          strings.TrimSpace(cfg.PublicURL),
		routingPolicy:      cfg.RoutingPolicy,
		clock:              cfg.Clock,
		agentUsersCache:    make(map[string]cachedAgentUsersEntry),
	}
}

func (s *Service) now() time.Time {
	return s.clock().UTC()
}

// mergedStatusSnapshots combines live in-memory Registry snapshots with persisted
// agents and node_health_snapshots rows so reads remain accurate across restarts and replicas.
func (s *Service) mergedStatusSnapshots(ctx context.Context) []StatusSnapshot {
	byID := make(map[string]StatusSnapshot)
	if s.registry != nil {
		for _, snap := range s.registry.Statuses() {
			byID[snap.Agent.ID] = snap
		}
	}

	if s.store != nil {
		if dbAgents, err := s.store.ListAgents(ctx); err == nil {
			for _, a := range dbAgents {
				existing, ok := byID[a.ID]
				if !ok {
					snap := StatusSnapshot{
						Agent: Identity{
							ID:     a.ID,
							Name:   a.Name,
							Groups: a.Groups,
						},
						Report: agentproto.StatusReport{
							AgentID:      a.ID,
							Role:         "agent-proxy",
							Healthy:      a.Healthy,
							Users:        a.ClientsCount,
							SyncRevision: a.SyncRevision,
							Xray: agentproto.XrayStatus{
								Running:    a.Healthy,
								Clients:    a.ClientsCount,
								EntryPoint: regionalEntryHost(a.ID),
							},
						},
					}
					if a.LastHeartbeat != nil {
						snap.UpdatedAt = a.LastHeartbeat.UTC()
					}
					byID[a.ID] = snap
				} else if existing.UpdatedAt.IsZero() && a.LastHeartbeat != nil {
					existing.UpdatedAt = a.LastHeartbeat.UTC()
					existing.Report.Healthy = a.Healthy
					existing.Report.Users = a.ClientsCount
					existing.Report.SyncRevision = a.SyncRevision
					existing.Report.Xray.Clients = a.ClientsCount
					byID[a.ID] = existing
				}
			}
		}

		if healthRows, err := s.store.ListLatestNodeHealthSnapshots(ctx); err == nil {
			for _, h := range healthRows {
				snap, ok := byID[h.NodeID]
				if !ok {
					var groups []string
					pg := strings.ToLower(strings.TrimSpace(h.PricingGroup))
					if agentproto.PublicResourceClass(pg) {
						groups = []string{agentResourceGroupPrefix + pg}
					}
					snap = StatusSnapshot{
						Agent: Identity{
							ID:     h.NodeID,
							Name:   h.NodeID,
							Groups: groups,
						},
						Report: agentproto.StatusReport{
							AgentID: h.NodeID,
							Role:    "agent-proxy",
							Healthy: h.Healthy,
							Xray: agentproto.XrayStatus{
								Running:      h.Healthy,
								NodeID:       h.NodeID,
								Region:       h.Region,
								EntryPoint:   regionalEntryHost(h.NodeID),
								LineCode:     h.LineCode,
								PricingGroup: h.PricingGroup,
								StatsEnabled: h.StatsEnabled,
								XrayRevision: h.XrayRevision,
							},
						},
						UpdatedAt: h.SampledAt.UTC(),
					}
				} else {
					if snap.Report.Xray.Region == "" {
						snap.Report.Xray.Region = h.Region
					}
					if snap.Report.Xray.LineCode == "" {
						snap.Report.Xray.LineCode = h.LineCode
					}
					if snap.Report.Xray.PricingGroup == "" {
						snap.Report.Xray.PricingGroup = h.PricingGroup
					}
					if snap.Report.Xray.XrayRevision == "" {
						snap.Report.Xray.XrayRevision = h.XrayRevision
					}
					if snap.Report.Xray.EntryPoint == "" {
						snap.Report.Xray.EntryPoint = regionalEntryHost(snap.Agent.ID)
					}
					if h.SampledAt.After(snap.UpdatedAt) {
						snap.UpdatedAt = h.SampledAt.UTC()
						snap.Report.Healthy = h.Healthy
						snap.Report.Xray.Running = h.Healthy
					}
				}
				byID[h.NodeID] = snap
			}
		}
	}

	out := make([]StatusSnapshot, 0, len(byID))
	for _, snap := range byID {
		out = append(out, snap)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Agent.ID < out[j].Agent.ID
	})
	return out
}

func (s *Service) enrollmentStatusSnapshots(ctx context.Context) []StatusSnapshot {
	snapshots := s.mergedStatusSnapshots(ctx)
	if s.store == nil {
		return snapshots
	}
	rows, err := s.store.ListTeamAgents(ctx)
	if err != nil {
		return nil
	}
	entries := make(map[string]TeamAgentEnrollment, len(rows))
	for _, e := range rows {
		entries[e.AgentID] = e
	}
	for i := range snapshots {
		e, found := entries[snapshots[i].Agent.ID]
		if found {
			snapshots[i].Agent.Groups = enrollmentGroups(e)
		}
		if found || managedTeam(snapshots[i].Agent.Groups) {
			ready := found && e.Status == "approved" &&
				snapshots[i].Report.Healthy &&
				snapshots[i].Report.Xray.Running &&
				snapshots[i].Report.Xray.LastSync != nil &&
				snapshots[i].Report.Xray.LastSync.After(e.UpdatedAt) &&
				strings.HasPrefix(snapshots[i].Report.SyncRevision, enrollmentRevision(e)+"-")
			if !ready {
				closed := false
				snapshots[i].Report.Xray.OpenToUsers = &closed
				snapshots[i].Agent.Groups = []string{managedTeamMarker, "access:dedicated-only"}
			}
		}
	}
	return snapshots
}

func (s *Service) networkSnapshots(ctx context.Context, access networkAccess) []StatusSnapshot {
	all := s.enrollmentStatusSnapshots(ctx)
	out := make([]StatusSnapshot, 0, len(all))
	for _, snap := range all {
		if networkScopeAllows(access, snap.Agent.Groups) {
			out = append(out, snap)
		}
	}
	return out
}

func (s *Service) networkAccessFor(ctx context.Context, userID string) (networkAccess, error) {
	if s.store == nil {
		return networkAccess{AccountID: userID, Mode: "personal", Allowed: true}, nil
	}
	member, err := s.store.GetNetworkMembership(ctx, userID)
	if err != nil {
		return networkAccess{}, err
	}
	if !member.DedicatedOnly && member.TeamID == "" {
		access := accessFromNetworkMembership(member, nil, s.now())
		access.AccountID = userID
		return access, nil
	}
	teams, err := s.store.ListNetworkTeams(ctx)
	if err != nil {
		return networkAccess{}, err
	}
	access := accessFromNetworkMembership(member, teams, s.now())
	access.AccountID = userID
	return access, nil
}

func (s *Service) networkAccessForUser(ctx context.Context, user *User) (networkAccess, error) {
	access, err := s.networkAccessFor(ctx, user.ID)
	if err != nil {
		return access, err
	}
	if !user.Active || user.ArchivedAt != nil || !accountAccessVerified(user) {
		access.Allowed = false
		return access, nil
	}
	if s.store != nil {
		blocked, err := s.store.ListProxyBlockedAccountUUIDs(ctx)
		if err != nil {
			return access, err
		}
		if blocked[user.ID] {
			access.Allowed = false
		}
	}
	return access, nil
}

func (s *Service) billingPackageName(ctx context.Context, user *User) (string, error) {
	if user == nil || s.store == nil {
		return "", nil
	}
	profile, err := s.store.GetAccountBillingProfile(ctx, user.ID)
	if errors.Is(err, ErrUserNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if profile == nil {
		return "", nil
	}
	return strings.ToLower(strings.TrimSpace(profile.PackageName)), nil
}

func (s *Service) quotaProfileAndStateForUser(ctx context.Context, user *User) (*AccountBillingProfile, *AccountQuotaState, bool, error) {
	if user == nil || s.store == nil {
		return nil, nil, true, nil
	}
	if isCustomDedicatedUser(user, "") || hasMediaPassthroughEntitlement(user, "") {
		return nil, nil, true, nil
	}
	if access, err := s.networkAccessFor(ctx, user.ID); err == nil && access.Mode == "dedicated" && access.Allowed {
		return nil, nil, true, nil
	}
	if !isMonthlyQuotaLimitMember(user) {
		return nil, nil, true, nil
	}
	profile, err := s.store.GetAccountBillingProfile(ctx, user.ID)
	if errors.Is(err, ErrUserNotFound) {
		return nil, nil, true, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	if profile == nil {
		return nil, nil, true, nil
	}
	if isCustomDedicatedUser(user, profile.PackageName) || hasMediaPassthroughEntitlement(user, profile.PackageName) {
		return nil, nil, true, nil
	}
	quota, err := s.store.GetAccountQuotaState(ctx, user.ID)
	if errors.Is(err, ErrUserNotFound) {
		return profile, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	return profile, quota, false, nil
}

func (s *Service) quotaExhaustedForUser(ctx context.Context, user *User) (bool, error) {
	profile, quota, exempt, err := s.quotaProfileAndStateForUser(ctx, user)
	if err != nil || exempt || profile == nil || profile.IncludedQuotaBytes <= 0 {
		return false, err
	}
	return quota == nil || quota.RemainingIncludedQuota <= 0, nil
}

func (s *Service) highSpeedQuotaExhaustedForUser(ctx context.Context, user *User) (bool, error) {
	profile, quota, exempt, err := s.quotaProfileAndStateForUser(ctx, user)
	if err != nil || exempt || profile == nil || profile.HighSpeedQuotaBytes <= 0 {
		return false, err
	}
	return quota == nil || quota.RemainingHighSpeedQuota <= 0, nil
}

func (s *Service) hasActiveHighSpeedQuotaBucket(ctx context.Context, user *User) (bool, error) {
	profile, _, exempt, err := s.quotaProfileAndStateForUser(ctx, user)
	if err != nil || exempt || profile == nil {
		return false, err
	}
	return profile.HighSpeedQuotaBytes > 0, nil
}

func (s *Service) quotaExhaustedForAgentScope(ctx context.Context, user *User, scope agentproto.UserScope, groups []string) (bool, error) {
	if scope.ResourceClass == agentResourceCustom || scope.ResourceClass == agentResourceTeam {
		return false, nil
	}
	if hasMediaPassthroughAgentGroup(groups) {
		return false, nil
	}
	if isOneTimeTrialMember(user) {
		return s.quotaExhaustedForUser(ctx, user)
	}
	if dualBucketProGateEnabled() && scope.ResourceClass == agentResourcePro {
		return s.highSpeedQuotaExhaustedForUser(ctx, user)
	}
	return s.quotaExhaustedForUser(ctx, user)
}

func (s *Service) evaluateDualBucketQuotaForUser(ctx context.Context, user *User) (userBucketExhaustion, error) {
	status := userBucketExhaustion{
		gateEnabled: dualBucketProGateEnabled(),
	}
	vpsExhausted, err := s.quotaExhaustedForUser(ctx, user)
	if err != nil {
		return status, err
	}
	status.vpsExhausted = vpsExhausted
	if isOneTimeTrialMember(user) {
		status.hasHighSpeedBucket = false
		status.highSpeedExhausted = vpsExhausted
		status.fullyExhausted = vpsExhausted
		return status, nil
	}
	if !status.gateEnabled {
		status.fullyExhausted = vpsExhausted
		return status, nil
	}
	hasHighSpeed, err := s.hasActiveHighSpeedQuotaBucket(ctx, user)
	if err != nil {
		return status, err
	}
	status.hasHighSpeedBucket = hasHighSpeed
	if hasHighSpeed {
		hsExhausted, err := s.highSpeedQuotaExhaustedForUser(ctx, user)
		if err != nil {
			return status, err
		}
		status.highSpeedExhausted = hsExhausted
	}
	status.fullyExhausted = vpsExhausted && (!hasHighSpeed || status.highSpeedExhausted)
	return status, nil
}

func (s *Service) proxyAccountBlocked(ctx context.Context, user *User) (bool, error) {
	if s.store == nil {
		return false, nil
	}
	blacklisted, err := s.store.IsBlacklisted(ctx, strings.ToLower(strings.TrimSpace(user.Email)))
	if err != nil || blacklisted {
		return blacklisted, err
	}
	blocked, err := s.store.ListProxyBlockedAccountUUIDs(ctx)
	return blocked[strings.TrimSpace(user.ID)], err
}

func (s *Service) reservedDedicatedHost(ctx context.Context, host string) bool {
	if s.store != nil {
		rows, err := s.store.ListTeamAgents(ctx)
		if err != nil {
			return true
		}
		for _, e := range rows {
			if normalizeHost(e.AgentID) == host {
				return true
			}
		}
	}
	for _, snapshot := range s.enrollmentStatusSnapshots(ctx) {
		team, valid := agentNetworkScope(snapshot.Agent.Groups)
		scope, scopeValid := agentResourceScope(snapshot.Agent.Groups)
		dedicated := !valid || team != "" || !scopeValid || scope.ResourceClass == agentResourceCustom
		if dedicated && (normalizeHost(snapshot.Agent.ID) == host || regionalEntryHost(snapshot.Report.Xray.EntryPoint) == host) {
			return true
		}
	}
	return false
}

func cloneAgentClients(src []agentproto.Client) []agentproto.Client {
	if len(src) == 0 {
		return []agentproto.Client{}
	}
	out := make([]agentproto.Client, len(src))
	for i, c := range src {
		if c.ExpiresAt != nil {
			exp := *c.ExpiresAt
			c.ExpiresAt = &exp
		}
		out[i] = c
	}
	return out
}

func cloneRoutingPolicy(src *agentproto.RoutingPolicy) *agentproto.RoutingPolicy {
	if src == nil {
		return nil
	}
	cp := *src
	cp.PricingGroups = append([]string(nil), src.PricingGroups...)
	cp.SubPoolTags = append([]string(nil), src.SubPoolTags...)
	cp.DirectDomains = append([]string(nil), src.DirectDomains...)
	cp.DirectIPs = append([]string(nil), src.DirectIPs...)
	cp.MediaDomains = append([]string(nil), src.MediaDomains...)
	cp.ProWhitelistDomains = append([]string(nil), src.ProWhitelistDomains...)
	return &cp
}

func (s *Service) authorizedAgentClientsForIdentityWithPolicy(ctx context.Context, identity Identity, rawAllowedEmails string) ([]agentproto.Client, *agentproto.RoutingPolicy, string, error) {
	if s.agentUsersCacheTTL > 0 {
		key := identity.ID + "\x00" + identity.NodeID + "\x00" + strings.Join(identity.Groups, ",") + "\x00" + rawAllowedEmails
		now := s.now()
		s.cacheMu.Lock()
		if entry, ok := s.agentUsersCache[key]; ok && now.Before(entry.expiresAt) {
			clients := cloneAgentClients(entry.clients)
			policy := cloneRoutingPolicy(entry.policy)
			revision := entry.revision
			s.cacheMu.Unlock()
			return clients, policy, revision, nil
		}
		s.cacheMu.Unlock()

		clients, policy, revision, err := s.computeAgentClientsForIdentityWithPolicy(ctx, identity, rawAllowedEmails)
		if err != nil {
			return nil, nil, "", err
		}
		s.cacheMu.Lock()
		if len(s.agentUsersCache) >= 256 {
			for k, v := range s.agentUsersCache {
				if !now.Before(v.expiresAt) {
					delete(s.agentUsersCache, k)
				}
			}
		}
		s.agentUsersCache[key] = cachedAgentUsersEntry{
			clients:   cloneAgentClients(clients),
			policy:    cloneRoutingPolicy(policy),
			revision:  revision,
			expiresAt: s.now().Add(s.agentUsersCacheTTL),
		}
		s.cacheMu.Unlock()
		return clients, policy, revision, nil
	}
	return s.computeAgentClientsForIdentityWithPolicy(ctx, identity, rawAllowedEmails)
}

func (s *Service) computeAgentClientsForIdentityWithPolicy(ctx context.Context, identity Identity, rawAllowedEmails string) ([]agentproto.Client, *agentproto.RoutingPolicy, string, error) {
	scope, valid := agentResourceScope(identity.Groups)
	if !valid {
		return nil, nil, "", errors.New("invalid agent resource scope")
	}
	baseClients, routingPolicy, baseRevision, err := s.authorizedAgentClientsWithPolicy(ctx, identity.Groups)
	if err != nil {
		return nil, nil, "", err
	}
	if scope.ResourceClass != agentResourceCustom {
		return baseClients, routingPolicy, baseRevision, nil
	}
	var allowed []string
	if err := json.Unmarshal([]byte(rawAllowedEmails), &allowed); err != nil || len(allowed) == 0 || len(allowed) > 256 {
		return nil, nil, "", errCustomEmailsRequired
	}
	filtered := make([]agentproto.Client, 0, len(baseClients))
	staticIDs := make(map[string]bool, len(baseClients))
	for _, client := range baseClients {
		if agentEmailAllowed(allowed, &User{Email: client.Email}) {
			filtered = append(filtered, client)
			staticIDs[client.ID] = true
		}
	}
	if strings.TrimSpace(identity.NodeID) != "" {
		tempClients, err := s.authorizedCustomTempFreeClients(ctx, identity, staticIDs)
		if err != nil {
			return nil, nil, "", err
		}
		filtered = append(filtered, tempClients...)
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].ID < filtered[j].ID })
	}
	data, err := json.Marshal(struct {
		Revision      string
		RoutingPolicy *agentproto.RoutingPolicy
		Clients       []agentproto.Client
	}{baseRevision, routingPolicy, filtered})
	if err != nil {
		return nil, nil, "", err
	}
	sum := sha256.Sum256(data)
	return filtered, routingPolicy, hex.EncodeToString(sum[:]), nil
}

func (s *Service) authorizedAgentClientsWithPolicy(ctx context.Context, groups []string) ([]agentproto.Client, *agentproto.RoutingPolicy, string, error) {
	if _, valid := agentNetworkScope(groups); !valid {
		return nil, nil, "", errors.New("invalid agent network scope")
	}
	if s.store == nil {
		return nil, nil, "", errors.New("store unavailable")
	}
	clients := make([]agentproto.Client, 0, 16)
	scope, valid := agentResourceScope(groups)
	if !valid {
		return nil, nil, "", errors.New("invalid agent resource scope")
	}
	routingPolicy := agentRoutingPolicyForScope(scope, s.routingPolicy)

	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	blocked, err := s.store.ListProxyBlockedAccountUUIDs(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	emails, err := s.store.ListBlacklist(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	blockedEmails := make(map[string]bool, len(emails))
	for _, email := range emails {
		blockedEmails[strings.ToLower(strings.TrimSpace(email))] = true
	}
	teams, err := s.store.ListNetworkTeams(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	members, err := s.store.ListNetworkMemberships(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	memberByUser := make(map[string]NetworkMembership, len(members))
	for _, member := range members {
		memberByUser[member.UserID] = member
	}

	now := s.now()
	for i := range users {
		u := &users[i]
		if !u.Active || u.ArchivedAt != nil {
			continue
		}
		access := accessFromNetworkMembership(memberByUser[u.ID], teams, now)
		if !networkScopeAllows(access, groups) {
			continue
		}
		packageName, err := s.billingPackageName(ctx, u)
		if err != nil {
			return nil, nil, "", err
		}
		publicEmailOverride := agentproto.PublicResourceClass(scope.ResourceClass) && access.Mode != "dedicated" && publicUnionEmailMatches(groups, u)
		if !agentResourceScopeAllowsUser(scope, access, u, packageName) && !publicEmailOverride {
			continue
		}
		if blocked[strings.TrimSpace(u.ID)] || blockedEmails[strings.ToLower(strings.TrimSpace(u.Email))] {
			continue
		}
		if exhausted, err := s.quotaExhaustedForAgentScope(ctx, u, scope, groups); err != nil {
			return nil, nil, "", err
		} else if exhausted {
			continue
		}
		if !accountAccessVerified(u) {
			continue
		}
		id := strings.TrimSpace(u.ProxyUUID)
		if id == "" {
			continue
		}
		clients = append(clients, agentproto.Client{
			ID:    id,
			Email: strings.ToLower(strings.TrimSpace(u.Email)),
			Flow:  agentproto.DefaultFlow,
		})
	}

	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	payload, err := json.Marshal(struct {
		Scope         agentproto.UserScope      `json:"scope"`
		RoutingPolicy *agentproto.RoutingPolicy `json:"routingPolicy,omitempty"`
		Clients       []agentproto.Client       `json:"clients"`
	}{Scope: scope, RoutingPolicy: routingPolicy, Clients: clients})
	if err != nil {
		return nil, nil, "", err
	}
	sum := sha256.Sum256(payload)
	return clients, routingPolicy, hex.EncodeToString(sum[:]), nil
}

func (s *Service) authorizedCustomTempFreeClients(ctx context.Context, identity Identity, staticIDs map[string]bool) ([]agentproto.Client, error) {
	nodeID := strings.TrimSpace(identity.NodeID)
	if !validAgentFreeGrantNodeID(nodeID) || s.store == nil {
		return nil, nil
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	blocked, err := s.store.ListProxyBlockedAccountUUIDs(ctx)
	if err != nil {
		return nil, err
	}
	emails, err := s.store.ListBlacklist(ctx)
	if err != nil {
		return nil, err
	}
	blockedEmails := make(map[string]bool, len(emails))
	for _, email := range emails {
		blockedEmails[strings.ToLower(strings.TrimSpace(email))] = true
	}
	teams, err := s.store.ListNetworkTeams(ctx)
	if err != nil {
		return nil, err
	}
	members, err := s.store.ListNetworkMemberships(ctx)
	if err != nil {
		return nil, err
	}
	memberByUser := make(map[string]NetworkMembership, len(members))
	for _, member := range members {
		memberByUser[member.UserID] = member
	}
	now := s.now()
	out := make([]agentproto.Client, 0)
	for i := range users {
		u := &users[i]
		grant, ok := activeAgentFreeGrant(u, nodeID, now)
		if !ok {
			continue
		}
		if !u.Active || u.ArchivedAt != nil {
			continue
		}
		if blocked[strings.TrimSpace(u.ID)] || blockedEmails[strings.ToLower(strings.TrimSpace(u.Email))] {
			continue
		}
		access := accessFromNetworkMembership(memberByUser[u.ID], teams, now)
		if !networkScopeAllows(access, identity.Groups) || access.Mode == "dedicated" {
			continue
		}
		packageName, err := s.billingPackageName(ctx, u)
		if err != nil {
			return nil, err
		}
		if effectiveAgentResourceClass(access, u, packageName) != agentResourceFree {
			continue
		}
		if exhausted, err := s.quotaExhaustedForUser(ctx, u); err != nil {
			return nil, err
		} else if exhausted {
			continue
		}
		if !accountAccessVerified(u) {
			continue
		}
		id := strings.TrimSpace(u.ProxyUUID)
		if id == "" || staticIDs[id] {
			continue
		}
		exp := grant.ExpiresAt.UTC()
		out = append(out, agentproto.Client{
			ID:        id,
			Email:     strings.ToLower(strings.TrimSpace(u.Email)),
			Flow:      agentproto.DefaultFlow,
			ExpiresAt: &exp,
		})
	}
	return out, nil
}

func filterCustomAgentClients(scope agentproto.UserScope, raw string, clients []agentproto.Client, revision string) ([]agentproto.Client, string, error) {
	if scope.ResourceClass != agentResourceCustom {
		return clients, revision, nil
	}
	var allowed []string
	if err := json.Unmarshal([]byte(raw), &allowed); err != nil || len(allowed) == 0 || len(allowed) > 256 {
		return nil, "", errCustomEmailsRequired
	}
	filtered := make([]agentproto.Client, 0, len(clients))
	for _, client := range clients {
		if agentEmailAllowed(allowed, &User{Email: client.Email}) {
			filtered = append(filtered, client)
		}
	}
	data, err := json.Marshal(struct {
		Revision string
		Clients  []agentproto.Client
	}{revision, filtered})
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return filtered, hex.EncodeToString(sum[:]), nil
}

func xconnectProxyIdentityRef(proxyUUID string) string {
	credential := strings.ToLower(strings.TrimSpace(proxyUUID))
	mac := hmac.New(sha256.New, []byte(credential))
	_, _ = io.WriteString(mac, xconnectProxyIdentityDom)
	return hex.EncodeToString(mac.Sum(nil))
}
