package agentserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ai-workspace-services/xconnect-controller/internal/agentproto"
	"github.com/ai-workspace-services/xconnect-controller/internal/auth"
)

type agentStatusEntry struct {
	ID           string           `json:"id"`
	Name         string           `json:"name,omitempty"`
	Groups       []string         `json:"groups,omitempty"`
	Healthy      bool             `json:"healthy"`
	Message      string           `json:"message,omitempty"`
	Users        int              `json:"users"`
	SyncRevision string           `json:"syncRevision,omitempty"`
	UpdatedAt    time.Time        `json:"updatedAt"`
	Xray         agentXraySummary `json:"xray"`
}

type agentXraySummary struct {
	Running  bool       `json:"running"`
	Clients  int        `json:"clients"`
	LastSync *time.Time `json:"lastSync,omitempty"`
}

// VlessNode matches the user-facing node payload returned by /api/agent-server/v1/nodes and /api/agent/nodes.
type VlessNode struct {
	Private                 bool     `json:"private,omitempty"`
	Name                    string   `json:"name"`
	Region                  string   `json:"region,omitempty"`
	PoolCount               int      `json:"pool_count,omitempty"`
	OpenToUsers             bool     `json:"open_to_users"`
	Address                 string   `json:"address"`
	Port                    int      `json:"port,omitempty"`
	Users                   []string `json:"users,omitempty"`
	Transport               string   `json:"transport,omitempty"`
	Path                    string   `json:"path,omitempty"`
	Mode                    string   `json:"mode,omitempty"`
	Security                string   `json:"security,omitempty"`
	Flow                    string   `json:"flow,omitempty"`
	ResourceClass           string   `json:"resource_class,omitempty"`
	RoutingPool             string   `json:"routing_pool,omitempty"`
	PricingGroup            string   `json:"pricing_group,omitempty"`
	SubPoolTags             []string `json:"sub_pool_tags,omitempty"`
	ServerName              string   `json:"server_name,omitempty"`
	XHTTPPort               int      `json:"xhttp_port,omitempty"`
	TCPPort                 int      `json:"tcp_port,omitempty"`
	URISchemeXHTTP          string   `json:"uri_scheme_xhttp,omitempty"`
	URISchemeTCP            string   `json:"uri_scheme_tcp,omitempty"`
	HighSpeedQuotaExhausted bool     `json:"highSpeedQuotaExhausted,omitempty"`
}

type nodeHeartbeatRequest struct {
	NodeID            string  `json:"nodeId"`
	Region            string  `json:"region"`
	LineCode          string  `json:"lineCode"`
	PricingGroup      string  `json:"pricingGroup"`
	StatsEnabled      bool    `json:"statsEnabled"`
	XrayRevision      string  `json:"xrayRevision"`
	Healthy           bool    `json:"healthy"`
	LatencyMS         int     `json:"latencyMs"`
	ErrorRate         float64 `json:"errorRate"`
	ActiveConnections int     `json:"activeConnections"`
	HealthScore       float64 `json:"healthScore"`
	SampledAt         string  `json:"sampledAt"`
}

type userNodesContext struct {
	user                    *User
	access                  networkAccess
	packageName             string
	resourceClass           string
	highSpeedQuotaExhausted bool
	nodes                   []VlessNode
	subNodes                []SubscriptionNode
}

func extractBearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	}
	return ""
}

func extractInternalToken(c *gin.Context) string {
	if token := strings.TrimSpace(c.GetHeader("X-Internal-Service-Token")); token != "" {
		return token
	}
	if token := strings.TrimSpace(c.GetHeader("X-Service-Token")); token != "" {
		return token
	}
	return extractBearerToken(c.GetHeader("Authorization"))
}

// GetAgentStatus handles GET /api/agent-server/v1/status (read-only).
func (s *Service) GetAgentStatus(c *gin.Context) {
	ctx := c.Request.Context()

	var (
		isInternal    bool
		agentIdentity *Identity
		jwtUser       *User
	)

	if s.verifier != nil {
		if candidate := extractInternalToken(c); candidate != "" && s.verifier.ValidateInternalToken(candidate) {
			isInternal = true
		}
	}
	if !isInternal {
		token := extractBearerToken(c.GetHeader("Authorization"))
		if token == "" {
			if cookie, err := c.Cookie("xc_session"); err == nil {
				token = strings.TrimSpace(cookie)
			}
		}
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
			return
		}
		if s.registry != nil {
			if id, ok := s.registry.Authenticate(token); ok && id != nil {
				agentIdentity = id
			}
		}
		if agentIdentity == nil && s.verifier != nil {
			claims, err := s.verifier.ValidateAccessToken(ctx, token)
			if err == nil && strings.TrimSpace(claims.UserID) != "" && claims.UserID != "system" {
				if s.store != nil {
					u, uErr := s.store.GetUserByID(ctx, claims.UserID)
					if uErr == nil && u != nil {
						if !u.Active || u.ArchivedAt != nil {
							c.JSON(http.StatusForbidden, gin.H{"error": "account_suspended"})
							return
						}
						jwtUser = u
					}
				}
				if jwtUser == nil {
					role := "user"
					if len(claims.Roles) > 0 {
						role = strings.TrimSpace(claims.Roles[0])
					}
					jwtUser = &User{
						ID:     strings.TrimSpace(claims.UserID),
						Email:  strings.TrimSpace(claims.Email),
						Role:   role,
						Active: true,
					}
				}
				if !isAdminOrOperatorRole(jwtUser.Role) {
					c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "message": "administrator or agent authentication required"})
					return
				}
			}
		}
		if agentIdentity == nil && jwtUser == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}
	}

	snapshots := s.enrollmentStatusSnapshots(ctx)
	if agentIdentity != nil {
		scope, valid := agentResourceScope(agentIdentity.Groups)
		if !valid {
			c.JSON(http.StatusForbidden, gin.H{"error": "agent_scope_invalid"})
			return
		}
		isWildcardManager := agentIdentity.ID == "*" && !managedTeam(agentIdentity.Groups) && scope.TeamID == ""
		if !isWildcardManager {
			filtered := make([]StatusSnapshot, 0, len(snapshots))
			for _, snap := range snapshots {
				if agentIdentity.NodeID != "" {
					if snap.Agent.ID == agentIdentity.ID || snap.Report.Xray.NodeID == agentIdentity.NodeID {
						filtered = append(filtered, snap)
					}
					continue
				}
				if scope.TeamID != "" {
					snapTeam, snapValid := agentNetworkScope(snap.Agent.Groups)
					if snapValid && snapTeam == scope.TeamID {
						filtered = append(filtered, snap)
					}
					continue
				}
				if snap.Agent.ID == agentIdentity.ID {
					filtered = append(filtered, snap)
				}
			}
			snapshots = filtered
		}
	} else if jwtUser != nil && !isRootRole(jwtUser.Role) {
		access, err := s.networkAccessForUser(ctx, jwtUser)
		if err != nil {
			respondError(c, http.StatusServiceUnavailable, "network_access_unavailable", "network access is unavailable")
			return
		}
		packageName, err := s.billingPackageName(ctx, jwtUser)
		if err != nil {
			respondError(c, http.StatusServiceUnavailable, "billing_profile_unavailable", "failed to evaluate subscription resource class")
			return
		}
		visible := make([]StatusSnapshot, 0, len(snapshots))
		for _, snap := range snapshots {
			if !networkScopeAllows(access, snap.Agent.Groups) {
				continue
			}
			scope, valid := agentResourceScope(snap.Agent.Groups)
			if valid && agentResourceScopeAllowsUser(scope, access, jwtUser, packageName) {
				visible = append(visible, snap)
			}
		}
		snapshots = visible
	}

	entries := make([]agentStatusEntry, 0, len(snapshots))
	for _, snap := range snapshots {
		entry := agentStatusEntry{
			ID:           snap.Agent.ID,
			Name:         snap.Agent.Name,
			Groups:       publicAgentDisplayGroups(snap.Agent.Groups),
			Healthy:      snap.Report.Healthy,
			Message:      snap.Report.Message,
			Users:        snap.Report.Users,
			SyncRevision: snap.Report.SyncRevision,
			UpdatedAt:    snap.UpdatedAt,
			Xray: agentXraySummary{
				Running: snap.Report.Xray.Running,
				Clients: snap.Report.Xray.Clients,
			},
		}
		if snap.Report.Xray.LastSync != nil {
			last := *snap.Report.Xray.LastSync
			entry.Xray.LastSync = &last
		}
		entries = append(entries, entry)
	}

	body, err := json.Marshal(gin.H{"agents": entries})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "status_encode_failed", "failed to encode status")
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	c.Header("ETag", etag)
	c.Header("Cache-Control", "no-store")
	if etagMatches(c.GetHeader("If-None-Match"), etag) {
		c.Status(http.StatusNotModified)
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", body)
}

// ReportAgentStatus handles POST /api/agent-server/v1/status.
func (s *Service) ReportAgentStatus(c *gin.Context) {
	if s.registry == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent_registry_unavailable"})
		return
	}
	token := extractBearerToken(c.GetHeader("Authorization"))
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
		return
	}
	credIdentity, ok := s.registry.Authenticate(token)
	if !ok || credIdentity == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	var report agentproto.StatusReport
	if err := c.ShouldBindJSON(&report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}
	identity, _, ok := s.resolveScopedAgent(c, *credIdentity, report.AgentID, false)
	if !ok {
		return
	}
	if identity.NodeID != "" && strings.TrimSpace(report.Xray.NodeID) != identity.NodeID {
		respondError(c, http.StatusForbidden, "agent_node_mismatch", "node ID is bound to credential")
		return
	}
	scope, _ := agentResourceScope(identity.Groups)
	report.Xray.CustomAllowFree = scope.CustomAllowFree
	if agentproto.PublicResourceClass(scope.ResourceClass) {
		report.Xray.AllowedEmails = publicUnionEmails(identity.Groups)
	} else if identity.NodeID != "" {
		report.Xray.AllowedEmails = append([]string(nil), identity.AllowedEmails...)
	}
	report.AgentID = identity.ID
	s.registry.ReportStatus(identity, report)

	if s.store != nil {
		nodeID := strings.TrimSpace(report.Xray.NodeID)
		if nodeID == "" {
			nodeID = identity.ID
		}
		_ = s.store.UpsertNodeHealthSnapshot(c.Request.Context(), &NodeHealthSnapshot{
			NodeID:       nodeID,
			Region:       strings.TrimSpace(report.Xray.Region),
			LineCode:     strings.TrimSpace(report.Xray.LineCode),
			PricingGroup: strings.TrimSpace(report.Xray.PricingGroup),
			StatsEnabled: report.Xray.StatsEnabled,
			XrayRevision: strings.TrimSpace(report.Xray.XrayRevision),
			Healthy:      report.Healthy,
			SampledAt:    s.now(),
		})
	}
	c.Status(http.StatusNoContent)
}

// ListAgentUsers handles GET /api/agent-server/v1/users with TTL caching, ETag/304, and zero DB writes.
func (s *Service) ListAgentUsers(c *gin.Context) {
	if s.registry == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent_registry_unavailable"})
		return
	}
	token := extractBearerToken(c.GetHeader("Authorization"))
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
		return
	}
	credIdentity, ok := s.registry.Authenticate(token)
	if !ok || credIdentity == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	identity, enrollment, ok := s.resolveScopedAgent(c, *credIdentity, "", true)
	if !ok {
		return
	}
	if enrollment != nil && enrollment.Status != "approved" {
		rev := enrollmentRevision(*enrollment)
		etag := `"` + rev + `"`
		c.Header("ETag", etag)
		c.Header("Cache-Control", "no-store")
		if etagMatches(c.GetHeader("If-None-Match"), etag) {
			c.Status(http.StatusNotModified)
			return
		}
		c.JSON(http.StatusOK, agentproto.ClientListResponse{
			EnrollmentStatus: enrollment.Status,
			Scope:            &agentproto.UserScope{ResourceClass: "team"},
			Clients:          []agentproto.Client{},
			Revision:         rev,
			GeneratedAt:      s.now(),
		})
		return
	}

	scope, valid := agentResourceScope(identity.Groups)
	if !valid {
		c.JSON(http.StatusForbidden, gin.H{"error": "agent_scope_invalid"})
		return
	}

	clients, policy, revision, err := s.authorizedAgentClientsForIdentityWithPolicy(c.Request.Context(), identity, c.GetHeader("X-Agent-Allowed-Emails"))
	if err != nil {
		if errors.Is(err, errCustomEmailsRequired) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "custom_emails_required"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list_users_failed"})
		return
	}
	approvalStatus := ""
	if enrollment != nil {
		approvalStatus = enrollment.Status
		revision = enrollmentRevision(*enrollment) + "-" + revision
	}
	etag := `"` + revision + `"`
	c.Header("ETag", etag)
	c.Header("Cache-Control", "no-store")
	if etagMatches(c.GetHeader("If-None-Match"), etag) {
		c.Status(http.StatusNotModified)
		return
	}
	c.JSON(http.StatusOK, agentproto.ClientListResponse{
		AgentID:          identity.ID,
		NodeID:           identity.NodeID,
		EnrollmentStatus: approvalStatus,
		Scope:            &scope,
		RoutingPolicy:    policy,
		Clients:          clients,
		Total:            len(clients),
		Revision:         revision,
		GeneratedAt:      s.now(),
	})
}

// WatchAgentUsers handles GET /api/agent-server/v1/users/events as an SSE stream on Go origin.
func (s *Service) WatchAgentUsers(c *gin.Context) {
	if s.registry == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent_registry_unavailable"})
		return
	}
	token := extractBearerToken(c.GetHeader("Authorization"))
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
		return
	}
	credIdentity, ok := s.registry.Authenticate(token)
	if !ok || credIdentity == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	identity, enrollment, ok := s.resolveScopedAgent(c, *credIdentity, "", true)
	if !ok {
		return
	}

	if enrollment != nil {
		revision := enrollmentRevision(*enrollment)
		if enrollment.Status == "approved" {
			_, _, usersRevision, err := s.authorizedAgentClientsWithPolicy(c.Request.Context(), identity.Groups)
			if err != nil {
				respondError(c, http.StatusServiceUnavailable, "agent_users_unavailable", "team users unavailable")
				return
			}
			revision += "-" + usersRevision
		}
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-store")
		c.Header("X-Agent-Event-Mode", "poll")
		c.String(http.StatusOK, "event: users-changed\ndata: %s\n\n", revision)
		return
	}

	scope, valid := agentResourceScope(identity.Groups)
	if !valid {
		respondError(c, http.StatusForbidden, "agent_scope_invalid", "invalid agent scope")
		return
	}
	if _, _, err := filterCustomAgentClients(scope, c.GetHeader("X-Agent-Allowed-Emails"), nil, ""); err != nil {
		respondError(c, http.StatusBadRequest, "custom_emails_required", "custom emails required")
		return
	}

	controller := http.NewResponseController(c.Writer)
	if err := controller.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "event_stream_unavailable"})
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache, no-transform")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	lastRevision := strings.Trim(strings.TrimSpace(c.GetHeader("Last-Event-ID")), `"`)
	ticker := time.NewTicker(s.eventPollInterval)
	defer ticker.Stop()
	heartbeats := 0

	for {
		_, _, revision, err := s.authorizedAgentClientsForIdentityWithPolicy(c.Request.Context(), identity, c.GetHeader("X-Agent-Allowed-Emails"))
		if err != nil {
			return
		}
		if revision != lastRevision {
			if _, err := c.Writer.Write([]byte("id: " + revision + "\nevent: users-changed\ndata: " + revision + "\n\n")); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
			lastRevision = revision
		}

		select {
		case <-c.Request.Context().Done():
			return
		case <-ticker.C:
			heartbeats++
			if heartbeats%3 == 0 {
				if _, err := c.Writer.Write([]byte(": keepalive\n\n")); err != nil {
					return
				}
				if err := controller.Flush(); err != nil {
					return
				}
			}
		}
	}
}

// NodeHeartbeat handles POST /api/agent-server/v1/nodes/heartbeat.
func (s *Service) NodeHeartbeat(c *gin.Context) {
	token := extractInternalToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
		return
	}

	var agentIdentity *Identity
	isInternal := s.verifier != nil && s.verifier.ValidateInternalToken(token)
	if !isInternal && s.registry != nil {
		if id, ok := s.registry.Authenticate(token); ok && id != nil {
			agentIdentity = id
		}
	}
	if !isInternal && agentIdentity == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	var req nodeHeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid_request", "invalid heartbeat payload")
		return
	}

	nodeID := strings.TrimSpace(req.NodeID)
	if agentIdentity != nil && agentIdentity.NodeID != "" {
		if nodeID != "" && nodeID != agentIdentity.NodeID {
			respondError(c, http.StatusForbidden, "agent_node_mismatch", "node ID is bound to credential")
			return
		}
		nodeID = agentIdentity.NodeID
	}
	if nodeID == "" {
		respondError(c, http.StatusBadRequest, "node_id_required", "node id is required")
		return
	}

	sampledAt, err := parseOptionalTime(req.SampledAt)
	if err != nil {
		respondError(c, http.StatusBadRequest, "invalid_sampled_at", "sampledAt must be RFC3339")
		return
	}
	if sampledAt.IsZero() {
		sampledAt = s.now()
	}

	if err := s.persistNodeHeartbeat(c, nodeID, req, sampledAt); err != nil {
		respondError(c, http.StatusInternalServerError, "heartbeat_persist_failed", "failed to persist node heartbeat")
		return
	}
	c.Status(http.StatusNoContent)
}

// InternalNodeHeartbeat handles POST /api/internal/nodes/heartbeat (behind InternalAuthMiddleware).
func (s *Service) InternalNodeHeartbeat(c *gin.Context) {
	var req nodeHeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid_request", "invalid heartbeat payload")
		return
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		respondError(c, http.StatusBadRequest, "node_id_required", "node id is required")
		return
	}
	sampledAt, err := parseOptionalTime(req.SampledAt)
	if err != nil {
		respondError(c, http.StatusBadRequest, "invalid_sampled_at", "sampledAt must be RFC3339")
		return
	}
	if sampledAt.IsZero() {
		sampledAt = s.now()
	}
	if err := s.persistNodeHeartbeat(c, nodeID, req, sampledAt); err != nil {
		respondError(c, http.StatusInternalServerError, "heartbeat_persist_failed", "failed to persist node heartbeat")
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Service) persistNodeHeartbeat(c *gin.Context, nodeID string, req nodeHeartbeatRequest, sampledAt time.Time) error {
	if s.store == nil {
		return errors.New("store unavailable")
	}
	return s.store.UpsertNodeHealthSnapshot(c.Request.Context(), &NodeHealthSnapshot{
		NodeID:            nodeID,
		Region:            strings.TrimSpace(req.Region),
		LineCode:          strings.TrimSpace(req.LineCode),
		PricingGroup:      strings.TrimSpace(req.PricingGroup),
		StatsEnabled:      req.StatsEnabled,
		XrayRevision:      strings.TrimSpace(req.XrayRevision),
		Healthy:           req.Healthy,
		LatencyMS:         req.LatencyMS,
		ErrorRate:         req.ErrorRate,
		ActiveConnections: req.ActiveConnections,
		HealthScore:       req.HealthScore,
		SampledAt:         sampledAt,
	})
}

// ListAgentNodes handles GET /api/agent-server/v1/nodes and GET /api/agent/nodes.
func (s *Service) ListAgentNodes(c *gin.Context) {
	resolved, ok := s.resolveUserNodes(c)
	if !ok {
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, resolved.nodes)
}

// GetSubscription handles GET /api/auth/sync/subscription, /api/auth/sync/subscription/:format, and /api/agent-server/v1/subscription.
func (s *Service) GetSubscription(c *gin.Context) {
	rawFormat := strings.TrimSpace(c.Param("format"))
	if rawFormat == "" {
		rawFormat = strings.TrimSpace(c.Query("format"))
	}
	format, err := ParseSubscriptionFormat(rawFormat)
	if err != nil {
		respondError(c, http.StatusBadRequest, "unsupported_subscription_format", err.Error())
		return
	}

	resolved, ok := s.resolveUserNodes(c)
	if !ok {
		return
	}

	isTrial := isOneTimeTrialMember(resolved.user) || strings.EqualFold(strings.TrimSpace(resolved.packageName), "trial")
	allowCustom := !isTrial && (resolved.resourceClass == agentResourceCustom ||
		resolved.resourceClass == agentResourceTeam ||
		(resolved.access.Mode != "dedicated" && isCustomDedicatedUser(resolved.user, resolved.packageName)))
	allowPro := resolved.resourceClass == agentResourcePro && !resolved.highSpeedQuotaExhausted

	body, contentType, err := RenderSubscription(format, SubscriptionRenderInput{
		UserID:      resolved.user.ID,
		UserEmail:   resolved.user.Email,
		AllowCustom: allowCustom,
		AllowPro:    allowPro,
		Policy:      s.routingPolicy,
		Nodes:       resolved.subNodes,
		GeneratedAt: s.now(),
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "subscription_render_failed", "failed to render subscription")
		return
	}

	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, contentType, body)
}

// SyncConfigSnapshot handles GET /api/auth/sync/config (read-only, zero DB writes).
func (s *Service) SyncConfigSnapshot(c *gin.Context) {
	user, ok := s.resolveAuthenticatedUser(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	if blocked, err := s.proxyAccountBlocked(ctx, user); err != nil {
		respondError(c, http.StatusServiceUnavailable, "network_access_unavailable", "network access is unavailable")
		return
	} else if blocked {
		respondError(c, http.StatusForbidden, "proxy_access_blocked", "proxy access is blocked")
		return
	}
	if strings.TrimSpace(user.ProxyUUID) == "" {
		respondError(c, http.StatusServiceUnavailable, "proxy_uuid_unavailable", "proxy UUID is not provisioned for this account")
		return
	}
	quotaStatus, err := s.evaluateDualBucketQuotaForUser(ctx, user)
	if err != nil {
		respondError(c, http.StatusServiceUnavailable, "quota_unavailable", "failed to evaluate quota")
		return
	}
	if quotaStatus.fullyExhausted {
		respondError(c, http.StatusForbidden, "quota_exhausted", "natural-month quota exhausted; configuration sync resumes next month")
		return
	}

	access, err := s.networkAccessForUser(ctx, user)
	if err != nil {
		respondError(c, http.StatusServiceUnavailable, "network_access_unavailable", "network access is unavailable")
		return
	}
	if !access.Allowed {
		respondError(c, http.StatusForbidden, "team_access_inactive", "team access is inactive")
		return
	}
	packageName, err := s.billingPackageName(ctx, user)
	if err != nil {
		respondError(c, http.StatusServiceUnavailable, "billing_profile_unavailable", "failed to evaluate subscription resource class")
		return
	}

	now := s.now()
	resourceClass := effectiveAgentResourceClass(access, user, packageName)
	selectedPools := regionalPoolsForUser(s.networkSnapshots(ctx, access), access, user, packageName, s.routingPolicy, now)
	if quotaStatus.gateEnabled {
		filtered := make([]regionalPool, 0, len(selectedPools))
		for _, pool := range selectedPools {
			if poolAllowedForQuota(pool.RoutingPool, quotaStatus) {
				filtered = append(filtered, pool)
			}
		}
		selectedPools = filtered
	}
	teamHosts := []string{}
	if access.Mode == "dedicated" {
		for _, pool := range selectedPools {
			if pool.OpenToUsers {
				teamHosts = append(teamHosts, pool.Entry)
			}
		}
		if len(teamHosts) == 0 {
			respondError(c, http.StatusServiceUnavailable, "team_nodes_unavailable", "dedicated team nodes are unavailable")
			return
		}
	}

	sinceVersion := int64(0)
	if raw := strings.TrimSpace(c.Query("since_version")); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || v < 0 {
			respondError(c, http.StatusBadRequest, "invalid_since_version", "since_version must be a non-negative integer")
			return
		}
		sinceVersion = v
	}

	version := deriveSyncVersion(user, now)
	updatedAt := now
	if !user.UpdatedAt.IsZero() {
		updatedAt = user.UpdatedAt.UTC()
	}

	changed := sinceVersion < version || access.Configured || access.Mode == "dedicated"
	renderedJSON := ""
	digest := ""
	warnings := []string{}
	if changed {
		var renderErr error
		if access.Mode == "dedicated" {
			renderedJSON, digest, warnings, renderErr = renderDedicatedClientConfig(user, teamHosts[0], poolXHTTPPath(envOrDefault("XRAY_XHTTP_PATH", defaultXHTTPPath), resourceClass))
		} else {
			domain := extractHostFromPublicURL(s.publicURL)
			if s.reservedDedicatedHost(ctx, domain) {
				renderErr = errors.New("configured domain is reserved for a dedicated team")
			} else if domain == "" {
				renderErr = errors.New("xray domain is not configured")
			} else {
				renderedJSON, digest, warnings, renderErr = renderNetworkXrayConfig(user, domain)
			}
		}
		if renderErr != nil && access.Mode == "dedicated" {
			respondError(c, http.StatusServiceUnavailable, "team_config_unavailable", "team configuration is unavailable")
			return
		}
		if renderErr != nil {
			renderedJSON = ""
			digest = ""
			warnings = append(warnings, "rendered xray config unavailable; falling back to node metadata")
		}
	}

	hasMedia, hasPro, hasCustom := false, false, false
	for _, pool := range selectedPools {
		if !pool.OpenToUsers {
			continue
		}
		switch pool.RoutingPool {
		case RoutingPoolProEC2:
			hasPro = true
		case RoutingPoolCustomDedicated:
			hasCustom = true
		default:
			hasMedia = true
		}
	}
	if !hasMedia && !hasPro && !hasCustom {
		switch resourceClass {
		case agentResourcePro:
			hasPro = !quotaStatus.gateEnabled || !quotaStatus.highSpeedExhausted
			hasMedia = !quotaStatus.gateEnabled || !quotaStatus.vpsExhausted
		case agentResourceCustom, agentResourceTeam:
			hasCustom = true
		default:
			hasMedia = true
		}
	}
	routes := BuildThreeTierRoutes(s.routingPolicy, hasMedia, hasPro, hasCustom)

	profiles := []gin.H{}
	nodes := []gin.H{}
	if changed {
		proxyUUID := strings.TrimSpace(user.ProxyUUID)
		xhttpPath := poolXHTTPPath(envOrDefault("XRAY_XHTTP_PATH", defaultXHTTPPath), resourceClass)
		xhttpMode := envOrDefault("XRAY_XHTTP_MODE", defaultXHTTPMode)

		for _, pool := range selectedPools {
			if !pool.OpenToUsers {
				continue
			}
			host := pool.Entry
			nodeName := pool.DisplayName
			if strings.TrimSpace(nodeName) == "" {
				nodeName = resolveNodeName(host)
			}
			countryCode := pool.Code
			nodeID := host
			pricingGroup := strings.TrimSpace(pool.ResourceClass)
			if pricingGroup == "" {
				pricingGroup = resourceClass
			}
			routingPool := strings.TrimSpace(pool.RoutingPool)
			if routingPool == "" {
				routingPool = s.routingPolicy.PoolForResourceClass(pricingGroup)
			}
			vlessURI := renderVLESSURIScheme(vlessXHTTPScheme, map[string]string{
				"UUID":   proxyUUID,
				"DOMAIN": host,
				"NODE":   host,
				"PATH":   url.QueryEscape(xhttpPath),
				"MODE":   url.QueryEscape(xhttpMode),
				"SNI":    host,
				"FP":     defaultTLSFP,
				"TAG":    url.QueryEscape(nodeName),
			})

			profiles = append(profiles, gin.H{
				"id":             nodeID,
				"remark":         nodeName,
				"display_name":   nodeName,
				"host":           host,
				"address":        host,
				"port":           443,
				"uuid":           proxyUUID,
				"flow":           "",
				"transport":      "xhttp",
				"security":       "tls",
				"source":         "server",
				"country_code":   countryCode,
				"resource_class": resourceClass,
				"routing_pool":   routingPool,
				"pricing_group":  pricingGroup,
				"vless_uri":      vlessURI,
			})
			nodes = append(nodes, gin.H{
				"id":               nodeID,
				"name":             nodeName,
				"display_name":     nodeName,
				"remark":           nodeName,
				"host":             host,
				"protocol":         "vless",
				"transport":        "xhttp",
				"security":         "tls",
				"address":          host,
				"port":             443,
				"server_name":      host,
				"uuid":             proxyUUID,
				"flow":             "",
				"source":           "server",
				"country_code":     countryCode,
				"resource_class":   resourceClass,
				"routing_pool":     routingPool,
				"pricing_group":    pricingGroup,
				"updated_at":       updatedAt,
				"vless_uri":        vlessURI,
				"uri_scheme_xhttp": vlessURI,
			})
		}
	}

	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"network_access": access,
		"schema_version": 1,
		"changed":        changed,
		"version":        version,
		"updated_at":     updatedAt,
		"profiles":       profiles,
		"nodes":          nodes,
		"rendered_json":  renderedJSON,
		"routes":         routes,
		"dns": gin.H{
			"mode":    "secure_tunnel",
			"servers": []string{},
		},
		"meta": gin.H{
			"digest":   digest,
			"warnings": warnings,
		},
		"digest":   digest,
		"warnings": warnings,
	})
}

// ListRegionalPools handles GET /api/agent-server/v1/regional-pools (read-only).
func (s *Service) ListRegionalPools(c *gin.Context) {
	user, ok := s.resolveAuthenticatedUser(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	c.Header("Cache-Control", "no-store")
	now := s.now()
	var pools []regionalPool
	if isRootRole(user.Role) {
		pools = registeredRegionalPools(s.enrollmentStatusSnapshots(ctx), s.routingPolicy, now)
	} else {
		if blocked, err := s.proxyAccountBlocked(ctx, user); err != nil {
			respondError(c, http.StatusServiceUnavailable, "network_access_unavailable", "network access is unavailable")
			return
		} else if blocked || !user.Active || user.ArchivedAt != nil {
			c.JSON(http.StatusOK, []regionalPool{})
			return
		}
		access, err := s.networkAccessForUser(ctx, user)
		if err != nil {
			respondError(c, http.StatusServiceUnavailable, "network_access_unavailable", "network access is unavailable")
			return
		}
		if !access.Allowed {
			c.JSON(http.StatusOK, []regionalPool{})
			return
		}
		packageName, err := s.billingPackageName(ctx, user)
		if err != nil {
			respondError(c, http.StatusServiceUnavailable, "billing_profile_unavailable", "failed to evaluate subscription resource class")
			return
		}
		pools = regionalPoolsForUser(s.networkSnapshots(ctx, access), access, user, packageName, s.routingPolicy, now)
		if dualBucketProGateEnabled() {
			quotaStatus, err := s.evaluateDualBucketQuotaForUser(ctx, user)
			if err != nil {
				respondError(c, http.StatusServiceUnavailable, "quota_unavailable", "failed to evaluate quota")
				return
			}
			filtered := make([]regionalPool, 0, len(pools))
			for _, pool := range pools {
				if poolAllowedForQuota(pool.RoutingPool, quotaStatus) {
					filtered = append(filtered, pool)
				}
			}
			pools = filtered
		}
	}
	if !isAdminOrOperatorRole(user.Role) {
		visible := make([]regionalPool, 0, len(pools))
		for _, pool := range pools {
			if pool.OpenToUsers {
				visible = append(visible, pool)
			}
		}
		pools = visible
	}
	c.JSON(http.StatusOK, pools)
}

// ResolveXConnectIdentity handles GET (and POST compatibility) /api/observability/internal/xconnect/identity.
func (s *Service) ResolveXConnectIdentity(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	var email, proxyUUID string
	if c.Request.Method == http.MethodGet {
		email = strings.ToLower(strings.TrimSpace(c.Query("email")))
		proxyUUID = strings.ToLower(strings.TrimSpace(c.Query("proxyUuid")))
		if proxyUUID == "" {
			proxyUUID = strings.ToLower(strings.TrimSpace(c.Query("proxy_uuid")))
		}
	} else {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4<<10)
		var req struct {
			Email     string `json:"email"`
			ProxyUUID string `json:"proxyUuid"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			respondError(c, http.StatusBadRequest, "invalid_identity_query", "provide exactly one email or proxyUuid")
			return
		}
		email = strings.ToLower(strings.TrimSpace(req.Email))
		proxyUUID = strings.ToLower(strings.TrimSpace(req.ProxyUUID))
	}

	if (email == "") == (proxyUUID == "") || len(email) > 320 || len(proxyUUID) > 128 {
		respondError(c, http.StatusBadRequest, "invalid_identity_query", "provide exactly one email or proxyUuid")
		return
	}
	if s.store == nil {
		respondError(c, http.StatusServiceUnavailable, "identity_lookup_unavailable", "identity store unavailable")
		return
	}

	var (
		user *User
		err  error
	)
	if email != "" {
		user, err = s.store.GetUserByEmail(c.Request.Context(), email)
	} else {
		user, err = s.store.GetUserByProxyUUID(c.Request.Context(), proxyUUID)
	}
	if errors.Is(err, ErrUserNotFound) {
		c.JSON(http.StatusOK, gin.H{"found": false, "identityRefVersion": 1})
		return
	}
	if err != nil {
		respondError(c, http.StatusInternalServerError, "identity_lookup_failed", "identity lookup failed")
		return
	}
	if user == nil || strings.TrimSpace(user.ProxyUUID) == "" {
		c.JSON(http.StatusOK, gin.H{"found": false, "identityRefVersion": 1})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"found":              true,
		"proxyIdentityRef":   xconnectProxyIdentityRef(user.ProxyUUID),
		"identityRefVersion": 1,
	})
}

func (s *Service) resolveAuthenticatedUser(c *gin.Context) (*User, bool) {
	userID := strings.TrimSpace(auth.GetUserID(c))
	if userID == "" || userID == "system" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session_token_required", "message": "authentication is required"})
		return nil, false
	}
	if s.store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user_store_unavailable"})
		return nil, false
	}
	user, err := s.store.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user_not_found"})
			return nil, false
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_fetch_user"})
		return nil, false
	}
	return user, true
}

func (s *Service) resolveUserNodes(c *gin.Context) (*userNodesContext, bool) {
	user, ok := s.resolveAuthenticatedUser(c)
	if !ok {
		return nil, false
	}
	ctx := c.Request.Context()
	if blocked, err := s.proxyAccountBlocked(ctx, user); err != nil {
		respondError(c, http.StatusServiceUnavailable, "network_access_unavailable", "network access is unavailable")
		return nil, false
	} else if blocked {
		respondError(c, http.StatusForbidden, "proxy_access_blocked", "proxy access is blocked")
		return nil, false
	}

	quotaStatus, err := s.evaluateDualBucketQuotaForUser(ctx, user)
	if err != nil {
		respondError(c, http.StatusServiceUnavailable, "quota_unavailable", "failed to evaluate quota")
		return nil, false
	}
	if quotaStatus.fullyExhausted {
		respondError(c, http.StatusForbidden, "quota_exhausted", "natural-month quota exhausted")
		return nil, false
	}

	if !user.Active || user.ArchivedAt != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "account_paused", "message": "account is paused"})
		return nil, false
	}

	proxyUUID := strings.TrimSpace(user.ProxyUUID)
	if proxyUUID == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "proxy_uuid_unavailable", "message": "proxy UUID is not provisioned for this account"})
		return nil, false
	}

	now := s.now()
	if user.ProxyUUIDExpiresAt != nil && now.After(*user.ProxyUUIDExpiresAt) {
		c.JSON(http.StatusForbidden, gin.H{"error": "proxy_uuid_expired", "message": "proxy access has expired, please renew"})
		return nil, false
	}

	access, err := s.networkAccessForUser(ctx, user)
	if err != nil {
		respondError(c, http.StatusServiceUnavailable, "network_access_unavailable", "network access is unavailable")
		return nil, false
	}
	if !access.Allowed {
		respondError(c, http.StatusForbidden, "team_access_inactive", "team access is inactive")
		return nil, false
	}

	packageName, err := s.billingPackageName(ctx, user)
	if err != nil {
		respondError(c, http.StatusServiceUnavailable, "billing_profile_unavailable", "failed to evaluate subscription resource class")
		return nil, false
	}

	resourceClass := effectiveAgentResourceClass(access, user, packageName)
	pools := regionalPoolsForUser(s.networkSnapshots(ctx, access), access, user, packageName, s.routingPolicy, now)

	xhttpMode := envOrDefault("XRAY_XHTTP_MODE", defaultXHTTPMode)
	xhttpPort := envIntOrDefault("XRAY_XHTTP_PORT", defaultXHTTPPort)
	tcpPort := envIntOrDefault("XRAY_TCP_PORT", defaultTCPPort)

	users := []string{proxyUUID}
	nodes := make([]VlessNode, 0, len(pools))
	subNodes := make([]SubscriptionNode, 0, len(pools))
	for _, pool := range pools {
		if !pool.OpenToUsers {
			continue
		}
		nodeClass := resourceClass
		if pool.ResourceClass == agentResourceFree {
			nodeClass = agentResourceFree
		}
		pricingGroup := strings.TrimSpace(pool.ResourceClass)
		if pricingGroup == "" {
			pricingGroup = nodeClass
		}
		routingPool := strings.TrimSpace(pool.RoutingPool)
		if routingPool == "" {
			routingPool = s.routingPolicy.PoolForResourceClass(pricingGroup)
		}
		if !poolAllowedForQuota(routingPool, quotaStatus) {
			continue
		}
		xhttpPath := poolXHTTPPath(envOrDefault("XRAY_XHTTP_PATH", defaultXHTTPPath), nodeClass)
		host := pool.Entry
		nodeName := pool.DisplayName
		if strings.TrimSpace(nodeName) == "" {
			nodeName = pool.Code
		}
		vlessXHTTP := renderVLESSURIScheme(vlessXHTTPScheme, map[string]string{
			"UUID":   proxyUUID,
			"DOMAIN": host,
			"NODE":   host,
			"PATH":   url.QueryEscape(xhttpPath),
			"MODE":   url.QueryEscape(xhttpMode),
			"SNI":    host,
			"FP":     defaultTLSFP,
			"TAG":    url.QueryEscape(nodeName),
		})
		vlessTCP := renderVLESSURIScheme(vlessTCPScheme, map[string]string{
			"UUID":   proxyUUID,
			"DOMAIN": host,
			"NODE":   host,
			"SNI":    host,
			"FP":     defaultTLSFP,
			"FLOW":   defaultTCPFlow,
			"TAG":    url.QueryEscape(nodeName),
		})
		nodes = append(nodes, VlessNode{
			Private:                 pool.Private,
			Name:                    nodeName,
			Region:                  pool.Code,
			PoolCount:               pool.PoolCount,
			OpenToUsers:             true,
			Address:                 host,
			Port:                    xhttpPort,
			Users:                   users,
			Transport:               "xhttp",
			Path:                    xhttpPath,
			Mode:                    xhttpMode,
			Security:                "tls",
			Flow:                    defaultTCPFlow,
			ResourceClass:           nodeClass,
			RoutingPool:             routingPool,
			PricingGroup:            pricingGroup,
			SubPoolTags:             append([]string(nil), pool.SubPoolTags...),
			ServerName:              host,
			XHTTPPort:               xhttpPort,
			TCPPort:                 tcpPort,
			URISchemeXHTTP:          vlessXHTTP,
			URISchemeTCP:            vlessTCP,
			HighSpeedQuotaExhausted: quotaStatus.gateEnabled && quotaStatus.highSpeedExhausted,
		})
		subNodes = append(subNodes, SubscriptionNode{
			ID:            host,
			Name:          nodeName,
			Region:        pool.Code,
			Address:       host,
			Port:          xhttpPort,
			UUID:          proxyUUID,
			Flow:          defaultTCPFlow,
			Transport:     "xhttp",
			Path:          xhttpPath,
			Mode:          xhttpMode,
			Security:      "tls",
			ServerName:    host,
			Fingerprint:   defaultTLSFP,
			ResourceClass: pricingGroup,
			RoutingPool:   routingPool,
			PricingGroup:  pricingGroup,
			SubPoolTags:   append([]string(nil), pool.SubPoolTags...),
			VlessURI:      vlessXHTTP,
		})
	}

	if access.Mode == "dedicated" && len(nodes) == 0 {
		respondError(c, http.StatusServiceUnavailable, "team_nodes_unavailable", "dedicated team nodes are unavailable")
		return nil, false
	}

	return &userNodesContext{
		user:                    user,
		access:                  access,
		packageName:             packageName,
		resourceClass:           resourceClass,
		highSpeedQuotaExhausted: quotaStatus.gateEnabled && quotaStatus.highSpeedExhausted,
		nodes:                   nodes,
		subNodes:                subNodes,
	}, true
}

func (s *Service) resolveScopedAgent(c *gin.Context, credential Identity, requested string, readOnly bool) (Identity, *TeamAgentEnrollment, bool) {
	if credential.NodeID != "" {
		id, ok := s.resolveNodeBoundAgent(c, credential, requested)
		return id, nil, ok
	}
	identity, enrollment, ok := s.resolveScopedAgentLegacy(c, credential, requested, readOnly)
	if !ok {
		return identity, nil, false
	}
	if enrollment != nil && enrollment.Status != "approved" {
		if c.GetHeader("X-Agent-Allowed-Emails") != "" || c.GetHeader("X-Agent-Email-Policy") != "" {
			respondError(c, http.StatusBadRequest, "agent_email_policy_invalid", "team nodes do not support email extensions")
			return identity, nil, false
		}
		return identity, enrollment, true
	}
	scope, valid := agentResourceScope(identity.Groups)
	if !valid {
		respondError(c, http.StatusForbidden, "agent_scope_invalid", "invalid node scope")
		return identity, nil, false
	}
	raw := c.GetHeader("X-Agent-Allowed-Emails")
	policy := c.GetHeader("X-Agent-Email-Policy")
	if scope.ResourceClass == agentResourceCustom {
		return identity, enrollment, true
	}
	if scope.ResourceClass == agentResourceTeam {
		if raw != "" || policy != "" {
			respondError(c, http.StatusBadRequest, "agent_email_policy_invalid", "team nodes do not support email extensions")
			return identity, nil, false
		}
		return identity, enrollment, true
	}
	groups := make([]string, 0, len(identity.Groups))
	for _, g := range identity.Groups {
		if !strings.HasPrefix(g, unionEmailPrefix) && !strings.HasPrefix(g, "node-email-policy:") {
			groups = append(groups, g)
		}
	}
	identity.Groups = groups
	if policy == "" && raw == "" {
		return identity, enrollment, true
	}
	if !agentproto.PublicResourceClass(scope.ResourceClass) || policy != agentproto.PublicEmailUnionPolicy {
		respondError(c, http.StatusBadRequest, "agent_email_policy_invalid", "public email extension requires public-union-v1")
		return identity, nil, false
	}
	var emails []string
	if err := json.Unmarshal([]byte(raw), &emails); err != nil {
		respondError(c, http.StatusBadRequest, "agent_email_policy_invalid", "email extension must be an array")
		return identity, nil, false
	}
	manager := false
	cs, cv := agentResourceScope(credential.Groups)
	for _, g := range credential.Groups {
		if g == "agent:configure-public" || (g == "internal" && credential.ID == "*" && cv && cs.ResourceClass == agentResourceShared) {
			manager = true
		}
	}
	if !manager || (credential.ID != "*" && credential.ID != identity.ID) {
		respondError(c, http.StatusForbidden, "agent_scope_mismatch", "email extension requires node configuration permission")
		return identity, nil, false
	}
	emails, err := agentproto.NormalizeNodeEmails(emails)
	if err != nil {
		respondError(c, http.StatusBadRequest, "agent_email_policy_invalid", "invalid node email list")
		return identity, nil, false
	}
	for _, email := range emails {
		identity.Groups = append(identity.Groups, unionEmailPrefix+email)
	}
	identity.Groups = append(identity.Groups, "node-email-policy:"+agentproto.PublicEmailUnionPolicy)
	return identity, enrollment, true
}

func (s *Service) resolveNodeBoundAgent(c *gin.Context, credential Identity, requested string) (Identity, bool) {
	for _, id := range []string{requested, c.GetHeader(agentIDHeader), c.Query("agentId")} {
		if id != "" && strings.TrimSpace(id) != credential.ID {
			respondError(c, http.StatusForbidden, "agent_scope_mismatch", "node credential cannot select another agent")
			return credential, false
		}
	}
	scope, valid := agentResourceScope(credential.Groups)
	if !valid {
		respondError(c, http.StatusForbidden, "agent_scope_invalid", "invalid enrolled node scope")
		return credential, false
	}
	if class := c.GetHeader("X-Agent-Resource-Class"); class != "" && class != scope.ResourceClass {
		respondError(c, http.StatusForbidden, "agent_scope_mismatch", "node scope is bound to credential")
		return credential, false
	}
	if team := c.GetHeader("X-Agent-Team-ID"); team != "" && team != scope.TeamID {
		respondError(c, http.StatusForbidden, "agent_scope_mismatch", "node team is bound to credential")
		return credential, false
	}
	raw := c.GetHeader("X-Agent-Custom-Allow-Free")
	if raw != "" && raw != "true" && raw != "false" {
		respondError(c, http.StatusBadRequest, "agent_scope_invalid", "invalid custom Free flag")
		return credential, false
	}
	if raw == "true" && !scope.CustomAllowFree {
		respondError(c, http.StatusForbidden, "agent_scope_mismatch", "custom Free audience is not enrolled")
		return credential, false
	}
	if scope.ResourceClass == agentResourceCustom {
		if len(credential.AllowedEmails) == 0 {
			respondError(c, http.StatusForbidden, "agent_scope_invalid", "custom node has no enrolled audience")
			return credential, false
		}
		encoded, _ := json.Marshal(credential.AllowedEmails)
		c.Request.Header.Set("X-Agent-Allowed-Emails", string(encoded))
	}
	return credential, true
}

func (s *Service) resolveScopedAgentLegacy(c *gin.Context, credential Identity, requested string, readOnly bool) (Identity, *TeamAgentEnrollment, bool) {
	identity, enrollment, ok := s.resolveScopedAgentBase(c, credential, requested, readOnly)
	if !ok {
		return identity, nil, false
	}
	raw := c.GetHeader("X-Agent-Custom-Allow-Free")
	if raw != "" && raw != "true" && raw != "false" {
		respondError(c, http.StatusBadRequest, "agent_scope_invalid", "custom allow free must be true or false")
		return identity, nil, false
	}
	groups := make([]string, 0, len(identity.Groups))
	for _, g := range identity.Groups {
		if g != "custom:allow-free" {
			groups = append(groups, g)
		}
	}
	identity.Groups = groups
	if raw != "true" {
		return identity, enrollment, true
	}
	scope, valid := agentResourceScope(groups)
	cs, cv := agentResourceScope(credential.Groups)
	manager := false
	for _, g := range credential.Groups {
		if g == "agent:configure-public" || (g == "internal" && credential.ID == "*" && cs.ResourceClass == agentResourceShared) {
			manager = true
		}
	}
	teamManager := valid && cv && scope.ResourceClass == "team" && cs.ResourceClass == "team" && scope.TeamID == cs.TeamID && credential.ID == identity.ID
	publicManager := valid && cv && scope.ResourceClass != "team" && cs.ResourceClass != "team" && manager && (credential.ID == "*" || credential.ID == identity.ID)
	if !valid || !cv || (!teamManager && !publicManager) {
		respondError(c, http.StatusForbidden, "agent_scope_mismatch", "Free audience requires public pool management or matching team scope")
		return identity, nil, false
	}
	identity.Groups = append(groups, "custom:allow-free")
	return identity, enrollment, true
}

func (s *Service) resolveScopedAgentBase(c *gin.Context, credential Identity, requested string, readOnly bool) (Identity, *TeamAgentEnrollment, bool) {
	if identity, enrollment, ok, handled := s.resolveManagedTeam(c, credential, requested, readOnly); handled {
		return identity, enrollment, ok
	}
	identity, ok := s.resolveAgentIdentity(c, credential, requested, readOnly)
	if !ok {
		return identity, nil, false
	}
	class := strings.TrimSpace(c.GetHeader("X-Agent-Resource-Class"))
	teamID := strings.TrimSpace(c.GetHeader("X-Agent-Team-ID"))
	if class == "" && teamID == "" {
		return identity, nil, true
	}
	if class != agentResourceShared && class != agentResourceFree && class != agentResourcePlus && class != agentResourcePro && class != agentResourceCustom && class != agentResourceTeam {
		respondError(c, http.StatusBadRequest, "agent_scope_invalid", "resource class must be shared, free, plus, pro, custom or team")
		return identity, nil, false
	}
	if class != agentResourceTeam && teamID != "" || class == agentResourceTeam && teamID == "" {
		respondError(c, http.StatusBadRequest, "agent_scope_invalid", "team ID is required only for team nodes")
		return identity, nil, false
	}
	scope, valid := agentResourceScope(identity.Groups)
	if !valid {
		respondError(c, http.StatusForbidden, "agent_scope_invalid", "invalid registered agent scope")
		return identity, nil, false
	}
	credentialScope, valid := agentResourceScope(credential.Groups)
	if !valid {
		respondError(c, http.StatusForbidden, "agent_scope_invalid", "invalid credential scope")
		return identity, nil, false
	}
	managePublic := false
	hasConfigurePublic := false
	for _, group := range credential.Groups {
		if group == "agent:configure-public" {
			hasConfigurePublic = true
		}
		if group == "agent:configure-public" || (group == "internal" && credential.ID == "*" && credentialScope.ResourceClass == agentResourceShared) {
			managePublic = true
		}
	}
	if class == agentResourceCustom && hasConfigurePublic {
		respondError(c, http.StatusForbidden, "agent_scope_mismatch", "agent:configure-public credentials cannot claim resource:custom")
		return identity, nil, false
	}
	managePublic = managePublic && (credential.ID == "*" || credential.ID == identity.ID)
	if managePublic && credentialScope.ResourceClass != agentResourceTeam && credentialScope.ResourceClass != agentResourceCustom && scope.ResourceClass != agentResourceTeam && class != agentResourceTeam && (class != agentResourceCustom || !hasConfigurePublic) {
		groups := make([]string, 0, len(identity.Groups)+1)
		for _, group := range identity.Groups {
			if !strings.HasPrefix(strings.TrimSpace(group), agentResourceGroupPrefix) {
				groups = append(groups, group)
			}
		}
		identity.Groups = append(groups, agentResourceGroupPrefix+class)
		return identity, nil, true
	}
	if scope.ResourceClass != class || scope.TeamID != teamID || (!managePublic && !equalStringSlices(scope, credentialScope)) {
		respondError(c, http.StatusForbidden, "agent_scope_mismatch", "requested class requires matching enrolled scope or public pool management permission")
		return identity, nil, false
	}
	return identity, nil, true
}

func equalStringSlices(a, b agentproto.UserScope) bool {
	return a.ResourceClass == b.ResourceClass && a.TeamID == b.TeamID && a.CustomAllowFree == b.CustomAllowFree && a.EmailPolicy == b.EmailPolicy && a.EmailDigest == b.EmailDigest
}

func (s *Service) resolveManagedTeam(c *gin.Context, credential Identity, requested string, readOnly bool) (Identity, *TeamAgentEnrollment, bool, bool) {
	class := strings.TrimSpace(c.GetHeader("X-Agent-Resource-Class"))
	if requested == "" {
		requested = strings.TrimSpace(c.GetHeader(agentIDHeader))
	}
	if requested == "" {
		requested = strings.TrimSpace(c.Query("agentId"))
	}
	if !deploymentCredential(credential) {
		return credential, nil, false, false
	}
	existingManaged := false
	if s.registry != nil {
		for _, a := range s.registry.Agents() {
			if a.ID == requested && managedTeam(a.Groups) {
				existingManaged = true
			}
		}
	}
	var existingEnrollment *TeamAgentEnrollment
	if s.store != nil {
		rows, err := s.store.ListTeamAgents(c.Request.Context())
		if err != nil {
			respondError(c, http.StatusServiceUnavailable, "agent_enrollment_unavailable", "team enrollment store unavailable")
			return credential, nil, false, true
		}
		for i := range rows {
			if rows[i].AgentID == requested {
				existingManaged = true
				cp := rows[i]
				existingEnrollment = &cp
				break
			}
		}
	}
	if class != "team" && !existingManaged {
		return credential, nil, false, false
	}
	if class != "team" {
		respondError(c, http.StatusForbidden, "agent_scope_mismatch", "registered team node cannot switch to a public scope")
		return credential, nil, false, true
	}
	suggested := strings.TrimSpace(c.GetHeader("X-Agent-Team-ID"))
	if requested == "" || requested == "*" || len(requested) > 253 || strings.ContainsAny(requested, " /\t\r\n") || (suggested != "" && !networkTeamIDPattern.MatchString(suggested)) {
		respondError(c, http.StatusBadRequest, "agent_scope_invalid", "team enrollment requires a valid node ID and optional suggested team ID")
		return credential, nil, false, true
	}
	if s.registry != nil {
		for _, a := range s.registry.Agents() {
			if a.ID == requested && !managedTeam(a.Groups) {
				team, valid := agentNetworkScope(a.Groups)
				if !valid || team != "" || a.NodeID != "" {
					respondError(c, http.StatusForbidden, "agent_scope_mismatch", "agent identity is bound to its credential")
					return credential, nil, false, true
				}
			}
		}
	}

	var e TeamAgentEnrollment
	if readOnly {
		if existingEnrollment != nil {
			e = *existingEnrollment
		} else {
			e = TeamAgentEnrollment{
				AgentID:         requested,
				SuggestedTeamID: suggested,
				Status:          "pending",
				UpdatedAt:       s.now(),
			}
		}
		identity := Identity{
			ID:     requested,
			Name:   requested,
			Groups: enrollmentGroups(e),
		}
		return identity, &e, true, true
	}

	if s.store == nil {
		respondError(c, http.StatusServiceUnavailable, "agent_enrollment_unavailable", "team enrollment store unavailable")
		return credential, nil, false, true
	}
	var err error
	e, err = s.store.RegisterTeamAgent(c.Request.Context(), requested, suggested)
	if err != nil {
		respondError(c, http.StatusServiceUnavailable, "agent_enrollment_unavailable", "team enrollment store unavailable")
		return credential, nil, false, true
	}
	identity := s.registry.RegisterAgent(requested, enrollmentGroups(e))
	identity.Groups = enrollmentGroups(e)
	s.registry.SetAgentGroups(identity.ID, identity.Groups)
	return identity, &e, true, true
}

func (s *Service) resolveAgentIdentity(c *gin.Context, credential Identity, requested string, readOnly bool) (Identity, bool) {
	team, valid := agentNetworkScope(credential.Groups)
	if !valid {
		respondError(c, http.StatusForbidden, "agent_scope_invalid", "agent credential has an invalid network scope")
		return credential, false
	}
	if requested == "" {
		requested = strings.TrimSpace(c.GetHeader(agentIDHeader))
	}
	if requested == "" {
		requested = strings.TrimSpace(c.Query("agentId"))
	}
	if requested == "" || requested == credential.ID {
		return credential, true
	}
	if team != "" {
		respondError(c, http.StatusForbidden, "agent_scope_mismatch", "agent identity is bound to its credential")
		return credential, false
	}
	for _, identity := range s.registry.Agents() {
		if identity.ID == requested {
			target, ok := agentNetworkScope(identity.Groups)
			if !ok || target != "" || identity.NodeID != "" {
				respondError(c, http.StatusForbidden, "agent_scope_mismatch", "agent identity is bound to its credential")
				return credential, false
			}
		}
	}
	if readOnly {
		return Identity{
			ID:     requested,
			Name:   requested,
			Groups: append([]string(nil), credential.Groups...),
		}, true
	}
	return s.registry.RegisterAgent(requested, credential.Groups), true
}

func deriveSyncVersion(user *User, now time.Time) int64 {
	if user == nil {
		return now.Unix()
	}
	if !user.UpdatedAt.IsZero() {
		return user.UpdatedAt.UTC().Unix()
	}
	if !user.CreatedAt.IsZero() {
		return user.CreatedAt.UTC().Unix()
	}
	return now.Unix()
}

func extractHostFromPublicURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Hostname())
}

func parseOptionalTime(value string) (time.Time, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err == nil {
		return parsed.UTC(), nil
	}
	return time.Parse("2006-01-02T15:04", trimmed)
}
