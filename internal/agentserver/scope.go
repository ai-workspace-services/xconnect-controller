package agentserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ai-workspace-services/xconnect-controller/internal/agentproto"
)

const (
	agentIDHeader            = "X-Agent-ID"
	agentResourceGroupPrefix = "resource:"
	agentResourceShared      = "shared"
	agentResourceFree        = "free"
	agentResourcePlus        = "plus"
	agentResourcePro         = "pro"
	agentResourceCustom      = "custom"
	agentResourceTeam        = "team"

	unionEmailPrefix       = "node-email-union:"
	managedTeamMarker      = "enrollment:team"
	teamAdminGroupPrefix   = "team-admin:"
	teamAdminRoleSuffix    = ":admin"
	regionalHeartbeatTTL   = 5 * time.Minute
	agentFreeGrantPrefix   = "agent:free-grant:"
	maxAgentFreeGrantTTL   = 120 * time.Hour
	defaultXHTTPPath       = "/split"
	defaultXHTTPMode       = "auto"
	defaultXHTTPPort       = 443
	defaultTCPPort         = 1443
	defaultTLSFP           = "chrome"
	defaultTCPFlow         = "xtls-rprx-vision"
)

var networkTeamIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type networkAccess struct {
	AccountID  string       `json:"accountId,omitempty"`
	Configured bool         `json:"-"`
	Mode       string       `json:"mode"`
	TeamID     string       `json:"teamId,omitempty"`
	Team       *NetworkTeam `json:"team,omitempty"`
	Role       string       `json:"role,omitempty"`
	Allowed    bool         `json:"allowed"`
}

func isRootRole(role string) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	return r == "root" || r == "superadmin"
}

func isAdminOrOperatorRole(role string) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	return isRootRole(r) || r == "admin" || r == "operator"
}

func accountAccessVerified(user *User) bool {
	if user == nil {
		return false
	}
	if user.EmailVerified {
		return true
	}
	for _, group := range user.Groups {
		if group == EmailOptionalRegistrationGroup {
			return true
		}
	}
	return false
}

func normalizeMonthlyQuotaGroup(group string) string {
	switch strings.TrimSpace(group) {
	case MonthlyFreeQuotaLimitGroup, MonthlyFreeQuota5GBAliasGroup:
		return MonthlyFreeQuotaLimitGroup
	case MonthlyPlusQuotaLimitGroup, MonthlyUnlimitedBetaQuotaGroup:
		return strings.TrimSpace(group)
	default:
		return ""
	}
}

var monthlyQuotaGroups = [...]string{
	MonthlyUnlimitedBetaQuotaGroup,
	MonthlyPlusQuotaLimitGroup,
	MonthlyFreeQuotaLimitGroup,
}

func monthlyQuotaGroup(user *User) string {
	if user == nil {
		return ""
	}
	for _, known := range monthlyQuotaGroups {
		for _, group := range user.Groups {
			if normalizeMonthlyQuotaGroup(group) == known {
				return known
			}
		}
	}
	return ""
}

func isWhitelistFreeMember(user *User) bool {
	if user == nil {
		return false
	}
	for _, group := range user.Groups {
		if strings.TrimSpace(group) == WhitelistFreeQuotaGroup {
			return true
		}
	}
	return false
}

func isOneTimeTrialMember(user *User) bool {
	if user == nil {
		return false
	}
	for _, group := range user.Groups {
		if strings.TrimSpace(group) == OneTimeTrialQuotaGroup {
			return true
		}
	}
	return false
}

func hasSubscriptionUnlimitedOverride(user *User, now time.Time) bool {
	if user == nil || !user.Active || user.ArchivedAt != nil {
		return false
	}
	if user.SubscriptionValidFrom != nil && now.Before(*user.SubscriptionValidFrom) {
		return false
	}
	if user.SubscriptionValidUntil != nil {
		end := user.SubscriptionValidUntil.UTC()
		if !now.UTC().Before(time.Date(end.Year(), end.Month(), end.Day()+1, 0, 0, 0, 0, time.UTC)) {
			return false
		}
	}
	var override, recurring, listed bool
	for _, group := range user.Groups {
		switch group {
		case SubscriptionUnlimitedOverrideGroup:
			override = true
		case SubscriptionListedGroup:
			listed = true
		case "segment:monthly", "segment:yearly", "segment:subscription:monthly", "segment:subscription:yearly":
			recurring = true
		}
	}
	return listed && override && recurring && monthlyQuotaGroup(user) == MonthlyPlusQuotaLimitGroup
}

func isMonthlyQuotaLimitMember(user *User) bool {
	if hasSubscriptionUnlimitedOverride(user, time.Now()) {
		return false
	}
	if isWhitelistFreeMember(user) || isOneTimeTrialMember(user) {
		return true
	}
	group := monthlyQuotaGroup(user)
	return group == MonthlyFreeQuotaLimitGroup || group == MonthlyPlusQuotaLimitGroup
}

func isCustomDedicatedUser(user *User, packageName string) bool {
	if strings.EqualFold(strings.TrimSpace(packageName), agentResourceCustom) {
		return true
	}
	if user == nil {
		return false
	}
	for _, group := range user.Groups {
		switch strings.ToLower(strings.TrimSpace(group)) {
		case "resource:custom", "segment:custom", "access:custom", "access:custom-dedicated", "pool:custom-dedicated":
			return true
		}
	}
	return false
}

func hasMediaPassthroughEntitlement(user *User, packageName string) bool {
	pkg := strings.ToLower(strings.TrimSpace(packageName))
	if pkg == "media-passthrough" || pkg == "unlimited" || pkg == "unlimited-beta" {
		return true
	}
	if user == nil {
		return false
	}
	for _, group := range user.Groups {
		switch strings.ToLower(strings.TrimSpace(group)) {
		case "media:passthrough", "segment:media-passthrough", "pool:media-passthrough", "segment:quota:unlimited":
			return true
		}
	}
	return false
}

func hasMediaPassthroughAgentGroup(groups []string) bool {
	for _, group := range groups {
		switch strings.ToLower(strings.TrimSpace(group)) {
		case "media:passthrough", "pool:media-passthrough":
			return true
		}
	}
	return false
}

func effectiveAgentResourceClass(access networkAccess, user *User, packageName string) string {
	if access.Mode == "dedicated" {
		return agentResourceTeam
	}
	if isCustomDedicatedUser(user, packageName) {
		return agentResourceCustom
	}
	if isOneTimeTrialMember(user) || strings.EqualFold(strings.TrimSpace(packageName), "trial") {
		return agentResourcePro
	}
	group := monthlyQuotaGroup(user)
	if strings.EqualFold(strings.TrimSpace(packageName), agentResourcePro) &&
		(group == MonthlyPlusQuotaLimitGroup || group == MonthlyUnlimitedBetaQuotaGroup) {
		return agentResourcePro
	}
	if group == MonthlyPlusQuotaLimitGroup || group == MonthlyUnlimitedBetaQuotaGroup {
		return agentResourcePlus
	}
	return agentResourceFree
}

func agentNetworkScope(groups []string) (string, bool) {
	team, dedicated := "", false
	for _, g := range groups {
		g = strings.TrimSpace(g)
		lower := strings.ToLower(g)
		if strings.HasPrefix(lower, "team-admin:") ||
			(strings.HasPrefix(lower, "team:") && !strings.HasPrefix(g, "team:")) ||
			(lower == "access:dedicated-only" && g != lower) {
			return "", false
		}
		if g == "access:dedicated-only" {
			dedicated = true
		}
		if strings.HasPrefix(g, "team:") {
			id := strings.TrimPrefix(g, "team:")
			if !networkTeamIDPattern.MatchString(id) || (team != "" && team != id) {
				return "", false
			}
			team = id
		}
	}
	return team, !dedicated || team != ""
}

func networkScopeAllows(access networkAccess, groups []string) bool {
	team, valid := agentNetworkScope(groups)
	if !valid || !access.Allowed {
		return false
	}
	if access.Mode == "dedicated" {
		return access.TeamID != "" && team == access.TeamID
	}
	return team == ""
}

func agentResourceScope(groups []string) (agentproto.UserScope, bool) {
	scope := agentproto.UserScope{ResourceClass: agentResourceShared}
	if hasPublicUnionPolicy(groups) {
		scope.EmailPolicy = agentproto.PublicEmailUnionPolicy
		scope.EmailDigest = agentproto.NodeEmailDigest(publicUnionEmails(groups))
	}
	for _, group := range groups {
		if group == "custom:allow-free" {
			scope.CustomAllowFree = true
		}
	}
	seen := ""
	hasConfigurePublic := false
	team, valid := agentNetworkScope(groups)
	if !valid {
		return agentproto.UserScope{}, false
	}
	if team != "" {
		scope.ResourceClass, scope.TeamID = "team", team
		seen = "team"
	}
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "agent:configure-public" {
			hasConfigurePublic = true
			continue
		}
		if !strings.HasPrefix(group, agentResourceGroupPrefix) {
			continue
		}
		class := strings.TrimPrefix(group, agentResourceGroupPrefix)
		if class != agentResourceShared && class != agentResourceFree && class != agentResourcePlus && class != agentResourcePro && class != agentResourceCustom {
			return agentproto.UserScope{}, false
		}
		if seen != "" && seen != class {
			return agentproto.UserScope{}, false
		}
		seen = class
		scope.ResourceClass = class
	}
	if hasConfigurePublic && scope.ResourceClass == agentResourceCustom {
		return agentproto.UserScope{}, false
	}
	if scope.ResourceClass == "team" && seen != "team" {
		return agentproto.UserScope{}, false
	}
	if scope.ResourceClass != "team" && scope.TeamID != "" {
		return agentproto.UserScope{}, false
	}
	return scope, true
}

func agentResourceScopeAllowsUser(scope agentproto.UserScope, access networkAccess, user *User, packageName string) bool {
	if scope.ResourceClass == "team" {
		return access.Mode == "dedicated" && access.TeamID == scope.TeamID
	}
	if access.Mode == "dedicated" {
		return false
	}
	class := effectiveAgentResourceClass(access, user, packageName)
	if scope.ResourceClass == agentResourceCustom {
		if isOneTimeTrialMember(user) || strings.EqualFold(strings.TrimSpace(packageName), "trial") {
			return false
		}
		return class == agentResourceCustom || class == agentResourcePlus || class == agentResourcePro || (scope.CustomAllowFree && class == agentResourceFree)
	}
	return publicAgentResourceClassAllows(scope.ResourceClass, class)
}

func publicAgentResourceClassAllows(poolClass, userClass string) bool {
	if poolClass == agentResourceShared && userClass == agentResourceCustom {
		return true
	}
	rank := map[string]int{agentResourceFree: 1, agentResourcePlus: 2, agentResourcePro: 3}
	userRank, known := rank[userClass]
	if !known {
		return false
	}
	if poolClass == agentResourceShared {
		return true
	}
	poolRank, known := rank[poolClass]
	return known && userRank >= poolRank
}

func accessFromNetworkMembership(member NetworkMembership, teams []NetworkTeam, now time.Time) networkAccess {
	access := networkAccess{Mode: "personal", Allowed: true, Configured: member.Configured}
	if !member.DedicatedOnly && member.TeamID == "" {
		return access
	}
	access.Mode, access.TeamID, access.Allowed = "dedicated", member.TeamID, false
	for i := range teams {
		team := teams[i]
		if team.ID == member.TeamID {
			access.Team = &team
			access.Allowed = team.Active && !now.Before(team.ValidFrom) && now.Before(team.ValidUntil)
			break
		}
	}
	return access
}

func hasPublicUnionPolicy(groups []string) bool {
	for _, g := range groups {
		if g == "node-email-policy:"+agentproto.PublicEmailUnionPolicy {
			return true
		}
	}
	return false
}

func publicUnionEmails(groups []string) []string {
	emails := []string{}
	for _, g := range groups {
		if strings.HasPrefix(g, unionEmailPrefix) {
			emails = append(emails, strings.TrimPrefix(g, unionEmailPrefix))
		}
	}
	normalized, err := agentproto.NormalizeNodeEmails(emails)
	if err != nil {
		return nil
	}
	return normalized
}

func publicUnionEmailMatches(groups []string, user *User) bool {
	emails := publicUnionEmails(groups)
	return len(emails) > 0 && agentEmailAllowed(emails, user)
}

func publicAgentDisplayGroups(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if !strings.HasPrefix(g, unionEmailPrefix) && !strings.HasPrefix(g, "node-email-policy:") {
			out = append(out, g)
		}
	}
	return out
}

func agentEmailAllowed(emails []string, user *User) bool {
	if len(emails) == 0 {
		return true
	}
	if user == nil {
		return false
	}
	for _, email := range emails {
		if strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(user.Email)) && strings.TrimSpace(email) != "" {
			return true
		}
	}
	return false
}

type agentFreeGrant struct {
	NodeID    string    `json:"nodeId"`
	AccountID string    `json:"accountId"`
	Email     string    `json:"email,omitempty"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func validAgentFreeGrantNodeID(nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || nodeID == "*" || len(nodeID) > 128 {
		return false
	}
	if strings.ContainsAny(nodeID, ": /\t\r\n") {
		return false
	}
	return true
}

func parseAgentFreeGrantGroup(raw, accountID, email string) (agentFreeGrant, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, agentFreeGrantPrefix) {
		return agentFreeGrant{}, false
	}
	rest := strings.TrimPrefix(raw, agentFreeGrantPrefix)
	nodeID, encoded, ok := strings.Cut(rest, ":")
	if !ok || !validAgentFreeGrantNodeID(nodeID) || encoded == "" {
		return agentFreeGrant{}, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return agentFreeGrant{}, false
	}
	var grant agentFreeGrant
	if err := json.Unmarshal(decoded, &grant); err != nil {
		return agentFreeGrant{}, false
	}
	if grant.NodeID != nodeID {
		return agentFreeGrant{}, false
	}
	accountID = strings.TrimSpace(accountID)
	if accountID != "" && grant.AccountID != "" && grant.AccountID != accountID {
		return agentFreeGrant{}, false
	}
	if grant.Status != "active" && grant.Status != "revoked" {
		return agentFreeGrant{}, false
	}
	if grant.ExpiresAt.IsZero() || grant.CreatedAt.IsZero() || grant.UpdatedAt.IsZero() {
		return agentFreeGrant{}, false
	}
	if grant.ExpiresAt.Sub(grant.UpdatedAt) > maxAgentFreeGrantTTL+time.Minute {
		return agentFreeGrant{}, false
	}
	return grant, true
}

func activeAgentFreeGrant(user *User, nodeID string, now time.Time) (agentFreeGrant, bool) {
	if user == nil || !user.Active || user.ArchivedAt != nil || !validAgentFreeGrantNodeID(nodeID) {
		return agentFreeGrant{}, false
	}
	now = now.UTC()
	var matched agentFreeGrant
	found := false
	for _, g := range user.Groups {
		trimmed := strings.TrimSpace(g)
		if !strings.HasPrefix(trimmed, agentFreeGrantPrefix+nodeID+":") {
			continue
		}
		grant, ok := parseAgentFreeGrantGroup(trimmed, user.ID, user.Email)
		if !ok {
			return agentFreeGrant{}, false
		}
		matched = grant
		found = true
	}
	if !found || matched.Status != "active" || !now.Before(matched.ExpiresAt) {
		return agentFreeGrant{}, false
	}
	return matched, true
}

func hasActiveAgentFreeGrant(user *User, nodeID string, now time.Time) bool {
	_, ok := activeAgentFreeGrant(user, nodeID, now)
	return ok
}

func managedTeam(groups []string) bool {
	for _, g := range groups {
		if g == managedTeamMarker {
			return true
		}
	}
	return false
}

func enrollmentGroups(e TeamAgentEnrollment) []string {
	if e.Status == "approved" {
		return []string{managedTeamMarker, "team:" + e.AssignedTeamID}
	}
	return []string{managedTeamMarker, "access:dedicated-only"}
}

func enrollmentRevision(e TeamAgentEnrollment) string {
	sum := sha256.Sum256([]byte(e.AgentID + "\x00" + e.Status + "\x00" + e.AssignedTeamID + "\x00" + e.UpdatedAt.UTC().Format(time.RFC3339Nano)))
	return "enrollment-" + hex.EncodeToString(sum[:])
}

func deploymentCredential(identity Identity) bool {
	scope, valid := agentResourceScope(identity.Groups)
	if !valid || scope.ResourceClass != agentResourceShared || identity.ID != "*" {
		return false
	}
	for _, g := range identity.Groups {
		if g == "internal" || g == "agent:configure-public" {
			return true
		}
	}
	return false
}

type regionalClosureReason string

const (
	regionalExplicitDisabled regionalClosureReason = "explicit_disabled"
	regionalStale            regionalClosureReason = "stale"
	regionalUnhealthy        regionalClosureReason = "unhealthy"
	regionalXrayNotRunning   regionalClosureReason = "xray_not_running"
)

type regionalPool struct {
	Private          bool                    `json:"private,omitempty"`
	Code             string                  `json:"code"`
	Entry            string                  `json:"entry"`
	DisplayName      string                  `json:"displayName,omitempty"`
	ResourceClass    string                  `json:"resourceClass,omitempty"`
	TeamID           string                  `json:"teamId,omitempty"`
	RoutingPool      string                  `json:"routingPool,omitempty"`
	MediaOnProAction string                  `json:"mediaOnProAction,omitempty"`
	PublicResource   bool                    `json:"publicResource"`
	SubPoolTags      []string                `json:"subPoolTags,omitempty"`
	PoolCount        int                     `json:"poolCount"`
	OpenToUsers      bool                    `json:"openToUsers"`
	ClosedReasons    []regionalClosureReason `json:"closedReasons"`
}

func populateRegionalPoolRoutingMetadata(pool *regionalPool, resourceClass string, report agentproto.StatusReport, policy RoutingPolicyConfig) {
	if pool == nil {
		return
	}
	if resourceClass == "" {
		pool.RoutingPool = ""
		pool.MediaOnProAction = ""
		pool.PublicResource = false
		return
	}
	routingPool := policy.PoolForResourceClass(resourceClass)
	if strings.EqualFold(strings.TrimSpace(report.Xray.RoutingPool), RoutingPoolCustomDedicated) {
		routingPool = RoutingPoolCustomDedicated
	}
	pool.RoutingPool = routingPool
	pool.MediaOnProAction = policy.MediaOnProActionFor(routingPool)
	pool.PublicResource = policy.IsPublicPool(routingPool)
	if len(report.Xray.SubPoolTags) > 0 {
		pool.SubPoolTags = append([]string(nil), report.Xray.SubPoolTags...)
	} else if tags := policy.SubPoolTagsFor(routingPool); len(tags) > 0 {
		pool.SubPoolTags = tags
	}
}

func reportedResourceClass(snapshot StatusSnapshot) (string, string) {
	if scope, valid := agentResourceScope(snapshot.Agent.Groups); valid {
		return scope.ResourceClass, strings.TrimSpace(scope.TeamID)
	}
	return "", ""
}

func regionalEntryHost(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || host == "*" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return ""
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ""
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return ""
			}
		}
	}
	return host
}

func regionalPoolsForUser(snapshots []StatusSnapshot, access networkAccess, user *User, packageName string, policy RoutingPolicyConfig, now time.Time) []regionalPool {
	wantClass := effectiveAgentResourceClass(access, user, packageName)
	wantTeam := strings.TrimSpace(access.TeamID)
	customAllowed := wantClass == agentResourceCustom || (access.Mode != "dedicated" && isCustomDedicatedUser(user, packageName))

	type aggregate struct {
		pool    regionalPool
		ids     map[string]bool
		reasons map[regionalClosureReason]bool
	}
	groups := map[string]*aggregate{}
	for _, snapshot := range snapshots {
		report := snapshot.Report
		resourceClass, teamID := reportedResourceClass(snapshot)
		if resourceClass == "" {
			continue
		}
		scope, scopeValid := agentResourceScope(snapshot.Agent.Groups)
		customEmails := report.Xray.AllowedEmails
		if len(customEmails) == 0 && snapshot.Agent.NodeID != "" {
			customEmails = snapshot.Agent.AllowedEmails
		}
		tempFreeAllowed := resourceClass == agentResourceCustom &&
			scopeValid &&
			access.Mode != "dedicated" &&
			wantClass == agentResourceFree &&
			snapshot.Agent.NodeID != "" &&
			len(customEmails) > 0 &&
			hasActiveAgentFreeGrant(user, snapshot.Agent.NodeID, now)
		if resourceClass == agentResourceCustom && !agentEmailAllowed(customEmails, user) && !tempFreeAllowed {
			continue
		}
		if snapshot.UpdatedAt.IsZero() || (report.Role != "" && report.Role != "agent-proxy") || !networkScopeAllows(access, snapshot.Agent.Groups) {
			continue
		}
		region := strings.ToLower(strings.TrimSpace(report.Xray.Region))
		entry := regionalEntryHost(report.Xray.EntryPoint)
		if entry == "" {
			entry = regionalEntryHost(snapshot.Agent.ID)
		}
		if region == "" && entry != "" {
			region = inferRegionFromHost(entry)
		}
		if region == "" || entry == "" {
			continue
		}
		isTrial := isOneTimeTrialMember(user) || strings.EqualFold(strings.TrimSpace(packageName), "trial")
		isCustomPool := resourceClass == agentResourceCustom ||
			strings.EqualFold(strings.TrimSpace(report.Xray.RoutingPool), RoutingPoolCustomDedicated)
		var classAllowed bool
		if resourceClass == agentResourceTeam {
			classAllowed = wantClass == agentResourceTeam && wantTeam != "" && teamID == wantTeam
		} else if isCustomPool {
			if isTrial {
				classAllowed = false
			} else if resourceClass == agentResourceCustom {
				if len(customEmails) > 0 {
					classAllowed = scopeValid && (customAllowed || wantClass == agentResourcePlus || wantClass == agentResourcePro || (scope.CustomAllowFree && wantClass == agentResourceFree) || tempFreeAllowed)
				} else {
					classAllowed = scopeValid && customAllowed
				}
			}
		} else {
			publicEmailOverride := agentproto.PublicResourceClass(resourceClass) && access.Mode != "dedicated" && publicUnionEmailMatches(snapshot.Agent.Groups, user)
			classAllowed = publicAgentResourceClassAllows(resourceClass, wantClass) || publicEmailOverride
		}
		if !classAllowed {
			continue
		}
		key := region + "\x00" + entry + "\x00" + resourceClass + "\x00" + teamID
		group := groups[key]
		if group == nil {
			pool := regionalPool{
				Private:       resourceClass == agentResourceCustom && len(customEmails) > 0,
				Code:          region,
				Entry:         entry,
				DisplayName:   strings.TrimSpace(snapshot.Agent.Name),
				ResourceClass: resourceClass,
				TeamID:        teamID,
				ClosedReasons: make([]regionalClosureReason, 0),
			}
			populateRegionalPoolRoutingMetadata(&pool, resourceClass, report, policy)
			group = &aggregate{pool: pool, ids: map[string]bool{}, reasons: map[regionalClosureReason]bool{}}
			groups[key] = group
		}
		if group.pool.DisplayName == "" {
			group.pool.DisplayName = strings.TrimSpace(snapshot.Agent.Name)
		}
		id := strings.TrimSpace(report.Xray.Pool)
		if id == "" {
			id = snapshot.Agent.ID
		}
		group.ids[id] = true
		fresh := !snapshot.UpdatedAt.After(now) && now.Sub(snapshot.UpdatedAt) <= regionalHeartbeatTTL
		open := report.Xray.OpenToUsers == nil || *report.Xray.OpenToUsers
		group.pool.OpenToUsers = group.pool.OpenToUsers || (open && fresh && report.Healthy && report.Xray.Running)
		if !open {
			group.reasons[regionalExplicitDisabled] = true
		}
		if !fresh {
			group.reasons[regionalStale] = true
		}
		if !report.Healthy {
			group.reasons[regionalUnhealthy] = true
		}
		if !report.Xray.Running {
			group.reasons[regionalXrayNotRunning] = true
		}
	}
	selected := make([]regionalPool, 0, len(groups))
	for _, group := range groups {
		group.pool.PoolCount = len(group.ids)
		if !group.pool.OpenToUsers {
			for _, reason := range []regionalClosureReason{regionalExplicitDisabled, regionalStale, regionalUnhealthy, regionalXrayNotRunning} {
				if group.reasons[reason] {
					group.pool.ClosedReasons = append(group.pool.ClosedReasons, reason)
				}
			}
		}
		selected = append(selected, group.pool)
	}
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].Code == selected[j].Code {
			return selected[i].Entry < selected[j].Entry
		}
		return selected[i].Code < selected[j].Code
	})
	return selected
}

func registeredRegionalPools(snapshots []StatusSnapshot, policy RoutingPolicyConfig, now time.Time) []regionalPool {
	type aggregate struct {
		pool    regionalPool
		ids     map[string]bool
		reasons map[regionalClosureReason]bool
	}
	groups := make(map[string]*aggregate)
	for _, snapshot := range snapshots {
		report := snapshot.Report
		if snapshot.UpdatedAt.IsZero() || (report.Role != "" && report.Role != "agent-proxy") {
			continue
		}
		region := strings.ToLower(strings.TrimSpace(report.Xray.Region))
		entry := regionalEntryHost(report.Xray.EntryPoint)
		if report.Xray.EntryPoint == "" {
			entry = regionalEntryHost(snapshot.Agent.ID)
		}
		if region == "" && entry != "" {
			region = inferRegionFromHost(entry)
		}
		if region == "" || entry == "" {
			continue
		}
		resourceClass, teamID := reportedResourceClass(snapshot)
		key := region + "\x00" + entry + "\x00" + resourceClass + "\x00" + teamID
		group := groups[key]
		if group == nil {
			pool := regionalPool{
				Code:          region,
				Entry:         entry,
				DisplayName:   strings.TrimSpace(snapshot.Agent.Name),
				ResourceClass: resourceClass,
				TeamID:        teamID,
				ClosedReasons: make([]regionalClosureReason, 0),
			}
			populateRegionalPoolRoutingMetadata(&pool, resourceClass, report, policy)
			group = &aggregate{
				pool:    pool,
				ids:     make(map[string]bool),
				reasons: make(map[regionalClosureReason]bool),
			}
			groups[key] = group
		}
		if group.pool.DisplayName == "" {
			group.pool.DisplayName = strings.TrimSpace(snapshot.Agent.Name)
		}
		id := strings.TrimSpace(report.Xray.Pool)
		if id == "" {
			id = snapshot.Agent.ID
		}
		group.ids[id] = true
		fresh := !snapshot.UpdatedAt.After(now) && now.Sub(snapshot.UpdatedAt) <= regionalHeartbeatTTL
		open := report.Xray.OpenToUsers == nil || *report.Xray.OpenToUsers
		group.pool.OpenToUsers = group.pool.OpenToUsers || (open && fresh && report.Healthy && report.Xray.Running)
		if !open {
			group.reasons[regionalExplicitDisabled] = true
		}
		if !fresh {
			group.reasons[regionalStale] = true
		}
		if !report.Healthy {
			group.reasons[regionalUnhealthy] = true
		}
		if !report.Xray.Running {
			group.reasons[regionalXrayNotRunning] = true
		}
	}
	pools := make([]regionalPool, 0, len(groups))
	for _, group := range groups {
		group.pool.PoolCount = len(group.ids)
		if !group.pool.OpenToUsers {
			for _, reason := range []regionalClosureReason{regionalExplicitDisabled, regionalStale, regionalUnhealthy, regionalXrayNotRunning} {
				if group.reasons[reason] {
					group.pool.ClosedReasons = append(group.pool.ClosedReasons, reason)
				}
			}
		}
		pools = append(pools, group.pool)
	}
	sort.Slice(pools, func(i, j int) bool {
		if pools[i].Code == pools[j].Code {
			return pools[i].Entry < pools[j].Entry
		}
		return pools[i].Code < pools[j].Code
	})
	return pools
}

func inferRegionFromHost(host string) string {
	prefix := strings.TrimSpace(host)
	if idx := strings.Index(prefix, "."); idx > 0 {
		prefix = prefix[:idx]
	}
	if idx := strings.Index(prefix, "-"); idx > 0 {
		prefix = prefix[:idx]
	}
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if len(prefix) == 2 {
		return prefix
	}
	return ""
}

func poolXHTTPPath(basePath, _ string) string {
	return "/" + strings.TrimLeft(strings.TrimSpace(basePath), "/")
}

func renderVLESSURIScheme(tpl string, values map[string]string) string {
	rendered := strings.TrimSpace(tpl)
	if rendered == "" {
		return ""
	}
	for key, value := range values {
		rendered = strings.ReplaceAll(rendered, "${"+key+"}", value)
	}
	return rendered
}

func resolveNodeName(host string) string {
	switch strings.ToLower(strings.SplitN(strings.TrimSpace(host), ".", 2)[0]) {
	case "jp-xconnect":
		return "JP-Connect"
	case "hk-xconnect":
		return "HK-Connect"
	case "ph-xconnect":
		return "PH-Connect"
	case "us-xconnect":
		return "US-Connect"
	}
	h := strings.TrimSpace(host)
	if h == "" {
		return "unknown-node"
	}
	return strings.ToLower(h)
}

func normalizeHost(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" || value == "*" {
		return ""
	}
	if strings.Contains(value, "://") {
		if u, err := url.Parse(value); err == nil {
			value = u.Hostname()
		}
	}
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	if strings.Contains(value, "/") {
		value = strings.SplitN(value, "/", 2)[0]
	}
	if strings.Contains(value, ":") {
		if host, _, found := strings.Cut(value, ":"); found {
			value = host
		}
	}
	return strings.TrimSpace(value)
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envIntOrDefault(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func dualBucketProGateEnabled() bool {
	raw := strings.TrimSpace(os.Getenv("DUAL_BUCKET_PRO_GATE_ENABLED"))
	if raw == "" {
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	return err == nil && enabled
}

type userBucketExhaustion struct {
	gateEnabled        bool
	vpsExhausted       bool
	highSpeedExhausted bool
	hasHighSpeedBucket bool
	fullyExhausted     bool
}

func poolAllowedForQuota(routingPool string, status userBucketExhaustion) bool {
	if !status.gateEnabled {
		return true
	}
	switch strings.TrimSpace(routingPool) {
	case RoutingPoolProEC2:
		return !status.highSpeedExhausted
	case RoutingPoolMediaPriority:
		return !status.vpsExhausted
	default:
		return true
	}
}

func respondError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"error": code, "message": message})
}

func etagMatches(ifNoneMatch string, etag string) bool {
	header := strings.TrimSpace(ifNoneMatch)
	target := strings.TrimSpace(etag)
	if header == "" || target == "" {
		return false
	}
	for _, part := range strings.Split(header, ",") {
		candidate := strings.TrimSpace(part)
		if candidate == "*" || candidate == target || strings.TrimPrefix(candidate, "W/") == target {
			return true
		}
	}
	return false
}

var _ = errors.New
var _ = context.Background
