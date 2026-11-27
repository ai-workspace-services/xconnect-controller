package agentserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	// ErrUserNotFound indicates an account record was not found.
	ErrUserNotFound = errors.New("user not found")
)

const (
	MonthlyFreeQuotaLimitGroup         = "segment:quota:free-3gb"
	MonthlyFreeQuota5GBAliasGroup      = "segment:quota:free-5gb"
	MonthlyPlusQuotaLimitGroup         = "segment:quota:plus-20gb"
	MonthlyUnlimitedBetaQuotaGroup     = "segment:quota:unlimited-beta"
	WhitelistFreeQuotaGroup            = "segment:whitelist:free"
	OneTimeTrialQuotaGroup             = "segment:trial:once-5gb"
	SubscriptionUnlimitedOverrideGroup = "segment:subscription:unlimited"
	SubscriptionListedGroup            = "segment:subscription:listed"
	EmailOptionalRegistrationGroup     = "account:registration:email-optional"
)

// User represents the read-only projection of public.users needed by agent-server and sync endpoints.
type User struct {
	ID                     string
	Name                   string
	Email                  string
	Role                   string
	Groups                 []string
	Permissions            []string
	EmailVerified          bool
	Active                 bool
	ProxyUUID              string
	ProxyUUIDExpiresAt     *time.Time
	SubscriptionValidFrom  *time.Time
	SubscriptionValidUntil *time.Time
	ArchivedAt             *time.Time
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// NetworkTeam mirrors public.network_teams.
type NetworkTeam struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	MemberLimit int       `json:"memberLimit"`
	ValidFrom   time.Time `json:"validFrom"`
	ValidUntil  time.Time `json:"validUntil"`
	Active      bool      `json:"active"`
}

// NetworkMembership mirrors public.network_team_members.
type NetworkMembership struct {
	UserID        string `json:"userId"`
	TeamID        string `json:"teamId,omitempty"`
	DedicatedOnly bool   `json:"dedicatedOnly"`
	Configured    bool   `json:"configured,omitempty"`
}

// TeamAgentEnrollment mirrors public.team_agent_enrollments.
type TeamAgentEnrollment struct {
	AgentID         string    `json:"agentId"`
	SuggestedTeamID string    `json:"suggestedTeamId"`
	AssignedTeamID  string    `json:"assignedTeamId"`
	Status          string    `json:"status"`
	DecidedBy       string    `json:"decidedBy,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

// AccountBillingProfile mirrors public.account_billing_profiles.
type AccountBillingProfile struct {
	AccountUUID         string  `json:"accountUuid"`
	PackageName         string  `json:"packageName"`
	IncludedQuotaBytes  int64   `json:"includedQuotaBytes"`
	HighSpeedQuotaBytes int64   `json:"highSpeedQuotaBytes"`
	BasePricePerByte    float64 `json:"basePricePerByte"`
}

// AccountQuotaState mirrors public.account_quota_states.
type AccountQuotaState struct {
	AccountUUID             string     `json:"accountUuid"`
	RemainingIncludedQuota  int64      `json:"remainingIncludedQuota"`
	RemainingHighSpeedQuota int64      `json:"remainingHighSpeedQuota"`
	CurrentBalance          float64    `json:"currentBalance"`
	Arrears                 bool       `json:"arrears"`
	ThrottleState           string     `json:"throttleState"`
	SuspendState            string     `json:"suspendState"`
	ProxyAccessState        string     `json:"proxyAccessState"`
	PeriodStart             *time.Time `json:"periodStart,omitempty"`
	PeriodEnd               *time.Time `json:"periodEnd,omitempty"`
}

// NodeHealthSnapshot mirrors public.node_health_snapshots.
type NodeHealthSnapshot struct {
	NodeID            string    `json:"nodeId"`
	Region            string    `json:"region"`
	LineCode          string    `json:"lineCode"`
	PricingGroup      string    `json:"pricingGroup"`
	StatsEnabled      bool      `json:"statsEnabled"`
	XrayRevision      string    `json:"xrayRevision"`
	Healthy           bool      `json:"healthy"`
	LatencyMS         int       `json:"latencyMs"`
	ErrorRate         float64   `json:"errorRate"`
	ActiveConnections int       `json:"activeConnections"`
	HealthScore       float64   `json:"healthScore"`
	SampledAt         time.Time `json:"sampledAt"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// Store abstracts read/write operations against accounts tables without performing DDL migrations.
type Store interface {
	RegistryStore

	ListUsers(ctx context.Context) ([]User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByProxyUUID(ctx context.Context, proxyUUID string) (*User, error)

	ListProxyBlockedAccountUUIDs(ctx context.Context) (map[string]bool, error)
	ListBlacklist(ctx context.Context) ([]string, error)
	IsBlacklisted(ctx context.Context, email string) (bool, error)

	ListNetworkTeams(ctx context.Context) ([]NetworkTeam, error)
	ListNetworkMemberships(ctx context.Context) ([]NetworkMembership, error)
	GetNetworkMembership(ctx context.Context, userID string) (NetworkMembership, error)

	GetAccountBillingProfile(ctx context.Context, accountUUID string) (*AccountBillingProfile, error)
	GetAccountQuotaState(ctx context.Context, accountUUID string) (*AccountQuotaState, error)

	ListTeamAgents(ctx context.Context) ([]TeamAgentEnrollment, error)
	RegisterTeamAgent(ctx context.Context, agentID, suggestedTeamID string) (TeamAgentEnrollment, error)

	UpsertNodeHealthSnapshot(ctx context.Context, snapshot *NodeHealthSnapshot) error
	ListLatestNodeHealthSnapshots(ctx context.Context) ([]NodeHealthSnapshot, error)
}

type schemaProbe struct {
	hasUsers                  bool
	userIDCol                 string
	userNameCol               string
	hasRole                   bool
	hasGroups                 bool
	hasPermissions            bool
	hasEmailVerified          bool
	hasEmailVerifiedAt        bool
	hasActive                 bool
	hasProxyUUID              bool
	hasProxyUUIDExpiresAt     bool
	hasSubscriptionValidFrom  bool
	hasSubscriptionValidUntil bool
	hasArchivedAt             bool
	hasCreatedAt              bool
	hasUpdatedAt              bool

	hasQuotaStates         bool
	quotaUserCol           string
	hasBillingProfiles     bool
	billingUserCol         string
	hasBlacklist           bool
	hasNetworkTeams        bool
	hasNetworkTeamMembers  bool
	teamMemberUserCol      string
	hasTeamAgentEnroll     bool
	hasAgents              bool
	hasNodeHealthSnapshots bool
}

// GORMStore implements Store on top of an existing *gorm.DB without running DDL migrations.
type GORMStore struct {
	db      *gorm.DB
	probeMu sync.RWMutex
	probe   *schemaProbe
}

// NewGORMStore returns a GORM-backed Store.
func NewGORMStore(db *gorm.DB) *GORMStore {
	if db == nil {
		return nil
	}
	return &GORMStore{db: db}
}

func tableColumnsSet(m gorm.Migrator, table string) map[string]bool {
	set := make(map[string]bool)
	cols, err := m.ColumnTypes(table)
	if err != nil {
		return set
	}
	for _, c := range cols {
		set[strings.ToLower(c.Name())] = true
	}
	return set
}

func (s *GORMStore) inspectSchema() schemaProbe {
	s.probeMu.RLock()
	if s.probe != nil {
		p := *s.probe
		s.probeMu.RUnlock()
		return p
	}
	s.probeMu.RUnlock()

	m := s.db.Migrator()
	p := schemaProbe{
		hasUsers:               m.HasTable("users"),
		hasQuotaStates:         m.HasTable("account_quota_states"),
		hasBillingProfiles:     m.HasTable("account_billing_profiles"),
		hasBlacklist:           m.HasTable("email_blacklist"),
		hasNetworkTeams:        m.HasTable("network_teams"),
		hasNetworkTeamMembers:  m.HasTable("network_team_members"),
		hasTeamAgentEnroll:     m.HasTable("team_agent_enrollments"),
		hasAgents:              m.HasTable("agents"),
		hasNodeHealthSnapshots: m.HasTable("node_health_snapshots"),
	}
	if p.hasUsers {
		cols := tableColumnsSet(m, "users")
		if cols["uuid"] && !cols["id"] {
			p.userIDCol = "uuid"
		} else {
			p.userIDCol = "id"
		}
		if cols["username"] && !cols["name"] {
			p.userNameCol = "username"
		} else if cols["name"] {
			p.userNameCol = "name"
		}
		p.hasRole = cols["role"]
		p.hasGroups = cols["groups"]
		p.hasPermissions = cols["permissions"]
		p.hasEmailVerified = cols["email_verified"]
		p.hasEmailVerifiedAt = cols["email_verified_at"]
		p.hasActive = cols["active"]
		p.hasProxyUUID = cols["proxy_uuid"]
		p.hasProxyUUIDExpiresAt = cols["proxy_uuid_expires_at"]
		p.hasSubscriptionValidFrom = cols["subscription_valid_from"]
		p.hasSubscriptionValidUntil = cols["subscription_valid_until"]
		p.hasArchivedAt = cols["archived_at"]
		p.hasCreatedAt = cols["created_at"]
		p.hasUpdatedAt = cols["updated_at"]
	}
	if p.hasQuotaStates {
		cols := tableColumnsSet(m, "account_quota_states")
		if cols["account_uuid"] && !cols["user_id"] {
			p.quotaUserCol = "account_uuid"
		} else {
			p.quotaUserCol = "user_id"
		}
	}
	if p.hasBillingProfiles {
		cols := tableColumnsSet(m, "account_billing_profiles")
		if cols["account_uuid"] && !cols["user_id"] {
			p.billingUserCol = "account_uuid"
		} else {
			p.billingUserCol = "user_id"
		}
	}
	if p.hasNetworkTeamMembers {
		cols := tableColumnsSet(m, "network_team_members")
		if cols["user_uuid"] && !cols["user_id"] {
			p.teamMemberUserCol = "user_uuid"
		} else {
			p.teamMemberUserCol = "user_id"
		}
	}

	s.probeMu.Lock()
	s.probe = &p
	s.probeMu.Unlock()
	return p
}

// ResetSchemaCache clears cached table/column introspection (useful in tests after migrations).
func (s *GORMStore) ResetSchemaCache() {
	s.probeMu.Lock()
	s.probe = nil
	s.probeMu.Unlock()
}

type rawUserRow struct {
	ID                     string     `gorm:"column:id"`
	Name                   string     `gorm:"column:name"`
	Email                  string     `gorm:"column:email"`
	Role                   string     `gorm:"column:role"`
	GroupsRaw              string     `gorm:"column:groups"`
	PermissionsRaw         string     `gorm:"column:permissions"`
	EmailVerified          *bool      `gorm:"column:email_verified"`
	EmailVerifiedAt        *time.Time `gorm:"column:email_verified_at"`
	Active                 bool       `gorm:"column:active"`
	ProxyUUID              string     `gorm:"column:proxy_uuid"`
	ProxyUUIDExpiresAt     *time.Time `gorm:"column:proxy_uuid_expires_at"`
	SubscriptionValidFrom  *time.Time `gorm:"column:subscription_valid_from"`
	SubscriptionValidUntil *time.Time `gorm:"column:subscription_valid_until"`
	ArchivedAt             *time.Time `gorm:"column:archived_at"`
	CreatedAt              *time.Time `gorm:"column:created_at"`
	UpdatedAt              *time.Time `gorm:"column:updated_at"`
}

func (p schemaProbe) userSelectCols() []string {
	cols := []string{
		"CAST(" + p.userIDCol + " AS TEXT) AS id",
		"COALESCE(email, '') AS email",
	}
	if p.userNameCol != "" {
		cols = append(cols, "COALESCE("+p.userNameCol+", '') AS name")
	}
	if p.hasRole {
		cols = append(cols, "COALESCE(role, 'user') AS role")
	}
	if p.hasGroups {
		cols = append(cols, "COALESCE(CAST(groups AS TEXT), '[]') AS groups")
	}
	if p.hasPermissions {
		cols = append(cols, "COALESCE(CAST(permissions AS TEXT), '[]') AS permissions")
	}
	if p.hasEmailVerified {
		cols = append(cols, "email_verified")
	}
	if p.hasEmailVerifiedAt {
		cols = append(cols, "email_verified_at")
	}
	if p.hasActive {
		cols = append(cols, "active")
	}
	if p.hasProxyUUID {
		cols = append(cols, "COALESCE(CAST(proxy_uuid AS TEXT), '') AS proxy_uuid")
	}
	if p.hasProxyUUIDExpiresAt {
		cols = append(cols, "proxy_uuid_expires_at")
	}
	if p.hasSubscriptionValidFrom {
		cols = append(cols, "subscription_valid_from")
	}
	if p.hasSubscriptionValidUntil {
		cols = append(cols, "subscription_valid_until")
	}
	if p.hasArchivedAt {
		cols = append(cols, "archived_at")
	}
	if p.hasCreatedAt {
		cols = append(cols, "created_at")
	}
	if p.hasUpdatedAt {
		cols = append(cols, "updated_at")
	}
	return cols
}

func (r rawUserRow) toUser(p schemaProbe) User {
	u := User{
		ID:                     strings.TrimSpace(r.ID),
		Name:                   strings.TrimSpace(r.Name),
		Email:                  strings.TrimSpace(r.Email),
		Role:                   strings.TrimSpace(r.Role),
		Groups:                 decodeStringSliceJSON(r.GroupsRaw),
		Permissions:            decodeStringSliceJSON(r.PermissionsRaw),
		Active:                 r.Active || !p.hasActive,
		ProxyUUID:              strings.TrimSpace(r.ProxyUUID),
		ProxyUUIDExpiresAt:     r.ProxyUUIDExpiresAt,
		SubscriptionValidFrom:  r.SubscriptionValidFrom,
		SubscriptionValidUntil: r.SubscriptionValidUntil,
		ArchivedAt:             r.ArchivedAt,
	}
	if r.EmailVerified != nil {
		u.EmailVerified = *r.EmailVerified
	}
	if r.EmailVerifiedAt != nil && !r.EmailVerifiedAt.IsZero() {
		u.EmailVerified = true
	}
	if !p.hasEmailVerified && !p.hasEmailVerifiedAt {
		u.EmailVerified = true
	}
	if r.CreatedAt != nil {
		u.CreatedAt = r.CreatedAt.UTC()
	}
	if r.UpdatedAt != nil {
		u.UpdatedAt = r.UpdatedAt.UTC()
	}
	return u
}

func (s *GORMStore) ListUsers(ctx context.Context) ([]User, error) {
	p := s.inspectSchema()
	if !p.hasUsers {
		return []User{}, nil
	}
	q := s.db.WithContext(ctx).Table("users").Select(p.userSelectCols())
	if p.hasCreatedAt {
		q = q.Order("created_at ASC")
	}
	var rows []rawUserRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]User, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.toUser(p))
	}
	return out, nil
}

func (s *GORMStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	p := s.inspectSchema()
	if !p.hasUsers {
		return nil, ErrUserNotFound
	}
	var row rawUserRow
	err := s.db.WithContext(ctx).Table("users").
		Select(p.userSelectCols()).
		Where("CAST("+p.userIDCol+" AS TEXT) = ?", strings.TrimSpace(id)).
		Limit(1).
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	u := row.toUser(p)
	return &u, nil
}

func (s *GORMStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	p := s.inspectSchema()
	if !p.hasUsers {
		return nil, ErrUserNotFound
	}
	var row rawUserRow
	err := s.db.WithContext(ctx).Table("users").
		Select(p.userSelectCols()).
		Where("LOWER(email) = LOWER(?)", strings.TrimSpace(email)).
		Limit(1).
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	u := row.toUser(p)
	return &u, nil
}

func (s *GORMStore) GetUserByProxyUUID(ctx context.Context, proxyUUID string) (*User, error) {
	p := s.inspectSchema()
	if !p.hasUsers || !p.hasProxyUUID {
		return nil, ErrUserNotFound
	}
	var row rawUserRow
	err := s.db.WithContext(ctx).Table("users").
		Select(p.userSelectCols()).
		Where("LOWER(CAST(proxy_uuid AS TEXT)) = LOWER(?)", strings.TrimSpace(proxyUUID)).
		Limit(1).
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	u := row.toUser(p)
	return &u, nil
}

func (s *GORMStore) ListProxyBlockedAccountUUIDs(ctx context.Context) (map[string]bool, error) {
	p := s.inspectSchema()
	if !p.hasQuotaStates {
		return map[string]bool{}, nil
	}
	var rows []struct {
		AccountUUID string `gorm:"column:account_uuid"`
	}
	err := s.db.WithContext(ctx).Table("account_quota_states").
		Select("CAST("+p.quotaUserCol+" AS TEXT) AS account_uuid").
		Where("suspend_state = ? OR proxy_access_state = ?", "suspended", "paused").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	blocked := make(map[string]bool, len(rows))
	for _, r := range rows {
		if id := strings.TrimSpace(r.AccountUUID); id != "" {
			blocked[id] = true
		}
	}
	return blocked, nil
}

func (s *GORMStore) ListBlacklist(ctx context.Context) ([]string, error) {
	p := s.inspectSchema()
	if !p.hasBlacklist {
		return nil, nil
	}
	var emails []string
	if err := s.db.WithContext(ctx).Table("email_blacklist").Pluck("email", &emails).Error; err != nil {
		return nil, err
	}
	return emails, nil
}

func (s *GORMStore) IsBlacklisted(ctx context.Context, email string) (bool, error) {
	p := s.inspectSchema()
	if !p.hasBlacklist {
		return false, nil
	}
	var count int64
	if err := s.db.WithContext(ctx).Table("email_blacklist").
		Where("LOWER(email) = LOWER(?)", strings.TrimSpace(email)).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *GORMStore) ListNetworkTeams(ctx context.Context) ([]NetworkTeam, error) {
	p := s.inspectSchema()
	if !p.hasNetworkTeams {
		return []NetworkTeam{}, nil
	}
	var rows []struct {
		ID          string    `gorm:"column:id"`
		Name        string    `gorm:"column:name"`
		MemberLimit int       `gorm:"column:member_limit"`
		ValidFrom   time.Time `gorm:"column:valid_from"`
		ValidUntil  time.Time `gorm:"column:valid_until"`
		Active      bool      `gorm:"column:active"`
	}
	if err := s.db.WithContext(ctx).Table("network_teams").
		Select("id, name, member_limit, valid_from, valid_until, active").
		Order("id ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]NetworkTeam, 0, len(rows))
	for _, r := range rows {
		out = append(out, NetworkTeam{
			ID:          r.ID,
			Name:        r.Name,
			MemberLimit: r.MemberLimit,
			ValidFrom:   r.ValidFrom.UTC(),
			ValidUntil:  r.ValidUntil.UTC(),
			Active:      r.Active,
		})
	}
	return out, nil
}

func (s *GORMStore) ListNetworkMemberships(ctx context.Context) ([]NetworkMembership, error) {
	p := s.inspectSchema()
	if !p.hasNetworkTeamMembers {
		return []NetworkMembership{}, nil
	}
	var rows []struct {
		UserID        string `gorm:"column:user_id"`
		TeamID        string `gorm:"column:team_id"`
		DedicatedOnly bool   `gorm:"column:dedicated_only"`
	}
	if err := s.db.WithContext(ctx).Table("network_team_members").
		Select("CAST(" + p.teamMemberUserCol + " AS TEXT) AS user_id, COALESCE(team_id, '') AS team_id, dedicated_only").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]NetworkMembership, 0, len(rows))
	for _, r := range rows {
		out = append(out, NetworkMembership{
			UserID:        strings.TrimSpace(r.UserID),
			TeamID:        strings.TrimSpace(r.TeamID),
			DedicatedOnly: r.DedicatedOnly,
			Configured:    true,
		})
	}
	return out, nil
}

func (s *GORMStore) GetNetworkMembership(ctx context.Context, userID string) (NetworkMembership, error) {
	member := NetworkMembership{UserID: strings.TrimSpace(userID)}
	p := s.inspectSchema()
	if !p.hasNetworkTeamMembers || member.UserID == "" {
		return member, nil
	}
	var row struct {
		TeamID        string `gorm:"column:team_id"`
		DedicatedOnly bool   `gorm:"column:dedicated_only"`
	}
	err := s.db.WithContext(ctx).Table("network_team_members").
		Select("COALESCE(team_id, '') AS team_id, dedicated_only").
		Where("CAST("+p.teamMemberUserCol+" AS TEXT) = ?", member.UserID).
		Limit(1).
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return member, nil
		}
		return member, err
	}
	member.TeamID = strings.TrimSpace(row.TeamID)
	member.DedicatedOnly = row.DedicatedOnly
	member.Configured = true
	return member, nil
}

func (s *GORMStore) GetAccountBillingProfile(ctx context.Context, accountUUID string) (*AccountBillingProfile, error) {
	p := s.inspectSchema()
	if !p.hasBillingProfiles {
		return nil, ErrUserNotFound
	}
	var row struct {
		AccountUUID         string  `gorm:"column:account_uuid"`
		PackageName         string  `gorm:"column:package_name"`
		IncludedQuotaBytes  int64   `gorm:"column:included_quota_bytes"`
		HighSpeedQuotaBytes int64   `gorm:"column:high_speed_quota_bytes"`
		BasePricePerByte    float64 `gorm:"column:base_price_per_byte"`
	}
	err := s.db.WithContext(ctx).Table("account_billing_profiles").
		Select("CAST("+p.billingUserCol+" AS TEXT) AS account_uuid, package_name, included_quota_bytes, high_speed_quota_bytes, base_price_per_byte").
		Where("CAST("+p.billingUserCol+" AS TEXT) = ?", strings.TrimSpace(accountUUID)).
		Limit(1).
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &AccountBillingProfile{
		AccountUUID:         strings.TrimSpace(row.AccountUUID),
		PackageName:         strings.TrimSpace(row.PackageName),
		IncludedQuotaBytes:  row.IncludedQuotaBytes,
		HighSpeedQuotaBytes: row.HighSpeedQuotaBytes,
		BasePricePerByte:    row.BasePricePerByte,
	}, nil
}

func (s *GORMStore) GetAccountQuotaState(ctx context.Context, accountUUID string) (*AccountQuotaState, error) {
	p := s.inspectSchema()
	if !p.hasQuotaStates {
		return nil, ErrUserNotFound
	}
	var row struct {
		AccountUUID             string     `gorm:"column:account_uuid"`
		RemainingIncludedQuota  int64      `gorm:"column:remaining_included_quota"`
		RemainingHighSpeedQuota int64      `gorm:"column:remaining_high_speed_quota"`
		CurrentBalance          float64    `gorm:"column:current_balance"`
		Arrears                 bool       `gorm:"column:arrears"`
		ThrottleState           string     `gorm:"column:throttle_state"`
		SuspendState            string     `gorm:"column:suspend_state"`
		ProxyAccessState        string     `gorm:"column:proxy_access_state"`
		PeriodStart             *time.Time `gorm:"column:period_start"`
		PeriodEnd               *time.Time `gorm:"column:period_end"`
	}
	err := s.db.WithContext(ctx).Table("account_quota_states").
		Select("CAST("+p.quotaUserCol+" AS TEXT) AS account_uuid, remaining_included_quota, remaining_high_speed_quota, current_balance, arrears, throttle_state, suspend_state, proxy_access_state, period_start, period_end").
		Where("CAST("+p.quotaUserCol+" AS TEXT) = ?", strings.TrimSpace(accountUUID)).
		Limit(1).
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &AccountQuotaState{
		AccountUUID:             strings.TrimSpace(row.AccountUUID),
		RemainingIncludedQuota:  row.RemainingIncludedQuota,
		RemainingHighSpeedQuota: row.RemainingHighSpeedQuota,
		CurrentBalance:          row.CurrentBalance,
		Arrears:                 row.Arrears,
		ThrottleState:           strings.TrimSpace(row.ThrottleState),
		SuspendState:            strings.TrimSpace(row.SuspendState),
		ProxyAccessState:        strings.TrimSpace(row.ProxyAccessState),
		PeriodStart:             row.PeriodStart,
		PeriodEnd:               row.PeriodEnd,
	}, nil
}

func (s *GORMStore) ListTeamAgents(ctx context.Context) ([]TeamAgentEnrollment, error) {
	p := s.inspectSchema()
	if !p.hasTeamAgentEnroll {
		return []TeamAgentEnrollment{}, nil
	}
	var rows []struct {
		AgentID         string    `gorm:"column:agent_id"`
		SuggestedTeamID string    `gorm:"column:suggested_team_id"`
		AssignedTeamID  string    `gorm:"column:assigned_team_id"`
		Status          string    `gorm:"column:status"`
		DecidedBy       string    `gorm:"column:decided_by"`
		Reason          string    `gorm:"column:reason"`
		UpdatedAt       time.Time `gorm:"column:updated_at"`
	}
	if err := s.db.WithContext(ctx).Table("team_agent_enrollments").
		Select("agent_id, suggested_team_id, assigned_team_id, status, decided_by, reason, updated_at").
		Order("agent_id ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]TeamAgentEnrollment, 0, len(rows))
	for _, r := range rows {
		out = append(out, TeamAgentEnrollment{
			AgentID:         r.AgentID,
			SuggestedTeamID: r.SuggestedTeamID,
			AssignedTeamID:  r.AssignedTeamID,
			Status:          r.Status,
			DecidedBy:       r.DecidedBy,
			Reason:          r.Reason,
			UpdatedAt:       r.UpdatedAt.UTC(),
		})
	}
	return out, nil
}

func (s *GORMStore) RegisterTeamAgent(ctx context.Context, agentID, suggestedTeamID string) (TeamAgentEnrollment, error) {
	p := s.inspectSchema()
	if !p.hasTeamAgentEnroll {
		return TeamAgentEnrollment{
			AgentID:         agentID,
			SuggestedTeamID: suggestedTeamID,
			Status:          "pending",
			UpdatedAt:       time.Now().UTC(),
		}, nil
	}
	now := time.Now().UTC()
	row := map[string]any{
		"agent_id":          agentID,
		"suggested_team_id": suggestedTeamID,
		"assigned_team_id":  "",
		"status":            "pending",
		"decided_by":        "",
		"reason":            "",
		"updated_at":        now,
	}
	if err := s.db.WithContext(ctx).Table("team_agent_enrollments").
		Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "agent_id"}}, DoNothing: true}).
		Create(row).Error; err != nil {
		return TeamAgentEnrollment{}, err
	}
	var out struct {
		AgentID         string    `gorm:"column:agent_id"`
		SuggestedTeamID string    `gorm:"column:suggested_team_id"`
		AssignedTeamID  string    `gorm:"column:assigned_team_id"`
		Status          string    `gorm:"column:status"`
		DecidedBy       string    `gorm:"column:decided_by"`
		Reason          string    `gorm:"column:reason"`
		UpdatedAt       time.Time `gorm:"column:updated_at"`
	}
	if err := s.db.WithContext(ctx).Table("team_agent_enrollments").
		Select("agent_id, suggested_team_id, assigned_team_id, status, decided_by, reason, updated_at").
		Where("agent_id = ?", agentID).
		Limit(1).
		Take(&out).Error; err != nil {
		return TeamAgentEnrollment{}, err
	}
	return TeamAgentEnrollment{
		AgentID:         out.AgentID,
		SuggestedTeamID: out.SuggestedTeamID,
		AssignedTeamID:  out.AssignedTeamID,
		Status:          out.Status,
		DecidedBy:       out.DecidedBy,
		Reason:          out.Reason,
		UpdatedAt:       out.UpdatedAt.UTC(),
	}, nil
}

func (s *GORMStore) ListAgents(ctx context.Context) ([]*AgentRecord, error) {
	p := s.inspectSchema()
	if !p.hasAgents {
		return []*AgentRecord{}, nil
	}
	var rows []struct {
		ID            string     `gorm:"column:id"`
		Name          string     `gorm:"column:name"`
		GroupsRaw     string     `gorm:"column:groups"`
		Healthy       bool       `gorm:"column:healthy"`
		LastHeartbeat *time.Time `gorm:"column:last_heartbeat"`
		ClientsCount  int        `gorm:"column:clients_count"`
		SyncRevision  string     `gorm:"column:sync_revision"`
		CreatedAt     time.Time  `gorm:"column:created_at"`
		UpdatedAt     time.Time  `gorm:"column:updated_at"`
	}
	if err := s.db.WithContext(ctx).Table("agents").
		Select("id, name, CAST(groups AS TEXT) AS groups, healthy, last_heartbeat, clients_count, sync_revision, created_at, updated_at").
		Order("id ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*AgentRecord, 0, len(rows))
	for _, r := range rows {
		var hb *time.Time
		if r.LastHeartbeat != nil {
			t := r.LastHeartbeat.UTC()
			hb = &t
		}
		out = append(out, &AgentRecord{
			ID:            r.ID,
			Name:          r.Name,
			Groups:        decodeStringSliceJSON(r.GroupsRaw),
			Healthy:       r.Healthy,
			LastHeartbeat: hb,
			ClientsCount:  r.ClientsCount,
			SyncRevision:  r.SyncRevision,
			CreatedAt:     r.CreatedAt.UTC(),
			UpdatedAt:     r.UpdatedAt.UTC(),
		})
	}
	return out, nil
}

func (s *GORMStore) UpsertAgent(ctx context.Context, agent *AgentRecord) error {
	if agent == nil {
		return errors.New("agent is required")
	}
	p := s.inspectSchema()
	if !p.hasAgents {
		return nil
	}
	groupsRaw, err := json.Marshal(nonNilStrings(agent.Groups))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	values := map[string]any{
		"id":             agent.ID,
		"name":           agent.Name,
		"groups":         string(groupsRaw),
		"healthy":        agent.Healthy,
		"last_heartbeat": agent.LastHeartbeat,
		"clients_count":  agent.ClientsCount,
		"sync_revision":  agent.SyncRevision,
		"created_at":     now,
		"updated_at":     now,
	}
	return s.db.WithContext(ctx).Table("agents").
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"name":           agent.Name,
				"groups":         string(groupsRaw),
				"healthy":        agent.Healthy,
				"last_heartbeat": agent.LastHeartbeat,
				"clients_count":  agent.ClientsCount,
				"sync_revision":  agent.SyncRevision,
				"updated_at":     now,
			}),
		}).
		Create(values).Error
}

func (s *GORMStore) UpsertNodeHealthSnapshot(ctx context.Context, snapshot *NodeHealthSnapshot) error {
	if snapshot == nil {
		return errors.New("node health snapshot is required")
	}
	p := s.inspectSchema()
	if !p.hasNodeHealthSnapshots {
		return nil
	}
	now := time.Now().UTC()
	sampledAt := snapshot.SampledAt.UTC()
	if sampledAt.IsZero() {
		sampledAt = now
	}
	values := map[string]any{
		"node_id":            strings.TrimSpace(snapshot.NodeID),
		"region":             strings.TrimSpace(snapshot.Region),
		"line_code":          strings.TrimSpace(snapshot.LineCode),
		"pricing_group":      strings.TrimSpace(snapshot.PricingGroup),
		"stats_enabled":      snapshot.StatsEnabled,
		"xray_revision":      strings.TrimSpace(snapshot.XrayRevision),
		"healthy":            snapshot.Healthy,
		"latency_ms":         snapshot.LatencyMS,
		"error_rate":         snapshot.ErrorRate,
		"active_connections": snapshot.ActiveConnections,
		"health_score":       snapshot.HealthScore,
		"sampled_at":         sampledAt,
		"created_at":         now,
		"updated_at":         now,
	}
	return s.db.WithContext(ctx).Table("node_health_snapshots").
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "node_id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"region":             strings.TrimSpace(snapshot.Region),
				"line_code":          strings.TrimSpace(snapshot.LineCode),
				"pricing_group":      strings.TrimSpace(snapshot.PricingGroup),
				"stats_enabled":      snapshot.StatsEnabled,
				"xray_revision":      strings.TrimSpace(snapshot.XrayRevision),
				"healthy":            snapshot.Healthy,
				"latency_ms":         snapshot.LatencyMS,
				"error_rate":         snapshot.ErrorRate,
				"active_connections": snapshot.ActiveConnections,
				"health_score":       snapshot.HealthScore,
				"sampled_at":         sampledAt,
				"updated_at":         now,
			}),
		}).
		Create(values).Error
}

func (s *GORMStore) ListLatestNodeHealthSnapshots(ctx context.Context) ([]NodeHealthSnapshot, error) {
	p := s.inspectSchema()
	if !p.hasNodeHealthSnapshots {
		return []NodeHealthSnapshot{}, nil
	}
	var rows []struct {
		NodeID            string    `gorm:"column:node_id"`
		Region            string    `gorm:"column:region"`
		LineCode          string    `gorm:"column:line_code"`
		PricingGroup      string    `gorm:"column:pricing_group"`
		StatsEnabled      bool      `gorm:"column:stats_enabled"`
		XrayRevision      string    `gorm:"column:xray_revision"`
		Healthy           bool      `gorm:"column:healthy"`
		LatencyMS         int       `gorm:"column:latency_ms"`
		ErrorRate         float64   `gorm:"column:error_rate"`
		ActiveConnections int       `gorm:"column:active_connections"`
		HealthScore       float64   `gorm:"column:health_score"`
		SampledAt         time.Time `gorm:"column:sampled_at"`
		CreatedAt         time.Time `gorm:"column:created_at"`
		UpdatedAt         time.Time `gorm:"column:updated_at"`
	}
	if err := s.db.WithContext(ctx).Table("node_health_snapshots").
		Select("node_id, region, line_code, pricing_group, stats_enabled, xray_revision, healthy, latency_ms, error_rate, active_connections, health_score, sampled_at, created_at, updated_at").
		Order("node_id ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]NodeHealthSnapshot, 0, len(rows))
	for _, r := range rows {
		out = append(out, NodeHealthSnapshot{
			NodeID:            r.NodeID,
			Region:            r.Region,
			LineCode:          r.LineCode,
			PricingGroup:      r.PricingGroup,
			StatsEnabled:      r.StatsEnabled,
			XrayRevision:      r.XrayRevision,
			Healthy:           r.Healthy,
			LatencyMS:         r.LatencyMS,
			ErrorRate:         r.ErrorRate,
			ActiveConnections: r.ActiveConnections,
			HealthScore:       r.HealthScore,
			SampledAt:         r.SampledAt.UTC(),
			CreatedAt:         r.CreatedAt.UTC(),
			UpdatedAt:         r.UpdatedAt.UTC(),
		})
	}
	return out, nil
}

func decodeStringSliceJSON(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(trimmed), &out); err != nil {
		return nil
	}
	return out
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

var _ = sql.ErrNoRows
