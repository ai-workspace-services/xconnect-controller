package agentserver_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ai-workspace-services/xconnect-controller/internal/agentproto"
	"github.com/ai-workspace-services/xconnect-controller/internal/agentserver"
	"github.com/ai-workspace-services/xconnect-controller/internal/auth"
	"github.com/ai-workspace-services/xconnect-controller/internal/httpapi"
)

type spyStore struct {
	mu           sync.RWMutex
	users        []agentserver.User
	blocked      map[string]bool
	blacklist    []string
	teams        []agentserver.NetworkTeam
	memberships  []agentserver.NetworkMembership
	billing      map[string]*agentserver.AccountBillingProfile
	quotas       map[string]*agentserver.AccountQuotaState
	teamAgents   []agentserver.TeamAgentEnrollment
	agents       []*agentserver.AgentRecord
	healthSnaps  []agentserver.NodeHealthSnapshot
	writeCounter atomic.Int64
}

func newSpyStore() *spyStore {
	return &spyStore{
		blocked: make(map[string]bool),
		billing: make(map[string]*agentserver.AccountBillingProfile),
		quotas:  make(map[string]*agentserver.AccountQuotaState),
	}
}

func (s *spyStore) ListAgents(_ context.Context) ([]*agentserver.AgentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*agentserver.AgentRecord, len(s.agents))
	copy(out, s.agents)
	return out, nil
}

func (s *spyStore) UpsertAgent(_ context.Context, agent *agentserver.AgentRecord) error {
	s.writeCounter.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *agent
	for i, existing := range s.agents {
		if existing.ID == cp.ID {
			s.agents[i] = &cp
			return nil
		}
	}
	s.agents = append(s.agents, &cp)
	return nil
}

func (s *spyStore) ListUsers(_ context.Context) ([]agentserver.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]agentserver.User, len(s.users))
	copy(out, s.users)
	return out, nil
}

func (s *spyStore) GetUserByID(_ context.Context, id string) (*agentserver.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.ID == id {
			cp := u
			return &cp, nil
		}
	}
	return nil, agentserver.ErrUserNotFound
}

func (s *spyStore) GetUserByEmail(_ context.Context, email string) (*agentserver.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if strings.EqualFold(u.Email, email) {
			cp := u
			return &cp, nil
		}
	}
	return nil, agentserver.ErrUserNotFound
}

func (s *spyStore) GetUserByProxyUUID(_ context.Context, proxyUUID string) (*agentserver.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if strings.EqualFold(u.ProxyUUID, proxyUUID) {
			cp := u
			return &cp, nil
		}
	}
	return nil, agentserver.ErrUserNotFound
}

func (s *spyStore) ListProxyBlockedAccountUUIDs(_ context.Context) (map[string]bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]bool, len(s.blocked))
	for k, v := range s.blocked {
		out[k] = v
	}
	return out, nil
}

func (s *spyStore) ListBlacklist(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.blacklist...), nil
}

func (s *spyStore) IsBlacklisted(_ context.Context, email string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, b := range s.blacklist {
		if strings.EqualFold(b, email) {
			return true, nil
		}
	}
	return false, nil
}

func (s *spyStore) ListNetworkTeams(_ context.Context) ([]agentserver.NetworkTeam, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]agentserver.NetworkTeam(nil), s.teams...), nil
}

func (s *spyStore) ListNetworkMemberships(_ context.Context) ([]agentserver.NetworkMembership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]agentserver.NetworkMembership(nil), s.memberships...), nil
}

func (s *spyStore) GetNetworkMembership(_ context.Context, userID string) (agentserver.NetworkMembership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.memberships {
		if m.UserID == userID {
			return m, nil
		}
	}
	return agentserver.NetworkMembership{UserID: userID}, nil
}

func (s *spyStore) GetAccountBillingProfile(_ context.Context, accountUUID string) (*agentserver.AccountBillingProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.billing[accountUUID]
	if !ok {
		return nil, agentserver.ErrUserNotFound
	}
	cp := *p
	return &cp, nil
}

func (s *spyStore) GetAccountQuotaState(_ context.Context, accountUUID string) (*agentserver.AccountQuotaState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	q, ok := s.quotas[accountUUID]
	if !ok {
		return nil, agentserver.ErrUserNotFound
	}
	cp := *q
	return &cp, nil
}

func (s *spyStore) ListTeamAgents(_ context.Context) ([]agentserver.TeamAgentEnrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]agentserver.TeamAgentEnrollment(nil), s.teamAgents...), nil
}

func (s *spyStore) RegisterTeamAgent(_ context.Context, agentID, suggested string) (agentserver.TeamAgentEnrollment, error) {
	s.writeCounter.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.teamAgents {
		if e.AgentID == agentID {
			return e, nil
		}
	}
	e := agentserver.TeamAgentEnrollment{
		AgentID:         agentID,
		SuggestedTeamID: suggested,
		Status:          "pending",
		UpdatedAt:       time.Now().UTC(),
	}
	s.teamAgents = append(s.teamAgents, e)
	return e, nil
}

func (s *spyStore) UpsertNodeHealthSnapshot(_ context.Context, snap *agentserver.NodeHealthSnapshot) error {
	s.writeCounter.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *snap
	for i, existing := range s.healthSnaps {
		if existing.NodeID == cp.NodeID {
			s.healthSnaps[i] = cp
			return nil
		}
	}
	s.healthSnaps = append(s.healthSnaps, cp)
	return nil
}

func (s *spyStore) ListLatestNodeHealthSnapshots(_ context.Context) ([]agentserver.NodeHealthSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]agentserver.NodeHealthSnapshot(nil), s.healthSnaps...), nil
}

func signJWT(t *testing.T, kid string, priv ed25519.PrivateKey, userID, email string, roles []string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, auth.Claims{
		UserID: userID,
		Email:  email,
		Roles:  roles,
		MFA:    true,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    "xcontrol-account",
			Audience:  []string{"xcontrol-access"},
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

type testHarness struct {
	router        *gin.Engine
	store         *spyStore
	registry      *agentserver.Registry
	verifier      *auth.Verifier
	jwtPriv       ed25519.PrivateKey
	now           time.Time
	setNow        func(time.Time)
	internalToken string
}

func newTestHarness(t *testing.T, cacheTTL time.Duration) *testHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	st := newSpyStore()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(auth.JWKS{
			Keys: []auth.JWK{{
				KeyType:   "OKP",
				Curve:     "Ed25519",
				Algorithm: "EdDSA",
				Use:       "sig",
				KeyID:     "accounts-jwt-test",
				X:         base64.RawURLEncoding.EncodeToString(pub),
			}},
		})
	}))
	t.Cleanup(jwksSrv.Close)

	internalToken := "internal-test-secret-token-32bytes"
	verifier := auth.NewVerifier(auth.VerifierConfig{
		JWKSURL:       jwksSrv.URL,
		InternalToken: internalToken,
	})

	registry, err := agentserver.NewRegistry(agentserver.Config{
		Credentials: []agentserver.Credential{
			{ID: "*", Name: "Wildcard", Token: "agent-wildcard-token", Groups: []string{"internal"}},
			{ID: "jp-xconnect-01.svc.plus", Name: "JP Free", Token: "agent-free-token", Groups: []string{"resource:free"}},
			{ID: "jp-xconnect-02.svc.plus", Name: "JP Pro", Token: "agent-pro-token", Groups: []string{"resource:pro"}},
			{
				ID:            "us-custom-01.svc.plus",
				NodeID:        "us-custom-01",
				Name:          "US Custom",
				Token:         "agent-custom-token",
				Groups:        []string{"resource:custom"},
				AllowedEmails: []string{"vip@example.test"},
			},
			{ID: "team-alpha-node", Name: "Alpha Node", Token: "agent-alpha-token", Groups: []string{"team:alpha"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	curNow := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	svc := agentserver.NewService(st, registry, verifier, agentserver.ServiceConfig{
		AgentUsersCacheTTL: cacheTTL,
		EventPollInterval:  100 * time.Millisecond,
		PublicURL:          "https://jp-xconnect-01.svc.plus",
		Clock:              func() time.Time { return curNow },
	})

	router := httpapi.NewRouter(httpapi.Server{
		AgentServer: svc,
		Verifier:    verifier,
		DBHealth:    func(_ context.Context) error { return nil },
	})

	return &testHarness{
		router:        router,
		store:         st,
		registry:      registry,
		verifier:      verifier,
		jwtPriv:       priv,
		now:           curNow,
		setNow:        func(tm time.Time) { curNow = tm },
		internalToken: internalToken,
	}
}

func TestAgentUsersAuthETagTTLCacheAndZeroWrites(t *testing.T) {
	h := newTestHarness(t, 15*time.Second)

	h.store.users = []agentserver.User{
		{
			ID: "u-free", Name: "free", Email: "free@example.test", Role: "user",
			Active: true, EmailVerified: true, ProxyUUID: "uuid-free-1",
			Groups: []string{agentserver.MonthlyFreeQuotaLimitGroup},
		},
		{
			ID: "u-pro", Name: "pro", Email: "pro@example.test", Role: "user",
			Active: true, EmailVerified: true, ProxyUUID: "uuid-pro-1",
			Groups: []string{agentserver.MonthlyPlusQuotaLimitGroup},
		},
		{
			ID: "u-vip", Name: "vip", Email: "vip@example.test", Role: "user",
			Active: true, EmailVerified: true, ProxyUUID: "uuid-vip-1",
			Groups: []string{"resource:custom"},
		},
		{
			ID: "u-blocked", Name: "blocked", Email: "blocked@example.test", Role: "user",
			Active: true, EmailVerified: true, ProxyUUID: "uuid-blocked-1",
		},
	}
	h.store.billing["u-pro"] = &agentserver.AccountBillingProfile{AccountUUID: "u-pro", PackageName: "pro"}
	h.store.blocked["u-blocked"] = true

	// Missing & invalid auth
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/users", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token got %d, want 401", rec.Code)
	}
	reqBad := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/users", nil)
	reqBad.Header.Set("Authorization", "Bearer wrong-token")
	rec = httptest.NewRecorder()
	h.router.ServeHTTP(rec, reqBad)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token got %d, want 401", rec.Code)
	}

	// Valid free node request
	req1 := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/users", nil)
	req1.Header.Set("Authorization", "Bearer agent-free-token")
	rec1 := httptest.NewRecorder()
	h.router.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("free users got %d: %s", rec1.Code, rec1.Body.String())
	}
	etag1 := rec1.Header().Get("ETag")
	if etag1 == "" {
		t.Fatal("expected ETag header")
	}
	var payload1 agentproto.ClientListResponse
	if err := json.Unmarshal(rec1.Body.Bytes(), &payload1); err != nil {
		t.Fatal(err)
	}
	if payload1.Total != 2 || payload1.RoutingPolicy == nil || payload1.RoutingPolicy.Pool != agentserver.RoutingPoolMediaPriority {
		t.Fatalf("unexpected free payload: %+v", payload1)
	}

	// If-None-Match -> 304 Not Modified (including weak ETag)
	req304 := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/users", nil)
	req304.Header.Set("Authorization", "Bearer agent-free-token")
	req304.Header.Set("If-None-Match", "W/"+etag1)
	rec304 := httptest.NewRecorder()
	h.router.ServeHTTP(rec304, req304)
	if rec304.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match got %d, want 304", rec304.Code)
	}

	// Add a new user while TTL cache is hot -> should still return cached revision
	h.store.mu.Lock()
	h.store.users = append(h.store.users, agentserver.User{
		ID: "u-free-2", Name: "free2", Email: "free2@example.test", Role: "user",
		Active: true, EmailVerified: true, ProxyUUID: "uuid-free-2",
	})
	h.store.mu.Unlock()

	reqCached := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/users", nil)
	reqCached.Header.Set("Authorization", "Bearer agent-free-token")
	recCached := httptest.NewRecorder()
	h.router.ServeHTTP(recCached, reqCached)
	if recCached.Header().Get("ETag") != etag1 {
		t.Fatalf("expected cached ETag %s, got %s", etag1, recCached.Header().Get("ETag"))
	}

	// Advance clock past 15s TTL -> sees new user and new ETag
	h.setNow(h.now.Add(16 * time.Second))
	reqFresh := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/users", nil)
	reqFresh.Header.Set("Authorization", "Bearer agent-free-token")
	recFresh := httptest.NewRecorder()
	h.router.ServeHTTP(recFresh, reqFresh)
	if recFresh.Header().Get("ETag") == etag1 {
		t.Fatalf("expected fresh ETag after TTL expiry, still got %s", etag1)
	}
	var payloadFresh agentproto.ClientListResponse
	if err := json.Unmarshal(recFresh.Body.Bytes(), &payloadFresh); err != nil {
		t.Fatal(err)
	}
	if payloadFresh.Total != 3 {
		t.Fatalf("expected 3 clients after TTL expiry, got %d", payloadFresh.Total)
	}

	// Custom node credential sees only enrolled audience
	reqCustom := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/users", nil)
	reqCustom.Header.Set("Authorization", "Bearer agent-custom-token")
	recCustom := httptest.NewRecorder()
	h.router.ServeHTTP(recCustom, reqCustom)
	if recCustom.Code != http.StatusOK {
		t.Fatalf("custom users got %d: %s", recCustom.Code, recCustom.Body.String())
	}
	var customPayload agentproto.ClientListResponse
	_ = json.Unmarshal(recCustom.Body.Bytes(), &customPayload)
	if customPayload.Total != 1 || customPayload.Clients[0].Email != "vip@example.test" {
		t.Fatalf("unexpected custom clients: %+v", customPayload.Clients)
	}

	// Verify ZERO writes occurred during all GET requests!
	if writes := h.store.writeCounter.Load(); writes != 0 {
		t.Fatalf("expected 0 store writes on GET handlers, got %d", writes)
	}
}

func TestResolveAgentUsersCacheTTLFromEnv(t *testing.T) {
	t.Setenv("XCONNECT_AGENT_USERS_CACHE_TTL", "")
	t.Setenv("ACCOUNTS_AGENT_USERS_CACHE_TTL", "")
	if got := agentserver.ResolveAgentUsersCacheTTL(); got != 15*time.Second {
		t.Fatalf("default TTL = %v, want 15s", got)
	}
	t.Setenv("XCONNECT_AGENT_USERS_CACHE_TTL", "30s")
	if got := agentserver.ResolveAgentUsersCacheTTL(); got != 30*time.Second {
		t.Fatalf("30s TTL = %v, want 30s", got)
	}
	t.Setenv("XCONNECT_AGENT_USERS_CACHE_TTL", "0")
	if got := agentserver.ResolveAgentUsersCacheTTL(); got != 0 {
		t.Fatalf("0 TTL = %v, want 0", got)
	}
}

func TestAgentUsersEventsSSEStream(t *testing.T) {
	h := newTestHarness(t, 0)
	h.store.users = []agentserver.User{
		{ID: "u1", Name: "u1", Email: "u1@example.test", Active: true, EmailVerified: true, ProxyUUID: "uuid-1"},
	}

	srv := httptest.NewUnstartedServer(h.router)
	srv.Config.WriteTimeout = 200 * time.Millisecond
	srv.Start()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/agent-server/v1/users/events", nil)
	req.Header.Set("Authorization", "Bearer agent-free-token")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SSE status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q", ct)
	}
	if xab := resp.Header.Get("X-Accel-Buffering"); xab != "no" {
		t.Fatalf("X-Accel-Buffering = %q", xab)
	}

	scanner := bufio.NewScanner(resp.Body)
	readData := func() string {
		t.Helper()
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				return strings.TrimPrefix(line, "data: ")
			}
		}
		t.Fatalf("stream ended early: %v", scanner.Err())
		return ""
	}
	rev1 := readData()
	time.Sleep(300 * time.Millisecond)

	h.store.mu.Lock()
	h.store.users = append(h.store.users, agentserver.User{
		ID: "u2", Name: "u2", Email: "u2@example.test", Active: true, EmailVerified: true, ProxyUUID: "uuid-2",
	})
	h.store.mu.Unlock()

	rev2 := readData()
	if rev2 == rev1 || rev2 == "" {
		t.Fatalf("expected updated revision after user added, got %q (initial %q)", rev2, rev1)
	}
}

func TestHeartbeatStatusNodesSyncAndObservabilityIdentity(t *testing.T) {
	h := newTestHarness(t, 0)
	h.store.users = []agentserver.User{
		{
			ID: "u-pro-1", Name: "alice", Email: "alice@example.test", Role: "user",
			Active: true, EmailVerified: true, ProxyUUID: "a55a9f3a-5d63-4b99-9c3a-9dfeb6d57da2",
			Groups:    []string{agentserver.MonthlyPlusQuotaLimitGroup},
			UpdatedAt: h.now,
		},
		{
			ID: "u-admin", Name: "root", Email: "root@example.test", Role: "root",
			Active: true, EmailVerified: true, ProxyUUID: "11111111-1111-4111-8111-111111111111",
		},
	}
	h.store.billing["u-pro-1"] = &agentserver.AccountBillingProfile{AccountUUID: "u-pro-1", PackageName: "pro"}

	// 1. POST /api/agent-server/v1/nodes/heartbeat (with agent token)
	hb1Body := `{"nodeId":"jp-xconnect-01.svc.plus","region":"jp","pricingGroup":"free","healthy":true,"xrayRevision":"v1"}`
	hb1Req := httptest.NewRequest(http.MethodPost, "/api/agent-server/v1/nodes/heartbeat", strings.NewReader(hb1Body))
	hb1Req.Header.Set("Authorization", "Bearer agent-free-token")
	hb1Req.Header.Set("Content-Type", "application/json")
	hb1Rec := httptest.NewRecorder()
	h.router.ServeHTTP(hb1Rec, hb1Req)
	if hb1Rec.Code != http.StatusNoContent {
		t.Fatalf("agent heartbeat got %d: %s", hb1Rec.Code, hb1Rec.Body.String())
	}

	// 2. POST /api/internal/nodes/heartbeat (with internal service token)
	hb2Body := `{"nodeId":"jp-xconnect-02.svc.plus","region":"jp","pricingGroup":"pro","healthy":true,"xrayRevision":"v2"}`
	hb2Req := httptest.NewRequest(http.MethodPost, "/api/internal/nodes/heartbeat", strings.NewReader(hb2Body))
	hb2Req.Header.Set("X-Internal-Service-Token", h.internalToken)
	hb2Req.Header.Set("Content-Type", "application/json")
	hb2Rec := httptest.NewRecorder()
	h.router.ServeHTTP(hb2Rec, hb2Req)
	if hb2Rec.Code != http.StatusNoContent {
		t.Fatalf("internal heartbeat got %d: %s", hb2Rec.Code, hb2Rec.Body.String())
	}

	// Reset write counter before testing all read endpoints!
	h.store.writeCounter.Store(0)

	// 3. GET /api/agent-server/v1/status (internal token, non-admin JWT forbidden, root JWT allowed, ETag 304)
	userJWT := signJWT(t, "accounts-jwt-test", h.jwtPriv, "u-pro-1", "alice@example.test", []string{"user"})
	rootJWT := signJWT(t, "accounts-jwt-test", h.jwtPriv, "u-admin", "root@example.test", []string{"root"})

	statusUserReq := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/status", nil)
	statusUserReq.Header.Set("Authorization", "Bearer "+userJWT)
	statusUserRec := httptest.NewRecorder()
	h.router.ServeHTTP(statusUserRec, statusUserReq)
	if statusUserRec.Code != http.StatusForbidden {
		t.Fatalf("non-admin user GET /status got %d, want 403", statusUserRec.Code)
	}

	statusRootReq := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/status", nil)
	statusRootReq.Header.Set("Authorization", "Bearer "+rootJWT)
	statusRootRec := httptest.NewRecorder()
	h.router.ServeHTTP(statusRootRec, statusRootReq)
	if statusRootRec.Code != http.StatusOK {
		t.Fatalf("root GET /status got %d: %s", statusRootRec.Code, statusRootRec.Body.String())
	}
	statusETag := statusRootRec.Header().Get("ETag")
	if statusETag == "" {
		t.Fatal("expected ETag on /status")
	}
	var statusPayload struct {
		Agents []json.RawMessage `json:"agents"`
	}
	_ = json.Unmarshal(statusRootRec.Body.Bytes(), &statusPayload)
	if len(statusPayload.Agents) < 2 {
		t.Fatalf("expected >= 2 agents in status, got %d", len(statusPayload.Agents))
	}

	status304Req := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/status", nil)
	status304Req.Header.Set("X-Internal-Service-Token", h.internalToken)
	status304Req.Header.Set("If-None-Match", statusETag)
	status304Rec := httptest.NewRecorder()
	h.router.ServeHTTP(status304Rec, status304Req)
	if status304Rec.Code != http.StatusNotModified {
		t.Fatalf("status If-None-Match got %d, want 304", status304Rec.Code)
	}

	// 4. GET /api/agent-server/v1/nodes & GET /api/agent/nodes
	for _, path := range []string{"/api/agent-server/v1/nodes", "/api/agent/nodes"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+userJWT)
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s got %d: %s", path, rec.Code, rec.Body.String())
		}
		var nodes []agentserver.VlessNode
		if err := json.Unmarshal(rec.Body.Bytes(), &nodes); err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 2 {
			t.Fatalf("GET %s expected 2 nodes, got %d (%+v)", path, len(nodes), nodes)
		}
	}

	// 5. GET /api/auth/sync/subscription & /api/auth/sync/subscription/:format & /api/auth/sync/config
	for _, tc := range []struct {
		path        string
		queryAuth   bool
		wantContain string
	}{
		{"/api/auth/sync/subscription", false, "proxies:"},
		{"/api/auth/sync/subscription?format=vless&token=" + userJWT, true, "vless://a55a9f3a-5d63-4b99-9c3a-9dfeb6d57da2@"},
		{"/api/auth/sync/subscription/singbox", false, `"outbounds"`},
		{"/api/auth/sync/subscription/xray", false, `"routing"`},
		{"/api/auth/sync/subscription/one", false, `"policy_revision"`},
		{"/api/auth/sync/config?since_version=0", false, `"routes"`},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if !tc.queryAuth {
			req.Header.Set("Authorization", "Bearer "+userJWT)
		}
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s got %d: %s", tc.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), tc.wantContain) {
			t.Fatalf("GET %s body missing %q: %s", tc.path, tc.wantContain, rec.Body.String())
		}
	}

	// 6. GET /api/observability/internal/xconnect/identity (InternalAuthMiddleware)
	obsUnauth := httptest.NewRecorder()
	h.router.ServeHTTP(obsUnauth, httptest.NewRequest(http.MethodGet, "/api/observability/internal/xconnect/identity?email=alice@example.test", nil))
	if obsUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauth observability identity got %d, want 401", obsUnauth.Code)
	}

	obsEmailReq := httptest.NewRequest(http.MethodGet, "/api/observability/internal/xconnect/identity?email=ALICE@example.test", nil)
	obsEmailReq.Header.Set("X-Internal-Service-Token", h.internalToken)
	obsEmailRec := httptest.NewRecorder()
	h.router.ServeHTTP(obsEmailRec, obsEmailReq)
	if obsEmailRec.Code != http.StatusOK {
		t.Fatalf("observability email lookup got %d: %s", obsEmailRec.Code, obsEmailRec.Body.String())
	}

	obsUUIDReq := httptest.NewRequest(http.MethodGet, "/api/observability/internal/xconnect/identity?proxyUuid=a55a9f3a-5d63-4b99-9c3a-9dfeb6d57da2", nil)
	obsUUIDReq.Header.Set("X-Internal-Service-Token", h.internalToken)
	obsUUIDRec := httptest.NewRecorder()
	h.router.ServeHTTP(obsUUIDRec, obsUUIDReq)
	if obsUUIDRec.Code != http.StatusOK {
		t.Fatalf("observability proxyUuid lookup got %d: %s", obsUUIDRec.Code, obsUUIDRec.Body.String())
	}

	var eRes, uRes struct {
		Found              bool   `json:"found"`
		ProxyIdentityRef   string `json:"proxyIdentityRef"`
		IdentityRefVersion int    `json:"identityRefVersion"`
	}
	_ = json.Unmarshal(obsEmailRec.Body.Bytes(), &eRes)
	_ = json.Unmarshal(obsUUIDRec.Body.Bytes(), &uRes)
	if !eRes.Found || !uRes.Found || eRes.ProxyIdentityRef == "" || eRes.ProxyIdentityRef != uRes.ProxyIdentityRef {
		t.Fatalf("identity ref mismatch: email=%+v uuid=%+v", eRes, uRes)
	}
	if bytes.Contains(obsEmailRec.Body.Bytes(), []byte("alice@example.test")) ||
		bytes.Contains(obsEmailRec.Body.Bytes(), []byte("a55a9f3a-5d63-4b99-9c3a-9dfeb6d57da2")) {
		t.Fatal("raw email or proxyUuid leaked in observability identity response")
	}

	// Verify ZERO writes occurred across all GET calls!
	if writes := h.store.writeCounter.Load(); writes != 0 {
		t.Fatalf("expected 0 writes across GET endpoints, got %d", writes)
	}
}

func TestGORMStoreAccountsSchemaAndGracefulOptionalTables(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:gorm-accounts-schema?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	// Create ONLY users and node_health_snapshots using accounts column naming (uuid, username, etc.)
	// Deliberately omit network_teams, account_billing_profiles, etc. to test graceful degradation without DDL.
	if err := db.Exec(`
		CREATE TABLE users (
			uuid TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			email TEXT,
			role TEXT NOT NULL DEFAULT 'user',
			groups TEXT NOT NULL DEFAULT '[]',
			permissions TEXT NOT NULL DEFAULT '[]',
			email_verified INTEGER NOT NULL DEFAULT 1,
			active INTEGER NOT NULL DEFAULT 1,
			proxy_uuid TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE node_health_snapshots (
			node_id TEXT PRIMARY KEY,
			region TEXT NOT NULL DEFAULT '',
			line_code TEXT NOT NULL DEFAULT '',
			pricing_group TEXT NOT NULL DEFAULT '',
			stats_enabled INTEGER NOT NULL DEFAULT 0,
			xray_revision TEXT NOT NULL DEFAULT '',
			healthy INTEGER NOT NULL DEFAULT 1,
			latency_ms INTEGER NOT NULL DEFAULT 0,
			error_rate REAL NOT NULL DEFAULT 0,
			active_connections INTEGER NOT NULL DEFAULT 0,
			health_score REAL NOT NULL DEFAULT 0,
			sampled_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);
		INSERT INTO users (uuid, username, email, role, groups, active, email_verified, proxy_uuid)
		VALUES ('usr-100', 'bob', 'bob@example.test', 'user', '["segment:quota:free-3gb"]', 1, 1, 'proxy-uuid-100');
	`).Error; err != nil {
		t.Fatal(err)
	}

	st := agentserver.NewGORMStore(db)
	ctx := context.Background()

	users, err := st.ListUsers(ctx)
	if err != nil || len(users) != 1 || users[0].ID != "usr-100" || users[0].ProxyUUID != "proxy-uuid-100" {
		t.Fatalf("ListUsers unexpected: users=%+v err=%v", users, err)
	}
	byID, err := st.GetUserByID(ctx, "usr-100")
	if err != nil || byID.ID != "usr-100" || byID.Email != "bob@example.test" || byID.ProxyUUID != "proxy-uuid-100" {
		t.Fatalf("GetUserByID on uuid-only users table failed: user=%+v err=%v", byID, err)
	}
	byEmail, err := st.GetUserByEmail(ctx, "BOB@example.test")
	if err != nil || byEmail.ID != "usr-100" {
		t.Fatalf("GetUserByEmail on uuid-only users table failed: user=%+v err=%v", byEmail, err)
	}
	byProxy, err := st.GetUserByProxyUUID(ctx, "PROXY-UUID-100")
	if err != nil || byProxy.ID != "usr-100" {
		t.Fatalf("GetUserByProxyUUID on uuid-only users table failed: user=%+v err=%v", byProxy, err)
	}
	if _, err := st.GetUserByID(ctx, "does-not-exist"); err != agentserver.ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound for unknown user, got %v", err)
	}
	if err := st.UpsertNodeHealthSnapshot(ctx, &agentserver.NodeHealthSnapshot{
		NodeID: "jp-xconnect-01.svc.plus", Region: "jp", PricingGroup: "free", Healthy: true, SampledAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertNodeHealthSnapshot failed: %v", err)
	}
	snaps, err := st.ListLatestNodeHealthSnapshots(ctx)
	if err != nil || len(snaps) != 1 || snaps[0].NodeID != "jp-xconnect-01.svc.plus" {
		t.Fatalf("ListLatestNodeHealthSnapshots unexpected: snaps=%+v err=%v", snaps, err)
	}
	// Missing optional tables must degrade cleanly without errors
	if blocked, err := st.ListProxyBlockedAccountUUIDs(ctx); err != nil || len(blocked) != 0 {
		t.Fatalf("ListProxyBlockedAccountUUIDs unexpected: %v %v", blocked, err)
	}
	if teams, err := st.ListNetworkTeams(ctx); err != nil || len(teams) != 0 {
		t.Fatalf("ListNetworkTeams unexpected: %v %v", teams, err)
	}
	if _, err := st.GetAccountBillingProfile(ctx, "usr-100"); err != agentserver.ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound for missing billing table, got %v", err)
	}
}

func TestWhitelistFreeUserAccessesMediaPoolPlusNodes(t *testing.T) {
	h := newTestHarness(t, 0)
	h.store.users = []agentserver.User{
		{
			ID:            "edfd5179-f9e7-40ba-89d0-d8a957b6cd7a",
			Name:          "Nora",
			Email:         "624220860@qq.com",
			Role:          "user",
			Active:        true,
			EmailVerified: true,
			ProxyUUID:     "uuid-whitelist-624",
			Groups:        []string{agentserver.WhitelistFreeQuotaGroup, "User"},
			UpdatedAt:     h.now,
		},
		{
			ID:            "u-free-regular",
			Name:          "free",
			Email:         "free@example.test",
			Role:          "user",
			Active:        true,
			EmailVerified: true,
			ProxyUUID:     "uuid-regular-free",
			Groups:        []string{agentserver.MonthlyFreeQuotaLimitGroup, "User"},
			UpdatedAt:     h.now,
		},
	}
	h.store.billing["edfd5179-f9e7-40ba-89d0-d8a957b6cd7a"] = &agentserver.AccountBillingProfile{
		AccountUUID:        "edfd5179-f9e7-40ba-89d0-d8a957b6cd7a",
		PackageName:        "whitelist",
		IncludedQuotaBytes: 5 << 30,
	}
	h.store.quotas["edfd5179-f9e7-40ba-89d0-d8a957b6cd7a"] = &agentserver.AccountQuotaState{
		AccountUUID:            "edfd5179-f9e7-40ba-89d0-d8a957b6cd7a",
		RemainingIncludedQuota: 5 << 30,
		SuspendState:           "active",
		ProxyAccessState:       "active",
	}
	hbNow := h.now
	h.store.agents = []*agentserver.AgentRecord{
		{
			ID:            "jp-plus-01.svc.plus",
			Name:          "jp-plus-01.svc.plus",
			Groups:        []string{"internal", "resource:plus"},
			Healthy:       true,
			LastHeartbeat: &hbNow,
			UpdatedAt:     hbNow,
		},
		{
			ID:            "us-custom-01.svc.plus",
			Name:          "us-custom-01.svc.plus",
			Groups:        []string{"internal", "resource:custom", "custom:allow-free"},
			Healthy:       true,
			LastHeartbeat: &hbNow,
			UpdatedAt:     hbNow,
		},
		{
			ID:            "jp-pro-01.svc.plus",
			Name:          "jp-pro-01.svc.plus",
			Groups:        []string{"internal", "resource:pro"},
			Healthy:       true,
			LastHeartbeat: &hbNow,
			UpdatedAt:     hbNow,
		},
	}
	h.store.healthSnaps = []agentserver.NodeHealthSnapshot{
		{NodeID: "jp-plus-01.svc.plus", Region: "jp", PricingGroup: "plus", Healthy: true, SampledAt: h.now},
		{NodeID: "us-custom-01.svc.plus", Region: "us", PricingGroup: "custom", Healthy: true, SampledAt: h.now},
		{NodeID: "jp-pro-01.svc.plus", Region: "jp", PricingGroup: "pro", Healthy: true, SampledAt: h.now},
	}

	// Whitelist free user sees Media-Pool (resource:plus) node, not Pro or un-allowlisted Custom.
	whitelistJWT := signJWT(t, "accounts-jwt-test", h.jwtPriv, "edfd5179-f9e7-40ba-89d0-d8a957b6cd7a", "624220860@qq.com", []string{"user"})
	req := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+whitelistJWT)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("whitelist GET /nodes got %d: %s", rec.Code, rec.Body.String())
	}
	var wlNodes []agentserver.VlessNode
	if err := json.Unmarshal(rec.Body.Bytes(), &wlNodes); err != nil {
		t.Fatal(err)
	}
	if len(wlNodes) != 1 || wlNodes[0].Address != "jp-plus-01.svc.plus" || !wlNodes[0].OpenToUsers || wlNodes[0].RoutingPool != agentserver.RoutingPoolMediaPriority {
		t.Fatalf("whitelist nodes unexpected: %+v", wlNodes)
	}

	// Regular non-whitelist free user still resolves to free and does not see resource:plus nodes.
	freeJWT := signJWT(t, "accounts-jwt-test", h.jwtPriv, "u-free-regular", "free@example.test", []string{"user"})
	freeReq := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/nodes", nil)
	freeReq.Header.Set("Authorization", "Bearer "+freeJWT)
	freeRec := httptest.NewRecorder()
	h.router.ServeHTTP(freeRec, freeReq)
	if freeRec.Code != http.StatusOK {
		t.Fatalf("regular free GET /nodes got %d: %s", freeRec.Code, freeRec.Body.String())
	}
	var freeNodes []agentserver.VlessNode
	if err := json.Unmarshal(freeRec.Body.Bytes(), &freeNodes); err != nil {
		t.Fatal(err)
	}
	if len(freeNodes) != 0 {
		t.Fatalf("regular free user unexpectedly received non-free nodes: %+v", freeNodes)
	}

	// Proxy client sync on a resource:plus agent includes whitelist-free user and excludes regular free user.
	syncReq := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/users", nil)
	syncReq.Header.Set("Authorization", "Bearer agent-wildcard-token")
	syncReq.Header.Set("X-Agent-ID", "jp-plus-sync-01.svc.plus")
	syncReq.Header.Set("X-Agent-Resource-Class", "plus")
	syncRec := httptest.NewRecorder()
	h.router.ServeHTTP(syncRec, syncReq)
	if syncRec.Code != http.StatusOK {
		t.Fatalf("plus agent GET /users got %d: %s", syncRec.Code, syncRec.Body.String())
	}
	var syncPayload agentproto.ClientListResponse
	if err := json.Unmarshal(syncRec.Body.Bytes(), &syncPayload); err != nil {
		t.Fatal(err)
	}
	if len(syncPayload.Clients) != 1 || syncPayload.Clients[0].Email != "624220860@qq.com" {
		t.Fatalf("plus agent clients unexpected: %+v", syncPayload.Clients)
	}
}
