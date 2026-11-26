package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ai-workspace-services/xconnect-controller/internal/auth"
	"github.com/ai-workspace-services/xconnect-controller/internal/overlay"
)

func signUserJWT(t *testing.T, kid string, priv ed25519.PrivateKey, userID, email string, roles []string) string {
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

func TestOverlayV1RouteInventoryAndJWKSFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open("file:httpapi-routes?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_, overlaySigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	svc, err := overlay.NewService(db, overlay.Config{
		SigningKeyID:      "zero-signing-test",
		SigningPrivateKey: overlaySigner,
		Clock:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	jwtPub, jwtPriv, err := ed25519.GenerateKey(rand.Reader)
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
				X:         base64.RawURLEncoding.EncodeToString(jwtPub),
			}},
		})
	}))
	defer jwksSrv.Close()

	verifier := auth.NewVerifier(auth.VerifierConfig{
		JWKSURL:       jwksSrv.URL,
		InternalToken: "internal-test-token",
	})
	router := NewRouter(Server{
		Overlay:  svc,
		Verifier: verifier,
		DBHealth: func(_ context.Context) error { return nil },
	})

	// 1. Verify exact 31 /api/overlay/v1 routes exist matching accounts inventory.
	var actual []string
	for _, rt := range router.Routes() {
		if strings.HasPrefix(rt.Path, "/api/overlay/v1") {
			actual = append(actual, rt.Method+" "+rt.Path)
		}
	}
	sort.Strings(actual)
	expected := []string{
		"DELETE /api/overlay/v1/admin/networks/:networkID",
		"DELETE /api/overlay/v1/admin/networks/:networkID/members/:userID",
		"GET /api/overlay/v1/admin/devices",
		"GET /api/overlay/v1/admin/invites",
		"GET /api/overlay/v1/admin/networks",
		"GET /api/overlay/v1/admin/networks/:networkID/members",
		"GET /api/overlay/v1/admin/networks/:networkID/policy",
		"GET /api/overlay/v1/admin/overview",
		"GET /api/overlay/v1/admin/registrations",
		"GET /api/overlay/v1/admin/telemetry",
		"GET /api/overlay/v1/enrollment/policy-artifacts/:generation/:digest",
		"GET /api/overlay/v1/enrollment/signed-config",
		"GET /api/overlay/v1/gateway/signed-config",
		"GET /api/overlay/v1/gateways",
		"GET /api/overlay/v1/signing-keys",
		"GET /api/overlay/v1/signed-config",
		"POST /api/overlay/v1/admin/devices/:deviceID/revoke",
		"POST /api/overlay/v1/admin/invites",
		"POST /api/overlay/v1/admin/networks/:networkID/members",
		"POST /api/overlay/v1/admin/networks/:networkID/policy/explain",
		"POST /api/overlay/v1/admin/networks/bootstrap",
		"POST /api/overlay/v1/admin/registrations/:registrationID/approve",
		"POST /api/overlay/v1/admin/registrations/:registrationID/reject",
		"POST /api/overlay/v1/device/session",
		"POST /api/overlay/v1/devices/enroll",
		"POST /api/overlay/v1/enrollment/signed-config/:generation/ack",
		"POST /api/overlay/v1/join-tokens/exchange",
		"POST /api/overlay/v1/registrations",
		"POST /api/overlay/v1/registrations/:registrationID/exchange",
		"POST /api/overlay/v1/signed-config/:generation/ack",
		"PUT /api/overlay/v1/admin/networks/:networkID/mode",
		"PUT /api/overlay/v1/admin/networks/:networkID/policy",
	}
	sort.Strings(expected)
	if len(actual) != len(expected) {
		t.Fatalf("route count mismatch: got %d (%v), want %d (%v)", len(actual), actual, len(expected), expected)
	}
	for i := range expected {
		if actual[i] != expected[i] {
			t.Fatalf("route[%d] = %q, want %q", i, actual[i], expected[i])
		}
	}

	// 2. /healthz and /readyz return 200.
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s returned %d: %s", path, rec.Code, rec.Body.String())
		}
	}

	// 3. Offline JWKS auth protects user & admin endpoints and supports bootstrap -> enroll -> signed-config -> ack.
	ownerJWT := signUserJWT(t, "accounts-jwt-test", jwtPriv, "11111111-2222-4333-8444-555555555555", "owner@example.test", []string{"user"})
	gwKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	bootstrapBody, _ := json.Marshal(map[string]any{
		"controller_url": "https://accounts.svc.plus",
		"network": map[string]any{
			"id":                           "net-standalone-01",
			"display_name":                 "Standalone Net",
			"cidr":                         "10.68.0.0/24",
			"gateway_id":                   "gw-standalone-01",
			"gateway_wireguard_public_key": gwKey,
			"gateway_wireguard_address":    "10.68.0.1/32",
			"gateway_endpoint_host":        "gw.example.test",
			"gateway_endpoint_port":        51820,
			"transport_server_name":        "gw.example.test",
			"transport_port":               443,
			"transport_auth_id":            "11111111-1111-1111-1111-111111111111",
		},
		"invite": map[string]any{
			"device_id":  "gw-standalone-01",
			"platform":   "linux",
			"role":       "gateway",
			"expires_at": now.Add(time.Hour),
		},
	})
	bootReq := httptest.NewRequest(http.MethodPost, "/api/overlay/v1/admin/networks/bootstrap", bytes.NewReader(bootstrapBody))
	bootReq.Header.Set("Authorization", "Bearer "+ownerJWT)
	bootReq.Header.Set("Content-Type", "application/json")
	bootRec := httptest.NewRecorder()
	router.ServeHTTP(bootRec, bootReq)
	if bootRec.Code != http.StatusCreated {
		t.Fatalf("bootstrap via JWKS failed: %d %s", bootRec.Code, bootRec.Body.String())
	}

	keysReq := httptest.NewRequest(http.MethodGet, "/api/overlay/v1/signing-keys", nil)
	keysReq.Header.Set("Authorization", "Bearer "+ownerJWT)
	keysRec := httptest.NewRecorder()
	router.ServeHTTP(keysRec, keysReq)
	if keysRec.Code != http.StatusOK {
		t.Fatalf("signing-keys failed: %d %s", keysRec.Code, keysRec.Body.String())
	}
}
