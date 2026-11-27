package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func signTestEdDSA(t *testing.T, kid string, priv ed25519.PrivateKey, userID, email string, roles []string) string {
	t.Helper()
	claims := Claims{
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
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestOfflineJWKSAndHS256Verification(t *testing.T) {
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwksHits := 0
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksHits++
		keys := []JWK{{
			KeyType:   "OKP",
			Curve:     "Ed25519",
			Algorithm: "EdDSA",
			Use:       "sig",
			KeyID:     "accounts-jwt-202611",
			X:         base64.RawURLEncoding.EncodeToString(pub1),
		}}
		if jwksHits >= 2 {
			keys = append(keys, JWK{
				KeyType:   "OKP",
				Curve:     "Ed25519",
				Algorithm: "EdDSA",
				Use:       "sig",
				KeyID:     "accounts-jwt-202612",
				X:         base64.RawURLEncoding.EncodeToString(pub2),
			})
		}
		_ = json.NewEncoder(w).Encode(JWKS{Keys: keys})
	}))
	defer jwksSrv.Close()

	verifier := NewVerifier(VerifierConfig{
		JWKSURL:       jwksSrv.URL,
		AccessSecret:  "hs256-fallback",
		InternalToken: "internal-secret-token",
		CacheTTL:      time.Minute,
		RefreshMinGap: time.Millisecond,
	})

	tok1 := signTestEdDSA(t, "accounts-jwt-202611", priv1, "user-1", "alice@example.test", []string{"user"})
	claims1, err := verifier.ValidateAccessToken(t.Context(), tok1)
	if err != nil || claims1.UserID != "user-1" {
		t.Fatalf("expected EdDSA token 1 valid, claims=%#v err=%v", claims1, err)
	}

	// Unknown kid triggers JWKS refresh and verifies newly rotated key.
	time.Sleep(5 * time.Millisecond)
	tok2 := signTestEdDSA(t, "accounts-jwt-202612", priv2, "user-2", "bob@example.test", []string{"root"})
	claims2, err := verifier.ValidateAccessToken(t.Context(), tok2)
	if err != nil || claims2.UserID != "user-2" {
		t.Fatalf("expected rotated EdDSA token 2 valid after JWKS refresh, claims=%#v err=%v", claims2, err)
	}

	// HS256 fallback also validates during transition.
	hsTok := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID: "user-hs",
		Roles:  []string{"admin"},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	hsSigned, _ := hsTok.SignedString([]byte("hs256-fallback"))
	hsClaims, err := verifier.ValidateAccessToken(t.Context(), hsSigned)
	if err != nil || hsClaims.UserID != "user-hs" {
		t.Fatalf("expected HS256 fallback valid, claims=%#v err=%v", hsClaims, err)
	}

	// Constant-time internal auth middleware check.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/internal", verifier.InternalAuthMiddleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	recBad := httptest.NewRecorder()
	reqBad := httptest.NewRequest(http.MethodPost, "/internal", nil)
	reqBad.Header.Set("X-Internal-Service-Token", "wrong")
	r.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong internal token, got %d", recBad.Code)
	}
	recOK := httptest.NewRecorder()
	reqOK := httptest.NewRequest(http.MethodPost, "/internal", nil)
	reqOK.Header.Set("X-Internal-Service-Token", "internal-secret-token")
	r.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid internal token, got %d", recOK.Code)
	}

	recSvcOK := httptest.NewRecorder()
	reqSvcOK := httptest.NewRequest(http.MethodPost, "/internal", nil)
	reqSvcOK.Header.Set("X-Service-Token", "internal-secret-token")
	r.ServeHTTP(recSvcOK, reqSvcOK)
	if recSvcOK.Code != http.StatusOK {
		t.Fatalf("expected 200 for X-Service-Token, got %d", recSvcOK.Code)
	}
}

func TestGORMUserReaderAccountsUUIDSchema(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:auth-uuid-schema?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`
		CREATE TABLE users (
			uuid TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			role TEXT NOT NULL,
			active INTEGER NOT NULL,
			permissions TEXT NOT NULL DEFAULT '[]'
		);
		CREATE TABLE account_quota_states (
			account_uuid TEXT PRIMARY KEY,
			suspend_state TEXT NOT NULL DEFAULT 'active'
		);
		INSERT INTO users (uuid, email, role, active, permissions) VALUES ('usr-uuid-1', 'u1@example.test', 'admin', 1, '["*"]');
		INSERT INTO account_quota_states (account_uuid, suspend_state) VALUES ('usr-uuid-1', 'suspended');
	`).Error; err != nil {
		t.Fatal(err)
	}
	reader := NewGORMUserReader(db)
	info, err := reader.LookupUserByID(t.Context(), "usr-uuid-1")
	if err != nil {
		t.Fatalf("LookupUserByID failed: %v", err)
	}
	if info.ID != "usr-uuid-1" || info.Role != "admin" || !info.Suspended {
		t.Fatalf("unexpected UserInfo: %+v", info)
	}
}
