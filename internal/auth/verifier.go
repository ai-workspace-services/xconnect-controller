package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

const (
	PermissionXConnectZeroRead   = "xconnect.zero.read"
	PermissionXConnectZeroManage = "xconnect.zero.manage"
)

// Claims matches the access token claims minted by ai-workspace-services/accounts.
type Claims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	MFA    bool     `json:"mfa_verified"`
	jwt.RegisteredClaims
}

// UserInfo holds the authenticated identity and optional shared-DB account state.
type UserInfo struct {
	ID          string
	Email       string
	Role        string
	Roles       []string
	Active      bool
	Suspended   bool
	ReadOnly    bool
	Permissions []string
}

// UserReader optionally resolves live user active/suspension/role metadata from shared PostgreSQL.
type UserReader interface {
	LookupUserByID(ctx context.Context, userID string) (*UserInfo, error)
	LookupUserByEmail(ctx context.Context, email string) (*UserInfo, error)
}

type GORMUserReader struct {
	db *gorm.DB
}

func NewGORMUserReader(db *gorm.DB) *GORMUserReader {
	if db == nil {
		return nil
	}
	return &GORMUserReader{db: db}
}

func (r *GORMUserReader) LookupUserByID(ctx context.Context, userID string) (*UserInfo, error) {
	col := r.userIDColumn()
	return r.lookup(ctx, col+" = ?", strings.TrimSpace(userID))
}

func (r *GORMUserReader) LookupUserByEmail(ctx context.Context, email string) (*UserInfo, error) {
	return r.lookup(ctx, "LOWER(email) = LOWER(?)", strings.TrimSpace(email))
}

func (r *GORMUserReader) userIDColumn() string {
	if r == nil || r.db == nil {
		return "id"
	}
	if cols, err := r.db.Migrator().ColumnTypes("users"); err == nil {
		hasID, hasUUID := false, false
		for _, c := range cols {
			switch strings.ToLower(c.Name()) {
			case "id":
				hasID = true
			case "uuid":
				hasUUID = true
			}
		}
		if hasUUID && !hasID {
			return "uuid"
		}
	}
	return "id"
}

func (r *GORMUserReader) lookup(ctx context.Context, where string, arg string) (*UserInfo, error) {
	if r == nil || r.db == nil || arg == "" {
		return nil, errors.New("user not found")
	}
	idCol := r.userIDColumn()
	selectCols := idCol + " AS id, email, role, active, permissions"
	var row struct {
		ID          string `gorm:"column:id"`
		Email       string `gorm:"column:email"`
		Role        string `gorm:"column:role"`
		Active      bool   `gorm:"column:active"`
		Permissions string `gorm:"column:permissions"`
	}
	if err := r.db.WithContext(ctx).Table("users").Select(selectCols).Where(where, arg).Limit(1).Take(&row).Error; err != nil {
		return nil, err
	}
	info := &UserInfo{
		ID:       strings.TrimSpace(row.ID),
		Email:    strings.TrimSpace(row.Email),
		Role:     strings.TrimSpace(row.Role),
		Roles:    []string{strings.TrimSpace(row.Role)},
		Active:   row.Active,
		ReadOnly: strings.EqualFold(strings.TrimSpace(row.Role), "demo"),
	}
	if strings.TrimSpace(row.Permissions) != "" {
		var perms []string
		if json.Unmarshal([]byte(row.Permissions), &perms) == nil {
			info.Permissions = perms
		}
	}
	if r.db.Migrator().HasTable("account_quota_states") {
		quotaUserCol := "user_id"
		if cols, err := r.db.Migrator().ColumnTypes("account_quota_states"); err == nil {
			hasUserID, hasAccountUUID := false, false
			for _, c := range cols {
				switch strings.ToLower(c.Name()) {
				case "user_id":
					hasUserID = true
				case "account_uuid":
					hasAccountUUID = true
				}
			}
			if hasAccountUUID && !hasUserID {
				quotaUserCol = "account_uuid"
			}
		}
		var quota struct {
			SuspendState string `gorm:"column:suspend_state"`
		}
		if err := r.db.WithContext(ctx).Table("account_quota_states").Select("suspend_state").Where(quotaUserCol+" = ?", info.ID).Limit(1).Take(&quota).Error; err == nil {
			info.Suspended = strings.EqualFold(strings.TrimSpace(quota.SuspendState), "suspended")
		}
	}
	return info, nil
}

type JWK struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	X         string `json:"x"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type VerifierConfig struct {
	JWKSURL         string
	AccessSecret    string
	InternalToken   string
	CacheTTL        time.Duration
	RefreshMinGap   time.Duration
	HTTPClient      *http.Client
	StaticEd25519   map[string]ed25519.PublicKey
	UserReader      UserReader
}

type Verifier struct {
	jwksURL       string
	accessSecret  string
	internalToken string
	cacheTTL      time.Duration
	refreshMinGap time.Duration
	httpClient    *http.Client
	userReader    UserReader

	mu          sync.RWMutex
	keys        map[string]ed25519.PublicKey
	lastFetched time.Time
}

func VerifierConfigFromEnv(userReader UserReader) VerifierConfig {
	return VerifierConfig{
		JWKSURL:       strings.TrimSpace(os.Getenv("ACCOUNTS_JWKS_URL")),
		AccessSecret:  strings.TrimSpace(os.Getenv("JWT_ACCESS_SECRET")),
		InternalToken: strings.TrimSpace(os.Getenv("INTERNAL_SERVICE_TOKEN")),
		CacheTTL:      5 * time.Minute,
		RefreshMinGap: 5 * time.Second,
		HTTPClient:    &http.Client{Timeout: 5 * time.Second},
		UserReader:    userReader,
	}
}

func NewVerifier(cfg VerifierConfig) *Verifier {
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.RefreshMinGap <= 0 {
		cfg.RefreshMinGap = 5 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	keys := make(map[string]ed25519.PublicKey, len(cfg.StaticEd25519))
	for k, v := range cfg.StaticEd25519 {
		keys[k] = append(ed25519.PublicKey(nil), v...)
	}
	return &Verifier{
		jwksURL:       cfg.JWKSURL,
		accessSecret:  cfg.AccessSecret,
		internalToken: cfg.InternalToken,
		cacheTTL:      cfg.CacheTTL,
		refreshMinGap: cfg.RefreshMinGap,
		httpClient:    cfg.HTTPClient,
		userReader:    cfg.UserReader,
		keys:          keys,
	}
}

func (v *Verifier) SetPublicKey(kid string, pub ed25519.PublicKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.keys == nil {
		v.keys = make(map[string]ed25519.PublicKey)
	}
	v.keys[kid] = append(ed25519.PublicKey(nil), pub...)
}

func (v *Verifier) LookupUserByEmail(ctx context.Context, email string) (*UserInfo, error) {
	if v.userReader == nil {
		return nil, errors.New("user lookup store unavailable")
	}
	return v.userReader.LookupUserByEmail(ctx, email)
}

func (v *Verifier) ed25519Key(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	now := time.Now()
	v.mu.RLock()
	pub, ok := v.pickKeyLocked(kid)
	expired := v.jwksURL != "" && (v.lastFetched.IsZero() || now.Sub(v.lastFetched) > v.cacheTTL)
	canRefresh := v.jwksURL != "" && (v.lastFetched.IsZero() || now.Sub(v.lastFetched) >= v.refreshMinGap)
	v.mu.RUnlock()

	if ok && !expired {
		return pub, nil
	}
	if canRefresh {
		if err := v.refreshJWKS(ctx); err == nil {
			v.mu.RLock()
			pub, ok = v.pickKeyLocked(kid)
			v.mu.RUnlock()
			if ok {
				return pub, nil
			}
		} else if ok {
			return pub, nil
		}
	} else if ok {
		return pub, nil
	}
	return nil, fmt.Errorf("signing key %q not found", kid)
}

func (v *Verifier) pickKeyLocked(kid string) (ed25519.PublicKey, bool) {
	if kid != "" {
		pub, ok := v.keys[kid]
		return pub, ok
	}
	if len(v.keys) == 1 {
		for _, pub := range v.keys {
			return pub, true
		}
	}
	return nil, false
}

func (v *Verifier) refreshJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}
	var doc JWKS
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	parsed := make(map[string]ed25519.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.KeyType != "OKP" || k.Curve != "Ed25519" || strings.TrimSpace(k.KeyID) == "" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			raw, err = base64.URLEncoding.DecodeString(k.X)
		}
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		parsed[k.KeyID] = ed25519.PublicKey(raw)
	}
	v.mu.Lock()
	for kid, pub := range parsed {
		v.keys[kid] = pub
	}
	v.lastFetched = time.Now()
	v.mu.Unlock()
	return nil
}

func (v *Verifier) ValidateAccessToken(ctx context.Context, rawToken string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(rawToken, &Claims{}, func(token *jwt.Token) (any, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodEd25519:
			kid, _ := token.Header["kid"].(string)
			return v.ed25519Key(ctx, strings.TrimSpace(kid))
		case *jwt.SigningMethodHMAC:
			if v.accessSecret == "" {
				return nil, errors.New("HS256 verification key not configured")
			}
			return []byte(v.accessSecret), nil
		default:
			return nil, fmt.Errorf("unsupported JWT algorithm: %v", token.Header["alg"])
		}
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid access token")
	}
	return claims, nil
}

type contextKey string

const (
	userIDKey   contextKey = "user_id"
	emailKey    contextKey = "email"
	rolesKey    contextKey = "roles"
	userInfoKey contextKey = "user_info"
)

func GetUserID(c *gin.Context) string {
	val, _ := c.Request.Context().Value(userIDKey).(string)
	return val
}

func GetUserInfo(c *gin.Context) *UserInfo {
	val, _ := c.Request.Context().Value(userInfoKey).(*UserInfo)
	return val
}

func extractBearerOrCookie(c *gin.Context) string {
	if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		if token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer ")); token != "" {
			return token
		}
	}
	if cookie, err := c.Cookie("xc_session"); err == nil && strings.TrimSpace(cookie) != "" {
		return strings.TrimSpace(cookie)
	}
	return ""
}

func extractBearerCookieOrQuery(c *gin.Context) string {
	if token := extractBearerOrCookie(c); token != "" {
		return token
	}
	if token := strings.TrimSpace(c.Query("token")); token != "" {
		return token
	}
	return ""
}

// AuthMiddleware verifies JWTs offline (via JWKS or HS256 transition secret) and optionally validates active status via UserReader.
func (v *Verifier) AuthMiddleware() gin.HandlerFunc {
	return v.authMiddleware(extractBearerOrCookie)
}

// AuthMiddlewareAllowQueryToken verifies JWTs from Authorization Bearer, xc_session cookie, or ?token= query parameter.
func (v *Verifier) AuthMiddlewareAllowQueryToken() gin.HandlerFunc {
	return v.authMiddleware(extractBearerCookieOrQuery)
}

func (v *Verifier) authMiddleware(extract func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extract(c)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}
		claims, err := v.ValidateAccessToken(c.Request.Context(), token)
		if err != nil || strings.TrimSpace(claims.UserID) == "" || claims.UserID == "system" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			c.Abort()
			return
		}
		info := &UserInfo{
			ID:     strings.TrimSpace(claims.UserID),
			Email:  strings.TrimSpace(claims.Email),
			Roles:  claims.Roles,
			Active: true,
		}
		if len(claims.Roles) > 0 {
			info.Role = strings.TrimSpace(claims.Roles[0])
		} else {
			info.Role = "user"
		}
		if v.userReader != nil {
			dbInfo, dbErr := v.userReader.LookupUserByID(c.Request.Context(), info.ID)
			if dbErr != nil || dbInfo == nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
				c.Abort()
				return
			}
			if !dbInfo.Active || dbInfo.Suspended {
				c.JSON(http.StatusForbidden, gin.H{"error": "account_suspended", "message": "your account has been suspended"})
				c.Abort()
				return
			}
			info = dbInfo
		}
		ctx := context.WithValue(c.Request.Context(), userIDKey, info.ID)
		ctx = context.WithValue(ctx, emailKey, info.Email)
		ctx = context.WithValue(ctx, rolesKey, info.Roles)
		ctx = context.WithValue(ctx, userInfoKey, info)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func IsRootRole(role string) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	return r == "root" || r == "superadmin"
}

func (v *Verifier) AuthorizeZeroAccess(c *gin.Context, permission string) (*UserInfo, bool) {
	info := GetUserInfo(c)
	if info == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session_token_required", "message": "authentication is required"})
		return nil, false
	}
	if !info.Active || info.Suspended {
		c.JSON(http.StatusForbidden, gin.H{"error": "account_suspended", "message": "your account has been suspended"})
		return nil, false
	}
	if info.ReadOnly && c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
		c.JSON(http.StatusForbidden, gin.H{"error": "read_only_account", "message": "demo account is read-only"})
		return nil, false
	}
	role := strings.ToLower(strings.TrimSpace(info.Role))
	switch {
	case IsRootRole(role), role == "admin", role == "user":
		return info, true
	case role == "operator":
		if !hasPermission(info.Permissions, permission) && len(info.Permissions) > 0 {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "message": "operator permission denied"})
			return nil, false
		}
		return info, true
	case role == "readonly":
		if (c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead) || !hasPermission(info.Permissions, permission) {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "message": "readonly permission denied"})
			return nil, false
		}
		return info, true
	default:
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "message": "insufficient permissions"})
		return nil, false
	}
}

func hasPermission(perms []string, target string) bool {
	for _, p := range perms {
		if p == "*" || p == target {
			return true
		}
	}
	return false
}

// InternalAuthMiddleware protects internal control-plane endpoints using INTERNAL_SERVICE_TOKEN.
func (v *Verifier) InternalAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if v.internalToken == "" {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "internal_auth_not_configured"})
			c.Abort()
			return
		}
		candidate := strings.TrimSpace(c.GetHeader("X-Internal-Service-Token"))
		if candidate == "" {
			candidate = strings.TrimSpace(c.GetHeader("X-Service-Token"))
		}
		if candidate == "" {
			if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
				candidate = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			}
		}
		if len(candidate) == 0 || subtle.ConstantTimeCompare([]byte(candidate), []byte(v.internalToken)) != 1 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_internal_token"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// ValidateInternalToken validates an internal service token using constant-time comparison.
func (v *Verifier) ValidateInternalToken(candidate string) bool {
	if v == nil || v.internalToken == "" || candidate == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(v.internalToken)) == 1
}
