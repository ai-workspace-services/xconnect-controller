package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ai-workspace-services/xconnect-controller/internal/auth"
	"github.com/ai-workspace-services/xconnect-controller/internal/overlay"
)

type Server struct {
	Overlay  *overlay.Service
	Verifier *auth.Verifier
	DBHealth func(context.Context) error
}

func NewRouter(s Server) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	RegisterRoutes(r, s)
	return r
}

func RegisterRoutes(r *gin.Engine, s Server) {
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	r.GET("/readyz", func(c *gin.Context) {
		if s.DBHealth == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "database": "not_configured"})
			return
		}
		probeCtx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := s.DBHealth(probeCtx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "database": "unavailable"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready", "database": "ok"})
	})

	if s.Overlay == nil {
		return
	}

	h := overlay.NewHTTPHandler(s.Overlay)
	v1 := r.Group("/api/overlay/v1")
	v1.POST("/registrations", h.Register)
	v1.POST("/registrations/:registrationID/exchange", h.RegistrationExchange)
	v1.POST("/join-tokens/exchange", h.Exchange)
	v1.POST("/device/session", h.MintSession)
	v1.GET("/enrollment/signed-config", h.EnrollmentConfig)
	v1.GET("/gateway/signed-config", h.GatewayConfig)
	v1.POST("/enrollment/signed-config/:generation/ack", h.AckEnrollment)
	v1.GET("/enrollment/policy-artifacts/:generation/:digest", h.PolicyArtifact)

	if s.Verifier != nil {
		userGroup := r.Group("/api/overlay/v1")
		userGroup.Use(s.Verifier.AuthMiddleware())
		userGroup.GET("/signing-keys", h.SigningKeys)
		userGroup.GET("/gateways", func(c *gin.Context) {
			userID := auth.GetUserID(c)
			if userID == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "user authentication required"})
				return
			}
			h.UserGateways(c, userID)
		})
		userGroup.POST("/devices/enroll", func(c *gin.Context) {
			userID := auth.GetUserID(c)
			if userID == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "user authentication required"})
				return
			}
			h.UserEnrollDevice(c, userID)
		})
		userGroup.GET("/signed-config", func(c *gin.Context) {
			userID := auth.GetUserID(c)
			if userID == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "user authentication required"})
				return
			}
			h.UserConfig(c, userID)
		})
		userGroup.POST("/signed-config/:generation/ack", func(c *gin.Context) {
			userID := auth.GetUserID(c)
			if userID == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "user authentication required"})
				return
			}
			h.AckUser(c, userID)
		})

		admin := r.Group("/api/overlay/v1/admin")
		admin.Use(s.Verifier.AuthMiddleware())
		admin.GET("/overview", s.adminOverview)
		admin.GET("/telemetry", s.adminTelemetry)
		admin.GET("/networks", s.adminNetworks)
		admin.DELETE("/networks/:networkID", s.adminDeleteNetwork)
		admin.PUT("/networks/:networkID/mode", s.adminUpdateNetworkMode)
		admin.GET("/networks/:networkID/members", s.adminNetworkMembers)
		admin.POST("/networks/:networkID/members", s.adminBindNetworkMember)
		admin.DELETE("/networks/:networkID/members/:userID", s.adminRemoveNetworkMember)
		admin.GET("/devices", s.adminDevices)
		admin.GET("/invites", s.adminInvites)
		admin.POST("/invites", s.adminCreateInvite)
		admin.GET("/registrations", s.adminRegistrations)
		admin.POST("/registrations/:registrationID/approve", s.adminApproveRegistration)
		admin.POST("/registrations/:registrationID/reject", s.adminRejectRegistration)
		admin.GET("/networks/:networkID/policy", s.adminPolicy)
		admin.PUT("/networks/:networkID/policy", s.adminUpdatePolicy)
		admin.POST("/networks/:networkID/policy/explain", s.adminExplainPolicy)
		admin.POST("/networks/bootstrap", s.adminBootstrap)
		admin.POST("/devices/:deviceID/revoke", s.adminRevokeDevice)

		internal := r.Group("/api/internal/overlay")
		internal.Use(s.Verifier.InternalAuthMiddleware())
		internal.POST("/networks/bootstrap", s.internalBootstrap)
		internal.POST("/gateways/reconcile-stable-owner", s.internalReconcileStableGateway)
	}
}

type adminBootstrapRequest struct {
	ControllerURL string `json:"controller_url"`
	Network       struct {
		ID                      string `json:"id"`
		DisplayName             string `json:"display_name"`
		CIDR                    string `json:"cidr"`
		GatewayID               string `json:"gateway_id"`
		GatewayWireGuardKey     string `json:"gateway_wireguard_public_key"`
		GatewayWireGuardAddress string `json:"gateway_wireguard_address"`
		GatewayEndpointHost     string `json:"gateway_endpoint_host"`
		GatewayEndpointPort     int    `json:"gateway_endpoint_port"`
		TransportServerName     string `json:"transport_server_name"`
		TransportPort           int    `json:"transport_port"`
		TransportAuthID         string `json:"transport_auth_id"`
		TransportKind           string `json:"transport_kind"`
		TransportPath           string `json:"transport_path"`
		TransportMode           string `json:"transport_mode"`
		TransportHost           string `json:"transport_host"`
		GatewayFrontend         string `json:"gateway_frontend"`
		GatewayListenSocket     string `json:"gateway_listen_socket"`
	} `json:"network"`
	Invite struct {
		DeviceID string    `json:"device_id"`
		Platform string    `json:"platform"`
		Role     string    `json:"role"`
		Expires  time.Time `json:"expires_at"`
	} `json:"invite"`
}

type internalBootstrapRequest struct {
	OwnerEmail string                `json:"owner_email"`
	Bootstrap  adminBootstrapRequest `json:"bootstrap"`
}

type internalStableGatewayReconcileRequest struct {
	Environment         string `json:"environment"`
	NetworkID           string `json:"network_id"`
	GatewayID           string `json:"gateway_id"`
	GatewayEndpointHost string `json:"gateway_endpoint_host"`
	OwnerEmail          string `json:"owner_email"`
}

type adminDeleteNetworkRequest struct {
	ConfirmNetworkID string `json:"confirm_network_id"`
}

type adminUpdateNetworkModeRequest struct {
	ConnectionMode string `json:"connection_mode"`
	Mode           string `json:"mode"`
}

type adminBindNetworkMemberRequest struct {
	Email  string `json:"email"`
	UserID string `json:"user_id"`
}

func adminContext(c *gin.Context, info *auth.UserInfo) context.Context {
	ctx := c.Request.Context()
	if info != nil && auth.IsRootRole(info.Role) {
		return overlay.WithRootAdmin(ctx)
	}
	return ctx
}

func (s Server) adminOverview(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroRead)
	if !ok {
		return
	}
	value, err := s.Overlay.AdminOverview(adminContext(c, info), auth.GetUserID(c))
	if err != nil {
		respondError(c, http.StatusInternalServerError, "overlay_admin_read_failed", "failed to load XConnect Zero overview")
		return
	}
	c.JSON(http.StatusOK, value)
}

func (s Server) adminTelemetry(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroRead)
	if !ok {
		return
	}
	value, err := s.Overlay.AdminTelemetry(adminContext(c, info), auth.GetUserID(c))
	if err != nil {
		respondError(c, http.StatusInternalServerError, "overlay_admin_read_failed", "failed to load XConnect Zero telemetry")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, value)
}

func (s Server) adminNetworks(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroRead)
	if !ok {
		return
	}
	value, err := s.Overlay.AdminNetworks(adminContext(c, info), auth.GetUserID(c))
	if err != nil {
		respondError(c, http.StatusInternalServerError, "overlay_admin_read_failed", "failed to load XConnect Zero networks")
		return
	}
	c.JSON(http.StatusOK, gin.H{"networks": value})
}

func (s Server) adminDeleteNetwork(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroManage)
	if !ok {
		return
	}
	var req adminDeleteNetworkRequest
	if !decodeStrictJSON(c, &req, 4096) || strings.TrimSpace(req.ConfirmNetworkID) != strings.TrimSpace(c.Param("networkID")) {
		respondError(c, http.StatusBadRequest, "network_confirmation_required", "confirm_network_id must exactly match the network ID")
		return
	}
	if err := s.Overlay.AdminDeleteNetwork(adminContext(c, info), auth.GetUserID(c), c.Param("networkID")); err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (s Server) adminUpdateNetworkMode(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroManage)
	if !ok {
		return
	}
	var req adminUpdateNetworkModeRequest
	if !decodeStrictJSON(c, &req, 64*1024) {
		return
	}
	mode := strings.TrimSpace(req.ConnectionMode)
	alt := strings.TrimSpace(req.Mode)
	if mode != "" && alt != "" && mode != alt {
		respondError(c, http.StatusBadRequest, "invalid_request", "conflicting XConnect Zero connection mode fields")
		return
	}
	if mode == "" {
		mode = alt
	}
	value, err := s.Overlay.AdminUpdateNetworkMode(adminContext(c, info), auth.GetUserID(c), c.Param("networkID"), mode)
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, value)
}

func (s Server) adminNetworkMembers(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroRead)
	if !ok {
		return
	}
	members, err := s.Overlay.AdminNetworkMembers(adminContext(c, info), auth.GetUserID(c), c.Param("networkID"))
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"members": members})
}

func (s Server) adminBindNetworkMember(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroManage)
	if !ok {
		return
	}
	var req adminBindNetworkMemberRequest
	if !decodeStrictJSON(c, &req, 64*1024) {
		return
	}
	targetUserID := strings.TrimSpace(req.UserID)
	targetEmail := strings.TrimSpace(req.Email)
	if targetUserID == "" && targetEmail == "" {
		respondError(c, http.StatusBadRequest, "invalid_request", "email or user_id is required")
		return
	}
	if targetUserID == "" && targetEmail != "" {
		user, err := s.Verifier.LookupUserByEmail(c.Request.Context(), targetEmail)
		if err != nil || user == nil {
			respondError(c, http.StatusNotFound, "user_not_found", "target user was not found")
			return
		}
		targetUserID = user.ID
		targetEmail = user.Email
	}
	member, err := s.Overlay.AdminBindNetworkMember(adminContext(c, info), auth.GetUserID(c), c.Param("networkID"), targetUserID, targetEmail)
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"member": member})
}

func (s Server) adminRemoveNetworkMember(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroManage)
	if !ok {
		return
	}
	networkID := strings.TrimSpace(c.Param("networkID"))
	targetUserID := strings.TrimSpace(c.Param("userID"))
	if err := s.Overlay.AdminRemoveNetworkMember(adminContext(c, info), auth.GetUserID(c), networkID, targetUserID); err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"deleted": true, "network_id": networkID, "user_id": targetUserID})
}

func (s Server) adminDevices(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroRead)
	if !ok {
		return
	}
	value, err := s.Overlay.AdminDevices(adminContext(c, info), auth.GetUserID(c))
	if err != nil {
		respondError(c, http.StatusInternalServerError, "overlay_admin_read_failed", "failed to load XConnect Zero devices")
		return
	}
	c.JSON(http.StatusOK, gin.H{"devices": value})
}

func (s Server) adminInvites(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroRead)
	if !ok {
		return
	}
	value, err := s.Overlay.AdminInvites(adminContext(c, info), auth.GetUserID(c))
	if err != nil {
		respondError(c, http.StatusInternalServerError, "overlay_admin_read_failed", "failed to load XConnect Zero invites")
		return
	}
	c.JSON(http.StatusOK, gin.H{"invites": value})
}

func (s Server) adminCreateInvite(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroManage)
	if !ok {
		return
	}
	var req overlay.AdminInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid_request", "invalid XConnect Zero invitation request")
		return
	}
	result, err := s.Overlay.AdminCreateInvite(adminContext(c, info), auth.GetUserID(c), req.ControllerURL, req)
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, result)
}

func (s Server) adminRegistrations(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroManage)
	if !ok {
		return
	}
	registrations, err := s.Overlay.AdminRegistrations(adminContext(c, info), auth.GetUserID(c), c.Query("cursor"))
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, registrations)
}

func (s Server) adminApproveRegistration(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroManage)
	if !ok {
		return
	}
	var req overlay.ApproveRegistrationRequest
	if !decodeStrictJSON(c, &req, 64*1024) {
		return
	}
	reg, err := s.Overlay.AdminApproveRegistration(adminContext(c, info), auth.GetUserID(c), c.Param("registrationID"), req.NetworkID)
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"registration": reg})
}

func (s Server) adminRejectRegistration(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroManage)
	if !ok {
		return
	}
	if c.Request.ContentLength != 0 {
		respondError(c, http.StatusBadRequest, "invalid_request", "XConnect Zero registration rejection does not accept a request body")
		return
	}
	reg, err := s.Overlay.AdminRejectRegistration(adminContext(c, info), auth.GetUserID(c), c.Param("registrationID"))
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"registration": reg})
}

func (s Server) adminPolicy(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroRead)
	if !ok {
		return
	}
	value, err := s.Overlay.AdminPolicy(adminContext(c, info), auth.GetUserID(c), c.Param("networkID"))
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.JSON(http.StatusOK, value)
}

func (s Server) adminExplainPolicy(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroRead)
	if !ok {
		return
	}
	var req overlay.PolicyExplainRequest
	if !decodeStrictJSON(c, &req, 64*1024) {
		return
	}
	value, err := s.Overlay.AdminExplainPolicy(adminContext(c, info), auth.GetUserID(c), c.Param("networkID"), req)
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, value)
}

func (s Server) adminUpdatePolicy(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroManage)
	if !ok {
		return
	}
	var policy overlay.PolicyArtifact
	if !decodeStrictJSON(c, &policy, 512*1024) {
		return
	}
	value, err := s.Overlay.AdminUpdatePolicy(adminContext(c, info), auth.GetUserID(c), strings.TrimSpace(c.Param("networkID")), policy)
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, value)
}

func (s Server) adminBootstrap(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroManage)
	if !ok {
		return
	}
	var req adminBootstrapRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "invalid_request", "invalid XConnect Zero bootstrap request")
		return
	}
	result, err := s.Overlay.AdminBootstrap(adminContext(c, info), toBootstrapConfig(req, auth.GetUserID(c)), req.ControllerURL, "")
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.JSON(http.StatusCreated, result)
}

func (s Server) adminRevokeDevice(c *gin.Context) {
	info, ok := s.Verifier.AuthorizeZeroAccess(c, auth.PermissionXConnectZeroManage)
	if !ok {
		return
	}
	if err := s.Overlay.AdminRevokeDevice(adminContext(c, info), auth.GetUserID(c), c.Param("deviceID")); err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (s Server) internalBootstrap(c *gin.Context) {
	var req internalBootstrapRequest
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.OwnerEmail) == "" {
		respondError(c, http.StatusBadRequest, "invalid_request", "invalid XConnect Zero automation request")
		return
	}
	owner, err := s.Verifier.LookupUserByEmail(c.Request.Context(), req.OwnerEmail)
	if err != nil || owner == nil || !owner.Active {
		respondError(c, http.StatusNotFound, "owner_not_found", "active XConnect Zero owner was not found")
		return
	}
	result, err := s.Overlay.AdminBootstrap(c.Request.Context(), toBootstrapConfig(req.Bootstrap, owner.ID), req.Bootstrap.ControllerURL, "")
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, result)
}

func (s Server) internalReconcileStableGateway(c *gin.Context) {
	var req internalStableGatewayReconcileRequest
	if !decodeStrictJSON(c, &req, 64*1024) {
		return
	}
	if strings.TrimSpace(req.OwnerEmail) == "" {
		respondError(c, http.StatusBadRequest, "invalid_request", "owner_email is required for XConnect Zero reconciliation")
		return
	}
	owner, err := s.Verifier.LookupUserByEmail(c.Request.Context(), req.OwnerEmail)
	if err != nil || owner == nil || !owner.Active {
		respondError(c, http.StatusNotFound, "owner_not_found", "active XConnect Zero owner was not found")
		return
	}
	result, err := s.Overlay.ReconcileStableGateway(c.Request.Context(), overlay.StableGatewayReconcileRequest{
		Environment: req.Environment, NetworkID: req.NetworkID, GatewayID: req.GatewayID,
		GatewayEndpointHost: req.GatewayEndpointHost, OwnerUserID: owner.ID,
	})
	if err != nil {
		respondOverlayAdminError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, result)
}

func toBootstrapConfig(request adminBootstrapRequest, ownerUserID string) overlay.BootstrapConfig {
	return overlay.BootstrapConfig{
		Network: overlay.BootstrapNetwork{
			ID: request.Network.ID, DisplayName: request.Network.DisplayName, CIDR: request.Network.CIDR,
			GatewayID: request.Network.GatewayID, GatewayWireGuardKey: request.Network.GatewayWireGuardKey,
			GatewayWireGuardAddress: request.Network.GatewayWireGuardAddress,
			GatewayEndpointHost:     request.Network.GatewayEndpointHost, GatewayEndpointPort: request.Network.GatewayEndpointPort,
			TransportServerName: request.Network.TransportServerName, TransportPort: request.Network.TransportPort,
			TransportAuthID: request.Network.TransportAuthID, TransportKind: request.Network.TransportKind,
			TransportPath: request.Network.TransportPath, TransportMode: request.Network.TransportMode,
			TransportHost: request.Network.TransportHost, GatewayFrontend: request.Network.GatewayFrontend,
			GatewayListenSocket: request.Network.GatewayListenSocket, OwnerUserID: ownerUserID,
		},
		Invite: overlay.BootstrapInvite{
			DeviceID: request.Invite.DeviceID, Platform: request.Invite.Platform,
			Role: request.Invite.Role, ExpiresAt: request.Invite.Expires,
		},
	}
}

func decodeStrictJSON(c *gin.Context, target any, limit int64) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		respondError(c, http.StatusBadRequest, "invalid_request", "invalid JSON request body")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		respondError(c, http.StatusBadRequest, "invalid_request", "invalid JSON request body")
		return false
	}
	return true
}

func respondError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"error": code, "message": message})
}

func respondOverlayAdminError(c *gin.Context, err error) {
	status := http.StatusInternalServerError
	code := "overlay_admin_failed"
	message := "XConnect Zero operation failed"
	switch {
	case errors.Is(err, overlay.ErrNotFound):
		status, code, message = http.StatusNotFound, "not_found", "XConnect Zero resource not found"
	case errors.Is(err, overlay.ErrInvalidInput):
		status, code, message = http.StatusBadRequest, "invalid_request", "invalid XConnect Zero resource"
	case errors.Is(err, overlay.ErrRegistrationExpired):
		status, code, message = http.StatusGone, "registration_expired", "XConnect One registration expired"
	case errors.Is(err, overlay.ErrRegistrationNotPending):
		status, code, message = http.StatusConflict, "registration_not_pending", "XConnect One registration is stale"
	case errors.Is(err, overlay.ErrRegistrationRejected):
		status, code, message = http.StatusConflict, "registration_rejected", "XConnect One registration was rejected"
	case errors.Is(err, overlay.ErrRegistrationConsumed):
		status, code, message = http.StatusConflict, "registration_consumed", "XConnect One registration was already consumed"
	case errors.Is(err, overlay.ErrForbidden):
		status, code, message = http.StatusForbidden, "forbidden", "XConnect Zero resource belongs to another user"
	case errors.Is(err, overlay.ErrConflict):
		status, code, message = http.StatusConflict, "conflict", "XConnect Zero stable Gateway identity is ambiguous"
	}
	respondError(c, status, code, message)
}

var _ = url.QueryEscape
