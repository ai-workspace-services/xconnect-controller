package contracts_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/ai-workspace-services/xconnect-controller/internal/overlay"
)

var updateGolden = flag.Bool("update", false, "regenerate golden-vectors.json")

type GoldenVectors struct {
	SchemaVersion int                    `json:"schema_version"`
	KeyID         string                 `json:"key_id"`
	SeedBase64    string                 `json:"seed_base64"`
	PublicKeyB64  string                 `json:"public_key_base64"`
	Policy        GoldenPolicyVector     `json:"policy"`
	ClientV1      GoldenClientVector     `json:"client_v1"`
	ClientV2      GoldenClientVector     `json:"client_v2"`
	GatewayV1     GoldenGatewayVector    `json:"gateway_v1"`
	GatewayV2     GoldenGatewayVector    `json:"gateway_v2"`
}

type GoldenPolicyVector struct {
	Artifact      overlay.PolicyArtifact `json:"artifact"`
	CanonicalJSON string                 `json:"canonical_json"`
	SHA256Digest  string                 `json:"sha256_digest"`
}

type GoldenClientVector struct {
	Config          overlay.SignedConfig `json:"config"`
	SigningBytes    string               `json:"signing_bytes"`
	SignatureBase64 string               `json:"signature_base64"`
}

type GoldenGatewayVector struct {
	Config          overlay.GatewaySignedConfig `json:"config"`
	SigningBytes    string                      `json:"signing_bytes"`
	SignatureBase64 string                      `json:"signature_base64"`
}

func buildGoldenVectors(t *testing.T) GoldenVectors {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	keyID := "zero-signing-golden-v1"

	issuedAt := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.Add(10 * time.Minute)

	policy := overlay.PolicyArtifact{
		SchemaVersion:   1,
		CompilerVersion: overlay.PolicyCompilerVersion,
		NetworkID:       "net-golden-01",
		Revision:        24,
		DefaultAction:   "deny",
		ProtectedFlows: []string{
			"control:controller-session",
			"control:gateway-apply-result",
			"control:gateway-heartbeat",
			"control:gateway-policy-artifact",
			"control:gateway-snapshot",
		},
		Rules: []overlay.PolicyRule{},
	}
	policyBytes, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	policySum := sha256.Sum256(policyBytes)
	policyDigest := hex.EncodeToString(policySum[:])

	baseTransport := overlay.Transport{
		Kind:     overlay.TransportVLESSXHTTP,
		Loopback: overlay.Endpoint{Host: "127.0.0.1", Port: 51830},
		Remote:   overlay.RemoteEndpoint{Host: "gw.example.test", Port: 443, ServerName: "gw.example.test"},
		AuthID:   "11111111-1111-1111-1111-111111111111",
		Path:     "/xconnect",
		Mode:     "auto",
		Host:     "gw.example.test",
	}
	baseWG := overlay.WireGuard{
		InterfaceName: "xconone0",
		Addresses:     []string{"10.67.0.4/32"},
		MTU:           1420,
		Peers: []overlay.WireGuardPeer{{
			GatewayID:                  "gw-golden-01",
			PublicKey:                  "Boqlv/riwPRycrqAGN/0j/TdUWqoI/qh770Q8UvDc0c=",
			AllowedIPs:                 []string{"10.67.0.0/16"},
			Endpoint:                   overlay.Endpoint{Host: "127.0.0.1", Port: 51830},
			PersistentKeepaliveSeconds: 12,
		}},
	}

	c1 := overlay.SignedConfig{
		SchemaVersion: 1,
		ConfigID:      "cfg_golden_c1",
		NetworkID:     "net-golden-01",
		DeviceID:      "one-golden-01",
		Generation:    24,
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
		ProxyCore:     "xray",
		Transport:     baseTransport,
		WireGuard:     baseWG,
	}
	c1Bytes, err := overlay.SigningBytes(c1)
	if err != nil {
		t.Fatal(err)
	}
	c1Sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, c1Bytes))
	c1.Signature = overlay.Signature{Algorithm: "Ed25519", KeyID: keyID, Value: c1Sig}

	c2 := c1
	c2.SchemaVersion = 2
	c2.ConfigID = "cfg_golden_c2"
	c2.Policy = &overlay.PolicyReference{
		Generation: 24,
		Digest:     policyDigest,
		Path:       "/api/overlay/v1/enrollment/policy-artifacts/24/" + policyDigest,
		MediaType:  overlay.PolicyMediaType,
	}
	c2Bytes, err := overlay.SigningBytes(c2)
	if err != nil {
		t.Fatal(err)
	}
	c2Sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, c2Bytes))
	c2.Signature = overlay.Signature{Algorithm: "Ed25519", KeyID: keyID, Value: c2Sig}

	gwTransport := overlay.GatewayTransport{
		Kind:         overlay.TransportVLESSXHTTP,
		ServerName:   "gw.example.test",
		Port:         443,
		AuthID:       "11111111-1111-1111-1111-111111111111",
		Path:         "/xconnect",
		Mode:         "auto",
		Host:         "gw.example.test",
		Frontend:     overlay.GatewayFrontendCaddyUnixH2C,
		ListenSocket: overlay.DefaultGatewayListenSocket,
	}
	gwPeers := []overlay.GatewayPeer{{
		DeviceID:           "one-golden-01",
		WireGuardPublicKey: "csgLIZEh0jQqa9kIA5ujhgfZ+W9Wnox5gAoMBUsacW0=",
		WireGuardAddress:   "10.67.0.4/32",
		AllowedIPs:         "10.67.0.4/32",
	}}
	g1 := overlay.GatewaySignedConfig{
		SchemaVersion:  1,
		Role:           overlay.RoleGateway,
		ConfigID:       "cfg_golden_g1",
		NetworkID:      "net-golden-01",
		GatewayID:      "gw-golden-01",
		Generation:     24,
		IssuedAt:       issuedAt,
		ExpiresAt:      expiresAt,
		ConnectionMode: overlay.ConnectionModeWGVLESSL3,
		InterfaceName:  "xconzero0",
		Address:        "10.67.0.1/32",
		ListenPort:     51820,
		MTU:            1420,
		Peers:          gwPeers,
		Transport:      gwTransport,
	}
	g1Bytes, err := overlay.GatewaySigningBytes(g1)
	if err != nil {
		t.Fatal(err)
	}
	g1Sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, g1Bytes))
	g1.Signature = overlay.Signature{Algorithm: "Ed25519", KeyID: keyID, Value: g1Sig}

	gwPolicy := policy
	gwPolicy.Rules = []overlay.PolicyRule{{
		ID:                 "allow-ssh",
		Action:             "allow",
		SourceDevices:      []string{"one-golden-01"},
		DestinationDevices: []string{"*"},
		Protocols:          []string{"tcp"},
		Ports:              []int{22},
	}}
	g2 := g1
	g2.SchemaVersion = 2
	g2.ConfigID = "cfg_golden_g2"
	g2.Policy = &gwPolicy
	g2Bytes, err := overlay.GatewaySigningBytes(g2)
	if err != nil {
		t.Fatal(err)
	}
	g2Sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, g2Bytes))
	g2.Signature = overlay.Signature{Algorithm: "Ed25519", KeyID: keyID, Value: g2Sig}

	return GoldenVectors{
		SchemaVersion: 1,
		KeyID:         keyID,
		SeedBase64:    base64.StdEncoding.EncodeToString(seed),
		PublicKeyB64:  base64.StdEncoding.EncodeToString(pub),
		Policy: GoldenPolicyVector{
			Artifact:      policy,
			CanonicalJSON: string(policyBytes),
			SHA256Digest:  policyDigest,
		},
		ClientV1:  GoldenClientVector{Config: c1, SigningBytes: string(c1Bytes), SignatureBase64: c1Sig},
		ClientV2:  GoldenClientVector{Config: c2, SigningBytes: string(c2Bytes), SignatureBase64: c2Sig},
		GatewayV1: GoldenGatewayVector{Config: g1, SigningBytes: string(g1Bytes), SignatureBase64: g1Sig},
		GatewayV2: GoldenGatewayVector{Config: g2, SigningBytes: string(g2Bytes), SignatureBase64: g2Sig},
	}
}

func TestOverlayV1GoldenVectors(t *testing.T) {
	computed := buildGoldenVectors(t)
	if *updateGolden {
		raw, err := json.MarshalIndent(computed, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("golden-vectors.json", append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}

	raw, err := os.ReadFile("golden-vectors.json")
	if err != nil {
		t.Fatalf("read golden-vectors.json: %v", err)
	}
	var expected GoldenVectors
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(expected.PublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}

	if computed.Policy.CanonicalJSON != expected.Policy.CanonicalJSON || computed.Policy.SHA256Digest != expected.Policy.SHA256Digest {
		t.Fatalf("policy golden mismatch")
	}
	for _, pair := range []struct {
		name string
		got  string
		want string
		sig  string
	}{
		{"client_v1", computed.ClientV1.SigningBytes, expected.ClientV1.SigningBytes, expected.ClientV1.SignatureBase64},
		{"client_v2", computed.ClientV2.SigningBytes, expected.ClientV2.SigningBytes, expected.ClientV2.SignatureBase64},
		{"gateway_v1", computed.GatewayV1.SigningBytes, expected.GatewayV1.SigningBytes, expected.GatewayV1.SignatureBase64},
		{"gateway_v2", computed.GatewayV2.SigningBytes, expected.GatewayV2.SigningBytes, expected.GatewayV2.SignatureBase64},
	} {
		if pair.got != pair.want {
			t.Fatalf("%s signingBytes mismatch:\ngot:  %s\nwant: %s", pair.name, pair.got, pair.want)
		}
		sigBytes, err := base64.StdEncoding.DecodeString(pair.sig)
		if err != nil || !ed25519.Verify(pub, []byte(pair.want), sigBytes) {
			t.Fatalf("%s signature failed Ed25519 verification", pair.name)
		}
	}
}
