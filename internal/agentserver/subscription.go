package agentserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ai-workspace-services/xconnect-controller/internal/agentproto"
)

// SubscriptionFormat identifies a supported subscription output format.
type SubscriptionFormat string

const (
	FormatClash   SubscriptionFormat = "clash"
	FormatSingBox SubscriptionFormat = "singbox"
	FormatXray    SubscriptionFormat = "xray"
	FormatOne     SubscriptionFormat = "one"
	FormatVLESS   SubscriptionFormat = "vless"

	vlessXHTTPScheme = "vless://${UUID}@${DOMAIN}:443?encryption=none&type=xhttp&security=tls&host=${DOMAIN}&path=${PATH}&mode=${MODE}&sni=${SNI}&fp=${FP}&alpn=h2%2Chttp%2F1.1%2Ch3#${TAG}"
	vlessTCPScheme   = "vless://${UUID}@${DOMAIN}:1443?encryption=none&type=tcp&security=tls&sni=${SNI}&fp=${FP}&flow=${FLOW}#${TAG}"
)

// ErrUnsupportedFormat is returned when a caller requests an unknown subscription format.
var ErrUnsupportedFormat = errors.New("unsupported subscription format")

// ParseSubscriptionFormat normalizes client format aliases into a canonical SubscriptionFormat.
func ParseSubscriptionFormat(raw string) (SubscriptionFormat, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "clash", "mihomo", "clash-meta", "clash.meta", "yaml":
		return FormatClash, nil
	case "singbox", "sing-box":
		return FormatSingBox, nil
	case "xray", "xray-json", "xrayjson", "v2ray":
		return FormatXray, nil
	case "one", "xconnect-one":
		return FormatOne, nil
	case "vless", "uri", "raw":
		return FormatVLESS, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedFormat, strings.TrimSpace(raw))
	}
}

// SubscriptionContentType returns the HTTP Content-Type header value for format.
func SubscriptionContentType(format SubscriptionFormat) string {
	switch format {
	case FormatClash:
		return "text/yaml; charset=utf-8"
	case FormatSingBox, FormatXray, FormatOne:
		return "application/json; charset=utf-8"
	case FormatVLESS:
		return "text/plain; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// SubscriptionNode describes an authorized proxy node available to a user.
type SubscriptionNode struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Region        string   `json:"region,omitempty"`
	Address       string   `json:"address"`
	Port          int      `json:"port"`
	UUID          string   `json:"uuid"`
	Flow          string   `json:"flow,omitempty"`
	Transport     string   `json:"transport,omitempty"`
	Path          string   `json:"path,omitempty"`
	Mode          string   `json:"mode,omitempty"`
	Security      string   `json:"security,omitempty"`
	ServerName    string   `json:"serverName,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	ResourceClass string   `json:"resourceClass,omitempty"`
	RoutingPool   string   `json:"routingPool,omitempty"`
	PricingGroup  string   `json:"pricingGroup,omitempty"`
	SubPoolTags   []string `json:"subPoolTags,omitempty"`
	VlessURI      string   `json:"vlessUri,omitempty"`
}

// RouteRule describes one tier of the canonical three-tier split routing policy.
type RouteRule struct {
	Priority         int      `json:"priority"`
	Name             string   `json:"name"`
	Target           string   `json:"target"`
	EffectiveTarget  string   `json:"effective_target"`
	MediaOnProAction string   `json:"media_on_pro_action,omitempty"`
	Domains          []string `json:"domains,omitempty"`
	IPs              []string `json:"ips,omitempty"`
	ClashRules       []string `json:"clash_rules,omitempty"`
}

// SubscriptionRenderInput holds user-scoped nodes and routing policy inputs.
type SubscriptionRenderInput struct {
	UserID      string
	UserEmail   string
	AllowCustom bool
	AllowPro    bool
	Policy      RoutingPolicyConfig
	Nodes       []SubscriptionNode
	GeneratedAt time.Time
}

// RenderSubscription builds a subscription document in the requested format.
func RenderSubscription(format SubscriptionFormat, input SubscriptionRenderInput) ([]byte, string, error) {
	policy := normalizePolicy(input.Policy)
	partitioned := partitionNodes(input, policy)

	var (
		data []byte
		err  error
	)
	switch format {
	case FormatClash:
		data, err = renderClash(partitioned, policy)
	case FormatSingBox:
		data, err = renderSingBox(partitioned, policy)
	case FormatXray:
		data, err = renderXray(partitioned, policy)
	case FormatOne:
		data, err = renderOne(input, partitioned, policy)
	case FormatVLESS:
		data, err = renderVLESS(partitioned)
	default:
		return nil, "", fmt.Errorf("%w: %s", ErrUnsupportedFormat, format)
	}
	if err != nil {
		return nil, "", err
	}
	return data, SubscriptionContentType(format), nil
}

// BuildThreeTierRoutes returns the canonical three-tier routing ruleset for One and /sync/config.
func BuildThreeTierRoutes(policy RoutingPolicyConfig, hasMedia, hasPro, hasCustom bool) []RouteRule {
	policy = normalizePolicy(policy)
	fallbackTarget := defaultFallbackTarget(hasMedia, hasCustom)
	proTarget := fallbackTarget
	if hasPro {
		proTarget = RoutingPoolProEC2
	}

	directIPs := make([]string, 0, 1+len(policy.Tiers.DirectCNPrivate.XrayIPs))
	directIPs = append(directIPs, "geoip:private")
	directIPs = append(directIPs, policy.Tiers.DirectCNPrivate.XrayIPs...)

	return []RouteRule{
		{
			Priority:        policy.Tiers.DirectCNPrivate.Priority,
			Name:            "direct_cn_private",
			Target:          policy.Tiers.DirectCNPrivate.Target,
			EffectiveTarget: TierTargetDirect,
			Domains:         append([]string(nil), policy.Tiers.DirectCNPrivate.XrayDomains...),
			IPs:             directIPs,
			ClashRules:      append([]string(nil), policy.Tiers.DirectCNPrivate.ClashRules...),
		},
		{
			Priority:         policy.Tiers.MediaPoolPriority.Priority,
			Name:             "media_pool_priority",
			Target:           policy.Tiers.MediaPoolPriority.Target,
			EffectiveTarget:  fallbackTarget,
			MediaOnProAction: policy.MediaOnProActionFor(RoutingPoolMediaPriority),
			Domains:          append([]string(nil), policy.Tiers.MediaPoolPriority.XrayDomains...),
			ClashRules:       rewriteClashRules(policy.Tiers.MediaPoolPriority.ClashRules, RoutingPoolMediaPriority, fallbackTarget),
		},
		{
			Priority:         policy.Tiers.ProEC2Whitelist.Priority,
			Name:             "pro_ec2_whitelist",
			Target:           policy.Tiers.ProEC2Whitelist.Target,
			EffectiveTarget:  proTarget,
			MediaOnProAction: policy.MediaOnProActionFor(RoutingPoolProEC2),
			Domains:          append([]string(nil), policy.Tiers.ProEC2Whitelist.XrayDomains...),
			ClashRules:       rewriteClashRules(policy.Tiers.ProEC2Whitelist.ClashRules, RoutingPoolProEC2, proTarget),
		},
		{
			Priority:        policy.Tiers.GlobalFallback.Priority,
			Name:            "global_fallback",
			Target:          policy.Tiers.GlobalFallback.Target,
			EffectiveTarget: fallbackTarget,
			ClashRules:      rewriteClashRules(policy.Tiers.GlobalFallback.ClashRules, RoutingPoolMediaPriority, fallbackTarget),
		},
	}
}

// BuildVLESSURI returns a standard vless:// URI without policy metadata embedded.
func BuildVLESSURI(node SubscriptionNode) string {
	if clean := strings.TrimSpace(node.VlessURI); clean != "" {
		return clean
	}
	port := node.Port
	if port <= 0 {
		port = 443
	}
	transport := strings.ToLower(strings.TrimSpace(node.Transport))
	if transport == "" {
		transport = "xhttp"
	}
	sni := strings.TrimSpace(node.ServerName)
	if sni == "" {
		sni = strings.TrimSpace(node.Address)
	}
	fp := strings.TrimSpace(node.Fingerprint)
	if fp == "" {
		fp = "chrome"
	}
	tag := strings.TrimSpace(node.Name)
	if tag == "" {
		tag = strings.TrimSpace(node.Address)
	}

	if transport == "tcp" {
		flow := strings.TrimSpace(node.Flow)
		if flow == "" {
			flow = agentproto.DefaultFlow
		}
		return fmt.Sprintf(
			"vless://%s@%s:%s?encryption=none&type=tcp&security=tls&sni=%s&fp=%s&flow=%s#%s",
			strings.TrimSpace(node.UUID),
			strings.TrimSpace(node.Address),
			strconv.Itoa(port),
			url.QueryEscape(sni),
			url.QueryEscape(fp),
			url.QueryEscape(flow),
			url.QueryEscape(tag),
		)
	}

	path := strings.TrimSpace(node.Path)
	if path == "" {
		path = "/split"
	}
	mode := strings.TrimSpace(node.Mode)
	if mode == "" {
		mode = "auto"
	}
	return fmt.Sprintf(
		"vless://%s@%s:%s?encryption=none&type=xhttp&security=tls&host=%s&path=%s&mode=%s&sni=%s&fp=%s&alpn=h2%%2Chttp%%2F1.1%%2Ch3#%s",
		strings.TrimSpace(node.UUID),
		strings.TrimSpace(node.Address),
		strconv.Itoa(port),
		url.QueryEscape(strings.TrimSpace(node.Address)),
		url.QueryEscape(path),
		url.QueryEscape(mode),
		url.QueryEscape(sni),
		url.QueryEscape(fp),
		url.QueryEscape(tag),
	)
}

type nodeBuckets struct {
	all    []SubscriptionNode
	media  []SubscriptionNode
	pro    []SubscriptionNode
	custom []SubscriptionNode
}

func normalizePolicy(p RoutingPolicyConfig) RoutingPolicyConfig {
	if p.Version == 0 && len(p.Pools) == 0 {
		return DefaultRoutingPolicy()
	}
	return p
}

func resolveNodeRoutingPool(node SubscriptionNode, policy RoutingPolicyConfig) string {
	pool := strings.TrimSpace(node.RoutingPool)
	if pool == RoutingPoolMediaPriority ||
		pool == RoutingPoolProEC2 ||
		pool == RoutingPoolCustomDedicated {
		return pool
	}
	return policy.PoolForResourceClass(node.ResourceClass)
}

func partitionNodes(input SubscriptionRenderInput, policy RoutingPolicyConfig) nodeBuckets {
	var out nodeBuckets
	usedNames := make(map[string]int, len(input.Nodes))
	for _, node := range input.Nodes {
		pool := resolveNodeRoutingPool(node, policy)
		if pool == RoutingPoolCustomDedicated && !input.AllowCustom {
			continue
		}
		if pool == RoutingPoolProEC2 && !input.AllowPro {
			continue
		}
		node.RoutingPool = pool
		if node.Port <= 0 {
			node.Port = 443
		}
		if strings.TrimSpace(node.Transport) == "" {
			node.Transport = "xhttp"
		}
		if strings.TrimSpace(node.Security) == "" {
			node.Security = "tls"
		}
		if strings.TrimSpace(node.ServerName) == "" {
			node.ServerName = node.Address
		}
		if strings.TrimSpace(node.Fingerprint) == "" {
			node.Fingerprint = "chrome"
		}
		if strings.TrimSpace(node.Name) == "" {
			node.Name = node.Address
		}
		usedNames[node.Name]++
		if usedNames[node.Name] > 1 {
			node.Name = fmt.Sprintf("%s-%d", node.Name, usedNames[node.Name])
		}
		node.VlessURI = BuildVLESSURI(node)

		out.all = append(out.all, node)
		switch pool {
		case RoutingPoolProEC2:
			out.pro = append(out.pro, node)
		case RoutingPoolCustomDedicated:
			out.custom = append(out.custom, node)
		default:
			out.media = append(out.media, node)
		}
	}
	return out
}

func defaultFallbackTarget(hasMedia, hasCustom bool) string {
	if hasMedia {
		return RoutingPoolMediaPriority
	}
	if hasCustom {
		return RoutingPoolCustomDedicated
	}
	return TierTargetDirect
}

func rewriteClashRules(rules []string, fromTarget, toTarget string) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		if fromTarget != toTarget {
			parts := strings.Split(rule, ",")
			if len(parts) >= 2 && parts[len(parts)-1] == fromTarget {
				parts[len(parts)-1] = toTarget
				rule = strings.Join(parts, ",")
			} else if len(parts) >= 3 && parts[len(parts)-2] == fromTarget {
				parts[len(parts)-2] = toTarget
				rule = strings.Join(parts, ",")
			}
		}
		out = append(out, rule)
	}
	return out
}

type clashConfig struct {
	Port        int              `yaml:"port"`
	SocksPort   int              `yaml:"socks-port"`
	AllowLan    bool             `yaml:"allow-lan"`
	Mode        string           `yaml:"mode"`
	LogLevel    string           `yaml:"log-level"`
	Proxies     []map[string]any `yaml:"proxies"`
	ProxyGroups []map[string]any `yaml:"proxy-groups"`
	Rules       []string         `yaml:"rules"`
}

func renderClash(b nodeBuckets, policy RoutingPolicyConfig) ([]byte, error) {
	proxies := make([]map[string]any, 0, len(b.all))
	for _, node := range b.all {
		entry := map[string]any{
			"name":               node.Name,
			"type":               "vless",
			"server":             node.Address,
			"port":               node.Port,
			"uuid":               node.UUID,
			"tls":                true,
			"servername":         node.ServerName,
			"client-fingerprint": node.Fingerprint,
			"udp":                true,
			"skip-cert-verify":   false,
		}
		transport := strings.ToLower(strings.TrimSpace(node.Transport))
		if transport == "tcp" {
			entry["network"] = "tcp"
			if strings.TrimSpace(node.Flow) != "" {
				entry["flow"] = node.Flow
			}
		} else {
			entry["network"] = "xhttp"
			path := strings.TrimSpace(node.Path)
			if path == "" {
				path = "/split"
			}
			mode := strings.TrimSpace(node.Mode)
			if mode == "" {
				mode = "auto"
			}
			entry["xhttp-opts"] = map[string]any{
				"path": path,
				"mode": mode,
			}
		}
		if len(node.ALPN) > 0 {
			entry["alpn"] = node.ALPN
		}
		proxies = append(proxies, entry)
	}

	mediaNames := nodeNames(b.media)
	proNames := nodeNames(b.pro)
	customNames := nodeNames(b.custom)

	groups := make([]map[string]any, 0, 4)
	if len(mediaNames) > 0 {
		urlTestURL, interval := urlTestSettings(policy, RoutingPoolMediaPriority, 300)
		groups = append(groups, map[string]any{
			"name":     RoutingPoolMediaPriority,
			"type":     "url-test",
			"url":      urlTestURL,
			"interval": interval,
			"proxies":  mediaNames,
		})
	}
	if len(proNames) > 0 {
		urlTestURL, interval := urlTestSettings(policy, RoutingPoolProEC2, 180)
		groups = append(groups, map[string]any{
			"name":     RoutingPoolProEC2,
			"type":     "url-test",
			"url":      urlTestURL,
			"interval": interval,
			"proxies":  proNames,
		})
	}
	if len(customNames) > 0 {
		groups = append(groups, map[string]any{
			"name":    RoutingPoolCustomDedicated,
			"type":    "select",
			"proxies": customNames,
		})
	}
	if len(groups) > 1 {
		topChoices := make([]string, 0, len(groups)+1)
		for _, g := range groups {
			if name, _ := g["name"].(string); name != "" {
				topChoices = append(topChoices, name)
			}
		}
		topChoices = append(topChoices, TierTargetDirect)
		groups = append([]map[string]any{{
			"name":    "XConnect",
			"type":    "select",
			"proxies": topChoices,
		}}, groups...)
	}

	routes := BuildThreeTierRoutes(policy, len(mediaNames) > 0, len(proNames) > 0, len(customNames) > 0)
	rules := make([]string, 0, 32)
	for _, tier := range routes {
		rules = append(rules, tier.ClashRules...)
	}

	cfg := clashConfig{
		Port:        7890,
		SocksPort:   7891,
		AllowLan:    false,
		Mode:        "rule",
		LogLevel:    "info",
		Proxies:     proxies,
		ProxyGroups: groups,
		Rules:       rules,
	}
	return yaml.Marshal(cfg)
}

func renderSingBox(b nodeBuckets, policy RoutingPolicyConfig) ([]byte, error) {
	outbounds := make([]map[string]any, 0, len(b.all)+5)
	mediaTags := make([]string, 0, len(b.media))
	proTags := make([]string, 0, len(b.pro))
	customTags := make([]string, 0, len(b.custom))

	for _, node := range b.all {
		tag := node.Name
		outbound := map[string]any{
			"type":        "vless",
			"tag":         tag,
			"server":      node.Address,
			"server_port": node.Port,
			"uuid":        node.UUID,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": node.ServerName,
				"utls": map[string]any{
					"enabled":     true,
					"fingerprint": node.Fingerprint,
				},
			},
		}
		transport := strings.ToLower(strings.TrimSpace(node.Transport))
		if transport == "tcp" {
			if strings.TrimSpace(node.Flow) != "" {
				outbound["flow"] = node.Flow
			}
		} else {
			path := strings.TrimSpace(node.Path)
			if path == "" {
				path = "/split"
			}
			mode := strings.TrimSpace(node.Mode)
			if mode == "" {
				mode = "auto"
			}
			outbound["transport"] = map[string]any{
				"type": "xhttp",
				"host": node.Address,
				"path": path,
				"mode": mode,
			}
		}
		outbounds = append(outbounds, outbound)

		switch node.RoutingPool {
		case RoutingPoolProEC2:
			proTags = append(proTags, tag)
		case RoutingPoolCustomDedicated:
			customTags = append(customTags, tag)
		default:
			mediaTags = append(mediaTags, tag)
		}
	}

	if len(mediaTags) > 0 {
		urlTestURL, _ := urlTestSettings(policy, RoutingPoolMediaPriority, 300)
		outbounds = append(outbounds, map[string]any{
			"type":      "urltest",
			"tag":       RoutingPoolMediaPriority,
			"outbounds": mediaTags,
			"url":       urlTestURL,
			"interval":  "5m",
		})
	}
	if len(proTags) > 0 {
		urlTestURL, _ := urlTestSettings(policy, RoutingPoolProEC2, 180)
		outbounds = append(outbounds, map[string]any{
			"type":      "urltest",
			"tag":       RoutingPoolProEC2,
			"outbounds": proTags,
			"url":       urlTestURL,
			"interval":  "3m",
		})
	}
	if len(customTags) > 0 {
		outbounds = append(outbounds, map[string]any{
			"type":      "selector",
			"tag":       RoutingPoolCustomDedicated,
			"outbounds": customTags,
		})
	}

	outbounds = append(outbounds,
		map[string]any{"type": "direct", "tag": "direct"},
		map[string]any{"type": "block", "tag": "block"},
	)

	fallbackTarget := singBoxTarget(defaultFallbackTarget(len(mediaTags) > 0, len(customTags) > 0))
	proTarget := fallbackTarget
	if len(proTags) > 0 {
		proTarget = RoutingPoolProEC2
	}

	rules := []map[string]any{
		{"ip_is_private": true, "outbound": "direct"},
	}
	if cnDomains := singBoxDomainConditions(policy.Tiers.DirectCNPrivate.XrayDomains); len(cnDomains) > 0 {
		rule := cloneAnyMap(cnDomains)
		rule["outbound"] = "direct"
		rules = append(rules, rule)
	}
	if len(policy.Tiers.DirectCNPrivate.XrayIPs) > 0 {
		rules = append(rules, map[string]any{
			"geoip":    stripPrefixes(policy.Tiers.DirectCNPrivate.XrayIPs, "geoip:"),
			"outbound": "direct",
		})
	}
	if mediaRule := singBoxDomainConditions(policy.Tiers.MediaPoolPriority.XrayDomains); len(mediaRule) > 0 {
		mediaRule["outbound"] = fallbackTarget
		rules = append(rules, mediaRule)
	}
	if proRule := singBoxDomainConditions(policy.Tiers.ProEC2Whitelist.XrayDomains); len(proRule) > 0 {
		proRule["outbound"] = proTarget
		rules = append(rules, proRule)
	}

	doc := map[string]any{
		"log": map[string]any{"level": "info"},
		"inbounds": []map[string]any{
			{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
		},
		"outbounds": outbounds,
		"route": map[string]any{
			"auto_detect_interface": true,
			"rules":                 rules,
			"final":                 fallbackTarget,
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func renderXray(b nodeBuckets, policy RoutingPolicyConfig) ([]byte, error) {
	outbounds := make([]map[string]any, 0, len(b.all)+2)
	balancers := make([]map[string]any, 0, 3)

	hasMedia := len(b.media) > 0
	hasPro := len(b.pro) > 0
	hasCustom := len(b.custom) > 0

	appendNodeOutbound := func(prefix string, idx int, node SubscriptionNode) {
		tag := fmt.Sprintf("%s-%d", prefix, idx+1)
		stream := map[string]any{
			"network":  "xhttp",
			"security": "tls",
			"tlsSettings": map[string]any{
				"serverName":  node.ServerName,
				"fingerprint": node.Fingerprint,
			},
		}
		user := map[string]any{
			"id":         node.UUID,
			"encryption": "none",
		}
		if strings.ToLower(strings.TrimSpace(node.Transport)) == "tcp" {
			stream["network"] = "tcp"
			if strings.TrimSpace(node.Flow) != "" {
				user["flow"] = node.Flow
			}
		} else {
			path := strings.TrimSpace(node.Path)
			if path == "" {
				path = "/split"
			}
			mode := strings.TrimSpace(node.Mode)
			if mode == "" {
				mode = "auto"
			}
			stream["xhttpSettings"] = map[string]any{
				"host": node.Address,
				"path": path,
				"mode": mode,
			}
		}
		outbounds = append(outbounds, map[string]any{
			"tag":      tag,
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []map[string]any{{
					"address": node.Address,
					"port":    node.Port,
					"users":   []map[string]any{user},
				}},
			},
			"streamSettings": stream,
		})
	}

	for idx, node := range b.media {
		appendNodeOutbound("media", idx, node)
	}
	for idx, node := range b.pro {
		appendNodeOutbound("pro", idx, node)
	}
	for idx, node := range b.custom {
		appendNodeOutbound("custom", idx, node)
	}

	if hasMedia {
		balancers = append(balancers, map[string]any{
			"tag":      RoutingPoolMediaPriority,
			"selector": []string{"media-"},
		})
	}
	if hasPro {
		balancers = append(balancers, map[string]any{
			"tag":      RoutingPoolProEC2,
			"selector": []string{"pro-"},
		})
	}
	if hasCustom {
		balancers = append(balancers, map[string]any{
			"tag":      RoutingPoolCustomDedicated,
			"selector": []string{"custom-"},
		})
	}

	outbounds = append(outbounds,
		map[string]any{"tag": "direct", "protocol": "freedom"},
		map[string]any{"tag": "block", "protocol": "blackhole"},
	)

	rules := []map[string]any{
		{
			"type":        "field",
			"ip":          []string{"geoip:private"},
			"outboundTag": "direct",
		},
	}
	if len(policy.Tiers.DirectCNPrivate.XrayDomains) > 0 {
		rules = append(rules, map[string]any{
			"type":        "field",
			"domain":      policy.Tiers.DirectCNPrivate.XrayDomains,
			"outboundTag": "direct",
		})
	}
	if len(policy.Tiers.DirectCNPrivate.XrayIPs) > 0 {
		rules = append(rules, map[string]any{
			"type":        "field",
			"ip":          policy.Tiers.DirectCNPrivate.XrayIPs,
			"outboundTag": "direct",
		})
	}

	fallbackTarget := defaultFallbackTarget(hasMedia, hasCustom)
	addPoolRule := func(rule map[string]any, target string) {
		if target == TierTargetDirect {
			rule["outboundTag"] = "direct"
		} else {
			rule["balancerTag"] = target
		}
		rules = append(rules, rule)
	}

	if len(policy.Tiers.MediaPoolPriority.XrayDomains) > 0 {
		addPoolRule(map[string]any{
			"type":   "field",
			"domain": policy.Tiers.MediaPoolPriority.XrayDomains,
		}, fallbackTarget)
	}
	if len(policy.Tiers.ProEC2Whitelist.XrayDomains) > 0 {
		proTarget := fallbackTarget
		if hasPro {
			proTarget = RoutingPoolProEC2
		}
		addPoolRule(map[string]any{
			"type":   "field",
			"domain": policy.Tiers.ProEC2Whitelist.XrayDomains,
		}, proTarget)
	}
	addPoolRule(map[string]any{
		"type":    "field",
		"network": "tcp,udp",
	}, fallbackTarget)

	routing := map[string]any{
		"domainStrategy": "IPIfNonMatch",
		"rules":          rules,
	}
	if len(balancers) > 0 {
		routing["balancers"] = balancers
	}

	doc := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []map[string]any{
			{"listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": map[string]any{"udp": true}},
			{"listen": "127.0.0.1", "port": 1081, "protocol": "http"},
		},
		"outbounds": outbounds,
		"routing":   routing,
	}
	return json.MarshalIndent(doc, "", "  ")
}

type onePoolSummary struct {
	PublicResource   bool               `json:"public_resource"`
	MediaOnProAction string             `json:"media_on_pro_action"`
	FallbackDefault  bool               `json:"fallback_default"`
	PricingGroups    []string           `json:"pricing_groups"`
	SubPoolTags      []string           `json:"sub_pool_tags,omitempty"`
	Nodes            []SubscriptionNode `json:"nodes"`
}

type onePayload struct {
	SchemaVersion  int                       `json:"schema_version"`
	Format         string                    `json:"format"`
	GeneratedAt    time.Time                 `json:"generated_at"`
	PolicyRevision string                    `json:"policy_revision"`
	Pools          map[string]onePoolSummary `json:"pools"`
	Nodes          []SubscriptionNode        `json:"nodes"`
	Routes         []RouteRule               `json:"routes"`
	VlessURIs      []string                  `json:"vless_uris"`
}

func renderOne(input SubscriptionRenderInput, b nodeBuckets, policy RoutingPolicyConfig) ([]byte, error) {
	generatedAt := input.GeneratedAt.UTC()
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}

	pools := make(map[string]onePoolSummary)
	addPool := func(name string, nodes []SubscriptionNode) {
		if len(nodes) == 0 {
			return
		}
		cfg, _ := policy.Pool(name)
		pools[name] = onePoolSummary{
			PublicResource:   policy.IsPublicPool(name),
			MediaOnProAction: policy.MediaOnProActionFor(name),
			FallbackDefault:  cfg.FallbackDefault,
			PricingGroups:    append([]string(nil), cfg.PricingGroups...),
			SubPoolTags:      append([]string(nil), cfg.SubPoolTags...),
			Nodes:            nodes,
		}
	}
	addPool(RoutingPoolMediaPriority, b.media)
	addPool(RoutingPoolProEC2, b.pro)
	if input.AllowCustom {
		addPool(RoutingPoolCustomDedicated, b.custom)
	}

	uris := make([]string, 0, len(b.all))
	for _, node := range b.all {
		uris = append(uris, BuildVLESSURI(node))
	}

	allNodes := b.all
	if allNodes == nil {
		allNodes = []SubscriptionNode{}
	}
	routes := BuildThreeTierRoutes(policy, len(b.media) > 0, len(b.pro) > 0, input.AllowCustom && len(b.custom) > 0)
	payload := onePayload{
		SchemaVersion:  1,
		Format:         string(FormatOne),
		GeneratedAt:    generatedAt,
		PolicyRevision: policy.Revision,
		Pools:          pools,
		Nodes:          allNodes,
		Routes:         routes,
		VlessURIs:      uris,
	}
	return json.MarshalIndent(payload, "", "  ")
}

func renderVLESS(b nodeBuckets) ([]byte, error) {
	lines := make([]string, 0, len(b.all))
	for _, node := range b.all {
		lines = append(lines, BuildVLESSURI(node))
	}
	if len(lines) == 0 {
		return []byte(""), nil
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func renderDedicatedClientConfig(user *User, host, path string) (string, string, []string, error) {
	config := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": map[string]any{"udp": true}}},
		"outbounds": []any{map[string]any{
			"tag": "proxy", "protocol": "vless",
			"settings":       map[string]any{"vnext": []any{map[string]any{"address": host, "port": envIntOrDefault("XRAY_XHTTP_PORT", defaultXHTTPPort), "users": []any{map[string]any{"id": user.ProxyUUID, "encryption": "none"}}}}},
			"streamSettings": map[string]any{"network": "xhttp", "security": "tls", "tlsSettings": map[string]any{"serverName": host, "fingerprint": defaultTLSFP}, "xhttpSettings": map[string]any{"path": path, "mode": envOrDefault("XRAY_XHTTP_MODE", defaultXHTTPMode)}},
		}},
	}
	buf, err := json.Marshal(config)
	if err != nil {
		return "", "", nil, err
	}
	digest := sha256.Sum256(buf)
	return string(buf), hex.EncodeToString(digest[:]), []string{}, nil
}

func renderNetworkXrayConfig(user *User, domain string) (string, string, []string, error) {
	clientID := strings.TrimSpace(user.ProxyUUID)
	if clientID == "" {
		return "", "", nil, fmt.Errorf("proxy UUID is not provisioned for account %q", strings.TrimSpace(user.ID))
	}
	doc := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch",
			"rules": []any{
				map[string]any{"type": "field", "ip": []string{"geoip:cn"}, "outboundTag": "block"},
			},
		},
		"inbounds": []any{
			map[string]any{
				"listen":   "0.0.0.0",
				"port":     defaultTCPPort,
				"protocol": "vless",
				"settings": map[string]any{
					"clients": []any{
						map[string]any{
							"id":    clientID,
							"email": strings.TrimSpace(user.ID),
							"flow":  agentproto.DefaultFlow,
						},
					},
					"decryption": "none",
				},
				"streamSettings": map[string]any{
					"network": "tcp",
					"security": "tls",
					"tlsSettings": map[string]any{
						"rejectUnknownSni": true,
						"minVersion":       "1.2",
						"certificates": []any{
							map[string]any{
								"ocspStapling":    3600,
								"certificateFile": fmt.Sprintf("/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/%s/%s.crt", domain, domain),
								"keyFile":         fmt.Sprintf("/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/%s/%s.key", domain, domain),
							},
						},
					},
				},
			},
		},
		"outbounds": []any{
			map[string]any{"protocol": "freedom", "tag": "direct"},
			map[string]any{"protocol": "blackhole", "tag": "block"},
		},
	}
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", "", nil, err
	}
	buf = append(buf, '\n')
	sum := sha256.Sum256(buf)
	return string(buf), hex.EncodeToString(sum[:]), []string{}, nil
}

func nodeNames(nodes []SubscriptionNode) []string {
	names := make([]string, 0, len(nodes))
	for _, node := range nodes {
		names = append(names, node.Name)
	}
	return names
}

func urlTestSettings(policy RoutingPolicyConfig, poolName string, defaultInterval int) (string, int) {
	u := "https://cp.cloudflare.com/generate_204"
	interval := defaultInterval
	if pool, ok := policy.Pool(poolName); ok && pool.URLTest != nil {
		if strings.TrimSpace(pool.URLTest.URL) != "" {
			u = pool.URLTest.URL
		}
		if pool.URLTest.Interval > 0 {
			interval = pool.URLTest.Interval
		}
	}
	return u, interval
}

func singBoxTarget(target string) string {
	if target == TierTargetDirect {
		return "direct"
	}
	return target
}

func singBoxDomainConditions(xrayDomains []string) map[string]any {
	var geosites, suffixes []string
	for _, item := range xrayDomains {
		trimmed := strings.TrimSpace(item)
		switch {
		case strings.HasPrefix(trimmed, "geosite:"):
			geosites = append(geosites, strings.TrimPrefix(trimmed, "geosite:"))
		case strings.HasPrefix(trimmed, "domain:"):
			suffixes = append(suffixes, strings.TrimPrefix(trimmed, "domain:"))
		case trimmed != "":
			suffixes = append(suffixes, trimmed)
		}
	}
	cond := map[string]any{}
	if len(geosites) > 0 {
		cond["geosite"] = geosites
	}
	if len(suffixes) > 0 {
		cond["domain_suffix"] = suffixes
	}
	return cond
}

func stripPrefixes(items []string, prefix string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, strings.TrimPrefix(strings.TrimSpace(item), prefix))
	}
	return out
}

func cloneAnyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
