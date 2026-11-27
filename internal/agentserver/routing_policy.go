package agentserver

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ai-workspace-services/xconnect-controller/internal/agentproto"
)

const (
	RoutingPoolMediaPriority   = "Media-Pool"
	RoutingPoolProEC2          = "Pro-EC2-Pool"
	RoutingPoolCustomDedicated = "Custom-Dedicated"
	TierTargetDirect           = "DIRECT"
	MediaOnProActionAllow      = "allow"
	MediaOnProActionBlackhole  = "blackhole"
	DefaultPolicyPathEnv       = "XCONNECT_ROUTING_POLICY_PATH"
)

// URLTestConfig describes Clash/Mihomo url-test health probe settings for a pool.
type URLTestConfig struct {
	URL      string `yaml:"url" json:"url"`
	Interval int    `yaml:"interval" json:"interval"`
}

// PoolPolicy defines the capabilities, access isolation, and node inventory of a routing pool.
type PoolPolicy struct {
	PublicResource   bool           `yaml:"public_resource" json:"publicResource"`
	MediaOnProAction string         `yaml:"media_on_pro_action" json:"mediaOnProAction"`
	FallbackDefault  bool           `yaml:"fallback_default" json:"fallbackDefault"`
	Unlimited        bool           `yaml:"unlimited,omitempty" json:"unlimited,omitempty"`
	Description      string         `yaml:"description,omitempty" json:"description,omitempty"`
	PricingGroups    []string       `yaml:"pricing_groups" json:"pricingGroups"`
	SubPoolTags      []string       `yaml:"sub_pool_tags_reserved,omitempty" json:"subPoolTags,omitempty"`
	URLTest          *URLTestConfig `yaml:"url_test,omitempty" json:"urlTest,omitempty"`
	Nodes            []string       `yaml:"nodes,omitempty" json:"nodes,omitempty"`
}

// TierPolicy defines one priority tier in the three-tier split routing policy.
type TierPolicy struct {
	Priority                     int      `yaml:"priority" json:"priority"`
	Target                       string   `yaml:"target" json:"target"`
	ServerOutboundTag            string   `yaml:"server_outbound_tag,omitempty" json:"serverOutboundTag,omitempty"`
	PrivateOutboundTag           string   `yaml:"private_outbound_tag,omitempty" json:"privateOutboundTag,omitempty"`
	ServerOutboundTagOnMediaPool string   `yaml:"server_outbound_tag_on_media_pool,omitempty" json:"serverOutboundTagOnMediaPool,omitempty"`
	ServerOutboundTagOnProPool   string   `yaml:"server_outbound_tag_on_pro_pool,omitempty" json:"serverOutboundTagOnProPool,omitempty"`
	ClashRules                   []string `yaml:"clash_rules,omitempty" json:"clashRules,omitempty"`
	XrayDomains                  []string `yaml:"xray_domains,omitempty" json:"xrayDomains,omitempty"`
	XrayIPs                      []string `yaml:"xray_ips,omitempty" json:"xrayIps,omitempty"`
}

// Tiers groups the canonical four-step / three-tier routing rules.
type Tiers struct {
	DirectCNPrivate   TierPolicy `yaml:"direct_cn_private" json:"directCnPrivate"`
	MediaPoolPriority TierPolicy `yaml:"media_pool_priority" json:"mediaPoolPriority"`
	ProEC2Whitelist   TierPolicy `yaml:"pro_ec2_whitelist" json:"proEc2Whitelist"`
	GlobalFallback    TierPolicy `yaml:"global_fallback" json:"globalFallback"`
}

// RoutingPolicyConfig represents the canonical XConnect three-tier routing policy.
type RoutingPolicyConfig struct {
	Version  int                   `yaml:"version" json:"version"`
	Revision string                `yaml:"revision" json:"revision"`
	Pools    map[string]PoolPolicy `yaml:"pools" json:"pools"`
	Tiers    Tiers                 `yaml:"tiers" json:"tiers"`
}

// DefaultRoutingPolicy returns a fresh copy of the canonical built-in three-tier routing policy.
func DefaultRoutingPolicy() RoutingPolicyConfig {
	return RoutingPolicyConfig{
		Version:  1,
		Revision: "2026-11-19.1",
		Pools: map[string]PoolPolicy{
			RoutingPoolMediaPriority: {
				PublicResource:   true,
				MediaOnProAction: MediaOnProActionAllow,
				FallbackDefault:  true,
				Unlimited:        true,
				Description:      "Public high-bandwidth pool (Free/Shared/Plus): media priority + global MATCH fallback, unlimited",
				PricingGroups:    []string{"free", "shared", "plus"},
				SubPoolTags:      []string{"media:video", "media:shopping", "media:ai-app"},
				URLTest: &URLTestConfig{
					URL:      "https://cp.cloudflare.com/generate_204",
					Interval: 300,
				},
				Nodes: []string{
					"jp-xconnect-01.svc.plus",
					"ph-xconnect.svc.plus",
					"jp-xconnect-free-01.svc.plus",
				},
			},
			RoutingPoolProEC2: {
				PublicResource:   true,
				MediaOnProAction: MediaOnProActionAllow,
				FallbackDefault:  false,
				Unlimited:        false,
				Description:      "Public EC2 high-speed quota pool (Pro only; invisible to Plus/Free/Shared): no streaming or download restriction; Pro plans access both Media-Pool (VPS) and Pro-EC2-Pool (high-speed)",
				PricingGroups:    []string{"pro"},
				URLTest: &URLTestConfig{
					URL:      "https://cp.cloudflare.com/generate_204",
					Interval: 180,
				},
				Nodes: []string{
					"jp-xconnect-02.svc.plus",
				},
			},
			RoutingPoolCustomDedicated: {
				PublicResource:   false,
				MediaOnProAction: MediaOnProActionAllow,
				FallbackDefault:  false,
				Unlimited:        true,
				Description:      "Non-public dedicated pool (Custom/Team whitelist-bound): never enters public discovery, unlimited",
				PricingGroups:    []string{"custom", "team"},
				Nodes: []string{
					"us-xconnect-los-angeles-custom-01.svc.plus",
					"us-xconnect.svc.plus",
				},
			},
		},
		Tiers: Tiers{
			DirectCNPrivate: TierPolicy{
				Priority:           1,
				Target:             TierTargetDirect,
				ServerOutboundTag:  "direct-cn",
				PrivateOutboundTag: "blocked-private",
				ClashRules: []string{
					"GEOIP,private,DIRECT,no-resolve",
					"GEOSITE,cn,DIRECT",
					"GEOIP,cn,DIRECT,no-resolve",
				},
				XrayDomains: []string{"geosite:cn"},
				XrayIPs:     []string{"geoip:cn"},
			},
			MediaPoolPriority: TierPolicy{
				Priority:                     2,
				Target:                       RoutingPoolMediaPriority,
				ServerOutboundTagOnMediaPool: "pool-media-stream",
				ServerOutboundTagOnProPool:   "blocked-media-on-pro",
				ClashRules: []string{
					"GEOSITE,youtube,Media-Pool",
					"GEOSITE,netflix,Media-Pool",
					"GEOSITE,disney,Media-Pool",
					"GEOSITE,tiktok,Media-Pool",
					"GEOSITE,twitch,Media-Pool",
					"GEOSITE,spotify,Media-Pool",
					"GEOSITE,bilibili,Media-Pool",
					"DOMAIN-SUFFIX,speedtest.net,Media-Pool",
					"DOMAIN-SUFFIX,fast.com,Media-Pool",
					"DOMAIN-SUFFIX,steamcontent.com,Media-Pool",
					"DOMAIN-SUFFIX,icloud-content.com,Media-Pool",
					"DOMAIN-SUFFIX,mega.nz,Media-Pool",
				},
				XrayDomains: []string{
					"geosite:youtube",
					"geosite:netflix",
					"geosite:disney",
					"geosite:tiktok",
					"geosite:twitch",
					"geosite:spotify",
					"geosite:bilibili",
					"domain:speedtest.net",
					"domain:fast.com",
					"domain:steamcontent.com",
					"domain:icloud-content.com",
					"domain:mega.nz",
				},
			},
			ProEC2Whitelist: TierPolicy{
				Priority:          3,
				Target:            RoutingPoolProEC2,
				ServerOutboundTag: "pool-pro-ai-dev",
				ClashRules: []string{
					"GEOSITE,openai,Pro-EC2-Pool",
					"GEOSITE,anthropic,Pro-EC2-Pool",
					"DOMAIN-SUFFIX,claude.ai,Pro-EC2-Pool",
					"DOMAIN-SUFFIX,cursor.sh,Pro-EC2-Pool",
					"DOMAIN-SUFFIX,cursor.com,Pro-EC2-Pool",
					"GEOSITE,github,Pro-EC2-Pool",
					"GEOSITE,google,Pro-EC2-Pool",
					"GEOSITE,cloudflare,Pro-EC2-Pool",
				},
				XrayDomains: []string{
					"geosite:openai",
					"geosite:anthropic",
					"domain:claude.ai",
					"domain:cursor.sh",
					"domain:cursor.com",
					"geosite:github",
					"geosite:google",
					"geosite:cloudflare",
				},
			},
			GlobalFallback: TierPolicy{
				Priority:                     4,
				Target:                       RoutingPoolMediaPriority,
				ServerOutboundTagOnMediaPool: "pool-media-fallback",
				ServerOutboundTagOnProPool:   "pool-pro-unclassified",
				ClashRules: []string{
					"MATCH,Media-Pool",
				},
			},
		},
	}
}

// LoadRoutingPolicyOrDefault loads the routing policy from path (or XCONNECT_ROUTING_POLICY_PATH),
// falling back to DefaultRoutingPolicy() when unset.
func LoadRoutingPolicyOrDefault(path string) (RoutingPolicyConfig, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		trimmed = strings.TrimSpace(os.Getenv(DefaultPolicyPathEnv))
	}
	if trimmed == "" {
		return DefaultRoutingPolicy(), nil
	}
	data, err := os.ReadFile(trimmed)
	if err != nil {
		return RoutingPolicyConfig{}, fmt.Errorf("read routing policy %q: %w", trimmed, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return RoutingPolicyConfig{}, errors.New("routing policy YAML is empty")
	}
	var parsed RoutingPolicyConfig
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return RoutingPolicyConfig{}, fmt.Errorf("parse routing policy YAML: %w", err)
	}
	def := DefaultRoutingPolicy()
	if parsed.Version == 0 {
		parsed.Version = def.Version
	}
	if strings.TrimSpace(parsed.Revision) == "" {
		parsed.Revision = def.Revision
	}
	if parsed.Pools == nil {
		parsed.Pools = def.Pools
	}
	return parsed, nil
}

// PoolForResourceClass maps a resource class to its canonical routing pool name.
func (p RoutingPolicyConfig) PoolForResourceClass(resourceClass string) string {
	normalized := strings.ToLower(strings.TrimSpace(resourceClass))
	if normalized == "" {
		return RoutingPoolMediaPriority
	}
	for _, poolName := range []string{RoutingPoolCustomDedicated, RoutingPoolProEC2, RoutingPoolMediaPriority} {
		if pool, ok := p.Pools[poolName]; ok {
			for _, group := range pool.PricingGroups {
				if strings.ToLower(strings.TrimSpace(group)) == normalized {
					return poolName
				}
			}
		}
	}
	switch normalized {
	case "pro":
		return RoutingPoolProEC2
	case "custom", "team":
		return RoutingPoolCustomDedicated
	default:
		return RoutingPoolMediaPriority
	}
}

// Pool returns a copy of the PoolPolicy for the named pool.
func (p RoutingPolicyConfig) Pool(name string) (PoolPolicy, bool) {
	pool, ok := p.Pools[name]
	return pool, ok
}

// IsPublicPool reports whether the named pool is eligible for public discovery.
func (p RoutingPolicyConfig) IsPublicPool(name string) bool {
	if name == RoutingPoolCustomDedicated {
		return false
	}
	pool, ok := p.Pools[name]
	if !ok {
		return false
	}
	return pool.PublicResource
}

// MediaOnProActionFor returns the configured media action for the named pool.
func (p RoutingPolicyConfig) MediaOnProActionFor(name string) string {
	pool, ok := p.Pools[name]
	if !ok || strings.TrimSpace(pool.MediaOnProAction) == "" {
		return MediaOnProActionAllow
	}
	return pool.MediaOnProAction
}

// SubPoolTagsFor returns a copy of reserved sub-pool tags for the named pool.
func (p RoutingPolicyConfig) SubPoolTagsFor(name string) []string {
	pool, ok := p.Pools[name]
	if !ok || len(pool.SubPoolTags) == 0 {
		return nil
	}
	return append([]string(nil), pool.SubPoolTags...)
}

func agentRoutingPolicyForScope(scope agentproto.UserScope, policy RoutingPolicyConfig) *agentproto.RoutingPolicy {
	poolName := policy.PoolForResourceClass(scope.ResourceClass)
	poolCfg, _ := policy.Pool(poolName)
	return &agentproto.RoutingPolicy{
		Version:             policy.Version,
		Revision:            policy.Revision,
		Pool:                poolName,
		PublicResource:      policy.IsPublicPool(poolName),
		MediaOnProAction:    policy.MediaOnProActionFor(poolName),
		FallbackDefault:     poolCfg.FallbackDefault,
		Unlimited:           poolCfg.Unlimited,
		PricingGroups:       append([]string(nil), poolCfg.PricingGroups...),
		SubPoolTags:         append([]string(nil), poolCfg.SubPoolTags...),
		DirectDomains:       append([]string(nil), policy.Tiers.DirectCNPrivate.XrayDomains...),
		DirectIPs:           append([]string(nil), policy.Tiers.DirectCNPrivate.XrayIPs...),
		MediaDomains:        append([]string(nil), policy.Tiers.MediaPoolPriority.XrayDomains...),
		ProWhitelistDomains: append([]string(nil), policy.Tiers.ProEC2Whitelist.XrayDomains...),
	}
}
