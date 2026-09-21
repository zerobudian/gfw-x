package rules

import "strings"

// Preset is a named rule template.
type Preset struct {
	Name  string
	Desc  string
	Rules []*Rule
}

// predefined categories used by *_CATEGORY rules.
const (
	CatSocial    = "social-media-overseas"
	CatAdult     = "adult"
	CatGambling  = "gambling"
	CatMalicious = "malicious"
	CatVPN       = "vpn-tunnel"
)

// CategoryCatalog is exposed to the dashboard so users know which categories
// a preset can intercept. It is a *reference catalog*, not an IP-based blocklist.
var CategoryCatalog = map[string]string{
	CatSocial:    "Overseas social media (user-configurable)",
	CatAdult:     "Adult websites",
	CatGambling:  "Gambling websites",
	CatMalicious: "Malicious / malware / phishing",
	CatVPN:       "Known VPN / tunneling services",
}

// categoryBlock builds a BLOCK_CATEGORY rule.
func categoryBlock(cat string) *Rule {
	return &Rule{
		ID:       NewID("preset"),
		Kind:     KindBlock,
		Enabled:  true,
		Category: cat,
		Source:   "preset",
		Matchers: []Matcher{{Field: FieldCategory(), Value: cat}},
	}
}

// allowDomain builds an ALLOW domain rule.
func allowDomain(d string) *Rule {
	return &Rule{
		ID:       NewID("preset"),
		Kind:     KindAllow,
		Enabled:  true,
		Name:     "allow " + d,
		Source:   "preset",
		Matchers: []Matcher{{Field: FieldDomain, Value: d}},
	}
}

// allowSuffix builds an ALLOW suffix rule.
func allowSuffix(s string) *Rule {
	return &Rule{
		ID:       NewID("preset"),
		Kind:     KindAllow,
		Enabled:  true,
		Name:     "allow *" + s,
		Source:   "preset",
		Matchers: []Matcher{{Field: FieldDomainSfx, Value: "*." + s}},
	}
}

// PresetBy returns a named preset builder.
func PresetBy(name string) (*Preset, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "balanced":
		p := balanced()
		return &p, true
	case "strict":
		p := strict()
		return &p, true
	case "developer":
		p := developer()
		return &p, true
	case "minimal":
		p := minimal()
		return &p, true
	case "custom":
		p := custom()
		return &p, true
	}
	return nil, false
}

// PresetNames lists available presets.
func PresetNames() []string { return []string{"balanced", "strict", "developer", "minimal", "custom"} }

func balanced() Preset {
	return Preset{
		Name: "balanced",
		Desc: "Block malicious, adult and VPN/tunnel categories on top of a permissive default.",
		Rules: []*Rule{
			categoryBlock(CatMalicious),
			categoryBlock(CatAdult),
			categoryBlock(CatVPN),
			allowSuffix("pages.dev"),
		},
	}
}

func strict() Preset {
	return Preset{
		Name: "strict",
		Desc: "Block social media, adult, gambling, malicious and VPN categories. Conservative.",
		Rules: []*Rule{
			categoryBlock(CatSocial),
			categoryBlock(CatAdult),
			categoryBlock(CatGambling),
			categoryBlock(CatMalicious),
			categoryBlock(CatVPN),
			allowSuffix("pages.dev"),
		},
	}
}

func developer() Preset {
	// Developer-friendly: allow AI services, open source communities, GitHub,
	// Hugging Face, Cloudflare Pages, GCP + Google APIs, X, WeChat, QQ, Douyin,
	// plus common software-update / CDN / auth endpoints. No IP-range blocks.
	return Preset{
		Name: "developer",
		Desc: "Allow AI, open-source, GitHub, Hugging Face, Cloudflare Pages, GCP & essential APIs.",
		Rules: []*Rule{
			categoryBlock(CatAdult),
			categoryBlock(CatGambling),
			categoryBlock(CatMalicious),
			// AI services
			allowSuffix("openai.com"),
			allowSuffix("anthropic.com"),
			allowSuffix("claude.ai"),
			allowSuffix("googleapis.com"),
			allowSuffix("gemini.google.com"),
			// Open source communities
			allowSuffix("github.com"),
			allowSuffix("githubusercontent.com"),
			allowSuffix("gitlab.com"),
			allowSuffix("sourceforge.net"),
			allowSuffix("huggingface.co"),
			// Cloudflare Pages
			allowSuffix("pages.dev"),
			allowSuffix("cloudflarercdn.com"),
			// Google Cloud + necessary Google APIs
			allowSuffix("google.com"),
			allowSuffix("googlevideo.com"),
			allowSuffix("ggpht.com"),
			allowSuffix("gstatic.com"),
			allowSuffix("gvt1.com"),
			allowSuffix("googleapis.cn"),
			// X / Twitter
			allowSuffix("x.com"),
			allowSuffix("twitter.com"),
			allowSuffix("twimg.com"),
			// WeChat
			allowSuffix("weixin.qq.com"),
			allowSuffix("wechat.com"),
			allowSuffix("wx.qq.com"),
			// QQ
			allowSuffix("qq.com"),
			allowSuffix("qpic.cn"),
			// Douyin
			allowSuffix("douyin.com"),
			allowSuffix("douyinvod.com"),
			allowSuffix("amemv.com"),
			// Software updates / CDN / auth
			allowSuffix("update.microsoft.com"),
			allowSuffix("download.microsoft.com"),
			allowSuffix("npupdate.com"),
			allowSuffix("s3.amazonaws.com"),
			allowSuffix("akamai.net"),
			allowSuffix("apple.com"),
		},
	}
}

func minimal() Preset {
	return Preset{
		Name: "minimal",
		Desc: "Only block malicious traffic. Everything else is permitted and observed.",
		Rules: []*Rule{
			categoryBlock(CatMalicious),
		},
	}
}

func custom() Preset {
	return Preset{
		Name:  "custom",
		Desc:  "Start empty. Load rules via the dashboard or CLI.",
		Rules: []*Rule{},
	}
}
