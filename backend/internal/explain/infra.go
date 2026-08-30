package explain

import "strings"

// Infra classifies a destination's network owner so the write-up can say how much the
// address itself tells you.
type Infra struct {
	Class string `json:"class"` // cdn | cloud | hosting | vendor | isp | transit | dns | unknown
	Label string `json:"label"`
	Note  string `json:"note"`
}

type infraRule struct {
	match []string
	infra Infra
}

var infraRules = []infraRule{
	{[]string{"cloudflare"}, Infra{"cdn", "Cloudflare", "CDN/reverse proxy fronting a huge share of the internet — the IP alone tells you little; the hostname/SNI does."}},
	{[]string{"fastly"}, Infra{"cdn", "Fastly", "CDN used by many package registries (PyPI, GitHub content, quay.io) and sites — identify by hostname/SNI."}},
	{[]string{"akamai", "linode"}, Infra{"cdn", "Akamai / Linode", "Akamai CDN (updates, games, streaming) or Linode hosting — identify by hostname."}},
	{[]string{"edgecast", "verizon digital", "limelight", "edgio", "cdn77", "datacamp", "stackpath", "highwinds", "bunny", "cachefly", "gcore", "g-core"}, Infra{"cdn", "CDN", "Content delivery network — shared by many services."}},
	{[]string{"amazon", "aws", "ec2"}, Infra{"cloud", "Amazon AWS", "Public cloud — could be anything hosted on AWS; check the hostname/SNI and whether other hosts use it."}},
	{[]string{"google"}, Infra{"cloud", "Google", "Google services or Google Cloud tenants (8.8.8.8/8.8.4.4 are Google Public DNS)."}},
	{[]string{"microsoft", "azure"}, Infra{"cloud", "Microsoft / Azure", "Microsoft services (updates, telemetry, Office 365) or Azure tenants."}},
	{[]string{"apple"}, Infra{"vendor", "Apple", "Apple services (iCloud, updates, push)."}},
	{[]string{"anthropic"}, Infra{"vendor", "Anthropic", "Anthropic API (Claude) — expected for AI assistants and developer tools."}},
	{[]string{"valve"}, Infra{"vendor", "Valve", "Steam."}},
	{[]string{"meta platforms", "facebook", "instagram", "whatsapp"}, Infra{"vendor", "Meta", "Facebook/Instagram/WhatsApp."}},
	{[]string{"netflix", "spotify", "discord", "twitch", "zoom"}, Infra{"vendor", "Consumer service", "A well-known consumer service's own network."}},
	{[]string{"hetzner", "ovh", "digitalocean", "contabo", "vultr", "scaleway", "ionos", "leaseweb", "choopa", "m247", "hostinger", "namecheap", "godaddy", "psychz", "colocrossing", "quadranet", "servermania", "hostwinds", "hostkey", "flokinet", "privatelayer", "serverion", "aeza", "stark industries", "the constant"}, Infra{"hosting", "Hosting provider", "Rented servers — used by open-source mirrors, self-hosters and also by attackers. rDNS and SNI usually say which."}},
	{[]string{"oracle"}, Infra{"cloud", "Oracle Cloud", "Public cloud tenants."}},
	{[]string{"alibaba", "aliyun", "taobao", "tencent", "huawei"}, Infra{"cloud", "Chinese cloud", "Alibaba/Tencent/Huawei cloud tenants — common for apps and devices from Chinese vendors."}},
	{[]string{"comcast", "verizon", "at&t", "spectrum", "charter", "cox", "t-mobile", "vodafone", "telekom", "orange", "bt ", "telefonica", "rogers", "bell canada", "telus", "sky uk", "virgin media"}, Infra{"isp", "Residential / mobile ISP", "A home or mobile connection — peer-to-peer traffic, remote access, or a scanner/attacker behind a consumer line."}},
	{[]string{"hurricane electric", "cogent", "lumen", "level 3", "zayo", "gtt", "telia", "arelion", "ntt"}, Infra{"transit", "Transit / backbone", "Backbone network — often a tenant or a CDN node, identify by hostname."}},
}

// Classify picks the best label from organisation / ISP / AS-org strings and the hostname.
func Classify(org, isp, asOrg, hostname string) Infra {
	hay := strings.ToLower(strings.Join([]string{org, isp, asOrg, hostname}, " | "))
	if hay == " |  |  | " {
		return Infra{"unknown", "Unknown", "Not enriched yet — refresh enrichment on the host page."}
	}
	for _, r := range infraRules {
		for _, m := range r.match {
			if strings.Contains(hay, m) {
				return r.infra
			}
		}
	}
	return Infra{"unknown", "Other network", "Not a network the knowledge base recognises; judge by rDNS, SNI and reputation."}
}
