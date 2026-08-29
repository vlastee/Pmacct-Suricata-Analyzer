package notify

import (
	"context"
	"fmt"
	"strings"

	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// ipCard is what a notification can say about one address: the user's nickname for it and
// whatever enrichment already knows (rDNS / learned names, geo, organisation, hosting/proxy,
// VirusTotal / AbuseIPDB / GreyNoise verdicts, threat lists).
type ipCard struct {
	IP    string
	Nick  string
	Kind  string
	Note  string
	Name  string
	Geo   string
	Org   string
	Flags []string
}

// Label renders the address as people know it: "petro-pc (10.0.0.115)" or the bare IP.
func (c *ipCard) Label() string {
	if c.Nick != "" {
		return c.Nick + " (" + c.IP + ")"
	}
	return c.IP
}

// Detail is the one-line context shown under an alert; "" when nothing is known.
func (c *ipCard) Detail() string {
	var parts []string
	if c.Nick != "" && c.Kind != "" && c.Kind != "other" {
		parts = append(parts, c.Kind)
	}
	if c.Name != "" {
		parts = append(parts, c.Name)
	}
	if c.Geo != "" {
		parts = append(parts, c.Geo)
	}
	if c.Org != "" {
		parts = append(parts, c.Org)
	}
	parts = append(parts, c.Flags...)
	if c.Note != "" {
		parts = append(parts, "note: "+c.Note)
	}
	return strings.Join(parts, " · ")
}

// cards looks every host/peer in the batch up once. Without a database (tests) it is empty.
func (d *Dispatcher) cards(ctx context.Context, alerts []db.Alert) map[string]*ipCard {
	out := map[string]*ipCard{}
	if d.DB == nil {
		return out
	}
	for _, a := range alerts {
		for _, p := range []*string{a.Host, a.Peer} {
			if p == nil || *p == "" || out[*p] != nil {
				continue
			}
			out[*p] = d.card(ctx, *p)
		}
	}
	return out
}

func (d *Dispatcher) card(ctx context.Context, ip string) *ipCard {
	c := &ipCard{IP: ip}
	if n, err := d.DB.GetNickname(ctx, ip); err == nil && n != nil {
		c.Nick, c.Kind = n.Nickname, n.Kind
		if n.Note != nil {
			c.Note = strings.TrimSpace(*n.Note)
		}
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return strings.TrimSpace(*p)
	}
	if info, err := d.DB.GetIPInfo(ctx, ip); err == nil && info != nil {
		c.Name = str(info.Hostname)
		var geo []string
		if cc := str(info.CountryCode); cc != "" {
			geo = append(geo, cc)
		} else if co := str(info.Country); co != "" {
			geo = append(geo, co)
		}
		if city := str(info.City); city != "" {
			geo = append(geo, city)
		}
		c.Geo = strings.Join(geo, ", ")
		for _, o := range []*string{info.ASOrg, info.Org, info.ISP} {
			if c.Org = str(o); c.Org != "" {
				break
			}
		}
		if info.IsHosting != nil && *info.IsHosting {
			c.Flags = append(c.Flags, "hosting")
		}
		if info.IsProxy != nil && *info.IsProxy {
			c.Flags = append(c.Flags, "proxy/VPN")
		}
		if info.VT != nil && info.VT.Malicious != nil && *info.VT.Malicious > 0 {
			c.Flags = append(c.Flags, fmt.Sprintf("VirusTotal %d malicious", *info.VT.Malicious))
		}
	}
	if c.Name == "" {
		if names, err := d.DB.IPNames(ctx, ip, 1); err == nil && len(names) > 0 {
			c.Name = names[0].Name
		}
	}
	if reps, err := d.DB.ReputationFor(ctx, ip); err == nil {
		for _, r := range reps {
			if !r.Flagged {
				continue
			}
			switch {
			case r.Source == "abuseipdb" && r.Score != nil:
				c.Flags = append(c.Flags, fmt.Sprintf("AbuseIPDB %d%%", *r.Score))
			case r.Source == "greynoise":
				c.Flags = append(c.Flags, "GreyNoise malicious")
			default:
				c.Flags = append(c.Flags, r.Source+" flagged")
			}
		}
	}
	if lists, err := d.DB.ThreatListsFor(ctx, ip); err == nil && len(lists) > 0 {
		c.Flags = append(c.Flags, "listed: "+strings.Join(lists, ", "))
	}
	return c
}

// labelIPs rewrites bare addresses in s as "nickname (ip)" for every nicknamed card, matching
// whole addresses only (10.0.0.11 is left alone when labelling 10.0.0.115; a trailing :port is fine).
func labelIPs(s string, cards map[string]*ipCard) string {
	for ip, c := range cards {
		if c.Nick == "" || !strings.Contains(s, ip) {
			continue
		}
		s = replaceWhole(s, ip, c.Label())
	}
	return s
}

func replaceWhole(s, ip, label string) string {
	isV6 := strings.Contains(ip, ":")
	boundary := func(b byte) bool {
		if b >= '0' && b <= '9' || b == '.' {
			return false
		}
		if isV6 && (b == ':' || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			return false
		}
		return true
	}
	var out strings.Builder
	for {
		i := strings.Index(s, ip)
		if i < 0 {
			out.WriteString(s)
			return out.String()
		}
		end := i + len(ip)
		ok := (i == 0 || boundary(s[i-1])) && (end == len(s) || boundary(s[end]))
		out.WriteString(s[:i])
		if ok {
			out.WriteString(label)
		} else {
			out.WriteString(ip)
		}
		s = s[end:]
	}
}
