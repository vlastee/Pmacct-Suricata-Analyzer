// Package notify delivers alerts to external channels (webhook, ntfy, Gotify, Telegram, Slack, email).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deezave/pmacct-analyzer/backend/internal/config"
	"github.com/deezave/pmacct-analyzer/backend/internal/db"
)

// Channel delivers one message.
type Channel interface {
	Name() string
	Send(ctx context.Context, m Message) error
}

// Message is a rendered notification.
type Message struct {
	Title    string
	Body     string
	Severity string // highest severity in the batch
	Alerts   []db.Alert
	URL      string
}

// Dispatcher applies severity filter, quiet hours and digest batching, then fans out to channels.
type Dispatcher struct {
	DB       *db.DB
	Cfg      *config.Config
	Channels []Channel
	Now      func() time.Time

	mu          sync.Mutex
	pending     []db.Alert
	sent        int64
	failed      int64
	last        time.Time
	lastErr     string
	minSeverity string // runtime override of Cfg.NotifyMinSeverity, persisted in settings["notify"]
}

// notifySettings is what the UI can change at runtime (settings["notify"]).
type notifySettings struct {
	MinSeverity string `json:"min_severity,omitempty"`
}

// MinSeverity returns the effective minimum severity: the persisted override, else NOTIFY_MIN_SEVERITY.
func (d *Dispatcher) MinSeverity() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.minSeverity != "" {
		return d.minSeverity
	}
	return d.Cfg.NotifyMinSeverity
}

// SetMinSeverity changes the minimum severity delivered and persists it.
func (d *Dispatcher) SetMinSeverity(ctx context.Context, sev string) error {
	sev = strings.ToLower(strings.TrimSpace(sev))
	if db.SeverityRank(sev) == 0 {
		return fmt.Errorf("invalid severity %q (info, warning or critical)", sev)
	}
	d.mu.Lock()
	d.minSeverity = sev
	d.mu.Unlock()
	if d.DB == nil {
		return nil
	}
	return d.DB.SetSetting(ctx, "notify", notifySettings{MinSeverity: sev})
}

// loadSettings applies the persisted override, if any.
func (d *Dispatcher) loadSettings(ctx context.Context) {
	if d.DB == nil {
		return
	}
	var s notifySettings
	if ok, err := d.DB.GetSetting(ctx, "notify", &s); err == nil && ok && db.SeverityRank(s.MinSeverity) > 0 {
		d.mu.Lock()
		d.minSeverity = s.MinSeverity
		d.mu.Unlock()
	}
}

// NewDispatcher builds channels from config.
func NewDispatcher(d *db.DB, cfg *config.Config, client *http.Client) *Dispatcher {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	disp := &Dispatcher{DB: d, Cfg: cfg, Now: time.Now}
	disp.loadSettings(context.Background())
	if cfg.NotifyWebhookURL != "" {
		disp.Channels = append(disp.Channels, &Webhook{URL: cfg.NotifyWebhookURL, Client: client})
	}
	if cfg.NotifyNtfyURL != "" {
		disp.Channels = append(disp.Channels, &Ntfy{URL: cfg.NotifyNtfyURL, Token: cfg.NotifyNtfyToken, Client: client})
	}
	if cfg.NotifyGotifyURL != "" && cfg.NotifyGotifyToken != "" {
		disp.Channels = append(disp.Channels, &Gotify{URL: cfg.NotifyGotifyURL, Token: cfg.NotifyGotifyToken, Client: client})
	}
	if cfg.NotifyTelegramToken != "" && cfg.NotifyTelegramChat != "" {
		disp.Channels = append(disp.Channels, &Telegram{Token: cfg.NotifyTelegramToken, ChatID: cfg.NotifyTelegramChat, Client: client})
	}
	if cfg.NotifySlackWebhook != "" {
		disp.Channels = append(disp.Channels, &Slack{URL: cfg.NotifySlackWebhook, Client: client})
	}
	if cfg.NotifySMTPHost != "" && cfg.NotifySMTPTo != "" {
		disp.Channels = append(disp.Channels, &Email{Host: cfg.NotifySMTPHost, Port: cfg.NotifySMTPPort, User: cfg.NotifySMTPUser, Pass: cfg.NotifySMTPPass, From: cfg.NotifySMTPFrom, To: cfg.NotifySMTPTo})
	}
	return disp
}

// ChannelNames lists configured channels.
func (d *Dispatcher) ChannelNames() []string {
	out := []string{}
	for _, c := range d.Channels {
		out = append(out, c.Name())
	}
	return out
}

// Stats is a snapshot for the API.
type Stats struct {
	Channels    []string  `json:"channels"`
	MinSeverity string    `json:"min_severity"`
	Digest      string    `json:"digest"`
	QuietHours  string    `json:"quiet_hours"`
	Pending     int       `json:"pending"`
	Sent        int64     `json:"sent"`
	Failed      int64     `json:"failed"`
	LastSent    time.Time `json:"last_sent"`
	LastError   string    `json:"last_error,omitempty"`
}

// Stats returns a snapshot.
func (d *Dispatcher) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	min := d.minSeverity
	if min == "" {
		min = d.Cfg.NotifyMinSeverity
	}
	return Stats{Channels: d.ChannelNames(), MinSeverity: min, Digest: d.Cfg.NotifyDigest.String(),
		QuietHours: d.Cfg.NotifyQuietHours, Pending: len(d.pending), Sent: d.sent, Failed: d.failed, LastSent: d.last, LastError: d.lastErr}
}

// inQuietHours reports whether local time falls in the configured "HH-HH" range.
func (d *Dispatcher) inQuietHours(t time.Time) bool {
	q := strings.TrimSpace(d.Cfg.NotifyQuietHours)
	if q == "" {
		return false
	}
	parts := strings.Split(q, "-")
	if len(parts) != 2 {
		return false
	}
	from, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	to, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return false
	}
	h := t.Local().Hour()
	if from <= to {
		return h >= from && h < to
	}
	return h >= from || h < to
}

// Notify implements rules.Notifier: queue alerts that pass the severity filter.
func (d *Dispatcher) Notify(ctx context.Context, alerts []db.Alert) {
	if len(d.Channels) == 0 {
		return
	}
	min := db.SeverityRank(d.MinSeverity())
	var keep []db.Alert
	for _, a := range alerts {
		if db.SeverityRank(a.Severity) >= min {
			keep = append(keep, a)
		}
	}
	if len(keep) == 0 {
		return
	}
	d.mu.Lock()
	d.pending = append(d.pending, keep...)
	d.mu.Unlock()
	if d.Cfg.NotifyDigest == 0 && !d.inQuietHours(d.Now()) {
		d.Flush(ctx)
	}
}

// Flush sends everything pending (respecting quiet hours unless force).
func (d *Dispatcher) Flush(ctx context.Context) {
	d.mu.Lock()
	if len(d.pending) == 0 || d.inQuietHours(d.Now()) {
		d.mu.Unlock()
		return
	}
	batch := d.pending
	d.pending = nil
	d.mu.Unlock()
	msg := d.render(ctx, batch)
	var ids []int64
	for _, a := range batch {
		ids = append(ids, a.ID)
	}
	ok := false
	for _, c := range d.Channels {
		if err := c.Send(ctx, msg); err != nil {
			slog.Warn("notification failed", "channel", c.Name(), "err", err)
			d.mu.Lock()
			d.failed++
			d.lastErr = c.Name() + ": " + err.Error()
			d.mu.Unlock()
			continue
		}
		ok = true
	}
	if ok {
		d.mu.Lock()
		d.sent++
		d.last = d.Now()
		d.mu.Unlock()
		if d.DB != nil {
			if err := d.DB.MarkNotified(ctx, ids); err != nil {
				slog.Error("mark notified", "err", err)
			}
		}
	}
}

// Run flushes digests periodically (and drains after quiet hours end).
func (d *Dispatcher) Run(ctx context.Context) {
	interval := d.Cfg.NotifyDigest
	if interval == 0 {
		interval = time.Minute // only used to drain after quiet hours
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.Flush(ctx)
		}
	}
}

// SendTest sends a synthetic message to all channels and returns per-channel errors.
func (d *Dispatcher) SendTest(ctx context.Context) map[string]string {
	out := map[string]string{}
	m := Message{Title: "pmacct-analyzer test notification", Body: "If you can read this, notifications work.", Severity: db.SevInfo, URL: d.Cfg.PublicURL}
	for _, c := range d.Channels {
		if err := c.Send(ctx, m); err != nil {
			out[c.Name()] = err.Error()
		} else {
			out[c.Name()] = "ok"
		}
	}
	return out
}

// viaOf extracts the agent-reported programs from an alert's details ("via": [...]).
func viaOf(details []byte) string {
	if len(details) == 0 {
		return ""
	}
	var d struct {
		Via []string `json:"via"`
	}
	if json.Unmarshal(details, &d) != nil || len(d.Via) == 0 {
		return ""
	}
	return strings.Join(d.Via, ", ")
}

// maxBodyChars keeps a batch under Telegram's 4096-character message limit with room for the link.
const maxBodyChars = 3600

// render formats a batch. Addresses are shown with their nicknames and each alert gets a line of
// context about the peer (and about the host when it has no nickname) from enrichment data.
func (d *Dispatcher) render(ctx context.Context, alerts []db.Alert) Message {
	top := db.SevInfo
	for _, a := range alerts {
		if db.SeverityRank(a.Severity) > db.SeverityRank(top) {
			top = a.Severity
		}
	}
	cards := d.cards(ctx, alerts)
	var b strings.Builder
	title := ""
	if len(alerts) == 1 {
		a := alerts[0]
		title = fmt.Sprintf("[%s] %s", strings.ToUpper(a.Severity), labelIPs(a.Title, cards))
	} else {
		title = fmt.Sprintf("[%s] %d new alerts", strings.ToUpper(top), len(alerts))
	}
	for i, a := range alerts {
		if i >= 20 || b.Len() > maxBodyChars {
			fmt.Fprintf(&b, "… and %d more\n", len(alerts)-i)
			break
		}
		text := labelIPs(a.Title, cards)
		fmt.Fprintf(&b, "• %s %s — %s", strings.ToUpper(a.Severity[:1]), a.Rule, text)
		if a.Host != nil && *a.Host != "" && !strings.Contains(text, *a.Host) {
			who := *a.Host
			if c := cards[who]; c != nil {
				who = c.Label()
			} else if a.HostName != nil {
				who = *a.HostName + " (" + who + ")"
			}
			fmt.Fprintf(&b, " [%s]", who)
		}
		if a.Count > 1 {
			fmt.Fprintf(&b, " (x%d)", a.Count)
		}
		if via := viaOf(a.Details); via != "" {
			fmt.Fprintf(&b, " · via %s", via)
		}
		b.WriteString("\n")
		if a.Host != nil {
			if c := cards[*a.Host]; c != nil && (c.Nick == "" || c.Note != "") {
				if det := c.Detail(); det != "" {
					fmt.Fprintf(&b, "   ↳ %s: %s\n", *a.Host, det)
				}
			}
		}
		if a.Peer != nil {
			if c := cards[*a.Peer]; c != nil {
				if det := c.Detail(); det != "" {
					fmt.Fprintf(&b, "   ↳ %s: %s\n", c.Label(), det)
				}
			}
		}
	}
	link := ""
	if d.Cfg.PublicURL != "" {
		link = d.Cfg.PublicURL + "/#/alerts"
		fmt.Fprintf(&b, "%s\n", link)
	}
	return Message{Title: title, Body: strings.TrimSpace(b.String()), Severity: top, Alerts: alerts, URL: link}
}

// ---- channels ----

func postJSON(ctx context.Context, c *http.Client, url string, headers map[string]string, v any) error {
	body, _ := json.Marshal(v)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// Surface the service's own explanation (e.g. Telegram's "Bad Request: chat not found")
		// instead of a bare status code, so "Send test" tells the user what to fix.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if d := strings.Join(strings.Fields(string(snippet)), " "); d != "" {
			return fmt.Errorf("http %d: %s", resp.StatusCode, d)
		}
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return nil
}

// Webhook posts the full alert batch as JSON.
type Webhook struct {
	URL    string
	Client *http.Client
}

func (w *Webhook) Name() string { return "webhook" }
func (w *Webhook) Send(ctx context.Context, m Message) error {
	return postJSON(ctx, w.Client, w.URL, nil, map[string]any{"title": m.Title, "body": m.Body, "severity": m.Severity, "url": m.URL, "alerts": m.Alerts})
}

// Ntfy publishes to an ntfy topic URL.
type Ntfy struct {
	URL, Token string
	Client     *http.Client
}

func (n *Ntfy) Name() string { return "ntfy" }
func (n *Ntfy) Send(ctx context.Context, m Message) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, strings.NewReader(m.Body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", m.Title)
	prio := map[string]string{db.SevCritical: "5", db.SevWarning: "4", db.SevInfo: "3"}[m.Severity]
	if prio != "" {
		req.Header.Set("Priority", prio)
	}
	req.Header.Set("Tags", "rotating_light")
	if m.URL != "" {
		req.Header.Set("Click", m.URL)
	}
	if n.Token != "" {
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// Surface the service's own explanation (e.g. Telegram's "Bad Request: chat not found")
		// instead of a bare status code, so "Send test" tells the user what to fix.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if d := strings.Join(strings.Fields(string(snippet)), " "); d != "" {
			return fmt.Errorf("http %d: %s", resp.StatusCode, d)
		}
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return nil
}

// Gotify posts to /message.
type Gotify struct {
	URL, Token string
	Client     *http.Client
}

func (g *Gotify) Name() string { return "gotify" }
func (g *Gotify) Send(ctx context.Context, m Message) error {
	prio := map[string]int{db.SevCritical: 8, db.SevWarning: 5, db.SevInfo: 2}[m.Severity]
	return postJSON(ctx, g.Client, strings.TrimRight(g.URL, "/")+"/message", map[string]string{"X-Gotify-Key": g.Token},
		map[string]any{"title": m.Title, "message": m.Body, "priority": prio})
}

// Telegram uses the bot API sendMessage.
type Telegram struct {
	Token, ChatID string
	Client        *http.Client
}

func (t *Telegram) Name() string { return "telegram" }
func (t *Telegram) Send(ctx context.Context, m Message) error {
	return postJSON(ctx, t.Client, "https://api.telegram.org/bot"+t.Token+"/sendMessage", nil,
		map[string]any{"chat_id": t.ChatID, "text": m.Title + "\n" + m.Body, "disable_web_page_preview": true})
}

// Slack posts to an incoming webhook.
type Slack struct {
	URL    string
	Client *http.Client
}

func (s *Slack) Name() string { return "slack" }
func (s *Slack) Send(ctx context.Context, m Message) error {
	return postJSON(ctx, s.Client, s.URL, nil, map[string]any{"text": "*" + m.Title + "*\n" + m.Body})
}

// Email sends via SMTP (STARTTLS when the server offers it, PLAIN auth when a user is set).
type Email struct {
	Host, User, Pass, From, To string
	Port                       int
}

func (e *Email) Name() string { return "email" }
func (e *Email) Send(ctx context.Context, m Message) error {
	from := e.From
	if from == "" {
		from = "pmacct-analyzer@" + e.Host
	}
	to := strings.Split(e.To, ",")
	for i := range to {
		to[i] = strings.TrimSpace(to[i])
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n", from, strings.Join(to, ", "), m.Title, m.Body)
	var auth smtp.Auth
	if e.User != "" {
		auth = smtp.PlainAuth("", e.User, e.Pass, e.Host)
	}
	return smtp.SendMail(fmt.Sprintf("%s:%d", e.Host, e.Port), auth, from, to, []byte(msg))
}

var _ = url.Parse
