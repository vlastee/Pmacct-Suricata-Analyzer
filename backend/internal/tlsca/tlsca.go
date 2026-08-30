// Package tlsca gives the analyzer its own HTTPS identity without any external tooling: an
// internal certificate authority plus a server certificate for the configured hosts, both
// generated on first start and kept in the database (settings table) so they survive rebuilds.
// Browsers and agents import / pin the CA; the leaf is renewed automatically.
package tlsca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store persists PEM material; the database implements it (settings table). nil = memory only.
type Store interface {
	GetSetting(ctx context.Context, key string, v any) (bool, error)
	SetSetting(ctx context.Context, key string, v any) error
}

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 397 * 24 * time.Hour // Apple caps leaf certificates at 398 days, even from private CAs
	renewBefore  = 30 * 24 * time.Hour
	keyCA        = "tls_ca"
	keyServer    = "tls_server"
)

type pemPair struct {
	CertPEM string   `json:"cert_pem"`
	KeyPEM  string   `json:"key_pem"`
	Hosts   []string `json:"hosts,omitempty"`
}

// Info is what the UI and agents need to trust the server.
type Info struct {
	CASubject     string    `json:"ca_subject"`
	CAFingerprint string    `json:"ca_fingerprint_sha256"` // colon-separated hex of the DER certificate
	CASPKI        string    `json:"ca_spki_sha256"`        // base64(sha256(SubjectPublicKeyInfo)) — pin this
	CANotAfter    time.Time `json:"ca_not_after"`
	Hosts         []string  `json:"hosts"`
	LeafNotAfter  time.Time `json:"leaf_not_after"`
	LeafRenewedAt time.Time `json:"leaf_issued_at"`
}

// Manager owns the CA and the current server certificate.
type Manager struct {
	store Store
	hosts []string
	now   func() time.Time

	mu     sync.RWMutex
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
	leaf   *tls.Certificate
	leafX  *x509.Certificate
}

// New loads (or creates) the CA and makes sure a valid server certificate for hosts exists.
// An empty hosts list means "this machine": its hostname plus every non-loopback address.
func New(ctx context.Context, store Store, hosts []string) (*Manager, error) {
	m := &Manager{store: store, hosts: normalizeHosts(hosts), now: time.Now}
	if err := m.loadOrCreateCA(ctx); err != nil {
		return nil, fmt.Errorf("tls ca: %w", err)
	}
	if err := m.ensureLeaf(ctx); err != nil {
		return nil, fmt.Errorf("tls server certificate: %w", err)
	}
	return m, nil
}

// normalizeHosts dedupes, lowercases names and fills in defaults for an empty list.
func normalizeHosts(hosts []string) []string {
	set := map[string]bool{}
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			set[h] = true
		}
	}
	for _, h := range hosts {
		add(h)
	}
	if len(set) == 0 {
		if hn, err := os.Hostname(); err == nil {
			add(hn)
		}
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
					add(ipn.IP.String())
				}
			}
		}
	}
	add("localhost")
	add("127.0.0.1")
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func (m *Manager) loadOrCreateCA(ctx context.Context) error {
	var p pemPair
	if m.store != nil {
		if ok, err := m.store.GetSetting(ctx, keyCA, &p); err != nil {
			return err
		} else if ok && p.CertPEM != "" {
			cert, key, err := parsePair(p)
			if err == nil && cert.IsCA && m.now().Before(cert.NotAfter) {
				m.caCert, m.caKey, m.caPEM = cert, key, []byte(p.CertPEM)
				return nil
			}
			slog.Warn("stored TLS CA unusable, generating a new one", "err", err)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "pmacct-analyzer internal CA", Organization: []string{"pmacct-analyzer"}},
		NotBefore:             m.now().Add(-time.Hour),
		NotAfter:              m.now().Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	p, err = encodePair(der, key)
	if err != nil {
		return err
	}
	if m.store != nil {
		if err := m.store.SetSetting(ctx, keyCA, p); err != nil {
			return err
		}
	}
	m.caCert, m.caKey, m.caPEM = cert, key, []byte(p.CertPEM)
	slog.Info("generated internal TLS CA", "fingerprint", fingerprint(cert), "valid_until", cert.NotAfter.Format("2006-01-02"))
	return nil
}

// ensureLeaf loads the stored server certificate if it still fits (same hosts, not close to
// expiry, signed by the current CA); otherwise issues a fresh one.
func (m *Manager) ensureLeaf(ctx context.Context) error {
	var p pemPair
	if m.store != nil {
		if ok, err := m.store.GetSetting(ctx, keyServer, &p); err != nil {
			return err
		} else if ok && p.CertPEM != "" {
			cert, key, err := parsePair(p)
			if err == nil && !m.needsRenewal(cert, p.Hosts) {
				return m.setLeaf(cert, key, p)
			}
		}
	}
	return m.issueLeaf(ctx)
}

func (m *Manager) needsRenewal(cert *x509.Certificate, hosts []string) bool {
	if cert == nil || m.now().Add(renewBefore).After(cert.NotAfter) || m.now().Before(cert.NotBefore) {
		return true
	}
	if err := cert.CheckSignatureFrom(m.caCert); err != nil {
		return true
	}
	return strings.Join(hosts, ",") != strings.Join(m.hosts, ",")
}

func (m *Manager) issueLeaf(ctx context.Context) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: m.hosts[0], Organization: []string{"pmacct-analyzer"}},
		NotBefore:    m.now().Add(-time.Hour),
		NotAfter:     m.now().Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range m.hosts {
		if a, err := netip.ParseAddr(h); err == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(a.AsSlice()))
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	p, err := encodePair(der, key)
	if err != nil {
		return err
	}
	p.Hosts = m.hosts
	if m.store != nil {
		if err := m.store.SetSetting(ctx, keyServer, p); err != nil {
			return err
		}
	}
	slog.Info("issued TLS server certificate", "hosts", m.hosts, "valid_until", cert.NotAfter.Format("2006-01-02"))
	return m.setLeaf(cert, key, p)
}

func (m *Manager) setLeaf(cert *x509.Certificate, key *ecdsa.PrivateKey, p pemPair) error {
	pair, err := tls.X509KeyPair([]byte(p.CertPEM+m.stringCAPEM()), []byte(p.KeyPEM))
	if err != nil {
		return err
	}
	_ = key
	pair.Leaf = cert
	m.mu.Lock()
	m.leaf, m.leafX = &pair, cert
	m.mu.Unlock()
	return nil
}

func (m *Manager) stringCAPEM() string { return string(m.caPEM) }

// GetCertificate serves the current leaf (chain includes the CA) and lets renewals hot-swap it.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.leaf == nil {
		return nil, errors.New("no server certificate")
	}
	return m.leaf, nil
}

// TLSConfig is a ready-to-use server config.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{GetCertificate: m.GetCertificate, MinVersion: tls.VersionTLS12}
}

// CAPEM returns the CA certificate for import / pinning.
func (m *Manager) CAPEM() []byte { return append([]byte(nil), m.caPEM...) }

// Info summarises the identity.
func (m *Manager) Info() Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info := Info{CASubject: m.caCert.Subject.CommonName, CAFingerprint: fingerprint(m.caCert), CASPKI: spki(m.caCert),
		CANotAfter: m.caCert.NotAfter, Hosts: append([]string(nil), m.hosts...)}
	if m.leafX != nil {
		info.LeafNotAfter, info.LeafRenewedAt = m.leafX.NotAfter, m.leafX.NotBefore.Add(time.Hour)
	}
	return info
}

// Run renews the server certificate when it gets close to expiry (checked daily).
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.mu.RLock()
			cert := m.leafX
			m.mu.RUnlock()
			if m.needsRenewal(cert, m.hosts) {
				if err := m.issueLeaf(ctx); err != nil {
					slog.Error("tls certificate renewal", "err", err)
				}
			}
		}
	}
}

// ---- helpers ----

func encodePair(der []byte, key *ecdsa.PrivateKey) (pemPair, error) {
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return pemPair{}, err
	}
	return pemPair{
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})),
	}, nil
}

func parsePair(p pemPair) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode([]byte(p.CertPEM))
	kb, _ := pem.Decode([]byte(p.KeyPEM))
	if cb == nil || kb == nil {
		return nil, nil, errors.New("bad PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func spki(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}
