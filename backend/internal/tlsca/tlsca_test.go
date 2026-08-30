package tlsca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"
)

// memStore is the settings table in memory.
type memStore map[string][]byte

func (m memStore) GetSetting(_ context.Context, key string, v any) (bool, error) {
	raw, ok := m[key]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(raw, v)
}
func (m memStore) SetSetting(_ context.Context, key string, v any) error {
	raw, err := json.Marshal(v)
	m[key] = raw
	return err
}

func TestGenerateAndVerify(t *testing.T) {
	store := memStore{}
	m, err := New(context.Background(), store, []string{"10.0.0.210", "Analyzer.Local"})
	if err != nil {
		t.Fatal(err)
	}
	info := m.Info()
	if info.CASPKI == "" || len(info.CAFingerprint) != 95 || info.Hosts[0] != "10.0.0.210" || info.LeafNotAfter.Before(time.Now().Add(390*24*time.Hour)) {
		t.Fatalf("info: %+v", info)
	}
	// A client that trusts only the CA verifies the served chain for both an IP and a DNS name.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(m.CAPEM()) {
		t.Fatal("CA PEM")
	}
	cert, err := m.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("chain should carry leaf + CA, got %d", len(cert.Certificate))
	}
	for _, host := range []string{"10.0.0.210", "analyzer.local", "localhost", "127.0.0.1"} {
		if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: host}); err != nil {
			t.Errorf("verify for %s: %v", host, err)
		}
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "other.local"}); err == nil {
		t.Error("unlisted name must not verify")
	}

	// Same store, same hosts → same CA and leaf are reused.
	m2, err := New(context.Background(), store, []string{"analyzer.local", "10.0.0.210"})
	if err != nil {
		t.Fatal(err)
	}
	if m2.Info().CAFingerprint != info.CAFingerprint || !m2.leafX.Equal(m.leafX) {
		t.Error("stored CA/leaf should be reused for the same hosts")
	}
	// New host → new leaf, same CA.
	m3, err := New(context.Background(), store, []string{"10.0.0.210", "10.0.0.211"})
	if err != nil {
		t.Fatal(err)
	}
	if m3.Info().CAFingerprint != info.CAFingerprint || m3.leafX.Equal(m.leafX) {
		t.Error("changed hosts should re-issue the leaf under the same CA")
	}
	if _, err := m3.leafX.Verify(x509.VerifyOptions{Roots: pool, DNSName: "10.0.0.211"}); err != nil {
		t.Errorf("new SAN: %v", err)
	}
	// Renewal is due inside the 30-day window.
	m3.now = func() time.Time { return m3.leafX.NotAfter.Add(-10 * 24 * time.Hour) }
	if !m3.needsRenewal(m3.leafX, m3.hosts) {
		t.Error("should renew 10 days before expiry")
	}
	m3.now = time.Now
	if m3.needsRenewal(m3.leafX, m3.hosts) {
		t.Error("fresh leaf should not need renewal")
	}
}

func TestDefaultHosts(t *testing.T) {
	hosts := normalizeHosts(nil)
	if len(hosts) < 2 {
		t.Fatalf("defaults should include hostname/addresses and localhost: %v", hosts)
	}
	found := false
	for _, h := range hosts {
		if h == "localhost" {
			found = true
		}
	}
	if !found {
		t.Error("localhost missing")
	}
}
