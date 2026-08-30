package enrich

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestMHRLookup(t *testing.T) {
	var asked []string
	m := &MHR{LookupTXT: func(_ context.Context, name string) ([]string, error) {
		asked = append(asked, name)
		switch {
		case strings.HasPrefix(name, "44d88612fea8a8f36de82e1278abb02f."): // EICAR
			return []string{"1788025842 87"}, nil
		case strings.HasPrefix(name, "d41d8cd98f00b204e9800998ecf8427e."):
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
		return nil, errors.New("SERVFAIL")
	}}
	got, err := m.Lookup(context.Background(), "44D88612FEA8A8F36DE82E1278ABB02F")
	if err != nil || got.Status != "listed" || got.Detection == nil || *got.Detection != 87 || got.LastSeen == nil || got.LastSeen.Year() != 2026 {
		t.Fatalf("listed: %+v %v", got, err)
	}
	if asked[0] != "44d88612fea8a8f36de82e1278abb02f.malware.hash.cymru.com" {
		t.Errorf("query name: %s", asked[0])
	}
	got, err = m.Lookup(context.Background(), "d41d8cd98f00b204e9800998ecf8427e")
	if err != nil || got.Status != "clean" {
		t.Fatalf("nxdomain should be clean: %+v %v", got, err)
	}
	if _, err = m.Lookup(context.Background(), "ffffffffffffffffffffffffffffffff"); err == nil {
		t.Error("resolver failure must be an error, not a verdict")
	}
	if _, err = m.Lookup(context.Background(), "abc"); err == nil {
		t.Error("bad hash length must be rejected")
	}
}
