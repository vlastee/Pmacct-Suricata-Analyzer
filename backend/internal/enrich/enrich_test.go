package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIPAPILookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/json/8.8.8.8":
			w.Write([]byte(`{"status":"success","country":"United States","countryCode":"US","regionName":"California","city":"Mountain View","lat":37.4,"lon":-122.1,"timezone":"America/Los_Angeles","isp":"Google LLC","org":"Google Public DNS","as":"AS15169 Google LLC","asname":"GOOGLE","reverse":"dns.google","mobile":false,"proxy":false,"hosting":true}`))
		case "/json/10.0.0.1":
			w.Write([]byte(`{"status":"fail","message":"private range"}`))
		default:
			w.WriteHeader(429)
		}
	}))
	defer srv.Close()
	p := &IPAPI{BaseURL: srv.URL}
	info, err := p.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if *info.ASN != "AS15169" || *info.ASOrg != "Google LLC" || *info.CountryCode != "US" || !*info.IsHosting || *info.Hostname != "dns.google" {
		t.Errorf("unexpected parse: %+v", info)
	}
	if _, err := p.Lookup(context.Background(), "10.0.0.1"); err == nil {
		t.Error("expected failure for private range")
	}
	if _, err := p.Lookup(context.Background(), "1.2.3.4"); err == nil {
		t.Error("expected error on 429")
	}

	e := &Enricher{Provider: p, ReverseDNS: false}
	r := e.Lookup(context.Background(), "1.2.3.4")
	if r.Status != "failed" || r.Error == nil || r.IP != "1.2.3.4" {
		t.Errorf("enricher should mark failed: %+v", r)
	}
	r = e.Lookup(context.Background(), "8.8.8.8")
	if r.Status != "ok" || *r.Source != "ip-api.com" {
		t.Errorf("enricher should mark ok: %+v", r)
	}
}

func TestIPInfoIOLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"ip":"1.1.1.1","hostname":"one.one.one.one","city":"Brisbane","region":"Queensland","country":"AU","loc":"-27.4,153.0","org":"AS13335 Cloudflare, Inc.","timezone":"Australia/Brisbane"}`))
	}))
	defer srv.Close()
	p := &IPInfoIO{BaseURL: srv.URL, Token: "tok"}
	info, err := p.Lookup(context.Background(), "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if *info.ASN != "AS13335" || *info.CountryCode != "AU" || *info.Lat > -27 || *info.Hostname != "one.one.one.one" {
		t.Errorf("unexpected parse: %+v", info)
	}
}
