package db

import "testing"

func TestCleanText(t *testing.T) {
	cases := map[string]string{
		"":                      "",
		"Microsoft Corporation": "Microsoft Corporation",
		"Contoso\x00\x00\x00":   "Contoso",
		"A\x00B":                "AB",
		"bad\xffbyte":           "bad\uFFFDbyte",
		"Zürich GmbH\x00":       "Zürich GmbH",
	}
	for in, want := range cases {
		if got := cleanText(in); got != want {
			t.Errorf("cleanText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProgramIdentitySanitize(t *testing.T) {
	p := ProgramIdentity{
		Exe:         `C:\Program Files\App\app.exe`,
		Company:     "Vendor\x00",
		Product:     "Prod\x00uct",
		FileVersion: "1.2.3\x00\x00",
		Description: "desc\xfe",
		Signer:      "Signer\x00",
	}
	p.sanitize()
	if p.Company != "Vendor" || p.Product != "Product" || p.FileVersion != "1.2.3" || p.Signer != "Signer" {
		t.Fatalf("NUL bytes not stripped: %+v", p)
	}
	if p.Description != "desc\uFFFD" {
		t.Fatalf("invalid UTF-8 not replaced: %q", p.Description)
	}
	if p.Exe != `C:\Program Files\App\app.exe` {
		t.Fatalf("clean value changed: %q", p.Exe)
	}
}
