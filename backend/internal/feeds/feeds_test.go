package feeds

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := `# comment
8.8.8.8
1.2.3.0/24 ; inline
203.0.113.5,extra,columns
2024-01-01 00:00:00,45.9.148.7,443
10.0.0.1
192.168.1.1
2001:db8::/32
not-an-ip
8.8.8.8
`
	nets, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	// 8.8.8.8/32, 1.2.3.0/24, 203.0.113.5/32, 45.9.148.7/32 (from column 2), 2001:db8::/32 ; privates + garbage + dup dropped
	got := strings.Join(nets, " ")
	if len(nets) != 5 || !strings.Contains(got, "8.8.8.8/32") || !strings.Contains(got, "1.2.3.0/24") || !strings.Contains(got, "45.9.148.7/32") || strings.Contains(got, "10.0.0.1") || strings.Contains(got, "192.168") {
		t.Errorf("parse: %v", nets)
	}
}
