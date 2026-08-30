package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const lolbasSample = `[
 {"Name":"Certutil.exe","Description":"Windows binary used for handling certificates","Commands":[
   {"Command":"certutil -urlcache -split -f http://x/y.exe","Category":"Download","MitreID":"T1105"},
   {"Command":"certutil -encode in out","Category":"Encode","MitreID":"T1027"},
   {"Command":"certutil -decode in out","Category":"Decode","MitreID":"T1140"}],
  "Full_Path":[{"Path":"C:\\Windows\\System32\\certutil.exe"},{"Path":"C:\\Windows\\SysWOW64\\certutil.exe"}],
  "url":"https://lolbas-project.github.io/lolbas/Binaries/Certutil/"},
 {"Name":"Msbuild.exe","Description":"Build tool","Commands":[{"Command":"msbuild x.csproj","Category":"AWL Bypass","MitreID":"T1127.001"}],"Full_Path":[{"Path":"N/A"}]}
]`

const gtfoSample = `{"functions":{"shell":{"label":"Shell","description":"spawns a shell","mitre":["T1059"]},"file-download":{"label":"File download","mitre":["T1105"]},"suid":{"label":"SUID"}},
"contexts":{"unprivileged":{"label":"Unprivileged"}},
"executables":{"curl":{"functions":{"file-download":[{"code":"curl x -o y"}],"file-upload":[{"code":"curl -T"}]}},
"bash":{"functions":{"shell":[{"code":"bash"}],"suid":[{"code":"bash -p"}]}}}}`

func TestParseLOLBAS(t *testing.T) {
	items, err := ParseLOLBAS(strings.NewReader(lolbasSample))
	if err != nil || len(items) != 2 {
		t.Fatalf("parse: %d %v", len(items), err)
	}
	c := items[0]
	if c.Name != "certutil" || c.Display != "Certutil.exe" || strings.Join(c.Functions, ",") != "Decode,Download,Encode" || strings.Join(c.Mitre, ",") != "T1027,T1105,T1140" || len(c.Paths) != 2 || !strings.HasSuffix(c.URL, "/Certutil/") {
		t.Errorf("certutil: %+v", c)
	}
	if m := items[1]; m.Name != "msbuild" || len(m.Paths) != 0 || m.URL != "https://lolbas-project.github.io/lolbas/Binaries/Msbuild/" {
		t.Errorf("msbuild: %+v", m)
	}
}

func TestParseGTFOBins(t *testing.T) {
	items, err := ParseGTFOBins(strings.NewReader(gtfoSample))
	if err != nil || len(items) != 2 {
		t.Fatalf("parse: %d %v", len(items), err)
	}
	if b := items[0]; b.Name != "bash" || strings.Join(b.Functions, ",") != "SUID,Shell" || strings.Join(b.Mitre, ",") != "T1059" || b.URL != "https://gtfobins.org/gtfobins/bash/" || !strings.Contains(b.Description, "suid, shell") {
		t.Errorf("bash: %+v", b)
	}
	// Unknown function ids keep their id as the label.
	if c := items[1]; c.Name != "curl" || strings.Join(c.Functions, ",") != "File download,file-upload" {
		t.Errorf("curl: %+v", c)
	}
}

func TestLOLBinsRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lolbas.json":
			// Twenty entries pass the sanity floor.
			var sb strings.Builder
			sb.WriteString("[")
			for i := 0; i < 20; i++ {
				if i > 0 {
					sb.WriteString(",")
				}
				sb.WriteString(`{"Name":"Bin` + string(rune('a'+i)) + `.exe","Commands":[{"Category":"Execute"}]}`)
			}
			sb.WriteString("]")
			w.Write([]byte(sb.String()))
		case "/api.json":
			w.Write([]byte(gtfoSample)) // only 2 entries: rejected, previous list kept
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	l := &LOLBins{LOLBASURL: srv.URL + "/lolbas.json", GTFOBinsURL: srv.URL + "/api.json"}
	if !l.Due() {
		t.Fatal("first refresh should be due")
	}
	res := l.Refresh(context.Background())
	if r := res["lolbas"]; r.Entries != 20 || r.Error != "" {
		t.Errorf("lolbas: %+v", r)
	}
	if r := res["gtfobins"]; r.Entries != 0 || !strings.Contains(r.Error, "only 2 entries") {
		t.Errorf("gtfobins sanity floor: %+v", r)
	}
	if l.Due() {
		t.Error("not due again right after a refresh")
	}
	// A disabled source is skipped silently.
	l2 := &LOLBins{GTFOBinsURL: ""}
	if res := l2.Refresh(context.Background()); len(res) != 0 {
		t.Errorf("no sources: %+v", res)
	}
}
