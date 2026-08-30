package api

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Agent distribution: the image carries the agent binaries (built in the Containerfile's agent
// stage) under AGENT_DIST_DIR, and installer scripts that the Agents page turns into one-liners.

//go:embed scripts/install.sh scripts/install.ps1
var installScripts embed.FS

// agentTargets maps a download target to the file name in the dist directory.
var agentTargets = map[string]string{
	"linux-amd64":   "pmacct-agent-linux-amd64",
	"windows-amd64": "pmacct-agent-windows-amd64.exe",
}

type agentBuild struct {
	Target string    `json:"target"`
	File   string    `json:"file"`
	Size   int64     `json:"size"`
	SHA256 string    `json:"sha256"`
	Built  time.Time `json:"built"`
}

var (
	buildCacheMu sync.Mutex
	buildCache   = map[string]agentBuild{} // keyed by path; invalidated by mtime/size
)

func (s *Server) distDir() string {
	if s.Cfg != nil && s.Cfg.AgentDistDir != "" {
		return s.Cfg.AgentDistDir
	}
	return "/app/agent"
}

// buildInfo stats (and hashes, cached) one target; ok=false when the file is absent.
func (s *Server) buildInfo(target string) (agentBuild, bool) {
	file, known := agentTargets[target]
	if !known {
		return agentBuild{}, false
	}
	path := filepath.Join(s.distDir(), file)
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return agentBuild{}, false
	}
	buildCacheMu.Lock()
	defer buildCacheMu.Unlock()
	if b, ok := buildCache[path]; ok && b.Size == st.Size() && b.Built.Equal(st.ModTime()) {
		return b, true
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return agentBuild{}, false
	}
	sum := sha256.Sum256(raw)
	b := agentBuild{Target: target, File: file, Size: st.Size(), SHA256: hex.EncodeToString(sum[:]), Built: st.ModTime()}
	buildCache[path] = b
	return b, true
}

// agentBuilds lists the targets this image can hand out.
func (s *Server) agentBuilds(w http.ResponseWriter, r *http.Request) {
	items := []agentBuild{}
	for _, t := range []string{"linux-amd64", "windows-amd64"} {
		if b, ok := s.buildInfo(t); ok {
			items = append(items, b)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "dir": s.distDir()})
}

// agentDownload serves a binary (or "<target>.sha256": its checksum line).
func (s *Server) agentDownload(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("target")
	wantSum := strings.HasSuffix(target, ".sha256")
	target = strings.TrimSuffix(target, ".sha256")
	b, ok := s.buildInfo(target)
	if !ok {
		writeErr(w, http.StatusNotFound, "no agent build for "+target+" in this image (build with WITH_AGENT=1)")
		return
	}
	if wantSum {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(b.SHA256 + "  " + b.File + "\n"))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+b.File+`"`)
	w.Header().Set("X-Checksum-Sha256", b.SHA256)
	http.ServeFile(w, r, filepath.Join(s.distDir(), b.File))
}

// agentInstallScript serves the installer for the requested platform.
func (s *Server) agentInstallScript(w http.ResponseWriter, r *http.Request) {
	name := "scripts/" + r.PathValue("script")
	raw, err := installScripts.ReadFile(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such installer")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(raw)
}
