// Package explain turns what the analyzer already knows about a program and its destinations
// into a deterministic write-up: identity from a knowledge base, destination context from
// enrichment and our own tables, signals, an assessment and OS-specific verification commands.
// No external services beyond a reverse-DNS lookup.
package explain

import (
	"path"
	"strings"
)

// Known is a knowledge-base entry for a well-known program.
type Known struct {
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Expected    string   `json:"expected"`
	Verify      []string `json:"verify,omitempty"`
	// Risk flags how the program's own nature affects the assessment:
	// "" | "interpreter" (identity is the script) | "lolbin" (abusable system utility) | "no-network" (must never talk out).
	Risk string `json:"risk,omitempty"`
}

type kbEntry struct {
	names []string
	k     Known
}

var kb = []kbEntry{
	{[]string{"chrome", "chromium", "chromium-browser", "google chrome", "brave", "brave-browser", "firefox", "firefox-bin", "msedge", "microsoft edge", "opera", "vivaldi", "safari", "librewolf"},
		Known{Title: "Web browser", Category: "browser", Description: "Destinations reflect what the user browses plus the browser's own services (sync, safe-browsing, updates, telemetry).",
			Expected: "CDNs (Cloudflare, Fastly, Akamai), Google/Microsoft/Mozilla services, ad and analytics networks, any site the user visits."}},
	{[]string{"pasta", "pasta.avx2", "passt", "passt.avx2", "slirp4netns", "rootlessport"},
		Known{Title: "User-mode network stack for rootless containers (passt/pasta)", Category: "container-networking",
			Description: "pasta ships with passt and is the default network stack for rootless Podman since 5.0 (it replaced slirp4netns). When a rootless container makes an outbound connection, pasta is the process that opens the socket on the host, so the connection appears to come from pasta rather than from the process inside the container. The .avx2 suffix is just the build optimised for CPUs with AVX2.",
			Expected:    "Whatever the containers behind it do: image pulls (registries behind Cloudflare/Fastly), package updates, application traffic. The container column names the container when the agent could match the destination against the container's own socket table.",
			Verify:      []string{"podman ps --all", "systemctl --user list-units 'podman*'", "podman exec <container> ss -tn"}}},
	{[]string{"podman", "docker", "dockerd", "containerd", "conmon", "crun", "runc", "buildah", "skopeo"},
		Known{Title: "Container runtime / tooling", Category: "container-runtime", Description: "Pulls images and talks to registries; the containers' own traffic shows under their processes or the pasta/slirp proxy.",
			Expected: "docker.io / registry-1.docker.io (Cloudflare), quay.io, ghcr.io (Fastly/GitHub), gcr.io, mirrors."}},
	{[]string{"systemd-resolved", "systemd-resolve", "systemd-timesyncd", "networkmanager", "dhclient", "dhcpcd", "avahi-daemon", "chronyd", "ntpd", "wpa_supplicant", "unbound", "dnsmasq"},
		Known{Title: "System networking service", Category: "system", Description: "Name resolution, time sync or link management.", Expected: "DNS resolvers on 53/853, NTP servers on 123, the local gateway."}},
	{[]string{"snapd", "apt", "apt-get", "aptd", "dpkg", "packagekitd", "unattended-upgr", "unattended-upgrade", "dnf", "yum", "zypper", "pacman", "flatpak", "fwupd", "fwupdmgr", "pip", "pip3", "cargo", "npm", "go"},
		Known{Title: "Package / update manager", Category: "updater", Description: "Fetches package metadata and downloads.", Expected: "Distribution mirrors and CDNs (Canonical/Fastly/Akamai), registries such as crates.io, npmjs (Cloudflare), pypi (Fastly), proxy.golang.org (Google)."}},
	{[]string{"steam", "steamwebhelper", "steam.exe", "steamservice", "steamservice.exe"},
		Known{Title: "Steam client", Category: "gaming", Description: "Valve's store/launcher with an embedded browser (steamwebhelper).", Expected: "Valve (AS32590), Akamai/Cloudflare CDNs for content, LAN discovery of media devices (e.g. Chromecast on 8009)."}},
	{[]string{"discord", "spotify", "slack", "teams", "ms-teams", "zoom", "telegram", "telegram-desktop", "signal-desktop", "whatsapp", "element-desktop"},
		Known{Title: "Messaging / media application", Category: "communication", Description: "Persistent connections to the vendor's realtime services and CDNs.", Expected: "Vendor infrastructure (often on Cloudflare, Google Cloud or AWS), media CDNs."}},
	{[]string{"code", "code.exe", "code - insiders", "codium", "cursor", "claude", "claude.exe", "idea", "pycharm", "goland", "rust-analyzer", "gopls", "copilot"},
		Known{Title: "Developer tool / assistant", Category: "devtools", Description: "Editors, language servers and AI assistants call their vendor APIs and extension marketplaces.", Expected: "Microsoft/GitHub (marketplace, Copilot), Anthropic API (AS399358, api.anthropic.com), JetBrains, package registries."}},
	{[]string{"ssh", "sshd", "scp", "sftp", "rsync", "git", "git-remote-https", "curl", "wget", "aria2c"},
		Known{Title: "Manual network tool", Category: "tooling", Description: "Driven by a user or a script; the destination is whatever was asked for.", Expected: "Anything — judge by the destination and by who ran it."}},
	{[]string{"python", "python3", "python3.12", "python3.13", "python.exe", "node", "node.exe", "java", "javaw", "java.exe", "ruby", "perl", "php", "deno", "bun", "dotnet"},
		Known{Title: "Interpreter / runtime", Category: "runtime", Description: "The program's identity is the script it runs, not the interpreter.", Expected: "Depends entirely on the script; enable command-line reporting (--send-cmdline) to see it.", Risk: "interpreter"}},
	{[]string{"svchost", "svchost.exe"},
		Known{Title: "Windows service host", Category: "windows-system", Description: "Hosts many Windows services (Windows Update, BITS, Delivery Optimization, time, diagnostics…). Which service is talking needs the service name.",
			Expected: "Microsoft (AS8075), Akamai/Edgecast/Level3 CDNs for updates, Delivery Optimization peers on 7680.", Verify: []string{`tasklist /svc /fi "pid eq <pid>"`}}},
	{[]string{"msmpeng", "msmpeng.exe", "mpcmdrun", "mpcmdrun.exe", "smartscreen", "smartscreen.exe", "securityhealthservice"},
		Known{Title: "Microsoft Defender / SmartScreen", Category: "windows-system", Description: "Signature updates and cloud protection lookups.", Expected: "Microsoft (AS8075) — wdcp.microsoft.com, *.update.microsoft.com."}},
	{[]string{"onedrive", "onedrive.exe", "outlook", "outlook.exe", "winword", "excel", "powerpnt", "officeclicktorun", "officeclicktorun.exe", "msedgewebview2", "msedgewebview2.exe", "searchhost", "searchhost.exe", "widgetservice", "widgetservice.exe", "runtimebroker", "runtimebroker.exe", "backgroundtaskhost", "backgroundtaskhost.exe", "explorer", "explorer.exe", "compattelrunner", "compattelrunner.exe", "mousocoreworker", "mousocoreworker.exe", "usoclient", "usoclient.exe", "sihclient", "sihclient.exe", "wsl", "wslhost", "wslhost.exe", "dashost", "dashost.exe", "yourphone", "phoneexperiencehost"},
		Known{Title: "Windows / Microsoft 365 component", Category: "windows-system", Description: "Built-in Windows or Office component with cloud connectivity (sync, updates, telemetry, web content).", Expected: "Microsoft (AS8075, Azure), Akamai."}},
	{[]string{"lsass", "lsass.exe", "winlogon", "winlogon.exe", "csrss", "csrss.exe", "services", "services.exe", "smss", "smss.exe", "wininit", "wininit.exe"},
		Known{Title: "Core Windows process that should not make outbound connections", Category: "windows-core", Description: "These processes never initiate internet connections themselves (lsass may talk to domain controllers on a LAN). Outbound connections from them indicate injection or a spoofed name.",
			Expected: "None beyond domain controllers on the LAN.", Risk: "no-network"}},
	{[]string{"powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe", "wscript", "wscript.exe", "cscript", "cscript.exe", "mshta", "mshta.exe", "rundll32", "rundll32.exe", "regsvr32", "regsvr32.exe", "certutil", "certutil.exe", "bitsadmin", "bitsadmin.exe", "msiexec", "msiexec.exe", "wmic", "wmic.exe"},
		Known{Title: "Scriptable system utility (living-off-the-land binary)", Category: "windows-lolbin", Description: "Legitimate admin tools that malware commonly abuses to download or run payloads. Legitimate use exists (updates, installers, admin scripts).",
			Expected: "Microsoft endpoints for legitimate use; anything else deserves a look — check the command line and parent.", Risk: "lolbin", Verify: []string{`Get-CimInstance Win32_Process -Filter "ProcessId = <pid>" | Select CommandLine, ParentProcessId`}}},
	{[]string{"tailscaled", "tailscale", "wireguard", "wg", "openvpn", "nordvpn", "protonvpn", "mullvad", "zerotier-one", "cloudflared", "warp-svc"},
		Known{Title: "VPN / overlay network client", Category: "vpn", Description: "Encrypted tunnel to the provider's relays or peers; other programs' traffic is hidden inside it.", Expected: "The provider's coordination servers and relays (often on hosting/cloud networks), UDP high ports."}},
	{[]string{"kodi", "plex", "plex media server", "jellyfin", "vlc", "mpv", "youtube", "netflix"},
		Known{Title: "Media player / server", Category: "media", Description: "Streams or serves media; metadata lookups to vendor APIs.", Expected: "Media CDNs, TheMovieDB/TVDB, vendor relay services."}},
	{[]string{"nextcloud", "syncthing", "dropbox", "megasync", "rclone", "restic", "borg", "duplicati"},
		Known{Title: "Sync / backup client", Category: "sync", Description: "Transfers files to a server or peers on a schedule.", Expected: "The configured server or storage provider; Syncthing relays/discovery."}},
	{[]string{"server"},
		Known{Title: "Generic name — identify by path", Category: "unknown", Description: "The process is called just \"server\"; the path, hash and container tell you which one.", Expected: "Depends on the software."}},
}

// Lookup finds the knowledge-base entry for a program by name or executable path.
func Lookup(name, exe string) *Known {
	cands := []string{strings.ToLower(strings.TrimSpace(name)), strings.ToLower(path.Base(strings.ReplaceAll(exe, `\`, "/")))}
	for _, c := range cands {
		if c == "" || c == "." {
			continue
		}
		for _, variant := range []string{c, strings.TrimSuffix(c, ".exe")} {
			for i := range kb {
				for _, n := range kb[i].names {
					if n == variant {
						k := kb[i].k
						return &k
					}
				}
			}
		}
	}
	return nil
}
