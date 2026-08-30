# pmacct-agent

Endpoint agent for pmacct-analyzer: reports **which program** on this machine opened **which
connection**, so the analyzer can show `via chrome.exe (petro)` on alerts and host pages.

```
agent-core/     shared library: wire model, per-minute aggregation, on-disk spool,
                pinned-TLS client, configuration (also the base for future mobile shells)
pmacct-agent/   the desktop agent: Linux eBPF (cgroup connect/sendmsg hooks) and /proc/net
                capture, Windows IP Helper capture, process resolution (exe, user, sha256),
                run loop, enroll/install CLI, systemd unit / Windows service
bpf/            the eBPF program (C, no libbpf dependency) and its compiled object
```

## Build

```
cargo build --release                                   # Linux (glibc, this machine)
cargo build --release --target x86_64-unknown-linux-musl  # Linux, fully static (rustup target add …; musl-tools) — what the analyzer image ships
cargo build --release --target x86_64-pc-windows-gnu    # Windows (rustup target add …; mingw-w64)
cargo test
```

## Use

```
pmacct-agent enroll --server https://10.0.0.210:8091 --token <enrollment token> --ca-pin <pin>
pmacct-agent install      # register + start the service (root / administrator)
pmacct-agent status       # config, pinned CA, one heartbeat
pmacct-agent uninstall
pmacct-agent update [--force]   # install the server's newer build now (auto-update does this itself)
pmacct-agent snapshot --capture poll                  # current connections with programs
sudo pmacct-agent snapshot --capture ebpf --seconds 10  # live events from the eBPF backend
```

Capture backend: `--capture auto|poll|ebpf` at enroll time (or `capture = "..."` in agent.toml).
`auto` tries eBPF (root, cgroup v2, kernel ≥ 5.8) and falls back to polling.

```
```

Configuration: `/etc/pmacct-agent/agent.toml` (Linux) or `%ProgramData%\pmacct-agent\agent.toml`
(Windows); override with `PMACCT_AGENT_CONFIG` / `PMACCT_AGENT_DIR`.

Spool (batches kept while the server is unreachable; bounded to 500 batches **and 50 MiB** by
default — `--spool-max-mb` / `spool_max_mb` — oldest dropped first, oversize batches refused):
`/var/lib/pmacct-agent/spool` (Linux) or `%ProgramData%\pmacct-agent\spool` (Windows). Put it on
the disk you prefer with `enroll --spool-dir DIR` (the installers pass `--spool-dir` /
`-SpoolDir`), `spool_dir` in `agent.toml`, or `PMACCT_AGENT_SPOOL`; the systemd unit's
`ReadWritePaths` follows it. `pmacct-agent status` shows the path, batch count and size.

## Updates

Every events ack carries the server's build for this platform. When the server's version is
newer and both the server policy and `auto_update` in `agent.toml` allow it, the agent downloads
the binary over the pinned connection, verifies the SHA-256, runs `--version` on it, renames the
running binary to `.old`, moves the new one in and restarts the service (systemd / SCM), after a
random delay of up to two minutes. Bump `[workspace.package] version` for every agent change.

## Security

* The only trusted root is the server's internal CA fetched at enrollment and verified against
  the `--ca-pin` (SPKI SHA-256 shown on the Agents page). No system roots.
* The agent token is stored 0600 (Linux) in the config; the server keeps only its hash.
* Reported data is metadata: local address, program path/name/user/hash, destination, port,
  protocol, count. Command lines only with `--send-cmdline`.
