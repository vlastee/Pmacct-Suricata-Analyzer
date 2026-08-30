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
cargo build --release                                   # Linux
cargo build --release --target x86_64-pc-windows-gnu    # Windows (rustup target add …; mingw-w64)
cargo test
```

## Use

```
pmacct-agent enroll --server https://10.0.0.210:8091 --token <enrollment token> --ca-pin <pin>
pmacct-agent install      # register + start the service (root / administrator)
pmacct-agent status       # config, pinned CA, one heartbeat
pmacct-agent uninstall
pmacct-agent snapshot --capture poll                  # current connections with programs
sudo pmacct-agent snapshot --capture ebpf --seconds 10  # live events from the eBPF backend
```

Capture backend: `--capture auto|poll|ebpf` at enroll time (or `capture = "..."` in agent.toml).
`auto` tries eBPF (root, cgroup v2, kernel ≥ 5.8) and falls back to polling.

```
```

Configuration: `/etc/pmacct-agent/agent.toml` (Linux) or `%ProgramData%\pmacct-agent\agent.toml`
(Windows); override with `PMACCT_AGENT_CONFIG` / `PMACCT_AGENT_DIR`. Spool: `<dir>/spool/`.

## Security

* The only trusted root is the server's internal CA fetched at enrollment and verified against
  the `--ca-pin` (SPKI SHA-256 shown on the Agents page). No system roots.
* The agent token is stored 0600 (Linux) in the config; the server keeps only its hash.
* Reported data is metadata: local address, program path/name/user/hash, destination, port,
  protocol, count. Command lines only with `--send-cmdline`.
