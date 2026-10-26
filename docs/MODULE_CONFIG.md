# Module Config (`monkeyx.config`)

> Part of the MonkeyX Core docs. See [`../CLAUDE.md`](../CLAUDE.md) for the index.

## Module config file (`monkeyx.config`)

Per-module defaults live in `monkeyx.config` (YAML). Two locations are read, user-first: `~/.monkeyx/monkeyx.config` takes priority over the repo-root `monkeyx.config`, merged per-module (shallow). This lets you override hardcoded module defaults (wordlists, thread counts, ports, etc.) without editing module code.

```yaml
# monkeyx.config
modules:
  ax_ffuf:
    wordlist: /home/op/lists/seclists/Discovery/Web-Content/raft-large-files.txt
    threads: 80
  ax_feroxbuster:
    wordlist: /home/op/lists/seclists/Discovery/Web-Content/raft-large-directories.txt
  ax_nmap_udp:
    ports: top-500
  ax_nmap_tcp:
    version_intensity: 5    # -sV probe depth 0-9 (nmap default 7; lower = faster)
    vuln_scripts: false     # opt in to the slow/noisy 'vuln and safe' (vulners) set
    max_retries: 3          # nmap --max-retries (its -T4 default ~10)
    # min_rate: 500         # nmap --min-rate pkts/sec (blank = adaptive)
    # timing: T4            # T0-T5;  host_timeout: 60m (per-host cap; lower on huge scopes)
    connect_fallback: false # re-scan up-but-0-port hosts with -sT, over the SAME ports as the
                            # primary scan (the `ports` setting, default top-1000). SYN-filter/
                            # rate-limit (or lost raw-socket) recovery; off by default
    connect_fallback_max_hosts: 32  # cap so a large empty scope can't trigger a slow -sT sweep
  ax_gowitness:
    threads: 2              # Chromium concurrency (forwarded as --threads); cap RAM
  snmp_sweep:
    # READ community strings to try (list OR comma-separated string). Overrides
    # the built-in 19 common defaults. Each is a UDP snmpwalk with its own
    # timeout, so a huge list x many hosts adds real wall-clock.
    communities: [public, private, community, s3cret]
    # community_file: /home/op/lists/snmp-communities.txt   # wordlist (merged in)
  smtp_security:
    skip_relay: false       # true = skip the non-destructive open-relay test
    # relay test issues MAIL FROM/RCPT TO (never DATA) on 25/587; on by default
  ax_dalfox:
    # Bounded by default (skip BAV + dict-mining, cap workers/timeout) so it
    # can't run for hours. See monkeyx.config for the full knob list.
    skip_bav: true
    skip_mining: true       # keeps DOM mining; drops the ~2500-name dictionary
    worker: 30
    req_timeout: 5          # per-request seconds
    timeout: 3600           # wall-clock backstop
  # gau / katana accept config keys today but do not yet read them all
  # (tracked in docs/RELEASE_HARDENING.md NS-6) — set with that caveat in mind.
```

**Priority order** (highest wins):
1. Workflow YAML step args (e.g. `args: {wordlist: ...}` in a workflow file)
2. `monkeyx.config` module defaults
3. Hardcoded defaults in the module Python code

The config file is optional — if it doesn't exist or a module has no entry, the hardcoded defaults are used. Any parameter a module accepts as a kwarg can be set here.

Implementation: `core/config.py` — `load_module_defaults()` reads and caches both files (user overlays repo). `_merge_kwargs()` in `workflows.py` layers config values between base kwargs and workflow step args.
