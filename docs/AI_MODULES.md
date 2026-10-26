# AI Modules (analyze, validate, focus, eval, knowledge base)

> Part of the MonkeyX Core docs. See [`../CLAUDE.md`](../CLAUDE.md) for the index.

## AI analysis module (`ai_analyze`)

Uses an AI provider to analyze scan results and produce:
- **Attack Paths** — ONE ranked, de-duplicated playbook. The four recommendation buckets (quick_wins, attack_chains, requires_verification, cve_research) are merged in the report into a single likelihood-ordered list — confirmed/exploitable first, then high- then medium-confidence chains, then detected-unverified, then CVE leads — each tagged with its confidence and rendered as step-by-step commands. (The four buckets remain in `ai-analysis.json` unchanged; `ai_validate`/`focus` still consume them by name — only the report merges them, via `_merge_attack_paths`.)
- **Service inventory** — a deterministic (no-AI) asset list of discovered service/version/port + host counts, built straight from scan data. (This replaced the former LLM "service research" pass: recalling CVEs from version strings is a training-cutoff-bound hallucination risk; CVE assessment now lives in the Attack Paths playbook, grounded in actual scanner findings.)

Reads normalized JSONL from `normalize` + structured JSON from `analyze`. Does
not require a fleet. NOT passthrough under `--dry-run` — it sends scan data to an
external AI provider, so a dry-run synthesizes empty output rather than making
the real call (the AI modules `ai_analyze`/`ai_analyze_gowitness`/`ai_validate`
are all excluded from `_PASSTHROUGH_DRY_RUN` for this reason).

Kwargs: `ai_provider` (override provider), `ai_depth` ("quick"/"standard"/"balanced"/"deep"/"unlimited"), `ai_multipass` (bool). (`ai_analyze` does **not** use provider web search — CVE assessment is grounded in scanner findings, not model recall.)

Output: `{data_prefix}-ai-analysis.json`, `{reports_prefix}-ai-analysis.md`.

**AI egress / anonymization.** With an external provider, `ai_analyze` sends scan
data off-host but **anonymizes the text first** via `core/anonymize.py`: client
IPs→`H1…` and domains→`D1…` are aliased before egress and de-aliased in the
response (the on-disk report has real values; the provider only saw aliases).
`ai_analyze_gowitness` uses the same aliasing for its **text metadata** (URLs,
titles, technologies) — but the **screenshot images it sends are unaltered** and
still carry identifying content (rendered hostnames, logos, page text); a vision
model can't analyze a scrubbed image, so that egress is irreducible. Aliasing is
**text tokens only** — banners, version strings, URL paths, and finding prose
still egress verbatim aside from the IP/domain substrings. The experimental
`ai_validate` does **not** anonymize (raw egress). For zero egress use
the Ollama local provider, or `--dry-run` (all egress modules synthesize).
Authoritative posture + limitations: `docs/AI_DATA_HANDLING.md`.

### Coverage: total-hosts cap + token-aware call packing

Two clearly separated controls (no silent under-coverage on big scopes):
- **`ai_max_hosts`** — the **total** hosts analysed (driven by `ai_depth` presets +
  `unlimited`, or set directly). The coverage/cost ceiling, in the unit operators
  think in. The service inventory is deterministic (no AI call).
- **How those hosts are split across AI calls = automatic, token-aware.** The
  selected hosts (signal-sorted) are packed into as few calls as fit the model's
  context window — each call filled to ~`CONTEXT_FRACTION` (0.5) of the window
  (estimated at ~4 chars/token). So a sparse scope of 1000 lean hosts goes in ONE
  call; a dense one splits. `ai_hosts_per_call` is an optional hard-count override.
- **`ai_context_window`** — tokens; default 1,000,000, auto-dropped to 200,000 on
  **Bedrock** (where the 1M window is a gated beta), detected via `aws_region`.
  Resolution order in `_context_window`: the per-run `ai_context_window` kwarg
  wins; else a **`context_window`** set in the provider's `credentials.yaml` block
  (the environment-level knob — set it once to `1000000` on a Bedrock account that
  HAS the 1M beta so it's never clamped); else the 1M/200k default. `ai_context_fraction`
  tunes the fill level. The assumed window + its source are logged at start.
- **Synthesis pass** (`_synthesize_recommendations`): when >1 call, merges + dedups
  the per-call recommendations, then one AI pass (anonymized) to stitch cross-host
  attack chains and re-rank. Falls back to the plain merge on failure — never loses
  data. Anything dropped by `ai_max_hosts` is reported in `truncation`, not silent.
- **Correlations feed the chaining pass.** The three passes now run
  research → **infrastructure relationships** (`_correlate_findings`) →
  recommendations. The correlation output is summarized (`_correlation_context`,
  already H1/D1-aliased) and injected into BOTH `_generate_recommendations` and the
  synthesis pass, so multi-host `attack_chains` can build on real cross-host
  relationships (shared creds/stack, trust links) instead of only what lands in a
  single token-packed batch. Correlation still runs once over all hosts and is
  stored in the output; reordering it earlier added no extra AI call.
- **Multi-pass (`--multi-pass` / `ai_multipass`, opt-in, OFF by default).** Runs
  the recommendations generation TWICE per batch — a **pure** leg (scan +
  correlations, `use_kb=False`, no knowledge base) and a **KB-grounded** leg —
  then the existing synthesis step reconciles the two result sets (merge, dedup,
  re-rank), surfacing what both legs agree on and catching what a KB-anchored pass
  tunnels past. ~2× the recommendations cost, so gate it on the eval harness.
  Metadata records `kb_references_used` (did the KB actually contribute this run?)
  and a `multipass` block; the report header states the analysis mode + KB usage.
- **Every AI call is logged.** `AIProvider.query`/`query_json` write the system
  prompt + user prompt + response of every call to `logs/ai-interactions.log`
  (the shared egress sink), and each call carries a `log_label` (e.g.
  `recommendations:pure` / `recommendations:kb`) so the multi-pass legs are
  distinguishable in the log rather than a wall of identical entries.

`ai_analyze_gowitness` mirrors this with its own controls: `ai_max_groups` /
`ai_max_singletons` cap the total items analysed (depth + unlimited), items beyond
the cap are reported (`meta.groups_dropped`/`singletons_dropped`), and a text-only
synthesis pass consolidates the visual findings. (Vision is image-bound, not
text-window-bound, so it stays count-batched, not token-packed.)

## AI validation module (`ai_validate`) — ⚠️ EXPERIMENTAL

> **Experimental, opt-in only.** `ai_validate` is never part of a built-in
> workflow — it runs only when explicitly invoked (`-m ai_validate` or
> `--rebuttal`). The agentic loop is unreliable: verdicts can be wrong in either
> direction, so treat them as leads to review, not ground truth. Not recommended
> for unattended use.

Agentic validation of findings from `ai_analyze`. For each recommendation, spawns a Claude tool_use agent loop that actively probes the target to confirm or refute the finding.

**Chain-aware validation:** a recommendation from the `attack_chains` bucket
(tagged `_category == "attack_chain"`, its ordered steps in the `commands` list)
is validated as a **sequence in one agent context** — `_run_agent_loop` swaps in
`SYSTEM_PROMPT_CHAIN` and a seed that enumerates the steps in order, so evidence
confirmed at step 1 (a credential, token, reachable service) carries forward into
step 2 instead of each step being a disconnected single-finding check. The chain
is "confirmed" only if the full sequence is demonstrated on executed commands; if
an early step can't be confirmed the agent reports how far it got (verdict carries
an optional per-step `steps[]` array). The tool-execution, scope/`host_scope`, and
`_guard_verdict` machinery is **identical** to single-finding validation — only
the framing prompt + seed differ, so the authorization ceiling is unchanged.
**Surfacing:** the validation report renders the chain's per-step walk
(`_render_chain_steps` — ✅/❌/⏭️ per step) so a confirmed chain reads as a kill
chain, not just a verdict; and `focus` already lists validated chains (its "plus"
path — multi-host recommendations that map to no single finding row), confirmed-first.

**Category playbooks:** `_classify_finding()` buckets each finding into web / crypto / network, and `_category_playbook()` injects category-specific validation guidance (preferred read-only tools + what actually constitutes proof) into the prompt — steering the agent away from confirming on weak signals (a page merely existing, a version string, an open port).

**Raw-evidence grounding:** validation does not rely only on `ai_analyze`'s prose summary. `_load_evidence_index()` indexes the original `*-normalized.jsonl` scanner records by host, and each finding is given the matching raw records (nuclei `template-id`/`matched-at`, nmap script output, banners — same-port first) in the prompt as the "source of truth". The agent is told to reason over those and lean toward refuting when the raw records don't support the summarized claim. Implementation: `_load_evidence_index()` + `_evidence_for_finding()` in `modules/ai_validate.py`.

**Tools available to the agent:** `curl_request`, `nmap_scan`, `nuclei_scan`, `testssl_check`, `dig_lookup`, `openssl_connect`, `ssh_audit`, `netcat_banner`, `whatweb_scan`, `ffuf_fuzz`, `snmp_check`, `smb_check`.

**Protocol-specific hints (tiered by test safety):** When a finding targets a known protocol/port, a validation checklist is injected into the agent prompt. Checklists are split into a **safe (read-only)** tier that is always included, and an **intrusive (state-changing)** tier that is only included with `--allow-intrusive-validation` (default OFF):
- **SMTP** (25/465/587): *safe* — banner, EHLO capability list, SPF/DMARC lookup, STARTTLS observation. *intrusive* — open-relay test (actually relays mail), VRFY/EXPN enumeration.
- **SNMP** (161/162): *safe* — default READ communities (`public`/`community`), tree walk, version note. *intrusive* — write/SET test with `private`.
- **FTP** (21): *safe* — banner, anonymous login, directory LIST. *intrusive* — STOR upload test (writes to the server).

This keeps ai_validate consistent with its "non-destructive" system prompt by default; state-changing checks require explicit operator opt-in. Hints are triggered by port numbers or protocol keywords in the finding's target/action/commands. Implementation: `_PROTOCOL_HINTS` dict (safe/intrusive keys) + `_get_protocol_hints(finding, allow_intrusive)` in `modules/ai_validate.py`; the flag threads via the `allow_intrusive` kwarg. The system prompt also requires **falsification** (rule out CDN/WAF/default-page/banner explanations) before confirming.

**Scope safety:** `_parse_scope()` (now a thin delegate to
`core.tool_runners.load_scope`) reads the target file + discovery ledger for all
in-scope IPs. Commands targeting out-of-scope IPs are blocked by
`_is_safe_command`. Command execution goes through `_execute_command`, an alias
of `tool_runners.run_argv` (argv list, `shell=False`).

**Command denylist — the "bad attacks" library (`core/attack_policy.py`):**
`_is_safe_command` delegates its command-content check to
`attack_policy.check_command(argv)`, a categorized, operator-extensible denylist
(destructive fs, system control, shell-spawn, reverse-shell, exploit-shell,
credential-spray, persistence, privilege, secret-exfil) that hardens and replaced
ai_validate's old flat `BLOCKED_PATTERNS`. Matching is per-token, case-insensitive
substring (per-token, not joined, because the agent's binaries are fixed by
`_build_command`, so a payload can only arrive smuggled inside one free-text value
token — this avoids cross-token false positives like `useradd` vs the `dd ` disk
pattern). Operators extend/relax it via `~/.monkeyx/attack-policy.yaml`
(`deny:` adds patterns, `allow:` drops a built-in for an authorized op) — see
`attack-policy.yaml.example`. This is the in-process **policy layer** (what may be
attempted); a network-layer containment (egress-firewalled runner) could
complement it later if a headless attacker is pursued, but is not implemented
today. The module is AI-free so any future component (an attacker agent) can share
one policy source.

**Explained validation steps:** every tool schema carries an optional `purpose`
field (injected uniformly over `TOOLS` after definition — `_build_command` reads
argv via explicit `.get()`, so the extra field never reaches the shell), and the
system prompt requires the agent to fill it with a one-sentence "what this checks
and why". Each `tool_history` entry records `purpose` plus the turn's free-text
`reasoning` (the text blocks preceding the tool calls) as a fallback. The report's
"Validation Steps" block prefaces each command with that explanation, so the report
*explains* the steps rather than just listing command+output. Rendering is shared
across the confirmed/refuted/unclear sections via `_render_validation_steps()`.

**Verdict write-back:** each result is joined to the `findings` row(s) `normalize` minted (recomputing the shared `finding_id` from the raw evidence via `_match_finding_ids()`), and the verdict is written to `scan.db` — see "Per-engagement SQLite store".

**Rebuttal pass (`--rebuttal`, opt-in, OFF by default):** an adversarial second
opinion. After the primary validation loop, `_ai_validate_rebuttal.apply_rebuttal_phase()`
spawns an *independent* agent for each **confirmed/refuted** finding, from a
**fresh context** (it does NOT inherit the actor's transcript — so it can escape
a wrong early assumption), tasked with *overturning* the verdict: a confirmed is
challenged as a false positive, a refuted as a missed real issue. It reuses the
same `TOOLS`/`_build_command`/`_is_safe_command` scope + `host_scope` gates, so
it respects the identical authorization ceiling. Reconciliation (`reconcile()`)
is conservative and mirrors `_guard_verdict`: a verdict **flips only to a
confirmed/refuted rebuttal conclusion**, which upstream can only be reached on a
command that actually ran (`_guard_verdict` downgrades an unsupported one to
`unclear`); a disagreeing `unclear`/`error` rebuttal marks the result
`contested` but never flips. Each result gains a `rebuttal` block
(`flipped`/`contested`/`corroborated` + evidence + tool_history), rendered by
`_render_rebuttal`; the reconciled verdict flows into scan.db/JSON/report
unchanged. Roughly doubles ai_validate cost (one extra agent loop per
confirmed/refuted finding), so it is opt-in and NOT wired into the shipped
workflows yet — gate adoption on the eval harness (precision/recall delta with
rebuttal on vs off). Lives in `modules/_ai_validate_rebuttal.py` (leading
underscore → helper, not auto-discovered); folds into the agent-loop file when
`ai_validate` is later split into a package.

**Attempt budget:** each finding gets `max_attempts` tool calls (default 6); a
verdict of "unclear" with "max validation attempts reached" means that budget was
exhausted. Configurable via `modules.ai_validate.max_attempts` in `monkeyx.config`
(int, or `"unlimited"` → a finite `_ATTEMPTS_UNLIMITED` ceiling since each command
is already time-bounded by `MAX_RUNTIME_PER_CMD`). The resolved value is printed at
run start ("up to N probe attempt(s) per finding"). `max_validate` is a separate
control — the number of *findings* validated per run (default 25).

Output: `{data_prefix}-validated-findings.json` (now including `finding_id`/`finding_ids`), `{reports_prefix}-validation-report.md`.

## Focus list (`focus`)

Runs after `ai_validate`. Emits ONE ranked "where do I start" list from data
already produced — **no new AI call**. It answers the tester's real question
("I have limited time, what do my hands touch first?") that the four separate
`ai_analyze` buckets don't answer directly.

**Sources (spine + plus, deduped):**
- **spine** — `scan.db` findings `LEFT JOIN validations` via the new
  `ScanDB.focus_rows()` accessor (one row per finding, latest validation by
  `id`). Filtered to genuine findings via `is_finding_record` (drops info-level
  `script_output` noise) — EXCEPT info findings that were *flagged*: an info
  finding still surfaces when `scan_db.focus_includes_info(verdict, poc)` is true
  (validation reached `confirmed`/`unclear`, or it carries proof). Refuted/
  unverified info stays suppressed. The webserver focus view calls the same
  predicate, so the live view and this report never diverge. Verdict prefers
  `findings.verdict` (the exact join ai_validate writes), else the joined
  validation's verdict.
- **plus** — validated recommendations that map to NO finding row (multi-host
  attack chains, unmapped cve-research). Dedup is a set-membership check on the
  `finding_id`/`finding_ids` ai_validate already recorded — NOT a re-run of the
  hashing join. Entries with a known `finding_id` are skipped (the spine wins).
- **fallback** — if `ai_validate` didn't run (no `validated-findings.json`),
  reads `ai-analysis.json` recommendations directly so the chains still surface
  (all tiered `unverified`; `attack_chains` use their `impact` as severity).

**Sort is confirmed-first:** `(false_positive, verdict_rank, severity_rank,
has_proof)`. A *confirmed* finding outranks an *unverified* higher-severity one;
`refuted`/false-positive rows sink to the bottom (kept for audit, never
dropped). Rank tiers: `confirmed < unclear < unverified/error < refuted`.

Local, no-fleet (`_NO_FLEET_MODULES` + `_PASSTHROUGH_DRY_RUN`). Wired into
`deep` as the final step, after the AI analysis modules.

Output: `{data_prefix}-focus.json`, `{reports_prefix}-focus.md` (leads with a
"Start Here" table of the top 15, then per-item detail with proof + evidence +
`finding_id`). `html_report.py` renders it into `report.html` as the **second
section, right after the Scan Debrief** (`_SECTION_ORDER` — so the report opens
on context, then the focus list, before the deeper analysis sections).

## Evaluation harness (measuring the AI modules)

`core/eval_harness.py` + `tests/corpus/` exist to make AI-module changes
measurable instead of faith-based. A corpus case is a directory with a
`ground_truth.json` (the correct verdicts — confirmed/refuted/unclear — keyed by
host+port+claim) and a `data/` scan snapshot. `score()` / `score_case()` compare
a produced `*-validated-findings.json` against the labels and report
precision / recall / accuracy and a confusion matrix (false confirmations vs.
missed real findings).

The harness is **offline** — it scores already-produced module output, so it runs
in CI with no API key (see `tests/test_eval_harness.py`). Actually running
ai_analyze/ai_validate against a target to produce that output is a separate,
credentialed, out-of-band step. Use it to gate AI-module changes: a change is an
improvement only if it holds/raises recall while raising precision (fewer
false confirmations like a CDN-fronted login panel — the first corpus case,
`tests/corpus/cdn-and-origin`).

## Knowledge base (`~/.monkeyx/knowledge.yaml`)

Provides reference documentation (SOPs, HackTricks, custom notes) to `ai_analyze` and `ai_validate` via prompt injection. Retrieves relevant chunks based on service names, ports, and protocols discovered during scanning.

**Config:** `~/.monkeyx/knowledge.yaml` (see `knowledge.yaml.example` in repo root)
**Index:** `~/.monkeyx/knowledge.db` (SQLite with FTS5)
**Sync:** `monkeyx --sync-knowledge` (clones/pulls git repos, re-indexes all sources)

Source types:
- `type: local` — points at an existing folder (e.g. Obsidian vault). No sync needed.
- `type: git` — sparse or full clone. Syncs on `--sync-knowledge`.

Retrieval strategy: path/filename matching first (exploits HackTricks naming like `pentesting-smtp.md`), FTS5 keyword fallback. User-priority sources rank above community.

Token budgets: configurable per-module via `kb_max_tokens` in `monkeyx.config` (ai_analyze default: 4000, ai_validate default: 2000).

Injection points:
- `ai_analyze._research_services()` — service names from the scan
- `ai_analyze._generate_recommendations()` — port/service keywords from host data
- `ai_validate._run_agent_loop()` — finding target/service/protocol

**Reference attribution (which docs were actually used).** `retrieve_with_refs()`
returns `(formatted_text, refs)` where `refs` is the list of chunks that actually
fit the token budget and were injected — i.e. what the model was shown, the right
thing to attribute. `retrieve()` is a thin wrapper that drops the refs. Callers
surface these as a call-out:
- `ai_analyze` accumulates refs across both passes into
  `metadata.knowledge_references` (order-preserving dedup) — **distinct from
  `metadata.knowledge_sources`**, which lists the *configured* sources whether
  used or not. The markdown report renders a "Knowledge Base References (consulted
  this run)" list.
- `ai_validate` attaches per-finding `kb_references` to each verdict (persisted in
  `validated-findings.json`) and the report renders a "Knowledge Base References"
  call-out under each finding.
The prompt-injected text still instructs the model to inline-cite
`[Source: <source>/<file_path>]`; the refs list is the deterministic, always-present
attribution regardless of whether the model cited.

Implementation: `core/knowledge.py`. The system is fully optional — if no `knowledge.yaml` exists, all retrieval calls return empty strings/empty refs and modules behave identically to before.
