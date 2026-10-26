# Knowledge Base

The knowledge base feeds your own reference material — SOPs, HackTricks, private
notes — into the AI modules (`ai_analyze`, `ai_validate`) as prompt context.
During a scan MonkeyX retrieves the chunks most relevant to what it found
(service names, ports, protocols) and injects them into the AI prompt, so
recommendations and validations are grounded in *your* playbooks instead of the
model's training data alone.

It is **entirely optional**. With no `~/.monkeyx/knowledge.yaml`, every retrieval
returns nothing and the AI modules behave exactly as they would without it.

## Quick Start

1. Copy the template and edit it:

   ```bash
   cp knowledge.yaml.example ~/.monkeyx/knowledge.yaml
   # edit ~/.monkeyx/knowledge.yaml — add your sources
   ```

2. Build (or refresh) the index:

   ```bash
   monkeyx --sync-knowledge
   ```

   This clones/pulls any `git` sources and re-indexes every source into
   `~/.monkeyx/knowledge.db` (SQLite + FTS5), then exits. Re-run it whenever you
   add a source or want to pull upstream updates.

3. Run the AI modules as usual — retrieval happens automatically:

   ```bash
   monkeyx --continue ./output -m ai_analyze ai_validate
   ```

## Configuration (`~/.monkeyx/knowledge.yaml`)

```yaml
settings:
  max_tokens_per_injection: 4000     # default token budget per AI prompt injection
  # db_path: ~/.monkeyx/knowledge.db # override index location

sources:
  # Local folder — manually maintained (e.g. an Obsidian vault). No sync needed.
  - name: internal-sops
    type: local
    path: ~/pentest-sops/
    priority: user                   # user ranks above community in retrieval
    file_glob: "**/*.md"

  # Git repo, sparse checkout — only pulls the listed subdirectories.
  - name: hacktricks
    type: git
    url: https://github.com/HackTricks-wiki/hacktricks.git
    branch: master
    path: ~/.monkeyx/knowledge/hacktricks
    priority: community
    file_glob: "**/*.md"
    sparse_paths:
      - network-services-pentesting/
      - pentesting-web/
      - linux-hardening/
      - windows-hardening/

  # Full git repo — omit sparse_paths to clone everything.
  # - name: my-notes
  #   type: git
  #   url: https://github.com/youruser/notes.git
  #   branch: main
  #   path: ~/.monkeyx/knowledge/my-notes
  #   priority: user
  #   file_glob: "**/*.md"
```

### Source fields

| Field | Applies to | Meaning |
|---|---|---|
| `name` | all | Unique label for the source. |
| `type` | all | `local` (an existing folder — no sync) or `git` (cloned/pulled by `--sync-knowledge`). |
| `path` | all | Where the files live. For `git`, the local clone destination. |
| `priority` | all | `user` or `community`. `user` sources rank above `community` in retrieval, so your own notes win ties. |
| `file_glob` | all | Which files to index (e.g. `"**/*.md"`). |
| `url` / `branch` | `git` | Repo to clone and branch to track. |
| `sparse_paths` | `git` | Optional list of subdirectories for a sparse checkout — pull only what's relevant instead of the whole repo. Omit to clone everything. |

## How retrieval works

- **Path/filename match first.** The retriever exploits predictable naming (e.g.
  HackTricks' `pentesting-smtp.md`) — a discovered SMTP service on port 25 pulls
  that file directly.
- **FTS5 keyword fallback.** If no filename matches, it runs a full-text search
  over the indexed content by service/port/protocol keywords.
- **Priority ranking.** `user` sources outrank `community` ones, so your SOPs are
  preferred over public references when both match.

Retrieved text is injected at these points:
- `ai_analyze` — when researching discovered services and when generating
  per-host recommendations.
- `ai_validate` — when validating a finding, keyed on its target/service/protocol.

## References in the output

When knowledge-base content informs the analysis, the sources actually consulted
are called out in the reports (not just left to an inline citation):
- **`ai_analyze`** — the AI-analysis report lists **"Knowledge Base References
  (consulted this run)"**: the specific docs whose chunks were injected into the
  prompts. This is distinct from the **"Knowledge Base"** line, which names the
  *configured* sources whether they were used or not. The JSON carries both
  (`metadata.knowledge_references` vs `metadata.knowledge_sources`).
- **`ai_validate`** — each validated finding gets a **"Knowledge Base References"**
  call-out for the docs consulted while validating it (also persisted per-finding
  as `kb_references` in `*-validated-findings.json`).

References reflect the chunks that fit the token budget and were actually shown to
the model. The injected prompt also asks the model to inline-cite
`[Source: <source>/<file>]`; the reference list is the deterministic attribution
that's always present regardless.

## Token budgets

Each injection is capped so KB context doesn't crowd out the scan data. The
default is `settings.max_tokens_per_injection` (4000). Override per-module via
`kb_max_tokens` in [`monkeyx.config`](MODULE_CONFIG.md):

```yaml
# monkeyx.config
modules:
  ai_analyze:
    kb_max_tokens: 4000    # default
  ai_validate:
    kb_max_tokens: 2000    # default
```

## Notes

- The index (`~/.monkeyx/knowledge.db`) is engine-owned and rebuilt by
  `--sync-knowledge`; you never edit it directly.
- `local` sources are read in place on every run — edit the files and the next
  `--sync-knowledge` (or next run, for content already indexed) picks them up.
- Implementation lives in `core/knowledge.py`.
