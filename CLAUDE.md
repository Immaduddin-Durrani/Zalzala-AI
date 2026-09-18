# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes, adapted from a
template used across the user's other projects. Merge with any task-specific
instructions given in chat.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial
tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

This matters more here than usual: under deadline pressure the student may
need to hand-patch this code if an AI assistant declines a step. Every file
must stay short enough, and every dependency plain enough, that a human can
read and fix it without re-deriving the design.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

---

## Project Rules

### Scope
Comsec class assignment: an automated, agentic pipeline that scans an
intentionally-vulnerable local target (OWASP Juice Shop, via Docker) and
correlates findings to CVEs/Exploit-DB. Not a product — optimize for a
working, explainable submission, not long-term maintainability.

### Documentation structure
This root `CLAUDE.md` covers project-wide rules. Each folder with its own
distinct concern (`agent/`, `Plan/`) gets its own `CLAUDE.md` describing what
lives there and any folder-specific rules — max ~100 lines each, so it's
something an agent actually loads and reads rather than skips. Update a
folder's `CLAUDE.md` in the same change that makes it stale — never left to
drift. `agent/README.md` remains the human-facing setup/run guide;
`agent/CLAUDE.md` is the coding-context companion to it, not a duplicate.

### Code quality
Follow SOLID and OOP principles where they clarify structure — Single
Responsibility per function/module, Open/Closed via small seams (e.g. the
tool functions in `tools.py`, the model list in `graph.py`), no leaky
abstractions, no duplicated logic. This doesn't override the simplicity
mandate below: a small script with clearly-scoped functions can satisfy
SOLID without a class hierarchy. Reach for a class only when there's real
state to encapsulate (e.g. the model-fallback rotator in `graph.py`); don't
wrap stateless functions in classes for its own sake.

### Simplicity mandate (hard constraint)
- Stdlib + whatever is already in `agent/requirements.txt` only. Don't add a
  new library without flagging it first — every dependency is something that
  may need to be explained or hand-debugged under deadline pressure.
- Flat files over packages: `agent/tools.py`, `agent/graph.py`,
  `agent/main.py`. Don't split further unless a file genuinely outgrows
  being readable in one sitting.
- Functions over classes unless state genuinely requires a class.
- Every external call (Docker, HTTP) fails loudly with a clear message, not
  silently — this is a scanning tool; a wrong silent result is worse than a
  crash.

### Tech stack
- **Language:** Python 3.
- **LLM access:** OpenRouter only, via `langchain-openai`'s `ChatOpenAI`
  pointed at OpenRouter's `base_url` — never a provider hardcoded directly.
  Model IDs live in `config.json` (`openrouter_models`, a fallback list), not
  in code. Free-tier model availability on OpenRouter changes often and has
  already broken this project once — verify a model ID against
  `GET https://openrouter.ai/api/v1/models` before assuming it still exists
  or is still free; don't add one from memory.
- **Orchestration:** LangGraph `StateGraph` (agent node ↔ tools node, looping
  via conditional edges). This project is intentionally agentic — the model
  decides which tool to call and when it's done — because that's the
  assignment's requirement, not a default to reuse elsewhere.
- **Secrets:** `.env` + `python-dotenv`, local only. `.env.example` is the
  committed template; never commit a real key.

### Target and scope enforcement
- The only approved target is whatever `config.json`'s `allowed_targets` /
  `target_url` says. Tools never accept a model-supplied host or container
  name — they always act on the configured target's host, even
  `http_request` (the active-testing tool), which lets the model choose
  path/method/payload but rejects a full URL or a different host outright.
  Adding a new approved target is a config change, not a code change.
- Never point this at a real/production host. Local, intentionally-vulnerable
  practice targets only (Juice Shop/DVWA/VulnHub-class).

### Known environment gotchas (Windows + Docker Desktop)
- `subprocess.run(["npm", ...])` fails on Windows because `npm` is a `.cmd`
  shim — resolve it with `shutil.which("npm")` first.
- The `bkimminich/juice-shop` image is distroless: no shell, no `npm` inside
  it. Use `docker cp` to pull files out of the container's filesystem, never
  `docker exec` with a shell command.
- The Bash tool (Git Bash/MSYS) auto-mangles POSIX-looking absolute paths
  (e.g. `/juice-shop`) before they reach `docker.exe`. This doesn't affect
  Python's own `subprocess` calls — it only matters when testing `docker`
  commands directly from the Bash tool.

### Git workflow
- Commits atomic: one commit = one change.
- No AI co-authorship trailer on commits in this repo, matching the user's
  other projects — commit authorship is the user's name only.

### No-GenAI step
Per the assignment's own rules, the OWASP Top 10 / CWE concept-mapping step
is done by hand, not by the agent or by Claude. `report.json` deliberately
has no category field — don't add one via an LLM call.
