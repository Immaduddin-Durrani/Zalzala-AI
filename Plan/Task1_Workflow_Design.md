# Automated Agentic Web Vulnerability Assessment: Task 1 Workflow Design

**Prepared by:** Abdullah Khan Sherwani

**Date:** 16 September 2026

**Environment:** VM environment; DVWA, OWASP Juice Shop, VulnHub

## 1. Objective and Scope
Build an automated, agent-driven pipeline that, given an approved intentionally-vulnerable
target, (a) discovers web vulnerabilities, (b) matches them to published exploits and CVEs,
and (c) produces a structured report, which is then mapped to core web-security concepts.
Execution is fully automated (agentic), not manual step-by-step.

**Scope boundary.** Testing is restricted to sanctioned practice environments only. The system
enforces this in code through a target *allowlist*: any target not on the list is rejected
before any action runs. All components execute inside an isolated Docker network with no route
to external or production hosts. This satisfies the academic-integrity requirement
programmatically, not merely as a stated policy.

## 2. Design Principle
The LLM agent plans, orchestrates, correlates, and reports; deterministic security tools
perform the actual scanning. This keeps results reproducible and auditable, and confines the
model's role to triage and reasoning, the stages where it adds value.

## 3. Pipeline Stages
1. **Scope and guardrails.** Load configuration (targets, credentials, scope), validate against
   the allowlist, and initialise logging and a run ID.
2. **Reconnaissance.** Stack and version fingerprinting (whatweb, nmap) and crawling
   (ZAP spider / katana) to build an inventory of endpoints, parameters, and software versions.
3. **Vulnerability detection (DAST).** Orchestrate OWASP ZAP (active and passive), Nikto
   (server misconfiguration), and Nuclei (template-based, CVE-tagged). Findings are normalised
   into a single schema.
4. **CVE and exploit correlation.** Detected software versions and vulnerability signatures are
   cross-referenced against the NVD API and Exploit-DB (searchsploit). The agent de-duplicates
   findings, maps each to CVE identifiers, ranks by CVSS/EPSS, and filters false positives by
   reasoning about applicability.
5. **Reporting.** Per finding: endpoint, vulnerability class, CVEs, CVSS, evidence, and
   remediation, emitted as JSON and as a human-readable report.
6. **Concept mapping (manual).** Each finding is mapped to OWASP Top 10 / CWE categories. Per the
   task rules, this step is authored without generative AI.

## 4. Agentic Framework and Tooling
- **Orchestration:** LangGraph. A stateful, controllable graph gives an auditable, resumable
  workflow well suited to a security pipeline.
- **Reasoning model:** a free or low-cost model served via OpenRouter (e.g. Gemma) acts as the
  orchestrator, backed by the fallback chain described in Section 7; a local model via Ollama
  serves as the final fallback.
- **Security tools:** nmap, whatweb, OWASP ZAP, Nikto, Nuclei, and sqlmap (used only to confirm
  findings, lab targets only).
- **Data sources:** NVD, Exploit-DB.
- **Integration:** each tool is wrapped as an agent tool that returns the common finding schema.

## 5. Generalization Strategy
The pipeline is target-agnostic. All target-specific information (URL, credentials, scope) lives
in configuration, and every tool is accessed through an adapter that emits the same finding
schema. Adding a new approved target means editing configuration.

## 6. Optional Extension: Fully Agentic Mode
The main design uses a fixed stage order with the model making decisions inside each stage. A
more autonomous variant can run as a parallel mode, where the agent receives the goal and the
toolset and decides the sequence itself.

Main differences:
- Goal-driven loop instead of a fixed graph. The agent reasons, picks a tool, reads the result,
  and chooses the next action until coverage is reached.
- Specialist agents for recon, scanning, correlation, and reporting, coordinated by a supervisor
  over shared state.
- A reflection step that checks endpoint coverage and finding credibility, then loops back if
  gaps remain.
- Termination on coverage targets or on iteration, time, and token budgets.

This mode stays limited to assessment and reporting. It discovers, correlates, and documents
vulnerabilities and does not execute or chain exploits. Any exploitability confirmation remains
a separate, human-approved step using standard tools against the lab instance only. Scope
enforcement wraps every tool call, so the allowlist and network isolation still hold even when
the agent selects its own actions.

## 7. Reliability and Fallback
Free-tier inference is the most common cause of an agent halting mid-run, so resilience is built
into the design:
- **Rate control:** client-side throttling below the provider's per-minute limit, with
  exponential backoff and jitter on HTTP 429 and 5xx responses.
- **Model fallback chain:** primary model, then alternate free model, then OpenRouter
  auto-router, then local Ollama model, rotating on repeated rate-limiting or provider refusal.
- **Checkpointing:** the LangGraph checkpointer persists state so a crash resumes from the last
  completed node rather than restarting the run.
- **Guards:** maximum-iteration and per-step timeout limits prevent stuck loops.
- **Graceful degradation:** if the reasoning step fails entirely, the pipeline falls back to the
  default scan profile and flags the finding for manual triage, so every run completes.

## 8. Deliverables and Timeline
- **16 Sep:** this workflow design (Task 1).
- **17 Sep:** execute the pipeline against approved targets; collect findings and CVE mappings.
- **18 Sep:** generalized working model plus full report, including the manual concept-mapping
  section.

## 9. Safety and Integrity Controls
Allowlist enforcement, network isolation, complete action logging, rate limiting, and a strict
prohibition on testing any real or production system. The design keeps all activity within
vulnerability *assessment and reporting* on sanctioned targets, the defensive and educational
scope defined by the task.