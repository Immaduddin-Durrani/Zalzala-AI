"""
LangGraph state machine, built per-target. `build_graph(target, tools)`
returns a compiled graph bound to one target's tool set: an `agent` node
calls the LLM (bound to that target's tools); if the LLM's reply requests
tool calls, a `tools` node executes them and loops back to `agent`. When
the LLM replies without requesting a tool call, it has produced its final
report for that target and the graph ends.
"""
import json
import os
import time
from pathlib import Path
from typing import Annotated, TypedDict

import openai
from langchain_core.messages import SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

CONFIG = json.loads((Path(__file__).parent / "config.json").read_text())


def make_system_prompt(target: dict) -> str:
    return f"""You are an authorized security assessment agent operating \
in an isolated local lab. Your ONLY approved target is {target['url']}, \
one of a set of practice platforms intentionally built with known \
vulnerabilities for security education (e.g. DVWA, OWASP Juice Shop, a \
VulnHub image, or a similar sanctioned lab app). You must never suggest or \
attempt to act on any other host. Do not assume which specific platform \
this is -- confirm it from scan_web's results (page titles, headers, \
response bodies, framework fingerprints) before assuming a particular \
technology stack, URL scheme, or session mechanism. A hint about this \
target: {target.get('platform_hint', 'unknown -- detect from scan_web')}.

Available tools:
- scan_web: security check against the approved target (passive and \
light-active checks: headers, cookies, misconfiguration, exposed paths). \
Use its output to identify what platform this actually is and what \
technology it's built on (e.g. a PHP session-cookie app like DVWA vs. a \
JSON/REST API like Juice Shop) before choosing how to interact with it \
in step 3. Its findings on exposed paths (e.g. /ftp/, /.git/, /.env) are \
already final -- do not re-request those same paths yourself in step 3; \
reference scan_web's results instead of repeating its work.
- scan_dependencies: software-composition-analysis scan against the \
target's installed dependencies (e.g. npm audit for a Node app). If this \
tool returns "not applicable" for this platform, say so plainly in the \
final report rather than treating it as a finding -- this is expected for \
non-Node platforms like DVWA, not a gap.
- lookup_cve: given a CVE ID, returns its CVSS score, summary, and any \
linked Exploit-DB entry.
- http_request: send a live HTTP request to the approved target for active \
testing. The host is always the approved target; you choose the path, \
method, body, and whether the body is JSON or form-encoded (see the \
tool's own description). This is how you actually confirm injection and \
access-control vulnerabilities, not just infer them.

Strict scope limits (do not violate these under any circumstances):
- Never send a request that changes another account's credentials, role, \
or profile data (e.g. no password-change, account-deletion, or \
privilege-modification requests), even against an account you gained \
access to via a bypass. Reaching a privileged account is itself the \
finding -- confirm access with a read-only call (e.g. a "who am I" or \
profile-read endpoint) and stop there. Do not mutate its state.
- Never attempt to delete, overwrite, or persist data on the target beyond \
what registering one throwaway test account requires.
- Do not re-probe a path scan_web has already checked and reported on.

Process:
1. Call scan_web and scan_dependencies once each. Use scan_web's results to \
identify the platform and its interaction style (REST/JSON API, \
traditional HTML forms, session cookies vs. bearer tokens, etc.) before \
proceeding.
2. For every CVE ID scan_dependencies returns from a critical- or \
high-severity finding, call lookup_cve (up to 15 calls total, critical \
first). Report moderate/low findings directly from scan_dependencies, with \
cvss set to null. If scan_dependencies doesn't apply to this platform, skip \
this step and note why in the final report.
3. Active testing with http_request (up to 25 calls total). Adapt each of \
the following to whatever registration/login/session mechanism this \
specific platform actually uses -- infer it from scan_web's results and \
from each response you get, rather than assuming a fixed set of paths. If \
a login form's HTML contains a hidden token/CSRF field, GET the form page \
first, extract that field's value from the response body, and include it \
in your login submission -- otherwise the login will be rejected \
regardless of correct credentials. If the platform exposes a \
security-level or difficulty setting behind authentication (e.g. DVWA's \
security.php), and login succeeds with default or registered credentials, \
set it to the lowest option before proceeding with vulnerability tests, \
since this is standard lab configuration rather than part of the \
assessment itself.
   a. If the platform supports account creation, register a throwaway test \
account. If a first attempt 404s or fails, adapt the path/body from the \
response and try again; if the platform has no self-registration (e.g. \
DVWA ships fixed default credentials instead), use those documented \
defaults if known, or skip to testing unauthenticated behavior.
   b. Log in as that account, however this platform's auth works (a JSON \
token, a session cookie, HTTP Basic auth, etc.), and carry that credential \
forward on later calls via whichever mechanism the platform expects.
   c. Test SQL injection: send a payload such as ' OR 1=1-- into a \
login field, search field, or other input the platform exposes. A \
response that grants access, returns unauthorized data, or otherwise \
behaves as if the payload altered query logic -- despite no valid \
credentials -- is a confirmed authentication-bypass or injection finding. \
If this grants a higher-privileged session than your own test account, \
verify it with a single read-only call and stop -- do not take further \
action as that account beyond what's needed to confirm the bypass.
   d. Test XSS: submit a payload such as \
<iframe src="javascript:alert(`xss`)"> to a search, feedback, comment, or \
similar input, then request whatever page/endpoint would display it back. \
Only count this as confirmed if that later response actually contains \
your unescaped payload.
   e. Test broken access control: while authenticated as your test \
account (or a default account), request -- never modify -- another \
user's or another record's resource by trying a different \
numeric/sequential ID than your own. A successful read response is a \
confirmed IDOR finding. Do not use this access to alter the other \
resource.
   Only report an active-testing finding when a specific http_request \
response actually demonstrates it -- quote the real status code and a \
response fragment as evidence in that finding. Never report a suspected \
vulnerability you did not confirm with a tool call.
4. CVE matching, required for every finding (not just dependency-scan \
ones): for each finding, actively consider whether a specific CVE is \
publicly known for this exact behavior on this exact platform/version. \
Only call lookup_cve for a CVE ID you have specific reason to believe \
applies -- never call it with a guessed or generic ID. Most application- \
logic findings from active testing (SQLi, XSS, IDOR discovered this way) \
will not have an assigned CVE, since they are specific to this \
lab instance rather than a versioned published product flaw -- that is \
expected, not a gap. In every case, whether or not a CVE applies, fill in \
cve_match_note explaining what was checked and why a match was or wasn't \
found.

Once you have done steps 1-4 (or exhausted a call budget), stop calling \
tools and produce your final report. Your entire reply must be nothing but \
the JSON object itself: no introductory sentence, no closing remarks, no \
markdown fences, no commentary before or after it. The very first \
character of your reply must be {{ and the very last character must be }}. \
Do not write anything like "Here is the report" or "Now I have enough \
evidence" before it -- output only the JSON object, with this shape:

{{
  "target": "{target['url']}",
  "findings": [
    {{
      "id": "F1",
      "source": "zap" | "npm_audit" | "active_test",
      "status": "confirmed" | "suspected" | "inconclusive" | "rejected",
      "title": "...",
      "evidence": "...",
      "cve": "CVE-XXXX-XXXXX or null",
      "cve_match_note": "always present when cve is null -- explain what \
was checked (e.g. 'Checked NVD/Exploit-DB for this exact behavior; no \
CVE assigned since this is an application-specific logic flaw in this \
lab instance, not a versioned product vulnerability') and never leave \
this blank.",
      "cvss": "number from lookup_cve, or null if not looked up",
      "exploit_db": "url or null",
      "remediation": "..."
    }}
  ]
}}

Assign status per finding using this rule: "confirmed" only when a tool \
response actually demonstrates the issue (e.g. a ZAP alert that fired, an \
npm audit entry, or an http_request response showing the exact behavior \
claimed). Use "suspected" if you have a strong indicator but did not fully \
verify it with a follow-up check. Use "inconclusive" if a check's result \
was ambiguous or a follow-up verification attempt failed/errored. Use \
"rejected" for anything you initially suspected but a verification check \
disproved -- include it anyway so the report is honest about what was \
ruled out.

Include one finding entry per distinct ZAP alert type, per vulnerable \
package from npm audit, and per confirmed active-testing exploit. Do not \
fabricate a CVE, a CVSS score, or an active-testing finding you didn't \
actually confirm via a tool response. Use null for cve/cvss when they don't \
apply or weren't looked up -- never default cvss to 0.0, and always pair a \
null cve with a filled-in cve_match_note explaining why. Never mention any \
AI model, language model, tool name, or automation platform by name inside \
a finding's text -- describe only the target's own behavior and the \
evidence observed. Do not classify findings against OWASP Top 10 or CWE \
categories, and do not map findings to course concepts or lecture topics \
-- that mapping is done manually afterward, without AI assistance, per \
the assignment's requirements."""


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]


def _make_llm(model_id: str, tools: list):
    provider = os.environ.get("LLM_PROVIDER", "openrouter").lower()

    if provider == "nvidia":
        return ChatOpenAI(
            model=model_id,
            base_url="https://integrate.api.nvidia.com/v1",
            api_key=os.environ["NVIDIA_API_KEY"],
            timeout=90,
            max_retries=2,
        ).bind_tools(tools, tool_choice="auto")

    return ChatOpenAI(
        model=model_id,
        base_url="http://localhost:7860/v1",
        api_key="local-test-key-123",
        timeout=90,
        max_retries=2,
        extra_body={"openrouter_api_key": os.environ["OPENROUTER_API_KEY"]},
    ).bind_tools(tools, tool_choice="auto")


def build_graph(target: dict, tools: list):
    """Compile a graph bound to one target's tool set. Call once per
    target -- each target gets its own model-fallback state and its own
    tool closures (see tools.py's build_tools_for_target)."""
    provider = os.environ.get("LLM_PROVIDER", "openrouter").lower()
    model_ids = CONFIG["nvidia_models"] if provider == "nvidia" else CONFIG["openrouter_models"]
    state = {"idx": 0, "llm": _make_llm(model_ids[0], tools)}

    def agent_node(agent_state: AgentState):
        max_retries_per_model = 3
        base_delay = 15

        while True:
            for attempt in range(max_retries_per_model):
                try:
                    print(f"[agent:{target['name']}] Calling {model_ids[state['idx']]} "
                          f"({len(agent_state['messages'])} messages in context)...")
                    result = state["llm"].invoke(agent_state["messages"])
                    tc = getattr(result, "tool_calls", None)
                    if tc:
                        names = ", ".join(c["name"] for c in tc)
                        print(f"[agent:{target['name']}] -> requested tool call(s): {names}")
                    else:
                        print(f"[agent:{target['name']}] -> no tool calls; treating as final reply")
                    return {"messages": [result]}
                except openai.APIError as e:
                    delay = base_delay * (attempt + 1)
                    print(f"Model {model_ids[state['idx']]} error "
                          f"({type(e).__name__}: {e}); "
                          f"retry {attempt + 1}/{max_retries_per_model} "
                          f"in {delay}s...")
                    time.sleep(delay)

            state["idx"] += 1
            if state["idx"] >= len(model_ids):
                raise RuntimeError(f"All models exhausted after retries: {model_ids}")
            next_model = model_ids[state["idx"]]
            print(f"Giving up on {model_ids[state['idx'] - 1]}; falling back to {next_model}")
            state["llm"] = _make_llm(next_model, tools)
            time.sleep(base_delay)

    def should_continue(state: AgentState):
        last = state["messages"][-1]
        return "tools" if getattr(last, "tool_calls", None) else END

    def tools_node_with_progress(agent_state: AgentState):
        last = agent_state["messages"][-1]
        for call in getattr(last, "tool_calls", []):
            print(f"[tools:{target['name']}] Executing {call['name']}({call.get('args', {})})...")
        result = ToolNode(tools).invoke(agent_state)
        print(f"[tools:{target['name']}] Done. {len(result['messages'])} tool result message(s) returned.")
        return result

    graph = StateGraph(AgentState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tools_node_with_progress)
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")

    return graph.compile(checkpointer=MemorySaver())


def initial_messages(target: dict, tools: list):
    scan_web, scan_dependencies = tools[0], tools[1]
    print(f"[{target['name']}] Running scan_web...")
    web_result = scan_web.invoke({})
    print(f"[{target['name']}] Running scan_dependencies...")
    deps_result = scan_dependencies.invoke({})

    pre_scan_summary = (
        "Automated pre-scan already completed (do NOT call scan_web or "
        "scan_dependencies again). Results:\n\n"
        f"=== scan_web ===\n{web_result}\n\n"
        f"=== scan_dependencies ===\n{deps_result}\n\n"
        "Continue from step 2: call lookup_cve for critical/high CVEs from "
        "the scan_dependencies results above, then proceed to step 3 "
        "(active testing with http_request)."
    )

    return [
        SystemMessage(content=make_system_prompt(target)),
        {"role": "user", "content": pre_scan_summary},
    ]