"""
Entry point: for each configured target, brings it up (checks it's
reachable -- doesn't start anything itself), runs the LangGraph agent to
completion, and writes that target's transcript and report to
output/<target>/. A combined output/report.json aggregates every target's
findings at the end.
"""
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

CONFIG = json.loads((Path(__file__).parent / "config.json").read_text())
OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


def extract_json_report(text: str):
    """Try to parse `text` as the agent's final JSON report, tolerating the
    common ways a model's reply strays from pure JSON: markdown code fences,
    or a sentence of commentary before or after the JSON object. Returns
    (report_dict, note) on success -- note is None for a clean direct parse,
    or a short string describing what had to be stripped. Returns
    (None, None) if no valid JSON object could be recovered at all."""
    stripped = text.strip()

    # 1. Clean, direct parse -- the common, expected case.
    try:
        return json.loads(stripped), None
    except json.JSONDecodeError:
        pass

    # 2. Markdown code fence, e.g. ```json ... ``` or ``` ... ```
    if stripped.startswith("```"):
        fenced = stripped.strip("`")
        if fenced.lower().startswith("json"):
            fenced = fenced[4:]
        try:
            return json.loads(fenced.strip()), "stripped a markdown code fence"
        except json.JSONDecodeError:
            pass

    # 3. Leading or trailing prose around the JSON object -- take the
    # outermost {...} span and try that on its own.
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = stripped[start:end + 1]
        try:
            return json.loads(candidate), "stripped leading or trailing text around the JSON object"
        except json.JSONDecodeError:
            pass

    return None, None

def run_target(target: dict) -> dict:
    from tools import ensure_target_running, build_tools_for_target
    from graph import build_graph, initial_messages

    target_output_dir = OUTPUT_DIR / target["name"]
    target_output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n=== Target: {target['name']} ({target['url']}) ===")
    print(f"Checking {target['url']} ...")
    ensure_target_running(target["url"])
    print(f"Target ready at {target['url']}")

    tools = build_tools_for_target(target)
    app = build_graph(target, tools)

    print(f"Running agent against {target['name']}...")
    final_state = app.invoke(
        {"messages": initial_messages(target, tools)},
        config={
            "recursion_limit": CONFIG["max_recursion"],
            "configurable": {"thread_id": f"assessment-{target['name']}"},
        },
    )

    messages = final_state["messages"]
    (target_output_dir / "transcript.json").write_text(
        json.dumps([m.model_dump() if hasattr(m, "model_dump") else m for m in messages],
                   indent=2, default=str),
        encoding="utf-8"
    )

    final_text = messages[-1].content
    (target_output_dir / "report_raw.txt").write_text(final_text, encoding="utf-8")

    report, extraction_note = extract_json_report(final_text)
    if report is not None:
        if extraction_note:
            report["_extraction_note"] = extraction_note
            print(f"{target['name']}: final reply needed cleanup before parsing "
                  f"({extraction_note}).")
        (target_output_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"{target['name']}: {len(report.get('findings', []))} finding(s).")
        return report
    else:
        print(f"{target['name']}: final reply was not valid JSON. "
              f"Raw text saved to output/{target['name']}/report_raw.txt.")
        return {"target": target["url"], "findings": [], "error": "final reply was not valid JSON"}


def main() -> None:
    import os
    provider = os.environ.get("LLM_PROVIDER", "openrouter").lower()
    if provider == "nvidia" and not os.environ.get("NVIDIA_API_KEY"):
        sys.exit("LLM_PROVIDER=nvidia but NVIDIA_API_KEY is not set in agent/.env.")
    if provider != "nvidia" and not os.environ.get("OPENROUTER_API_KEY"):
        sys.exit("Set OPENROUTER_API_KEY in agent/.env (copy .env.example) before running.")

    all_reports = []
    for target in CONFIG["targets"]:
        report = run_target(target)
        all_reports.append(report)

    combined = {"targets": all_reports}
    (OUTPUT_DIR / "report.json").write_text(json.dumps(combined, indent=2), encoding="utf-8")

    total_findings = sum(len(r.get("findings", [])) for r in all_reports)
    print(f"\nAll targets done. {total_findings} total finding(s) across "
          f"{len(all_reports)} target(s). See output/report.json for the "
          f"combined report, or output/<target>/report.json per target.")


if __name__ == "__main__":
    main()