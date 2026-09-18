"""
Orchestrator: starts G0DM0D3 and Juice Shop as background processes,
waits for both to become reachable, then runs the Zalzala AI agent
against them. Logs all three processes' output to timestamped files
under logs/. Run this from D:\Comsec\Assignment 3\ directly.
"""
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

BASE = Path(__file__).parent
G0DM0D3_DIR = BASE / "G0DM0D3"
JUICESHOP_DIR = BASE / "juice-shop"
AGENT_DIR = BASE / "Zalzala-AI" / "agent"
LOGS_DIR = BASE / "logs"
LOGS_DIR.mkdir(exist_ok=True)

TS = datetime.now().strftime("%Y%m%d-%H%M%S")

G0DM0D3_URL = "http://localhost:7860/v1/tier"
JUICESHOP_URL = "http://localhost:3000"


def start_logged(name: str, cmd: list[str], cwd: Path) -> tuple[subprocess.Popen, object]:
    log_path = LOGS_DIR / f"{name}-{TS}.log"
    log_file = open(log_path, "w", encoding="utf-8")
    print(f"Starting {name} (logging to {log_path}) ...")
    proc = subprocess.Popen(
        cmd, cwd=str(cwd), stdout=log_file, stderr=subprocess.STDOUT,
        shell=True,
    )
    return proc, log_file


def wait_until_reachable(name: str, url: str, timeout_s: int = 90) -> None:
    print(f"Waiting for {name} at {url} ...")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if requests.get(url, timeout=2).status_code < 500:
                print(f"{name} is up.")
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError(f"{name} did not become reachable at {url} within {timeout_s}s")


def main() -> None:
    procs: list[tuple[subprocess.Popen, object]] = []
    try:
        g0dm0d3_proc = start_logged("g0dm0d3", ["npm", "run", "api"], G0DM0D3_DIR)
        procs.append(g0dm0d3_proc)

        juiceshop_proc = start_logged("juiceshop", ["npm", "start"], JUICESHOP_DIR)
        procs.append(juiceshop_proc)

        wait_until_reachable("G0DM0D3", G0DM0D3_URL, timeout_s=60)
        wait_until_reachable("Juice Shop", JUICESHOP_URL, timeout_s=120)

        DVWA_URL = "http://localhost/DVWA/login.php"
        try:
            wait_until_reachable("DVWA", DVWA_URL, timeout_s=15)
        except RuntimeError:
            raise RuntimeError(
                "DVWA is not reachable at http://localhost/DVWA. "
                "Start Apache and MySQL from the XAMPP control panel first."
            )

        print("\nBoth services are up. Running the agent...\n")
        agent_log_path = LOGS_DIR / f"agent-{TS}.log"
        with open(agent_log_path, "w", encoding="utf-8") as agent_log:
            agent_proc = subprocess.Popen(
                [sys.executable, "-u", "main.py"],
                cwd=str(AGENT_DIR),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in agent_proc.stdout:
                print(line, end="")
                agent_log.write(line)
            agent_proc.wait()

        if agent_proc.returncode != 0:
            print(f"\nAgent exited with code {agent_proc.returncode}. See {agent_log_path}")
        else:
            print(f"\nAgent run complete. Full log: {agent_log_path}")
            print(f"Report: {AGENT_DIR / 'output' / 'report.json'}")

    except Exception as e:
        print(f"\nRun failed: {e}")

    finally:
        print("\nShutting down G0DM0D3 and Juice Shop...")
        for proc, log_file in procs:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            log_file.close()
        print("Done.")


if __name__ == "__main__":
    main()