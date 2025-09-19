import sys
import os
import json
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape

WRAPPER_URL = "http://10.0.12.62:8000/analyze"

console = Console()

def upload_and_get_report(apk_path):
    if not os.path.isfile(apk_path):
        console.print(f"[red]APK file not found: {apk_path}[/red]")
        sys.exit(1)
    console.print(f"[*] Uploading {apk_path} to server...")
    with open(apk_path, "rb") as f:
        files = {"file": (os.path.basename(apk_path), f, "application/vnd.android.package-archive")}
        try:
            response = requests.post(WRAPPER_URL, files=files)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            console.print(f"[red]Server communication error: {e}[/red]")
            sys.exit(1)

def print_static_info(report):
    console.print("[bold yellow]====== APK Information ======[/bold yellow]")
    table = Table(show_header=False)
    for key in ["app_name", "package_name", "version_name", "version_code", "min_sdk", "target_sdk", "main_activity", "size"]:
        table.add_row(key.replace("_", " ").title(), escape(str(report.get(key, "[N/A]"))))
    console.print(table)
    hashes = Table(show_header=False)
    for h in ["md5", "sha1", "sha256"]:
        hashes.add_row(h.upper(), escape(report.get(h, "[N/A]")))
    console.print(hashes)

def print_activities(report):
    activities = report.get("activities", [])
    if activities:
        console.print(Panel.fit("\n".join(f"- {escape(a)}" for a in activities), title="⚙️ Activities"))
    exported = report.get("exported_activities", "")
    if exported:
        console.print(Panel.fit(exported, title="🚪 Exported Activities"))

def print_permissions(report):
    perms = report.get("permissions", {})
    if perms:
        console.print("[bold blue]====== Permissions ======[/bold blue]")
        table = Table()
        table.add_column("Permission")
        table.add_column("Status")
        table.add_column("Description")
        for p, d in perms.items():
            table.add_row(escape(p), escape(d.get("status", "N/A")), escape(d.get("description", "")))
        console.print(table)

def print_vulnerabilities(report):
    sec_issues = []
    appsec = report.get("appsec", {})
    for sv in ["high", "warning", "info"]:
        for issue in appsec.get(sv, []):
            issue['severity'] = sv
            sec_issues.append(issue)
    console.print("[bold red]====== Vulnerabilities ======[/bold red]")
    if not sec_issues:
        console.print("[green]No security issues found.[/green]")
        return
    table = Table()
    table.add_column("Title", style="cyan")
    table.add_column("Severity", style="bold red")
    table.add_column("Description")
    for issue in sec_issues:
        table.add_row(escape(issue.get("title", "[N/A]")), escape(issue.get("severity", "[N/A]").upper()), escape(issue.get("description", "")))
    console.print(table)

def print_insecure_patterns(report):
    console.print("[bold red]====== Insecure Storage & Communication ======[/bold red]")
    storage = detect_insecure_storage(report)
    comm = detect_insecure_communication(report)
    if not storage and not comm:
        console.print("[green]No insecure patterns detected.[/green]")
        return
    for i in storage:
        console.print(f"- [yellow]Storage:[/yellow] {i}")
    for i in comm:
        console.print(f"- [yellow]Communication:[/yellow] {i}")

def print_novelty(novelty):
    console.print("[bold magenta]====== Novelty Analysis ======[/bold magenta]")
    risk = novelty.get("risk", {})
    console.print(f"[yellow]Risk Score:[/yellow] {risk.get('score', 0)}")
    for issue in risk.get("issues", []):
        console.print(f" - {issue}")

    mapped = novelty.get("masvs_mapping", [])
    if mapped:
        table = Table(title="OWASP MASVS Mapping")
        table.add_column("Title", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("MASVS", style="green")
        for item in mapped:
            table.add_row(item["title"], item["severity"], item["masvs"])
        console.print(table)

    grouped = novelty.get("grouped_vulns", {})
    for cat, details in grouped.items():
        if not details["issues"]:
            continue
        panel_text = "\n".join(details["issues"]) + "\n\n[green]Preventive:[/green] " + details["preventive"]
        console.print(Panel(panel_text, title=cat))

    # ---------- Novelty Additions ----------
    if "malware_reputation" in novelty:
        console.print("[bold blue]Malware Reputation:[/bold blue]")
        rep = novelty["malware_reputation"]
        console.print(f"- Hash flagged on {rep.get('source','N/A')}: {rep.get('flagged','No')}")
    if "library_risk" in novelty:
        console.print("[bold blue]Third-Party Library Risks:[/bold blue]")
        for lib, risk in novelty["library_risk"].items():
            console.print(f"- {lib}: {risk}")
    if "privacy_risk" in novelty:
        console.print("[bold blue]Privacy Risks:[/bold blue]")
        for item in novelty["privacy_risk"]:
            console.print(f"- {item}")

# ---------- Insecure Checks remain unchanged (reuse original definitions) ----------
def detect_insecure_storage(report):
    results = []
    # ... (same as before)
    return results

def detect_insecure_communication(report):
    findings = []
    # ... (same as before)
    return findings

def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage:[/red] python client_with_novelty.py <apk_path>")
        sys.exit(1)
    apk = sys.argv[1]
    report = upload_and_get_report(apk)

    with open("raw_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    console.print("[cyan][*] Raw report saved to raw_report.json[/cyan]")

    mobsf_report = report.get("mobsf_report", report)
    print_static_info(mobsf_report)
    print_activities(mobsf_report)
    print_permissions(mobsf_report)
    print_vulnerabilities(mobsf_report)
    print_insecure_patterns(mobsf_report)

    if "novelty" in report:
        print_novelty(report["novelty"])

if __name__ == "__main__":
    main()
