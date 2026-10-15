"""SOAR-style response playbook: ingest -> enrich -> decide -> group -> ticket -> (approval-gated) containment -> audit log.
Runs in DRY-RUN by default: containment commands are written to an approval queue and only 'applied' (to a local blocklist file) with --approve,
and never for allow-listed or internal addresses. The UNSW-NB15 flows carry no IP addresses, so documentation-range IPs (203.0.113.0/24) are
assigned deterministically as a SYNTHETIC source indicator to exercise grouping/containment logic.
Usage: python src/soar.py flows.csv [--n 200] [--out soar_run] [--approve] [--backend template|ollama:<model>]"""
import argparse, hashlib, json, sys, time, ipaddress
from collections import defaultdict
from pathlib import Path
import pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parent))
import triage_lib as T, rules as rl, triage, copilot as C
ALLOWLIST = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "203.0.113.250/32")]     # internal + a pinned 'critical' host

def synth_src(alert_id, pool=40):
    h = int(hashlib.sha256(str(alert_id).encode()).hexdigest(), 16) % pool; return f"203.0.113.{h + 1}"
def allowlisted(ip): return any(ipaddress.ip_address(ip) in n for n in ALLOWLIST)

def run_playbook(rows, out_dir, approve=False, backend=None, window_key=None):
    """rows: DataFrame (triage output joined with flow fields). Returns metrics dict."""
    out = Path(out_dir); (out / "tickets").mkdir(parents=True, exist_ok=True); audit = open(out / "audit_log.jsonl", "w")
    rules = rl.load_rules(T.ROOT / "rules"); rmeta = C.rule_index(rules); backend = backend or C.TemplateSummarizer()
    incidents = defaultdict(list); queue = []; blocked = []; t_all = time.perf_counter(); lat = []; steps = 0
    log = lambda **k: (audit.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **k}) + "\n"))
    for _, r in rows.iterrows():
        t0 = time.perf_counter(); aid = int(r["id"]); src = synth_src(aid)
        ctx = C.build_context(r, r, rmeta); enr = C.enrich(ctx, backend); steps += 3        # ingest, enrich, decide
        log(step="enrich", alert=aid, src=src, model_action=enr["model_action"], final_action=enr["final_action"], policy=ctx["policy_action"])
        if enr["final_action"] == "CLOSE": log(step="auto_close", alert=aid); steps += 1; lat.append(time.perf_counter() - t0); continue
        key = (src, ctx["rules_fired"][0] if ctx["rules_fired"] else "model-only"); incidents[key].append((aid, enr, ctx))      # group into incidents
        lat.append(time.perf_counter() - t0)
    for n, ((src, rule), items) in enumerate(sorted(incidents.items()), 1):
        aid0, enr, ctx = max(items, key=lambda x: x[2]["score"]); sev = max((i[1]["final_action"] for i in items), key=C.ACTIONS.index); iid = f"INC-{n:04d}"
        ticket = {"incident": iid, "severity": sev, "source_indicator(synthetic)": src, "alerts": len(items), "lead_alert": aid0, "trigger_rule": rule, "attack_ids": ctx["attack_ids"],
                  "summary": enr["summary"], "score": ctx["score"], "next_steps": ["Validate in SIEM/EDR", "Check asset criticality", "Decide containment (human approval)"]}
        (out / "tickets" / f"{iid}.json").write_text(json.dumps(ticket, indent=1)); steps += 2; log(step="ticket", incident=iid, alerts=len(items), severity=sev)
        if sev == "ESCALATE":
            cmd = f"iptables -A INPUT -s {src} -j DROP"
            if allowlisted(src): log(step="containment_refused", incident=iid, reason="allowlisted"); continue
            queue.append({"incident": iid, "command": cmd, "status": "AWAITING_APPROVAL"}); steps += 1; log(step="containment_proposed", incident=iid, command=cmd)
            if approve: blocked.append(src); log(step="containment_applied(local blocklist file only)", incident=iid, src=src)
    (out / "approval_queue.json").write_text(json.dumps(queue, indent=1)); (out / "blocklist.txt").write_text("\n".join(sorted(set(blocked))))
    m = {"alerts_ingested": len(rows), "auto_closed": int(sum(1 for _ in rows.itertuples()) - sum(len(v) for v in incidents.values())), "incidents_created": len(incidents),
         "alerts_per_incident_mean": round(sum(len(v) for v in incidents.values()) / max(1, len(incidents)), 2), "containment_proposals": len(queue),
         "containment_applied": len(set(blocked)), "automated_steps": steps, "median_pipeline_latency_ms_per_alert": round(1000 * float(pd.Series(lat).median()), 2),
         "total_runtime_s": round(time.perf_counter() - t_all, 2)}
    audit.close(); (out / "metrics.json").write_text(json.dumps(m, indent=1)); return m

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("csv"); ap.add_argument("--n", type=int, default=200); ap.add_argument("--out", default="soar_run"); ap.add_argument("--approve", action="store_true")
    ap.add_argument("--backend", default="template"); a = ap.parse_args()
    df = pd.read_csv(a.csv).head(a.n); rep = triage.triage(df)
    rows = rep.join(df[[c for c in df.columns if c not in rep.columns]])
    be = C.TemplateSummarizer() if a.backend == "template" else C.OllamaSummarizer(a.backend.split(":", 1)[1])
    print(json.dumps(run_playbook(rows, a.out, a.approve, be), indent=1))
