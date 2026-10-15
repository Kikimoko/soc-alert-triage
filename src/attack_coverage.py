"""MITRE ATT&CK coverage + detection-effectiveness report for the Sigma-style rules and the ML triage policy.
Attack-category -> technique mapping is MY analyst judgement (UNSW-NB15 has no ATT&CK labels) and is editable below.
Two views: (1) tag coverage: is any rule tagged with the technique?  (2) measured detection: share of test flows of that category that any rule / the triage policy flags.
Output: attack_coverage.json, docs/ATTACK_COVERAGE.md"""
import json, sys
from pathlib import Path
import pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parent))
import triage_lib as T, rules as rl, triage, copilot as C
CATEGORY_TO_TECH = {"Reconnaissance": ["T1046", "T1595"], "Analysis": ["T1595", "T1190"], "Fuzzers": ["T1190", "T1499"], "DoS": ["T1498", "T1499"], "Exploits": ["T1190", "T1203"],
                    "Shellcode": ["T1203", "T1059"], "Backdoor": ["T1095", "T1071"], "Worms": ["T1210"], "Generic": ["T1600"]}
TECH_NAMES = {**{k.upper(): v for k, v in C.ATTACK_NAMES.items()}, "T1595": "Active Scanning", "T1499": "Endpoint Denial of Service", "T1059": "Command and Scripting Interpreter", "T1071": "Application Layer Protocol",
              "T1210": "Exploitation of Remote Services", "T1600": "Weaken Encryption"}
if __name__ == "__main__":
    _, te, _ = T.load_data(); rules = rl.load_rules(T.ROOT / "rules"); rmeta = C.rule_index(rules)
    tagged = {}
    for t, m in rmeta.items():
        for a in m["attack"]: tagged.setdefault(a.split(".")[0], []).append(rules[[r["title"] for r in rules].index(t)]["id"])
    H = rl.rule_hits(rules, te); any_rule = H.any(axis=1); rep = triage.triage(te).sort_index(); review = (rep.decision == "REVIEW").values
    rows = []
    for cat, techs in CATEGORY_TO_TECH.items():
        m = (te.attack_cat == cat).values; n = int(m.sum())
        rows.append({"attack_category": cat, "flows": n, "mapped_techniques": techs, "techniques_with_a_tagged_rule": [t for t in techs if t in tagged], "techniques_without_tagged_rule": [t for t in techs if t not in tagged],
                     "flagged_by_any_rule": round(float(any_rule[m].mean()), 3), "kept_for_review_by_ML_policy": round(float(review[m].mean()), 3)})
    covered = {t for v in CATEGORY_TO_TECH.values() for t in v if t in tagged}; allt = {t for v in CATEGORY_TO_TECH.values() for t in v}
    out = {"technique_tag_coverage": {"techniques_in_scope": len(allt), "with_a_tagged_rule": len(covered), "share": round(len(covered) / len(allt), 3)}, "per_category": rows,
           "rule_to_technique": {t: m["attack"] for t, m in rmeta.items()}, "normal_traffic_review_rate(alert_noise)": round(float(review[(te.label == 0).values].mean()), 3)}
    Path(T.ROOT / "attack_coverage.json").write_text(json.dumps(out, indent=1))
    md = ["# ATT&CK coverage and detection effectiveness (test partition, 52,738 flows)\n", f"Tag coverage: **{len(covered)} of {len(allt)}** in-scope techniques have at least one tagged rule ({out['technique_tag_coverage']['share']:.0%}).\n",
          "| Attack category | Flows | Mapped ATT&CK | Tagged rule exists | Flagged by any rule | Kept for review by ML policy |", "|---|---|---|---|---|---|"]
    for r in rows: md.append(f"| {r['attack_category']} | {r['flows']} | {', '.join(r['mapped_techniques'])} | {', '.join(r['techniques_with_a_tagged_rule']) or 'none'} | {r['flagged_by_any_rule']:.0%} | {r['kept_for_review_by_ML_policy']:.0%} |")
    md += ["", f"Benign traffic kept for review (analyst noise): **{out['normal_traffic_review_rate(alert_noise)']:.0%}**.", "", "Gaps: techniques with no tagged rule are detection-engineering backlog items; categories with low rule detection depend on the ML policy alone."]
    Path(T.ROOT / "docs/ATTACK_COVERAGE.md").write_text("\n".join(md)); print("\n".join(md))
