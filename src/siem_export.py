"""Export the Sigma-style rules to SIEM query languages so they can be loaded into a SIEM (Elastic KQL + Elastic detection-rule JSON, Splunk SPL).
Field names follow UNSW-NB15 columns, so in a real deployment you map them to your index schema (e.g. ECS) first. Exports are generated here;
they have NOT been loaded into a live Elastic/Splunk instance in this build environment.
Usage: python src/siem_export.py  ->  exported/elastic_rules.ndjson, exported/splunk_searches.spl, exported/rules.kql"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import triage_lib as T, rules as rl
KQL_OP = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}; SEV = {"low": (21, "low"), "medium": (47, "medium"), "high": (73, "high")}
def q(v): return f'"{v}"' if isinstance(v, str) else str(v)
def to_kql(rule):
    parts = []
    for key, val in rule["detection"]["selection"].items():
        f, _, op = key.partition("|")
        if op in KQL_OP: parts.append(f"{f} {KQL_OP[op]} {q(val)}")
        elif op == "ne": parts.append(f"not {f}: {q(val)}")
        elif op == "in" or isinstance(val, list): parts.append("(" + " or ".join(f"{f}: {q(x)}" for x in val) + ")")
        else: parts.append(f"{f}: {q(val)}")
    return " and ".join(parts)
def to_spl(rule):
    parts = []
    for key, val in rule["detection"]["selection"].items():
        f, _, op = key.partition("|")
        if op in KQL_OP: parts.append(f"{f}{KQL_OP[op]}{q(val)}")
        elif op == "ne": parts.append(f"{f}!={q(val)}")
        elif op == "in" or isinstance(val, list): parts.append("(" + " OR ".join(f"{f}={q(x)}" for x in val) + ")")
        else: parts.append(f"{f}={q(val)}")
    return "index=network_flow " + " ".join(parts)
def to_dsl(rule):
    """Elasticsearch query DSL (bool/filter) equivalent of the rule - what the loader actually sends to Elasticsearch"""
    flt, must_not = [], []
    RNG = {"gt": "gt", "gte": "gte", "lt": "lt", "lte": "lte"}
    for key, val in rule["detection"]["selection"].items():
        f, _, op = key.partition("|")
        if op in RNG: flt.append({"range": {f: {RNG[op]: val}}})
        elif op == "ne": must_not.append({"term": {f: val}})
        elif op == "in" or isinstance(val, list): flt.append({"terms": {f: list(val)}})
        else: flt.append({"term": {f: val}})
    return {"bool": {"filter": flt, "must_not": must_not}}
def dsl_mask(dsl, df):
    """tiny local evaluator of the DSL above (used to prove the export is equivalent to the rule engine)"""
    import pandas as pd
    m = pd.Series(True, index=df.index)
    for c in dsl["bool"]["filter"]:
        (kind, body), = c.items(); (f, cond), = body.items()
        if kind == "range": (op, v), = cond.items(); m &= {"gt": df[f] > v, "gte": df[f] >= v, "lt": df[f] < v, "lte": df[f] <= v}[op]
        elif kind == "terms": m &= df[f].isin(cond)
        else: m &= df[f] == cond
    for c in dsl["bool"]["must_not"]:
        (_, body), = c.items(); (f, v), = body.items(); m &= df[f] != v
    return m
if __name__ == "__main__":
    out = T.ROOT / "exported"; out.mkdir(exist_ok=True); rules = rl.load_rules(T.ROOT / "rules"); ndj, spl, kql = [], [], []
    for r in rules:
        k = to_kql(r); sev, name = SEV.get(r.get("level", "low"), SEV["low"])
        techs = [t.split(".", 1)[1].upper() for t in r.get("tags", []) if t.startswith("attack.t")]
        ndj.append(json.dumps({"rule_id": r["id"], "name": r["title"], "description": r.get("description", ""), "type": "query", "language": "kuery", "query": k, "dsl": to_dsl(r), "index": ["network_flow*"],
                               "severity": name, "risk_score": sev, "interval": "5m", "enabled": True, "threat": [{"framework": "MITRE ATT&CK", "technique": [{"id": t.split(".")[0]} for t in techs]}]}))
        spl.append(f"# {r['title']}\n{to_spl(r)}\n"); kql.append(f"{r['id']}: {k}")
    (out / "elastic_rules.ndjson").write_text("\n".join(ndj)); (out / "splunk_searches.spl").write_text("\n".join(spl)); (out / "rules.kql").write_text("\n".join(kql)); print("\n".join(kql))
