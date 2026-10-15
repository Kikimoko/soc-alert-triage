"""Load UNSW-NB15 test flows + triage output into a LOCAL Elasticsearch and verify that every exported detection returns
exactly the same number of hits as the local rule engine.  Start Elasticsearch first:  docker compose -f siem/docker-compose.yml up -d
Usage: python siem/load_and_verify.py [--n 20000]    (standard library + pandas only; writes siem/verification.json)
Note: written and unit-tested against the local DSL evaluator; run it against a real Elasticsearch yourself — that live run is what
lets you state 'rules deployed and verified in Elastic'."""
import argparse, json, sys, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import triage_lib as T, rules as rl, triage, siem_export as S
ES = "http://127.0.0.1:9200"
def call(method, path, body=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(ES + path, data, {"Content-Type": "application/x-ndjson" if raw is not None else "application/json"}, method=method)
    return json.loads(urllib.request.urlopen(req, timeout=120).read())
if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--n", type=int, default=20000); a = ap.parse_args()
    _, te, _ = T.load_data(); te = te.head(a.n).copy(); rep = triage.triage(te).sort_index(); te["triage_score"] = rep.score.values; te["triage_decision"] = rep.decision.values
    try: call("DELETE", "/network_flow")
    except Exception: pass
    call("PUT", "/network_flow", {"mappings": {"properties": {"proto": {"type": "keyword"}, "service": {"type": "keyword"}, "state": {"type": "keyword"}, "triage_decision": {"type": "keyword"}}}})
    lines = []
    for _, r in te.iterrows(): lines += [json.dumps({"index": {"_index": "network_flow"}}), json.dumps({k: (v.item() if hasattr(v, "item") else v) for k, v in r.items()})]
    for i in range(0, len(lines), 10000): call("POST", "/_bulk?refresh=false", raw=("\n".join(lines[i:i + 10000]) + "\n").encode())
    call("POST", "/network_flow/_refresh"); res = []; ok = True
    for rule in rl.load_rules(T.ROOT / "rules"):
        local = int(rl.evaluate_rule(rule, te).sum()); es = call("POST", "/network_flow/_count", {"query": S.to_dsl(rule)})["count"]
        res.append({"rule": rule["id"], "local_hits": local, "elastic_hits": es, "match": local == es}); ok &= local == es; print(res[-1])
    Path(__file__).with_name("verification.json").write_text(json.dumps({"flows_loaded": len(te), "all_rules_match": ok, "rules": res}, indent=1)); print("ALL MATCH" if ok else "MISMATCH - investigate")
