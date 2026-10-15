"""Rank network-flow alerts for an analyst and explain each ranking.

Usage:  python src/triage.py flows.csv [--top 25] [--out report.csv]
Input:  CSV with UNSW-NB15 flow columns (id, proto, service, state, dur, ...). A `label`/`attack_cat` column is ignored
        for scoring (used only to echo ground truth when present, e.g. in the demo).
Output: alerts sorted by priority score, each with REVIEW / AUTO-CLOSE (policy: keep >= 95 % of attacks, chosen on
        out-of-fold training scores) plus the Sigma-style rules that fired and the most unusual features vs normal traffic.
"""
import argparse, sys
from pathlib import Path
import numpy as np, pandas as pd, joblib
sys.path.insert(0, str(Path(__file__).resolve().parent))
import triage_lib as T, rules as rl

def triage(df, bundle=None, top_k_reasons=3):
    bundle = bundle or joblib.load(T.ROOT / "models_triage.joblib")
    fb, model = bundle["feature_builder"], bundle["model"]
    X = fb.transform(df)[bundle["features"]]
    score = model.predict_proba(X)[:, 1]
    R = rl.load_rules(T.ROOT / "rules"); H = rl.rule_hits(R, df)
    titles = {r["id"]: r["title"] for r in R}
    med, mad = pd.Series(bundle["normal_median"]), pd.Series(bundle["normal_mad"]).replace(0, np.nan)
    num = [c for c in fb.num if c in med.index]
    z = ((df[num].astype(float) - med[num]) / (1.4826 * mad[num])).replace([np.inf, -np.inf], np.nan).abs()
    out = pd.DataFrame({"score": score.round(4)}, index=df.index)
    out["decision"] = np.where(score >= bundle["policy_threshold_95"], "REVIEW", "AUTO-CLOSE")
    out["rules_fired"] = [", ".join(titles[c] for c in H.columns if H.at[i, c]) or "-" for i in df.index]
    out["most_unusual_features"] = [", ".join(f"{c} (x{z.at[i, c]:.0f} from normal)" for c in z.loc[i].dropna().sort_values(ascending=False).index[:top_k_reasons]) for i in df.index]
    for c in ("id", "proto", "service", "state", "attack_cat", "label"):
        if c in df.columns: out[c] = df[c]
    return out.sort_values("score", ascending=False)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv"); ap.add_argument("--top", type=int, default=25); ap.add_argument("--out")
    a = ap.parse_args()
    rep = triage(pd.read_csv(a.csv))
    if a.out: rep.to_csv(a.out, index=False)
    n_rev = int((rep.decision == "REVIEW").sum())
    print(f"{len(rep)} alerts -> {n_rev} to review, {len(rep)-n_rev} auto-closed ({(len(rep)-n_rev)/len(rep):.0%})")
    print(rep.head(a.top).to_string(index=False))
