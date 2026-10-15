"""Shared code: data hygiene, features, models, workload metrics for the SOC alert-triage project."""
import numpy as np, pandas as pd
from pathlib import Path
from sklearn.metrics import roc_curve
import rules as rl

ROOT = Path(__file__).resolve().parent.parent
TRAIN = ROOT / "data/UNSW_NB15_training-set.csv"
TEST = ROOT / "data/UNSW_NB15_testing-set.csv"
CATS = ["proto", "service", "state"]
# Columns tied to the lab testbed rather than attacker behaviour: TTL values and TCP initial sequence numbers.
ARTIFACT = ["sttl", "dttl", "ct_state_ttl", "stcpb", "dtcpb"]
LEVEL = {"low": 1, "medium": 2, "high": 3, "critical": 4}

def _hash(df, cols):
    return pd.util.hash_pandas_object(df[cols], index=False).values

def load_data():
    """Official UNSW-NB15 train/test with hygiene: dedupe, drop conflicting labels, remove test rows seen in train."""
    tr, te = pd.read_csv(TRAIN), pd.read_csv(TEST)
    F = [c for c in tr.columns if c not in ("id", "attack_cat", "label")]
    st = {"train_raw": len(tr), "test_raw": len(te)}
    tr, te = tr.drop_duplicates(subset=F + ["label"]), te.drop_duplicates(subset=F + ["label"])
    st["train_after_dedupe"], st["test_after_dedupe"] = len(tr), len(te)
    for name in ("tr", "te"):
        d = tr if name == "tr" else te
        bad = d.duplicated(subset=F, keep=False)          # identical features, different labels
        st[f"{'train' if name=='tr' else 'test'}_conflicting_label_rows_removed"] = int(bad.sum())
        d = d[~bad]
        if name == "tr": tr = d
        else: te = d
    leak = np.isin(_hash(te, F), _hash(tr, F))
    st["test_rows_identical_to_a_train_row_removed"] = int(leak.sum())
    te = te[~leak]
    st.update(train_final=len(tr), test_final=len(te), train_attack_share=round(float(tr.label.mean()), 3),
              test_attack_share=round(float(te.label.mean()), 3))
    return tr.reset_index(drop=True), te.reset_index(drop=True), st

class FeatureBuilder:
    """Numeric flow features + categorical codes (unknown category -> 0) + rule-hit features."""
    def __init__(self, rules, drop=()):
        self.rules, self.drop = rules, set(drop)
    def fit(self, df):
        self.cat_levels = {c: {v: i + 1 for i, v in enumerate(sorted(df[c].astype(str).unique()))} for c in CATS}
        self.num = [c for c in df.columns if c not in CATS + ["id", "attack_cat", "label"] and c not in self.drop]
        return self
    def transform(self, df, use_rules=True):
        X = df[self.num].astype(float).copy()
        for c in CATS: X[c] = df[c].astype(str).map(self.cat_levels[c]).fillna(0).astype(int)
        if use_rules:
            H = rl.rule_hits(self.rules, df)
            for c in H: X["rule_" + c] = H[c].astype(int)
            X["n_rules_fired"] = H.sum(axis=1)
            X["max_rule_level"] = H.mul([LEVEL[r["level"]] for r in self.rules], axis=1).max(axis=1)
        return X
    @property
    def cat_mask_names(self): return CATS

def severity_score(rules, df, rng):
    """Baseline analyst heuristic: sum of fired-rule levels, random tie-break."""
    H = rl.rule_hits(rules, df)
    return H.mul([LEVEL[r["level"]] for r in rules], axis=1).sum(axis=1).values + rng.random(len(df)) * 1e-6

# ------------------------- workload metrics -------------------------
def workload_at_recall(y, s, R, p=None):
    """Fraction of the alert queue an analyst must review (top-scored first) to catch a fraction R of attacks.
    p = attack prevalence to evaluate at (defaults to the observed one); FPR/TPR are prevalence-independent."""
    y = np.asarray(y); p = float(y.mean()) if p is None else p
    fpr, tpr, thr = roc_curve(y, s)
    f = float(np.interp(R, tpr, fpr))
    return p * R + (1 - p) * f

def operating_point(y, s, thr):
    y = np.asarray(y); pred = s >= thr
    return float(pred[y == 1].mean()), float(pred[y == 0].mean())      # TPR, FPR

def threshold_for_recall(y, s, R):
    fpr, tpr, thr = roc_curve(y, s)
    return float(thr[np.argmax(tpr >= R)])

def queue_share(tpr, fpr, p):
    return p * tpr + (1 - p) * fpr
