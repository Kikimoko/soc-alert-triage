"""Run: pytest -q   (needs data/ from src/download_data.sh for the two data-hygiene tests)"""
import sys
from pathlib import Path
import numpy as np, pandas as pd
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import rules as rl, triage_lib as T

def _rule(sel): return {"id": "t", "title": "t", "level": "low", "detection": {"selection": sel, "condition": "selection"}}

def test_rule_operators():
    df = pd.DataFrame({"a": [1, 5, 10], "p": ["tcp", "udp", "tcp"]})
    assert rl.evaluate_rule(_rule({"a|gte": 5}), df).tolist() == [False, True, True]
    assert rl.evaluate_rule(_rule({"a|lt": 5, "p": "tcp"}), df).tolist() == [True, False, False]
    assert rl.evaluate_rule(_rule({"p|in": ["udp"]}), df).tolist() == [False, True, False]
    assert rl.evaluate_rule(_rule({"a|ne": 5}), df).tolist() == [True, False, True]

def test_unknown_field_and_modifier_are_errors():
    df = pd.DataFrame({"a": [1]})
    for sel, exc in [({"nope": 1}, KeyError), ({"a|weird": 1}, ValueError)]:
        try: rl.evaluate_rule(_rule(sel), df); assert False
        except exc: pass

def test_all_shipped_rules_load_and_reference_real_columns():
    cols = pd.read_csv(ROOT / "data/UNSW_NB15_training-set.csv", nrows=5)
    hits = rl.rule_hits(rl.load_rules(ROOT / "rules"), cols)
    assert hits.shape[1] >= 10

def test_workload_metric_random_and_perfect():
    rng = np.random.default_rng(0); y = (rng.random(20000) < 0.3).astype(int)
    assert abs(T.workload_at_recall(y, rng.random(20000), 0.95) - 0.95) < 0.02      # random order ~ review everything
    perfect = T.workload_at_recall(y, y + rng.random(20000) * 0.01, 0.95)
    assert abs(perfect - 0.3 * 0.95) < 0.01                                          # perfect scorer: only true attacks

def test_workload_depends_on_base_rate():
    rng = np.random.default_rng(1); y = (rng.random(20000) < 0.3).astype(int); s = y * 0.6 + rng.random(20000) * 0.7
    assert T.workload_at_recall(y, s, 0.95, 0.01) < T.workload_at_recall(y, s, 0.95, 0.3)

def test_no_identical_flows_shared_between_train_and_test():
    tr, te, st = T.load_data()
    F = [c for c in tr.columns if c not in ("id", "attack_cat", "label")]
    assert len(set(T._hash(tr, F)) & set(T._hash(te, F))) == 0
    assert not tr.duplicated(subset=F).any() and not te.duplicated(subset=F).any()
