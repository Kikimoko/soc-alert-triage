"""Tiny Sigma-style rule engine for network-flow records (pandas).

Rule format (subset of Sigma): YAML with `detection.selection` = {field[|modifier]: value}, all conditions ANDed,
`condition: selection`. Modifiers: gt, gte, lt, lte, in, ne. A bare field means equality (lists mean "in").
"""
from pathlib import Path
import pandas as pd, yaml

OPS = {"gt": lambda s, v: s > v, "gte": lambda s, v: s >= v, "lt": lambda s, v: s < v,
       "lte": lambda s, v: s <= v, "ne": lambda s, v: s != v, "in": lambda s, v: s.isin(v)}

def load_rules(folder):
    rules = []
    for f in sorted(Path(folder).glob("*.yml")):
        r = yaml.safe_load(f.read_text())
        if r.get("detection", {}).get("condition") != "selection":
            raise ValueError(f"{f.name}: only 'condition: selection' is supported")
        rules.append(r)
    return rules

def evaluate_rule(rule, df):
    mask = pd.Series(True, index=df.index)
    for key, val in rule["detection"]["selection"].items():
        field, _, op = key.partition("|")
        if field not in df.columns:
            raise KeyError(f"rule {rule['id']}: unknown field {field!r}")
        if op:
            if op not in OPS: raise ValueError(f"rule {rule['id']}: unsupported modifier {op!r}")
            mask &= OPS[op](df[field], val)
        else:
            mask &= df[field].isin(val) if isinstance(val, list) else (df[field] == val)
    return mask

def rule_hits(rules, df):
    """DataFrame of booleans, one column per rule id."""
    return pd.DataFrame({r["id"]: evaluate_rule(r, df) for r in rules}, index=df.index)
