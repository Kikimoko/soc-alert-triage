"""End-to-end evaluation of the SOC alert-triage system.  Usage: bash src/download_data.sh && python src/evaluate.py

Protocol
  * official UNSW-NB15 train / test partition (test has a different attack mix => realistic shift)
  * hygiene: dedupe, drop conflicting labels, remove test rows identical to train rows
  * rules reviewed on TRAIN only; model tuned + selected on TRAIN cross-validation only
  * auto-close thresholds chosen from out-of-fold TRAIN predictions, then applied once to TEST
  * workload reported at the observed prevalence AND at realistic SOC base rates (5 %, 1 %)
  * bootstrap 95 % CIs, per-attack-category misses, feature-group ablations
"""
import json, warnings
import numpy as np, pandas as pd
from scipy.stats import loguniform, randint
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, RandomizedSearchCV, cross_val_predict
from sklearn.metrics import roc_auc_score, average_precision_score
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
import triage_lib as T, rules as rl
warnings.filterwarnings("ignore")
SEED = 42; rng = np.random.default_rng(SEED)
R = {}

tr, te, R["data_hygiene"] = T.load_data(); print(R["data_hygiene"])
RULES = rl.load_rules(T.ROOT / "rules")

# ---------- rules: stats on TRAIN only ----------
H = rl.rule_hits(RULES, tr); base = tr.label.mean()
R["rules_train"] = {r["id"]: {"fires": int(H[r["id"]].sum()), "precision": round(float(tr[H[r["id"]]].label.mean()), 3),
                                "attack_recall": round(float(H[r["id"]][tr.label == 1].mean()), 3), "level": r["level"]} for r in RULES}
Ht = rl.rule_hits(RULES, te); any_tr, any_te = H.any(axis=1), Ht.any(axis=1)
R["rules_only_baseline"] = {"train": {"alert_share": round(float(any_tr.mean()), 3), "precision": round(float(tr[any_tr].label.mean()), 3), "recall": round(float(any_tr[tr.label == 1].mean()), 3)},
                            "test": {"alert_share": round(float(any_te.mean()), 3), "precision": round(float(te[any_te].label.mean()), 3), "recall": round(float(any_te[te.label == 1].mean()), 3)}}
print("rules-only", R["rules_only_baseline"])

# ---------- model factories ----------
def make_hgb(fb, X, **kw):
    mask = [c in fb.cat_mask_names for c in X.columns]
    return HistGradientBoostingClassifier(random_state=SEED, categorical_features=mask, **kw)
cv = StratifiedKFold(5, shuffle=True, random_state=SEED)
space = {"learning_rate": loguniform(0.03, 0.3), "max_depth": [None, 4, 8], "l2_regularization": loguniform(1e-3, 10),
         "max_leaf_nodes": randint(15, 63), "min_samples_leaf": randint(20, 200)}

def run_config(name, drop, use_rules):
    fb = FB(drop)
    Xtr, Xte = fb.transform(tr, use_rules), fb.transform(te, use_rules)
    ytr, yte = tr.label.values, te.label.values
    search = RandomizedSearchCV(make_hgb(fb, Xtr), space, n_iter=8, scoring="average_precision", cv=cv, random_state=SEED, n_jobs=1).fit(Xtr, ytr)
    model = search.best_estimator_
    oof = cross_val_predict(model, Xtr, ytr, cv=cv, method="predict_proba")[:, 1]       # out-of-fold TRAIN scores
    s = model.predict_proba(Xte)[:, 1]
    out = {"cv_pr_auc_train": round(float(search.best_score_), 4), "oof_roc_auc_train": round(float(roc_auc_score(ytr, oof)), 4),
           "test_roc_auc": round(float(roc_auc_score(yte, s)), 4), "test_pr_auc": round(float(average_precision_score(yte, s)), 4),
           "best_params": {k: (float(v) if isinstance(v, float) else v) for k, v in search.best_params_.items()}}
    for p_name, p in [("observed", None), ("5%", 0.05), ("1%", 0.01)]:
        out[f"workload_share_to_catch_{p_name}"] = {f"{int(Rr*100)}%_of_attacks": round(T.workload_at_recall(yte, s, Rr, p), 4) for Rr in (0.90, 0.95, 0.99)}
    # auto-close policy: threshold from out-of-fold train scores, applied once to test
    pol = {}
    for Rr in (0.95, 0.99):
        thr = T.threshold_for_recall(ytr, oof, Rr); tpr, fpr = T.operating_point(yte, s, thr)
        pol[f"target_recall_{int(Rr*100)}%"] = {"threshold": round(thr, 4), "train_oof_recall": round(T.operating_point(ytr, oof, thr)[0], 4),
              "test_recall": round(tpr, 4), "test_fpr": round(fpr, 4),
              "auto_closed_share_observed": round(1 - T.queue_share(tpr, fpr, float(yte.mean())), 4),
              "auto_closed_share_5%": round(1 - T.queue_share(tpr, fpr, 0.05), 4), "auto_closed_share_1%": round(1 - T.queue_share(tpr, fpr, 0.01), 4)}
    out["auto_close_policy"] = pol
    return fb, model, Xtr, Xte, s, oof, out

def FB(drop): return T.FeatureBuilder(RULES, drop).fit(tr)

configs = {"A_all_features+rules": ([], True), "B_robust(no testbed-artifact cols)+rules": (T.ARTIFACT, True),
           "C_robust_no_rules": (T.ARTIFACT, False)}
R["configs"], store = {}, {}
for n, (drop, ur) in configs.items():
    fb, m, Xtr, Xte, s, oof, out = run_config(n, drop, ur); R["configs"][n] = out; store[n] = (fb, m, Xtr, Xte, s, oof)
    print(n, {k: v for k, v in out.items() if k in ("cv_pr_auc_train", "oof_roc_auc_train", "test_roc_auc", "test_pr_auc")})
    print("   workload (observed):", out["workload_share_to_catch_observed"], "| at 5%:", out["workload_share_to_catch_5%"])

# ---------- headline config = B (robust). Baselines + CI + per-category ----------
fb, model, Xtr, Xte, s, oof = store["B_robust(no testbed-artifact cols)+rules"]
yte = te.label.values
sev = T.severity_score(RULES, te, rng)
R["baselines_test"] = {"random_review": {f"{int(Rr*100)}%": round(Rr, 4) for Rr in (0.90, 0.95, 0.99)},
                       "rule_severity_ranking_observed": {f"{int(Rr*100)}%": round(T.workload_at_recall(yte, sev, Rr), 4) for Rr in (0.90, 0.95, 0.99)},
                       "rule_severity_ranking_5%": {f"{int(Rr*100)}%": round(T.workload_at_recall(yte, sev, Rr, 0.05), 4) for Rr in (0.90, 0.95, 0.99)},
                       "rule_severity_roc_auc": round(float(roc_auc_score(yte, sev)), 4)}
# logistic-regression comparison (numeric only, log-scaled)
num = fb.num; Xl_tr, Xl_te = np.log1p(tr[num].clip(lower=0)), np.log1p(te[num].clip(lower=0))
lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000)).fit(Xl_tr, tr.label)
sl = lr.predict_proba(Xl_te)[:, 1]
R["baselines_test"]["logistic_regression_roc_auc"] = round(float(roc_auc_score(yte, sl)), 4)
R["baselines_test"]["logistic_regression_workload_observed"] = {f"{int(Rr*100)}%": round(T.workload_at_recall(yte, sl, Rr), 4) for Rr in (0.90, 0.95, 0.99)}

B = 300; idx = [rng.integers(0, len(yte), len(yte)) for _ in range(B)]
def ci(f):
    v = np.array([f(yte[i], s[i]) for i in idx if 0 < yte[i].sum() < len(i)]); return [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)]
R["bootstrap_95ci_headline"] = {"roc_auc": ci(lambda y, x: roc_auc_score(y, x)),
    "workload_95%_observed": ci(lambda y, x: T.workload_at_recall(y, x, 0.95)),
    "workload_95%_at_5%_base_rate": ci(lambda y, x: T.workload_at_recall(y, x, 0.95, 0.05))}
print("CI", R["bootstrap_95ci_headline"])

pol_thr = R["configs"]["B_robust(no testbed-artifact cols)+rules"]["auto_close_policy"]["target_recall_95%"]["threshold"]
missed = te.assign(score=s, closed=s < pol_thr)
per = {}
for c, g in missed[missed.label == 1].groupby("attack_cat"):
    per[c] = {"n": len(g), "missed_when_auto_closing_at_95%_policy": round(float(g.closed.mean()), 3), "rule_alert_recall": round(float(rl.rule_hits(RULES, g).any(axis=1).mean()), 3)}
R["per_attack_category_test"] = per
print("per-category", per)

# permutation importance (drop in ROC-AUC) on a test subsample
from sklearn.inspection import permutation_importance
sub = np.random.default_rng(SEED).choice(len(Xte), 6000, replace=False)
pi = permutation_importance(model, Xte.iloc[sub], yte[sub], n_repeats=3, random_state=SEED, scoring="roc_auc", n_jobs=1)
R["top_features_permutation_roc_auc_drop"] = {k: round(float(v), 4) for k, v in pd.Series(pi.importances_mean, index=Xte.columns).sort_values(ascending=False).head(10).items()}
print(R["top_features_permutation_roc_auc_drop"])

# ---------- figure: analyst effort vs attacks caught ----------
fig, ax = plt.subplots(1, 2, figsize=(11, 4))
for a, p, title in [(ax[0], None, f"Observed test prevalence ({yte.mean():.0%} attacks)"), (ax[1], 0.05, "Realistic SOC base rate (5% attacks)")]:
    rr = np.linspace(0.01, 0.999, 120)
    for lab, sc, sty in [("ML triage (robust features + rules)", s, "-"), ("Rule-severity ranking", sev, "--"), ("Logistic regression", sl, ":")]:
        a.plot([T.workload_at_recall(yte, sc, r, p) for r in rr], rr, sty, label=lab)
    a.plot(rr, rr, "k", lw=.8, label="Random review order"); a.axhline(.95, color="grey", lw=.5)
    a.set(xlabel="Share of the alert queue reviewed", ylabel="Share of attacks caught", title=title, xlim=(0, 1), ylim=(0, 1))
ax[0].legend(fontsize=7, loc="lower right"); plt.tight_layout(); plt.savefig(T.ROOT / "reports/workload_curves.png", dpi=150)

(T.ROOT / "evaluation_results.json").write_text(json.dumps(R, indent=2, default=float))
import joblib
joblib.dump({"model": model, "features": list(Xtr.columns), "feature_builder": fb, "policy_threshold_95": pol_thr,
             "normal_median": tr[tr.label == 0][num].median().to_dict(), "normal_mad": (tr[tr.label == 0][num] - tr[tr.label == 0][num].median()).abs().median().to_dict()},
            T.ROOT / "models_triage.joblib")
print("saved evaluation_results.json, reports/workload_curves.png, models_triage.joblib")
