# -*- coding: utf-8 -*-
"""Run inference with the artifacts saved by DPN.py.

The training script writes `models/` next to its results: one joblib per
estimator, the fitted MICE imputer, and `manifest.json` describing the exact
feature order the estimators were fitted on. This script replays the same
preprocessing — drop the `_无效列` columns, coerce markers to NaN, impute with
the saved imputer (averaged over the same number of posterior draws), rename to
the English feature names — and then predicts.

Usage:
    python3 predict_dpn.py new_data.xlsx
    python3 predict_dpn.py new_data.xlsx --model XGBoost --output /tmp/pred
    python3 predict_dpn.py /opt/taa/input/cases.xlsx --model-dir /opt/taa/output/result/models
"""

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

from DPN import (
    LABEL_COL,
    MICE_ROUNDS,
    OUTPUT_DIR,
    transform_averaged,
)

DEFAULT_MODEL = "CatBoost"
DEFAULT_THRESHOLD = 0.5


def load_manifest(model_dir: str) -> dict:
    """Read the manifest that records the training-time feature contract."""
    path = os.path.join(model_dir, "manifest.json")
    if not os.path.exists(path):
        raise SystemExit(f"manifest not found: {path}")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_model(model_dir: str, name: str, available: list):
    """Load one saved estimator by name."""
    import joblib

    if name not in available:
        raise SystemExit(f"unknown model {name!r}; choose from: {', '.join(available)}")
    path = os.path.join(model_dir, f"{name}.joblib")
    if not os.path.exists(path):
        raise SystemExit(f"model file not found: {path}")
    return joblib.load(path)


def prepare_features(path: str, model_dir: str, manifest: dict) -> tuple:
    """Build the inference matrix exactly as the estimators saw it during training.

    Returns (features, label) where `label` is None when the source file has no
    outcome column.
    """
    df = pd.read_excel(path)
    df = df.drop(columns=[c for c in df.columns if "_无效列" in c], errors="ignore")

    feature_cn = manifest["feature_cn"]
    missing = [c for c in feature_cn if c not in df.columns]
    if missing:
        raise SystemExit(f"input is missing required columns: {missing}")

    label = None
    if LABEL_COL in df.columns:
        label = pd.to_numeric(df[LABEL_COL], errors="coerce").astype("Int64")

    X = df[feature_cn].copy()
    X = X.replace("ND", np.nan)
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    import joblib

    imp = joblib.load(os.path.join(model_dir, "imputer.joblib"))
    X = transform_averaged(imp, X, manifest.get("mice_rounds", MICE_ROUNDS))
    X.columns = manifest["feature_en"]
    return X, label


def main() -> int:
    parser = argparse.ArgumentParser(description="DPN inference using DPN.py artifacts")
    parser.add_argument("input", help="Excel file with the training-time column layout")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"estimator to use (default: {DEFAULT_MODEL})")
    parser.add_argument("--model-dir", default=None,
                        help="directory holding the saved artifacts "
                             "(default: <result dir>/models)")
    parser.add_argument("--output", "-o", default=None,
                        help="output directory (default: $TAA_OUTPUT_DIR or ./predictions)")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"decision threshold for the binary label (default: {DEFAULT_THRESHOLD})")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = os.path.abspath(args.model_dir or os.path.join(OUTPUT_DIR, "models"))
    out_dir = os.path.abspath(args.output or os.environ.get("TAA_OUTPUT_DIR")
                              or os.path.join(script_dir, "predictions"))
    os.makedirs(out_dir, exist_ok=True)

    manifest = load_manifest(model_dir)
    model = load_model(model_dir, args.model, manifest["models"])

    X, label = prepare_features(args.input, model_dir, manifest)
    prob = model.predict_proba(X)[:, 1]
    pred = (prob >= args.threshold).astype(int)

    result = pd.DataFrame({
        "row_id": np.arange(1, len(X) + 1),
        "prob_DPN": np.round(prob, 6),
        "pred_DPN": pred,
    })
    if label is not None and label.notna().all():
        result["label_DPN"] = label.astype(int).values

    stem = os.path.splitext(os.path.basename(args.input))[0]
    csv_path = os.path.join(out_dir, f"{stem}_pred_{args.model}.csv")
    xlsx_path = os.path.join(out_dir, f"{stem}_pred_{args.model}.xlsx")
    result.to_csv(csv_path, index=False, encoding="utf-8-sig")
    result.to_excel(xlsx_path, index=False)

    print(f"model      : {args.model}")
    print(f"samples    : {len(result)}")
    print(f"predicted +: {int(pred.sum())} ({pred.mean():.1%})")
    print(f"prob range : [{prob.min():.4f}, {prob.max():.4f}]")
    if "label_DPN" in result.columns:
        from sklearn.metrics import accuracy_score, roc_auc_score

        y = result["label_DPN"].values
        if len(np.unique(y)) > 1:
            print(f"AUC        : {roc_auc_score(y, prob):.4f}")
        print(f"accuracy   : {accuracy_score(y, pred):.4f}")
    print(f"written    : {csv_path}")
    print(f"             {xlsx_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
