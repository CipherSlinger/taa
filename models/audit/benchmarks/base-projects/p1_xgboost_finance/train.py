"""
Training pipeline for Credit Card Fraud Detection benchmark (P1).
Executes feature preprocessing, model fitting, metric evaluation,
and lifecycle hook invocation.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, List

# Ensure local directory is on import path
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from dataset import (
    load_creditcard_records,
    normalize_feature_matrix,
    split_train_val_records,
)
from model import FinancialFraudClassifier


def calculate_binary_metrics(y_true: List[int], y_prob: List[float], threshold: float = 0.5) -> Dict[str, float]:
    """Compute binary classification metrics: accuracy, precision, recall, f1, and roc_auc."""
    tp = fp = tn = fn = 0
    for t, p in zip(y_true, y_prob):
        pred = 1 if p >= threshold else 0
        if t == 1 and pred == 1:
            tp += 1
        elif t == 0 and pred == 1:
            fp += 1
        elif t == 0 and pred == 0:
            tn += 1
        else:
            fn += 1

    total_items = max(1, len(y_true))
    acc_score = (tp + tn) / float(total_items)
    precision_score = tp / float(tp + fp) if (tp + fp) > 0 else 0.0
    recall_score = tp / float(tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = (
        2.0 * precision_score * recall_score / (precision_score + recall_score)
        if (precision_score + recall_score) > 0
        else 0.0
    )

    # Approximate Wilcoxon-Mann-Whitney AUC calculation
    pos_probs = [p for t, p in zip(y_true, y_prob) if t == 1]
    neg_probs = [p for t, p in zip(y_true, y_prob) if t == 0]
    if pos_probs and neg_probs:
        auc_pairs = 0.0
        for pp in pos_probs:
            for np_val in neg_probs:
                if pp > np_val:
                    auc_pairs += 1.0
                elif pp == np_val:
                    auc_pairs += 0.5
        auc_score = auc_pairs / float(len(pos_probs) * len(neg_probs))
    else:
        auc_score = 0.5

    return {
        "accuracy": round(acc_score, 4),
        "precision": round(precision_score, 4),
        "recall": round(recall_score, 4),
        "f1": round(f1_score, 4),
        "auc": round(auc_score, 4),
    }


def run_training_pipeline(csv_path: str = None, output_dir: str = None) -> Dict[str, Any]:
    """Run full credit card fraud tabular training and evaluation pipeline."""
    if csv_path is None:
        csv_path = str(CURRENT_DIR / "data" / "creditcard_sample.csv")
    if output_dir is None:
        output_dir = str(CURRENT_DIR / "output")

    features_raw, labels_raw, column_names = load_creditcard_records(csv_path)
    features_scaled = normalize_feature_matrix(features_raw)

    train_f, train_l, val_f, val_l = split_train_val_records(features_scaled, labels_raw, val_ratio=0.2)

    classifier = FinancialFraudClassifier(n_estimators=30, max_depth=3, learning_rate=0.08)
    classifier.fit(train_f, train_l)

    val_predictions = classifier.predict_proba(val_f)
    metrics = calculate_binary_metrics(val_l, val_predictions, threshold=0.5)

    os.makedirs(output_dir, exist_ok=True)
    out_model_path = os.path.join(output_dir, "model_fraud_xgb.json")
    classifier.save_model_file(out_model_path)

    print(f"P1 Training complete: F1={metrics['f1']}, AUC={metrics['auc']}")

    # --- TAA Audit Variant Lifecycle Hook ---
    try:
        import benchmark_variant
        benchmark_variant.on_epoch_end(epoch=0, metrics=metrics)
    except (ImportError, AttributeError):
        pass

    return metrics


if __name__ == "__main__":
    run_training_pipeline()
