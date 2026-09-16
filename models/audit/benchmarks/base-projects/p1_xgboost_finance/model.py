"""
XGBoost tabular classifier module with standalone fallback implementation.
Provides training, probabilistic inference, and artifact serialization.
"""

import json
import math
import os
from typing import List, Dict, Any, Optional

try:
    import xgboost as xgb
    _HAS_XGBOOST = True
except ImportError:
    xgb = None
    _HAS_XGBOOST = False


class FinancialFraudClassifier:
    """Gradient boosted tabular classifier for financial fraud detection."""

    def __init__(
        self,
        n_estimators: int = 50,
        max_depth: int = 3,
        learning_rate: float = 0.05,
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.is_fitted = False

        if _HAS_XGBOOST:
            self.model = xgb.XGBClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                learning_rate=self.learning_rate,
                eval_metric="logloss",
                random_state=42,
            )
        else:
            # Standalone linear logistic regression fallback
            self.model = None
            self.coef_list: List[float] = []
            self.bias_val: float = 0.0

    def fit(self, feature_rows: List[List[float]], label_list: List[int]) -> "FinancialFraudClassifier":
        """Fit classifier on training feature matrix and binary labels."""
        if not feature_rows:
            return self

        if _HAS_XGBOOST:
            self.model.fit(feature_rows, label_list)
        else:
            num_samples = len(feature_rows)
            num_features = len(feature_rows[0])
            self.coef_list = [0.0] * num_features
            self.bias_val = 0.0

            # Lightweight gradient descent optimization
            step_size = self.learning_rate
            for _ in range(self.n_estimators * 4):
                grad_coef = [0.0] * num_features
                grad_bias = 0.0
                for r in range(num_samples):
                    linear_val = self.bias_val + sum(
                        self.coef_list[c] * feature_rows[r][c] for c in range(num_features)
                    )
                    prob_val = 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, linear_val))))
                    diff = prob_val - float(label_list[r])
                    grad_bias += diff
                    for c in range(num_features):
                        grad_coef[c] += diff * feature_rows[r][c]

                self.bias_val -= (step_size / num_samples) * grad_bias
                for c in range(num_features):
                    self.coef_list[c] -= (step_size / num_samples) * grad_coef[c]

        self.is_fitted = True
        return self

    def predict_proba(self, feature_rows: List[List[float]]) -> List[float]:
        """Compute predicted fraud probability for each feature row."""
        if not self.is_fitted:
            raise RuntimeError("Classifier must be fitted before calling predict_proba")

        if _HAS_XGBOOST:
            probs = self.model.predict_proba(feature_rows)
            return [float(p[1]) for p in probs]

        results = []
        num_features = len(self.coef_list)
        for row in feature_rows:
            linear_val = self.bias_val + sum(
                self.coef_list[c] * row[c] for c in range(min(len(row), num_features))
            )
            prob_val = 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, linear_val))))
            results.append(prob_val)
        return results

    def predict(self, feature_rows: List[List[float]], threshold: float = 0.5) -> List[int]:
        """Predict binary classification labels based on decision threshold."""
        prob_scores = self.predict_proba(feature_rows)
        return [1 if p >= threshold else 0 for p in prob_scores]

    def save_model_file(self, output_path: str):
        """Save model configuration and learned parameters into a JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        summary_payload = {
            "model_type": "xgboost" if _HAS_XGBOOST else "linear_fallback",
            "n_estimators": self.n_estimators,
            "max_depth": self.max_depth,
            "learning_rate": self.learning_rate,
            "is_fitted": self.is_fitted,
            "coef_summary": self.coef_list[:5] if not _HAS_XGBOOST else [],
            "bias_val": self.bias_val if not _HAS_XGBOOST else 0.0,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(summary_payload, f, indent=2)
