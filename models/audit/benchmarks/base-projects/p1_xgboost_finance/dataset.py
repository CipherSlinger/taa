"""
Dataset loader and preprocessor for Credit Card Fraud Detection benchmark.
Handles CSV ingestion, feature normalization, and train/val splitting.
"""

import csv
import math
from typing import Tuple, List, Dict, Any

try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    np = None
    _HAS_NUMPY = False


def load_creditcard_records(csv_path: str) -> Tuple[List[List[float]], List[int], List[str]]:
    """Load credit card fraud detection CSV into feature rows and label list.

    Args:
        csv_path: Path to the creditcard_sample.csv file.

    Returns:
        feature_rows: 2D list of numeric features (Time, V1..V28, Amount).
        label_list: List of binary integer targets (0=normal, 1=fraud).
        column_names: Feature column names.
    """
    feature_rows = []
    label_list = []
    column_names = []

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        column_names = [col.strip() for col in header[:-1]]

        for row in reader:
            if not row:
                continue
            # Parse features (all columns except the last one 'Class')
            feat_vals = [float(val.strip()) for val in row[:-1]]
            target_val = int(float(row[-1].strip()))
            feature_rows.append(feat_vals)
            label_list.append(target_val)

    return feature_rows, label_list, column_names


def normalize_feature_matrix(feature_rows: List[List[float]]) -> List[List[float]]:
    """Apply standard z-score normalization (mean 0, std 1) across features."""
    if not feature_rows:
        return []

    num_rows = len(feature_rows)
    num_cols = len(feature_rows[0])
    normalized = [[0.0] * num_cols for _ in range(num_rows)]

    for c in range(num_cols):
        col_vals = [feature_rows[r][c] for r in range(num_rows)]
        mean_val = sum(col_vals) / float(num_rows)
        variance = sum((v - mean_val) ** 2 for v in col_vals) / float(max(1, num_rows - 1))
        std_val = math.sqrt(variance) if variance > 1e-9 else 1.0

        for r in range(num_rows):
            normalized[r][c] = (feature_rows[r][c] - mean_val) / std_val

    return normalized


def split_train_val_records(
    feature_rows: List[List[float]],
    label_list: List[int],
    val_ratio: float = 0.2,
) -> Tuple[List[List[float]], List[int], List[List[float]], List[int]]:
    """Split records into training and validation sets deterministically."""
    total_count = len(feature_rows)
    val_size = int(total_count * val_ratio)
    split_index = total_count - val_size

    train_feats = feature_rows[:split_index]
    train_lbls = label_list[:split_index]
    val_feats = feature_rows[split_index:]
    val_lbls = label_list[split_index:]

    return train_feats, train_lbls, val_feats, val_lbls
