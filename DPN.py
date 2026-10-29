# -*- coding: utf-8 -*-

import os
import sys
import json
import hashlib
import tempfile
import warnings
import zipfile
from datetime import datetime, timezone

warnings.filterwarnings("ignore")


def _bootstrap_bundled_deps() -> None:
    """Expose the wheels shipped next to this script.

    TAA unpacks the model archive verbatim, so `wheels/*.whl` ends up beside this
    file. A wheel carrying native extensions cannot be imported straight out of
    its zip, so the wheels are unpacked once into a cache directory keyed by
    their names and sizes, and that directory is prepended to sys.path. Missing
    `wheels/` is not an error: the interpreter's own site-packages are used.
    """
    wheel_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wheels")
    if not os.path.isdir(wheel_dir):
        return
    wheels = sorted(
        os.path.join(wheel_dir, name)
        for name in os.listdir(wheel_dir)
        if name.endswith(".whl")
    )
    if not wheels:
        return

    digest = hashlib.sha1()
    for path in wheels:
        digest.update(os.path.basename(path).encode())
        digest.update(str(os.path.getsize(path)).encode())
    target = os.path.join(tempfile.gettempdir(), "dpn-deps-" + digest.hexdigest()[:16])

    marker = os.path.join(target, ".complete")
    if not os.path.exists(marker):
        os.makedirs(target, exist_ok=True)
        for path in wheels:
            with zipfile.ZipFile(path) as archive:
                archive.extractall(target)
        open(marker, "w").close()

    if target not in sys.path:
        sys.path.insert(0, target)


_bootstrap_bundled_deps()

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    roc_auc_score, accuracy_score, precision_score, recall_score,
    f1_score, brier_score_loss, roc_curve, precision_recall_curve, auc,
)
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.experimental import enable_iterative_imputer   # noqa: F401
from sklearn.impute import IterativeImputer
from sklearn.linear_model import BayesianRidge
import xgboost as xgb
import lightgbm as lgb
import catboost as cb
import shap

# ============================================================
# 1. 全局配置
# ============================================================
# Original paths (macOS desktop), kept for reference:
# FILE_PATH = "/Users/Zhuanz/Desktop/糖尿病文章修改5月/糖尿病患者合并数据_cleaned 2.xlsx"
# OUTPUT_DIR = "/Users/Zhuanz/Desktop/糖尿病6月投稿修改版/internal_model_v2"

# TAA runtime contract (README: model.input / model.output.*):
#   input    /opt/taa/input                     read-only imported dataset
#   result   /opt/taa/output/result            artifacts (figures, tables)
#   log      /opt/taa/output/log               *.log / *.jsonl streamed by modelLog
#   progress /opt/taa/output/progress/progress.json
# stdout is captured by TAA's process runner; the script additionally writes the
# progress, log and result artifacts that TAA's watcher reads.
TAA_INPUT_DIR = "/opt/taa/input"
TAA_RESULT_DIR = "/opt/taa/output/result"

# Outside the sandbox those paths do not exist; fall back to the repository so the
# script stays runnable on a workstation.
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
IN_TAA = os.path.isdir(TAA_INPUT_DIR)

# Name of the dataset supplied through model.input; set it to the file that the
# imported dataset actually contains.
DATA_FILE_NAME = "DPN_mock_data.xlsx"

FILE_PATH = os.path.join(TAA_INPUT_DIR if IN_TAA else REPO_ROOT, DATA_FILE_NAME)
OUTPUT_DIR = TAA_RESULT_DIR if IN_TAA else os.path.join(REPO_ROOT, "internal_model_v2")
RANDOM_STATE = 42
TEST_SIZE = 0.3
MICE_ROUNDS = 5
MICE_MAX_ITER = 15
BOOTSTRAP_B = 1000
DPI = 300

LABEL_COL = "糖尿病周围神经病变"

KEEP_FEATURES = [
    "肌酐(CR)", "二氧化碳(CO2)", "糖(GLU)", "甲状腺球蛋白抗体(TG-Ab)",
    "氯(CL)", "冠状动脉狭窄（含冠心病/冠状动脉粥样硬化性心脏病/冠状动脉硬化性心脏病）",
    "甲状腺微粒体抗体(TPO-Ab)", "估算肾小球滤过率(eGFR)", "钾(K)",
    "无机磷(IP)", "尿量(Volume)", "糖化血红蛋白(HbA1c)", "钠(Na)",
    "尿尿酸(UA)", "血清C-肽（空腹）(CPS（0h）)", "肌肝清除率(Ccr)",
    "胰岛素自身抗体(IAA)", "胰岛素（1小时）(IRI（1h）)",
    "血清C-肽（1小时）(CPS（1h）)", "胰岛素（空腹）(IRI（0h）)",
]

# 中英特征名映射（用于图表英文标注）
RENAME_MAP = {
    "糖尿病周围神经病变": "DPN",
    "肌酐(CR)": "Creatinine(CR)",
    "二氧化碳(CO2)": "Bicarbonate(CO2)",
    "糖(GLU)": "Glucose(GLU)",
    "甲状腺球蛋白抗体(TG-Ab)": "Anti-TG(TG-Ab)",
    "氯(CL)": "Chloride(CL)",
    "冠状动脉狭窄（含冠心病/冠状动脉粥样硬化性心脏病/冠状动脉硬化性心脏病）": "Coronary_Stenosis",
    "甲状腺微粒体抗体(TPO-Ab)": "Anti-TPO(TPO-Ab)",
    "估算肾小球滤过率(eGFR)": "eGFR",
    "钾(K)": "Potassium(K)",
    "无机磷(IP)": "Phosphate(IP)",
    "尿量(Volume)": "Urine_Volume",
    "糖化血红蛋白(HbA1c)": "HbA1c",
    "钠(Na)": "Sodium(Na)",
    "尿尿酸(UA)": "Uric_Acid(UA)",
    "血清C-肽（空腹）(CPS（0h）)": "C-Peptide_0h",
    "肌肝清除率(Ccr)": "Ccr",
    "胰岛素自身抗体(IAA)": "IAA",
    "胰岛素（1小时）(IRI（1h）)": "Insulin_1h",
    "血清C-肽（1小时）(CPS（1h）)": "C-Peptide_1h",
    "胰岛素（空腹）(IRI（0h）)": "Insulin_0h",
}

MODELS = {
    "RandomForest": RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE),
    "XGBoost": xgb.XGBClassifier(random_state=RANDOM_STATE, eval_metric="logloss"),
    "LightGBM": lgb.LGBMClassifier(random_state=RANDOM_STATE, verbose=-1),
    "CatBoost": cb.CatBoostClassifier(random_state=RANDOM_STATE, verbose=0),
}


# ============================================================
# TAA runtime artifacts (progress / log / result)
# ============================================================
# TAA injects the destination env vars; outside the sandbox they are absent and
# the artifacts fall back to the local repository, next to OUTPUT_DIR.
def _resolve_progress_path() -> str:
    """Resolve the progress file path from TAA_PROGRESS_DIR.

    The value is a file path by default but TAA accepts a directory too, so a
    non-`.json` value is treated as a directory holding progress.json.
    """
    raw = os.environ.get("TAA_PROGRESS_DIR")
    if not raw:
        return os.path.join(REPO_ROOT, "internal_model_v2", "progress", "progress.json")
    if raw.lower().endswith(".json"):
        return raw
    return os.path.join(raw, "progress.json")


PROGRESS_PATH = _resolve_progress_path()
LOG_PATH = os.path.join(
    os.environ.get("TAA_LOG_DIR") or os.path.join(REPO_ROOT, "internal_model_v2", "logs"),
    "DPN.log",
)
RESULT_PATH = os.path.join(
    os.environ.get("TAA_OUTPUT_DIR") or OUTPUT_DIR,
    "training_result.json",
)


def now_iso() -> str:
    """Current UTC time as an RFC3339 timestamp with second precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_parent(path: str) -> None:
    """Create the parent directory of `path` if it does not exist yet."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def write_progress(percent: float) -> None:
    """Atomically write the progress file so the watcher never reads a partial one."""
    ensure_parent(PROGRESS_PATH)
    tmp_path = PROGRESS_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump({"percent": float(percent), "timestamp": now_iso()}, f,
                  ensure_ascii=False)
    os.replace(tmp_path, PROGRESS_PATH)


def log_milestone(message: str) -> None:
    """Append one timestamped line to the log file TAA streams as modelLog."""
    ensure_parent(LOG_PATH)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"[{now_iso()}] {message}\n")


def report_milestone(percent: float, message: str) -> None:
    """Record a milestone in both the progress file and the log."""
    write_progress(percent)
    log_milestone(message)


def write_result(dataset: dict) -> None:
    """Write training_result.json; TAA only reads the `dataset` object."""
    ensure_parent(RESULT_PATH)
    tmp_path = RESULT_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump({"dataset": dataset}, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, RESULT_PATH)


# ============================================================
# 2. 工具函数
# ============================================================
def setup_dirs(base_dir: str) -> tuple:
    """创建输出目录结构，返回 (fig_dir, table_dir)。"""
    fig_dir = os.path.join(base_dir, "images")
    table_dir = os.path.join(base_dir, "tables")
    os.makedirs(fig_dir, exist_ok=True)
    os.makedirs(table_dir, exist_ok=True)
    return fig_dir, table_dir


def load_and_select_features(path: str) -> pd.DataFrame:
    """读取 Excel，剔除无效列，严格校验特征集完整。"""
    df = pd.read_excel(path)
    drop_cols = [c for c in df.columns if "_无效列" in c]
    df = df.drop(columns=drop_cols, errors="ignore")

    cols_needed = [LABEL_COL] + KEEP_FEATURES
    missing = [c for c in cols_needed if c not in df.columns]
    if missing:
        raise ValueError(f"以下特征列不存在于数据文件：{missing}")

    df = df[cols_needed].copy()
    assert len(df.columns) == len(cols_needed), (
        f"特征列数与预期不符：预期 {len(cols_needed)}，实际 {len(df.columns)}"
    )
    return df


def transform_averaged(imp, X: pd.DataFrame, rounds: int = MICE_ROUNDS) -> pd.DataFrame:
    """Apply a fitted imputer `rounds` times and average the results.

    Training and inference must go through this same function: the imputer
    draws from the posterior on every `transform`, so a single draw at
    prediction time would land on a different point than the averaged one the
    models were fitted on.
    """
    imputed_sets = []
    for i in range(rounds):
        # sklearn freezes the RNG into `random_state_` at fit time and reuses
        # that same advancing stream for every transform, so reassigning
        # `random_state` afterwards has no effect. Replacing `random_state_`
        # with a freshly seeded generator is what makes round i reproducible:
        # training and a reloaded model then draw the same posterior samples.
        imp.random_state_ = np.random.RandomState(RANDOM_STATE + i)
        imputed_sets.append(pd.DataFrame(imp.transform(X), columns=X.columns))
    return sum(imputed_sets) / rounds


def run_mice(df: pd.DataFrame, rounds: int = MICE_ROUNDS) -> tuple:
    """真 MICE 多重链式插补：BayesianRidge + 后验抽样，多轮取均值（Rubin 规则近似）。

    说明：仅对特征列插补；结局标签列（LABEL_COL）保持原始 0/1 值不参与插补。
    对每一轮生成一个完整数据集，最终以多轮插补均值作为建模数据，
    比单次中位数填充更能保留变量间非线性关系、减少缺失偏倚。

    返回 (插补后的数据, 已拟合的插补器, 插补所用的特征列顺序)。
    后两者必须落盘：推理时要复现训练期的同一套插补，否则输入分布对不上。
    """
    # ND -> NaN，全部转数值
    df = df.replace("ND", np.nan)
    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # 结局标签不参与插补
    y_raw = df[LABEL_COL].astype(float)

    imp = IterativeImputer(
        estimator=BayesianRidge(),
        max_iter=MICE_MAX_ITER,
        random_state=RANDOM_STATE,
        sample_posterior=True,          # 后验抽样，反映插补不确定性
    )
    feat_cols = [c for c in df.columns if c != LABEL_COL]
    imp.fit(df[feat_cols])

    df_imputed = transform_averaged(imp, df[feat_cols], rounds)
    df_imputed[LABEL_COL] = y_raw.values
    return df_imputed, imp, feat_cols


def bootstrap_auc_ci(y_true, y_prob, n_boot: int = BOOTSTRAP_B,
                     seed: int = RANDOM_STATE) -> tuple:
    """AUC 的 1000 次 Bootstrap 95% 置信区间。"""
    rng = np.random.default_rng(seed)
    idx = np.arange(len(y_true))
    aucs = []
    for _ in range(n_boot):
        bi = rng.choice(idx, size=len(idx), replace=True)
        if len(np.unique(y_true[bi])) < 2:
            continue
        aucs.append(roc_auc_score(y_true[bi], y_prob[bi]))
    return float(np.percentile(aucs, 2.5)), float(np.percentile(aucs, 97.5))


def save_artifacts(base_dir: str, models: dict, imp, feat_cols: list) -> str:
    """Persist every trained model plus the fitted imputer and its manifest.

    The imputer is part of the model: it was fitted on the training data and
    carries the medians/regressions that fill missing values. Saving it
    alongside the estimators is what makes a later prediction reproducible.
    """
    import joblib

    model_dir = os.path.join(base_dir, "models")
    os.makedirs(model_dir, exist_ok=True)

    for name, model in models.items():
        joblib.dump(model, os.path.join(model_dir, f"{name}.joblib"))
    joblib.dump(imp, os.path.join(model_dir, "imputer.joblib"))

    manifest = {
        "label_col": LABEL_COL,
        "label_col_en": RENAME_MAP[LABEL_COL],
        "feature_cn": list(feat_cols),
        "feature_en": [RENAME_MAP[c] for c in feat_cols],
        "models": list(models.keys()),
        "mice_rounds": MICE_ROUNDS,
        "mice_max_iter": MICE_MAX_ITER,
        "random_state": RANDOM_STATE,
        "trained_at": now_iso(),
    }
    with open(os.path.join(model_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return model_dir


def save_versions(table_dir: str) -> None:
    """记录运行环境版本号，保证可复现性。"""
    import sklearn, sys
    versions = {
        "python": sys.version.split()[0],
        "pandas": pd.__version__,
        "numpy": np.__version__,
        "sklearn": sklearn.__version__,
        "xgboost": xgb.__version__,
        "lightgbm": lgb.__version__,
        "catboost": cb.__version__,
        "shap": shap.__version__,
        "run_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(os.path.join(table_dir, "environment_versions.json"), "w",
              encoding="utf-8") as f:
        json.dump(versions, f, ensure_ascii=False, indent=2)


# ============================================================
# 3. 主流程
# ============================================================
def main():
    report_milestone(0, "run started")
    print("== 1/6 读取数据并校验特征 ==")
    df = load_and_select_features(FILE_PATH)
    n0 = len(df)
    print(f"    原始样本量 n = {n0}（DPN+ {int(df[LABEL_COL].sum())} / DPN- {int((df[LABEL_COL] == 0).sum())}）")
    report_milestone(10, "1/6 dataset loaded and feature set validated")

    print("== 2/6 真 MICE 多重插补（5 轮） ==")
    df_imputed, imp, feat_cols = run_mice(df)
    df_imputed[LABEL_COL] = df_imputed[LABEL_COL].astype(int)
    print(f"    插补完成，样本量 n = {len(df_imputed)}")
    report_milestone(30, "2/6 MICE imputation completed")

    print("== 3/6 中英命名 + 7:3 分层划分 ==")
    df_imputed.rename(columns=RENAME_MAP, inplace=True)
    y = df_imputed["DPN"].astype(int)
    X = df_imputed.drop(columns=["DPN"])
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"    训练集 n={len(X_train)}（DPN+ {int(y_train.sum())}），"
          f"测试集 n={len(X_test)}（DPN+ {int(y_test.sum())}）")
    # The dataset shape is final here; TAA reads it from training_result.json.
    write_result({
        "total_samples": int(len(X_train) + len(X_test)),
        "splits": {"train": int(len(X_train)), "test": int(len(X_test))},
    })
    report_milestone(45, "3/6 renamed features and split into train/test")

    print("== 4/6 构建 5 种模型并训练 ==")
    base_models = [
        ("rf", MODELS["RandomForest"]),
        ("xgb", MODELS["XGBoost"]),
        ("lgb", MODELS["LightGBM"]),
        ("cat", MODELS["CatBoost"]),
    ]
    stack_model = StackingClassifier(
        estimators=base_models,
        final_estimator=lgb.LGBMClassifier(random_state=RANDOM_STATE),
        cv=5,
    )
    all_models = dict(MODELS)
    all_models["Stacking"] = stack_model
    report_milestone(55, "4/6 built 5 models including stacking ensemble")

    fig_dir, table_dir = setup_dirs(OUTPUT_DIR)
    save_versions(table_dir)

    # 特征清单存档
    feat_df = pd.DataFrame({"feature_cn": KEEP_FEATURES,
                            "feature_en": [RENAME_MAP[c] for c in KEEP_FEATURES]})
    feat_df.to_csv(os.path.join(table_dir, "features_used.csv"), index=False)

    print("== 5/6 训练 + 评价 ==")
    results = []
    roc_data, pr_data = {}, {}

    for name, model in all_models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]

        auc_val = roc_auc_score(y_test, y_prob)
        lo, hi = bootstrap_auc_ci(y_test.values, y_prob)
        results.append([
            name,
            round(auc_val, 4), round(lo, 4), round(hi, 4),
            round(accuracy_score(y_test, y_pred), 4),
            round(precision_score(y_test, y_pred), 4),
            round(recall_score(y_test, y_pred), 4),
            round(f1_score(y_test, y_pred), 4),
            round(brier_score_loss(y_test, y_prob), 4),
        ])
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        roc_data[name] = (fpr, tpr)
        p, r, _ = precision_recall_curve(y_test, y_prob)
        pr_data[name] = (p, r)

    res_df = pd.DataFrame(
        results,
        columns=["Model", "AUC", "AUC_2.5%", "AUC_97.5%", "ACC",
                 "Precision", "Recall", "F1", "Brier"],
    )
    res_df.to_excel(os.path.join(table_dir, "Model_Performance_Internal.xlsx"), index=False)
    print(res_df.to_string(index=False))
    res_df.to_csv(os.path.join(table_dir, "Model_Performance_Internal.csv"), index=False)

    model_dir = save_artifacts(OUTPUT_DIR, all_models, imp, feat_cols)
    print(f"    模型与插补器已保存至：{model_dir}")
    report_milestone(90, "5/6 training and evaluation completed; artifacts saved")

    print("== 6/6 绘图（ROC / PR / SHAP） ==")
    # ROC
    plt.figure(figsize=(10, 8), dpi=DPI)
    for name, (fpr, tpr) in roc_data.items():
        plt.plot(fpr, tpr, label=f"{name} AUC={auc(fpr, tpr):.4f}")
    plt.plot([0, 1], [0, 1], "--", color="gray", label="Random Guess")
    plt.xlabel("1 - Specificity")
    plt.ylabel("Sensitivity")
    plt.title("ROC Curves — Internal Cohort (After MICE Imputation)")
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(os.path.join(fig_dir, "ROC.png"), bbox_inches="tight")
    plt.close()

    # PR
    baseline_ap = y_test.mean()
    plt.figure(figsize=(10, 8), dpi=DPI)
    plt.plot([0, 1], [baseline_ap, baseline_ap], "--", color="gray",
             label=f"Random Guess (AP={baseline_ap:.4f})")
    for name, (p, r) in pr_data.items():
        plt.plot(r, p, label=name)
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision-Recall Curves — Internal Cohort (After MICE Imputation)")
    plt.legend(loc="upper right")
    plt.tight_layout()
    plt.savefig(os.path.join(fig_dir, "PR.png"), bbox_inches="tight")
    plt.close()

    # SHAP（CatBoost）
    model_shap = all_models["CatBoost"]
    explainer = shap.TreeExplainer(model_shap)
    shap_values = explainer.shap_values(X_test)

    plt.figure(dpi=DPI)
    shap.summary_plot(shap_values, X_test, show=False)
    plt.savefig(os.path.join(fig_dir, "SHAP_Summary.png"), bbox_inches="tight")
    plt.close()

    plt.figure(dpi=DPI)
    shap.summary_plot(shap_values, X_test, plot_type="bar", show=False)
    plt.savefig(os.path.join(fig_dir, "SHAP_Bar.png"), bbox_inches="tight")
    plt.close()

    mean_shap = np.abs(shap_values).mean(axis=0)
    shap_rank = (pd.DataFrame({"Feature": X.columns, "Mean_SHAP": mean_shap})
                 .sort_values("Mean_SHAP", ascending=False))
    shap_rank.to_csv(os.path.join(table_dir, "shap_importance.csv"), index=False)
    top3 = shap_rank.head(3)["Feature"].tolist()
    for i, feat in enumerate(top3, 1):
        plt.figure(figsize=(8, 6), dpi=DPI)
        shap.dependence_plot(feat, shap_values, X_test, show=False)
        plt.savefig(os.path.join(fig_dir, f"SHAP_Top{i}.png"), bbox_inches="tight")
        plt.close()

    report_milestone(100, "6/6 plots and SHAP outputs written")
    print(f"\n完成。全部结果已保存至：{OUTPUT_DIR}")
    log_milestone(f"run completed; result file: {RESULT_PATH}; output dir: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
