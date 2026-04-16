"""
LOLBin ML Model Trainer
=======================
Trains a RandomForest classifier to detect LOLBin abuse from process telemetry.
No hardcoded rules — the model learns patterns from labeled data.

By default, trains on both locally available LMD datasets (2.6M real rows).
You can also point it at any CSV or OTRF JSON file.

Usage:
  python train_model.py                          # Train on default LMD datasets
  python train_model.py --dataset data.csv       # Train on custom CSV dataset
  python train_model.py --dataset "a.csv|b.csv"  # Train on multiple CSVs
  python train_model.py --dataset otrf.json --format otrf
  python train_model.py --max-rows 300000        # Cap rows per file (faster)

CSV format expected (auto-detected columns):
  process_name, command_line, parent_process, label (0=benign, 1=malicious)
  OR: Image, CommandLine, ParentImage, label

After training, the model is saved to: lolbin_model.pkl
Load it in detector.py automatically.
"""

import argparse
import os
import sys
import json
import warnings
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

warnings.filterwarnings("ignore")

MODEL_OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "lolbin_model.pkl")

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT DATASET PATHS  (already downloaded locally)
# ─────────────────────────────────────────────────────────────────────────────

_BASE = os.path.join(os.path.dirname(__file__), "Lateral-Movement-Dataset--LMD_Collections")
DEFAULT_DATASETS = [
    os.path.join(_BASE, "LMD-2022", "LMD-2022", "LMD-2022 [870K Elements]",
                 "Labelled LMD-2022", "LMD-2022 [870K Elements][Labelled].csv"),
    os.path.join(_BASE, "LMD-2023", "LMD-2023 [1.75M Elements]",
                 "LMD-2023 [1.75M Elements] Checked", "Labelled LMD-2023",
                 "LMD-2023 [1.75M Elements][Labelled]checked.csv"),
]

# ─────────────────────────────────────────────────────────────────────────────
# DATASET LOADERS
# ─────────────────────────────────────────────────────────────────────────────

_COL_ALIASES = {
    "process_name":  ["process_name", "image", "processname", "proc_name", "process"],
    "command_line":  ["command_line", "commandline", "cmdline", "cmd_line", "cmd"],
    "parent_process":["parent_process", "parentimage", "parent_image", "parentprocessname", "parent"],
    "label":         ["label", "class", "target", "is_malicious", "malicious", "attack", "category"],
}

def _resolve_columns(df: pd.DataFrame) -> pd.DataFrame:
    rename = {}
    cols_lower = {c.lower().replace(" ", "_"): c for c in df.columns}
    for canonical, aliases in _COL_ALIASES.items():
        if canonical not in df.columns:
            for alias in aliases:
                if alias in cols_lower:
                    rename[cols_lower[alias]] = canonical
                    break
    df = df.rename(columns=rename)
    return df


def _pick_usecols(header_cols: list) -> list:
    """Return only the 4 columns we need (using alias matching)."""
    cols_lower = {c.lower().replace(" ", "_"): c for c in header_cols}
    needed = []
    for canonical, aliases in _COL_ALIASES.items():
        for alias in aliases:
            if alias in cols_lower:
                needed.append(cols_lower[alias])
                break
        else:
            if canonical in header_cols:
                needed.append(canonical)
    return needed


def load_csv_dataset(path: str, max_rows: int = None) -> pd.DataFrame:
    # Detect encoding and read only needed columns to save memory
    enc_used = "utf-8"
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            header_df = pd.read_csv(path, nrows=0, encoding=enc)
            enc_used = enc
            break
        except UnicodeDecodeError:
            continue
    else:
        raise ValueError(f"Could not decode {path} with utf-8/latin-1/cp1252")

    usecols = _pick_usecols(list(header_df.columns)) or None

    for enc in (enc_used, "latin-1", "cp1252"):
        try:
            df = pd.read_csv(path, low_memory=False, encoding=enc, usecols=usecols)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise ValueError(f"Could not decode {path} with utf-8/latin-1/cp1252")

    df = _resolve_columns(df)

    required = {"process_name", "command_line", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(
            f"Could not find columns {missing} in CSV. "
            f"Available: {list(df.columns)}\n"
            "Rename your columns to: process_name, command_line, parent_process, label"
        )

    if "parent_process" not in df.columns:
        df["parent_process"] = ""

    # Normalize label to 0/1  (LMD uses 0=normal, 1=EoRS, 2=EoHT)
    def _norm(v):
        s = str(v).strip().lower()
        if s in ("0", "normal", "benign", "clean", "false", "no"):
            return 0
        return 1

    df["label"] = df["label"].apply(_norm)

    # Optional row cap — stratified sample to preserve class balance
    if max_rows and len(df) > max_rows:
        _, df = train_test_split(df, test_size=max_rows / len(df), stratify=df["label"], random_state=42)
        df = df.reset_index(drop=True)
        print(f"[csv] Sampled {len(df)} rows (from full dataset)")
    df = df[["process_name", "command_line", "parent_process", "label"]].dropna(subset=["command_line"])
    print(f"[csv] Loaded {len(df)} rows — {(df.label==0).sum()} benign, {(df.label==1).sum()} malicious")
    return df


def load_otrf_dataset(path: str) -> pd.DataFrame:
    """Load OTRF Security Datasets (newline-delimited JSON, all malicious)."""
    records = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                ed = (event.get("winlog", {}) or {}).get("event_data", {}) or event.get("EventData", {}) or event
                process_name = ed.get("Image") or ed.get("process_name") or ""
                cmd          = ed.get("CommandLine") or ed.get("command_line") or ""
                parent       = ed.get("ParentImage") or ed.get("parent_process") or ""
                if cmd:
                    records.append({"process_name": process_name, "command_line": cmd, "parent_process": parent, "label": 1})
            except Exception:
                continue
    df = pd.DataFrame(records)
    print(f"[otrf] Loaded {len(df)} malicious events from {path}")
    return df


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE ENGINEERING
# ─────────────────────────────────────────────────────────────────────────────

def add_numeric_features(df: pd.DataFrame) -> pd.DataFrame:
    cmd = df["command_line"].fillna("").str.lower()
    df = df.copy()
    df["cmd_length"]      = cmd.str.len()
    df["num_args"]        = cmd.str.count(r"\s")
    df["has_http"]        = cmd.str.contains(r"https?://", regex=True).astype(int)
    df["has_ip"]          = cmd.str.contains(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", regex=True).astype(int)
    df["num_special"]     = cmd.apply(lambda x: sum(1 for c in x if c in "^|&;`$%@"))
    df["has_long_token"]  = cmd.apply(lambda x: int(any(len(t) > 40 for t in x.split())))
    df["word_count"]      = cmd.str.split().apply(lambda x: len(x) if isinstance(x, list) else 0)
    return df

NUMERIC_COLS = ["cmd_length", "num_args", "has_http", "has_ip", "num_special", "has_long_token", "word_count"]


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_pipeline() -> Pipeline:
    preprocessor = ColumnTransformer(transformers=[
        ("cmd_char",  TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), max_features=400, sublinear_tf=True), "command_line"),
        ("cmd_word",  TfidfVectorizer(analyzer="word",    ngram_range=(1, 2), max_features=200, sublinear_tf=True), "command_line"),
        ("proc",      TfidfVectorizer(analyzer="word",    ngram_range=(1, 1), max_features=60),                      "process_name"),
        ("parent",    TfidfVectorizer(analyzer="word",    ngram_range=(1, 1), max_features=60),                      "parent_process"),
        ("numeric",   "passthrough",                                                                                  NUMERIC_COLS),
    ], remainder="drop")

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=1,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )

    return Pipeline([("preprocessor", preprocessor), ("classifier", clf)])


# ─────────────────────────────────────────────────────────────────────────────
# TRAINING
# ─────────────────────────────────────────────────────────────────────────────

def train_and_evaluate(df: pd.DataFrame) -> Pipeline:
    df = add_numeric_features(df)

    # Fill missing text
    for col in ["process_name", "command_line", "parent_process"]:
        df[col] = df[col].fillna("").astype(str).str.lower()

    X = df.drop(columns=["label"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    print(f"\n[train] {len(X_train)} train, {len(X_test)} test samples")
    print(f"[train] Class balance -- benign: {(y_train==0).sum()}, malicious: {(y_train==1).sum()}")

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    # Evaluate
    y_pred  = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    print("\n-- Classification Report ------------------------------------------")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    try:
        auc = roc_auc_score(y_test, y_proba)
        print(f"ROC-AUC: {auc:.4f}")
    except Exception:
        pass

    cm = confusion_matrix(y_test, y_pred)
    print(f"Confusion Matrix:\n  TN={cm[0,0]}  FP={cm[0,1]}\n  FN={cm[1,0]}  TP={cm[1,1]}")

    # Cross-validation on a stratified sample (avoid OOM on 1.7M+ rows)
    print("\n-- 5-Fold Cross-Validation (sample) ------------------------------")
    cv_sample = min(100_000, len(X))
    _, X_cv, _, y_cv = train_test_split(X, y, test_size=cv_sample / len(X),
                                        stratify=y, random_state=42)
    cv_scores = cross_val_score(build_pipeline(), X_cv, y_cv,
                                cv=StratifiedKFold(5), scoring="f1", n_jobs=1)
    print(f"F1 scores: {cv_scores.round(3)}")
    print(f"Mean F1:   {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")

    return pipeline


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Train LOLBin ML detection model")
    parser.add_argument("--dataset",   type=str, default=None,
                        help="Pipe-separated paths to CSV or OTRF JSON files. "
                             "Defaults to locally downloaded LMD-2022 + LMD-2023.")
    parser.add_argument("--format",    type=str, default="csv", choices=["csv", "otrf"],
                        help="Dataset format")
    parser.add_argument("--max-rows",  type=int, default=None,
                        help="Cap rows per CSV file (stratified sample, for speed)")
    parser.add_argument("--output",    type=str, default=MODEL_OUTPUT_PATH,
                        help="Output path for saved model")
    args = parser.parse_args()

    print("=" * 60)
    print("  LOLBin ML Model Trainer  (100% real data, no synthetics)")
    print("=" * 60)

    paths = []
    if args.dataset:
        paths = [p.strip() for p in args.dataset.split("|") if p.strip()]
    else:
        print("[info] Using default local datasets (LMD-2022 + LMD-2023).\n")
        paths = DEFAULT_DATASETS

    frames = []
    for p in paths:
        if not os.path.exists(p):
            print(f"[warn] Dataset not found, skipping: {p}")
            continue
        if args.format == "otrf":
            frames.append(load_otrf_dataset(p))
        else:
            frames.append(load_csv_dataset(p, max_rows=args.max_rows))

    if not frames:
        print("[error] No datasets could be loaded. Exiting.")
        sys.exit(1)

    df = pd.concat(frames, ignore_index=True)
    print(f"\n[combined] {len(df):,} total rows — "
          f"{(df.label==0).sum():,} benign, {(df.label==1).sum():,} malicious")

    pipeline = train_and_evaluate(df)

    joblib.dump(pipeline, args.output, compress=3)
    print(f"\n[saved] Model saved -> {args.output}")
    print("[done]  Run detector.py or live_monitor.py — model will load automatically.\n")


if __name__ == "__main__":
    main()
