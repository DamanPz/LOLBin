"""
example_detector.py
====================
Loads real samples from the LMD dataset (benign + malicious),
runs them through the trained ML detector, and prints results.

Usage:
  python example_detector.py                  # 5 benign + 5 malicious (default)
  python example_detector.py --samples 20     # custom count per class
  python example_detector.py --seed 99        # different random sample
"""

import json
import argparse
import os
import sys
import pandas as pd
from detector import detect_suspicious_activity

# ── Dataset paths ─────────────────────────────────────────────────────────────
_BASE = os.path.join(os.path.dirname(__file__), "Lateral-Movement-Dataset--LMD_Collections")
DATASETS = [
    os.path.join(_BASE, "LMD-2022", "LMD-2022", "LMD-2022 [870K Elements]",
                 "Labelled LMD-2022", "LMD-2022 [870K Elements][Labelled].csv"),
    os.path.join(_BASE, "LMD-2023", "LMD-2023 [1.75M Elements]",
                 "LMD-2023 [1.75M Elements] Checked", "Labelled LMD-2023",
                 "LMD-2023 [1.75M Elements][Labelled]checked.csv"),
]

COL_ALIASES = {
    "process_name":  ["image", "process_name", "processname"],
    "command_line":  ["commandline", "command_line", "cmdline"],
    "parent_process":["parentimage", "parent_process", "parent_image"],
    "label":         ["label", "class", "target"],
}


def _resolve(df):
    rename = {}
    cl = {c.lower().replace(" ", "_"): c for c in df.columns}
    for canon, aliases in COL_ALIASES.items():
        for a in aliases:
            if a in cl:
                rename[cl[a]] = canon
                break
    df = df.rename(columns=rename)
    keep = [c for c in ["process_name", "command_line", "parent_process", "label"] if c in df.columns]
    df = df[keep].copy()
    if "parent_process" not in df.columns:
        df["parent_process"] = ""
    df = df.dropna(subset=["command_line"])
    def norm(v):
        s = str(v).strip().lower()
        return 0 if s in ("0", "normal", "benign", "clean", "false", "no") else 1
    df["label"] = df["label"].apply(norm)
    return df


def load_samples(n_per_class=5, seed=42):
    """
    Read enough chunks from the datasets to collect n_per_class benign
    and n_per_class malicious rows.
    """
    benign, malicious = [], []
    needed = n_per_class * 20   # read a buffer so stratified pick works

    for path in DATASETS:
        if not os.path.exists(path):
            print(f"[warn] Not found, skipping: {os.path.basename(path)}")
            continue

        enc = "utf-8"
        for e in ("utf-8", "latin-1", "cp1252"):
            try:
                pd.read_csv(path, nrows=0, encoding=e)
                enc = e
                break
            except Exception:
                continue

        collected = 0
        for chunk in pd.read_csv(path, encoding=enc, low_memory=False,
                                  on_bad_lines="skip", chunksize=10000):
            chunk = _resolve(chunk)
            benign.append(chunk[chunk.label == 0])
            malicious.append(chunk[chunk.label == 1])
            collected += len(chunk)
            if collected >= needed:
                break

        if len(benign) and len(malicious):
            break   # got enough from first dataset

    if not benign or not malicious:
        print("[error] Could not load dataset samples.")
        sys.exit(1)

    df_b = pd.concat(benign, ignore_index=True).sample(
        min(n_per_class, len(pd.concat(benign))), random_state=seed)
    df_m = pd.concat(malicious, ignore_index=True).sample(
        min(n_per_class, len(pd.concat(malicious))), random_state=seed)

    return df_b, df_m


def rows_to_logs(df, label_str):
    logs = []
    for _, row in df.iterrows():
        logs.append({
            "process_name":  str(row.get("process_name", "") or ""),
            "command_line":  str(row.get("command_line",  "") or ""),
            "parent_process": str(row.get("parent_process", "") or ""),
            "source":        label_str,
        })
    return logs


def main():
    parser = argparse.ArgumentParser(description="LOLBin detector demo using real LMD data")
    parser.add_argument("--samples", type=int, default=5,
                        help="Number of samples per class (benign + malicious)")
    parser.add_argument("--seed",    type=int, default=42,
                        help="Random seed for reproducible sampling")
    args = parser.parse_args()

    print("=" * 60)
    print("  LOLBin Detector — Real Dataset Demo")
    print("=" * 60)
    print(f"[info] Loading {args.samples} benign + {args.samples} malicious samples from LMD...\n")

    df_benign, df_malicious = load_samples(n_per_class=args.samples, seed=args.seed)

    sample_logs = rows_to_logs(df_benign, "benign") + rows_to_logs(df_malicious, "malicious")

    print("--- Input Logs (from LMD dataset) ---")
    print(json.dumps(sample_logs, indent=4))
    print("\n" + "=" * 60 + "\n")

    analyzed_logs = detect_suspicious_activity(sample_logs)

    print("--- Detection Results ---")
    print(json.dumps(analyzed_logs, indent=4))

    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    for log in analyzed_logs:
        src   = log.get("source", "?")
        proc  = log.get("process_name", "?")[:30]
        score = log.get("risk_score", 0)
        level = log.get("risk_level", "?")
        flag  = "*** ALERT ***" if log.get("is_anomalous") else ""
        print(f"  [{src:<9}]  {proc:<32}  score={score:>3}  {level:<6}  {flag}")
    print()


if __name__ == "__main__":
    main()
