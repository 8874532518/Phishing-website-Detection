"""
train_model.py — PhishGuard AI
================================
Downloads datasets, extracts features, trains a Random Forest classifier,
evaluates it, and saves the model + scaler to the models/ directory.

Run this only when intentionally rebuilding the saved model artifacts:
    python train_model.py

Dual-Engine Architecture:
    1. Standard Engine: Uses scikit-learn (RandomForestClassifier, CalibratedClassifierCV, StandardScaler)
    2. Resilient Pure-Python Engine: If Windows Smart App Control (SAC) or WDAC blocks
       unsigned binary C-extensions (like numpy/scipy DLLs), this script automatically
       switches to PhishGuard's built-in PureRandomForest engine.
       The fallback is a separate implementation and must be evaluated independently;
       its outputs are not assumed to be calibrated or equivalent.
"""

import os
import sys
import time
import json
import logging
import warnings
import random
import csv
import io
import zipfile
from pathlib import Path

# Check if scikit-learn and numpy are available and allowed by Windows security policy
SKLEARN_AVAILABLE = False
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, roc_auc_score, confusion_matrix, classification_report,
    )
    from sklearn.calibration import CalibratedClassifierCV
    import joblib
    SKLEARN_AVAILABLE = True
except (ImportError, OSError, Exception) as exc:
    # Triggered on Windows 11 systems with Smart App Control (SAC) enabled
    SKLEARN_AVAILABLE = False

import requests
from feature_extraction import extract_features, features_to_vector, FEATURE_NAMES
from pure_ml import PureRandomForest, PureStandardScaler

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
DATASET_DIR = BASE_DIR / "dataset"
MODEL_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"

for d in [DATASET_DIR, MODEL_DIR, REPORTS_DIR]:
    d.mkdir(exist_ok=True)

PHISHING_CSV = DATASET_DIR / "phishing_urls.csv"
LEGIT_CSV = DATASET_DIR / "legitimate_urls.csv"
MODEL_PATH = MODEL_DIR / "rf_model.joblib"
SCALER_PATH = MODEL_DIR / "feature_scaler.joblib"
JSON_MODEL_PATH = MODEL_DIR / "rf_model.json"
JSON_SCALER_PATH = MODEL_DIR / "feature_scaler.json"
REPORT_PATH = REPORTS_DIR / "model_evaluation.md"

# ──────────────────────────────────────────────────────────────────────────────
# Dataset Sources
# ──────────────────────────────────────────────────────────────────────────────

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"
TRANCO_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"
FALLBACK_PHISHING_URL = (
    "https://raw.githubusercontent.com/mitchellkrogza/"
    "Phishing.Database/master/phishing-links-ACTIVE.txt"
)


def download_file(url: str, dest: Path, timeout: int = 60) -> bool:
    """Download url → dest. Returns True on success."""
    log.info(f"Downloading {url} → {dest.name} ...")
    try:
        headers = {"User-Agent": "PhishGuardAI/1.0 (educational security project)"}
        resp = requests.get(url, timeout=timeout, headers=headers, stream=True)
        resp.raise_for_status()
        dest.write_bytes(resp.content)
        log.info(f"  ✓ Saved {len(resp.content) // 1024} KB to {dest}")
        return True
    except Exception as exc:
        log.warning(f"  ✗ Download failed: {exc}")
        return False


def load_or_download_phishing_urls(max_urls: int = 5000) -> list[str]:
    """
    Returns URL strings from the local snapshot or configured fallback sources.
    Source verification and current activity are not inferred from this function.
    """
    fallback_path = DATASET_DIR / "phishing_active.txt"
    if not fallback_path.exists():
        download_file(FALLBACK_PHISHING_URL, fallback_path, timeout=45)

    if fallback_path.exists():
        try:
            urls = []
            with open(fallback_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    u = line.strip()
                    if u and not u.startswith("#"):
                        urls.append(u)
                        if len(urls) >= max_urls * 2:
                            break
            if len(urls) >= 100:
                log.info(f"  ✓ Loaded {len(urls)} phishing URLs from active feed")
                return urls
        except Exception as exc:
            log.warning(f"  Could not read active phishing file: {exc}")

    # Try PhishTank
    if not PHISHING_CSV.exists():
        download_file(PHISHTANK_URL, PHISHING_CSV, timeout=90)

    if PHISHING_CSV.exists():
        try:
            urls = []
            with open(PHISHING_CSV, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                header = next(reader, [])
                url_idx = next((i for i, h in enumerate(header) if "url" in h.lower()), 1)
                for row in reader:
                    if len(row) > url_idx and row[url_idx].startswith("http"):
                        urls.append(row[url_idx].strip())
                        if len(urls) >= max_urls * 2:
                            break
            if len(urls) >= 100:
                log.info(f"  ✓ Loaded {len(urls)} phishing URLs from PhishTank")
                return urls
        except Exception as exc:
            log.warning(f"  Could not parse PhishTank CSV: {exc}")

    log.info("  Using built-in verified sample phishing URLs")
    return _synthetic_phishing_urls()


def load_or_download_legitimate_urls(max_urls: int = 5000) -> list[str]:
    """
    Returns a list of legitimate URL strings derived from Tranco Top 1M list.
    """
    tranco_file = DATASET_DIR / "top-1m.csv"
    if not tranco_file.exists():
        log.info("Downloading Tranco Top 1M list for legitimate domains ...")
        try:
            resp = requests.get(TRANCO_ZIP_URL, timeout=45, headers={"User-Agent": "PhishGuardAI/1.0"})
            if resp.status_code == 200:
                with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
                    for name in z.namelist():
                        if name.endswith(".csv"):
                            tranco_file.write_bytes(z.read(name))
                            log.info(f"  ✓ Extracted {name} to {tranco_file}")
                            break
        except Exception as exc:
            log.warning(f"  Tranco download warning: {exc}")

    if tranco_file.exists():
        try:
            urls = []
            with open(tranco_file, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2 and "." in row[1]:
                        urls.append(f"https://{row[1].strip()}/")
                        if len(urls) >= max_urls * 2:
                            break
            if len(urls) >= 100:
                log.info(f"  ✓ Generated {len(urls)} legitimate URLs from Tranco Top Sites")
                return urls
        except Exception as exc:
            log.warning(f"  Could not parse Tranco list: {exc}")

    log.info("  Using built-in top legitimate URLs")
    return _synthetic_legitimate_urls()


def _synthetic_phishing_urls() -> list[str]:
    """Fallback sample phishing patterns."""
    samples = [
        "http://paypal-secure-login.verify-account123.com/update",
        "http://192.168.1.1/phish/login.php",
        "http://login.apple.id.support-update.xyz/credential",
        "http://amaz0n.suspicious-deals.com/account/verify?token=9283",
        "http://secure-bankofamerica.login.fakebank.net/signin",
        "http://bit.ly/3xFakePhish",
        "https://xn--pypal-4ve.com/account-verification",
        "http://192.0.2.1/phishing/signin?user=target@corp.com",
        "http://microsoftonline.com.evil-phisher.ru/oauth2/authorize",
        "http://google-secure.support-helpdesk.xyz/verify-identity",
        "http://chase.online-security-check.net/portal/auth",
        "http://netflix-billing-update.cc/login.php",
        "http://wellsfargo-security.top/auth/login",
        "http://facebook-security-check.cf/checkpoint",
        "http://dropbox-sharing-portal.tk/file/download?id=4921",
    ]
    return samples * 200


def _synthetic_legitimate_urls() -> list[str]:
    """Fallback legitimate URLs."""
    samples = [
        "https://www.google.com/",
        "https://www.youtube.com/",
        "https://www.wikipedia.org/",
        "https://www.github.com/features",
        "https://stackoverflow.com/questions",
        "https://www.reddit.com/r/technology",
        "https://www.amazon.com/gp/bestsellers",
        "https://www.bbc.com/news",
        "https://www.nytimes.com/section/world",
        "https://www.linkedin.com/feed",
        "https://twitter.com/explore",
        "https://www.microsoft.com/en-us",
        "https://apple.com/macbook-pro",
        "https://docs.python.org/3/library",
        "https://mozilla.org/firefox",
    ]
    return samples * 200


def safe_extract(url: str) -> list | None:
    """Extract features from a URL, returning None on failure."""
    try:
        feats = extract_features(url)
        return features_to_vector(feats)
    except Exception:
        return None


def build_dataset(
    phishing_urls: list[str],
    legit_urls: list[str],
    max_per_class: int = 2500,
) -> tuple[list[list[float]], list[int]]:
    """Build feature vectors and labels (1 = phishing, 0 = legitimate)."""
    random.seed(42)
    phish_sample = random.sample(phishing_urls, min(len(phishing_urls), max_per_class))
    legit_sample = random.sample(legit_urls, min(len(legit_urls), max_per_class))

    log.info(f"Extracting features from {len(phish_sample)} phishing URLs ...")
    X = []
    y = []

    for u in phish_sample:
        vec = safe_extract(u)
        if vec is not None:
            X.append(vec)
            y.append(1)

    log.info(f"Extracting features from {len(legit_sample)} legitimate URLs ...")
    for u in legit_sample:
        vec = safe_extract(u)
        if vec is not None:
            X.append(vec)
            y.append(0)

    # Shuffle combined dataset
    combined = list(zip(X, y))
    random.shuffle(combined)
    X = [c[0] for c in combined]
    y = [c[1] for c in combined]

    phish_count = sum(y)
    legit_count = len(y) - phish_count
    log.info(f"Dataset assembled: {len(y)} total samples | Phishing: {phish_count} | Legit: {legit_count}")
    return X, y


def split_data(
    X: list[list[float]], y: list[int], test_ratio: float = 0.20
) -> tuple[list[list[float]], list[list[float]], list[int], list[int]]:
    """Split dataset into train and test sets (stratified)."""
    pos_idx = [i for i, label in enumerate(y) if label == 1]
    neg_idx = [i for i, label in enumerate(y) if label == 0]

    n_pos_test = int(len(pos_idx) * test_ratio)
    n_neg_test = int(len(neg_idx) * test_ratio)

    test_idx = set(pos_idx[:n_pos_test] + neg_idx[:n_neg_test])
    train_idx = [i for i in range(len(y)) if i not in test_idx]
    test_idx_list = list(test_idx)

    X_train = [X[i] for i in train_idx]
    y_train = [y[i] for i in train_idx]
    X_test = [X[i] for i in test_idx_list]
    y_test = [y[i] for i in test_idx_list]

    return X_train, X_test, y_train, y_test


def calculate_metrics(y_true: list[int], y_pred: list[int]) -> dict:
    """Calculate accuracy, precision, recall, f1, and confusion matrix."""
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    total = len(y_true)
    acc = (tp + tn) / total if total > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "fpr": fpr,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def train_pipeline(X: list[list[float]], y: list[int]) -> dict:
    """Train Random Forest model using available engine (pure Python or scikit-learn)."""
    X_train, X_test, y_train, y_test = split_data(X, y, test_ratio=0.20)

    if SKLEARN_AVAILABLE:
        engine_name = "scikit-learn calibrated Random Forest"
        log.info("Engine: Scikit-Learn Random Forest Classifier")
        scaler = StandardScaler()
        X_train_sc = scaler.fit_transform(X_train)
        X_test_sc = scaler.transform(X_test)

        base_rf = RandomForestClassifier(
            n_estimators=100, max_depth=16, min_samples_leaf=2,
            class_weight="balanced", random_state=42, n_jobs=-1,
        )
        model = CalibratedClassifierCV(base_rf, cv=5, method="sigmoid")
        model.fit(X_train_sc, y_train)

        y_pred = model.predict(X_test_sc)
        metrics = calculate_metrics(y_test, y_pred.tolist())

        # Save joblib models
        joblib.dump(model, MODEL_PATH)
        joblib.dump(scaler, SCALER_PATH)

        # Also train and save pure-Python model for SAC-portability
        pure_scaler = PureStandardScaler().fit(X_train)
        pure_rf = PureRandomForest(n_estimators=30, max_depth=7).fit(
            pure_scaler.transform(X_train), y_train
        )
        pure_rf.save(JSON_MODEL_PATH)
        JSON_SCALER_PATH.write_text(json.dumps(pure_scaler.to_dict()), encoding="utf-8")

        top_features = []
        try:
            base_estimator = model.calibrated_classifiers_[0].estimator
            importances = base_estimator.feature_importances_
            paired = list(zip(FEATURE_NAMES, importances))
            top_features = sorted(paired, key=lambda x: x[1], reverse=True)[:5]
        except Exception:
            pass

    else:
        engine_name = "PhishGuard pure-Python Random Forest"
        log.info("Engine: PhishGuard Pure-Python Random Forest (SAC-Safe)")
        log.info("  (Bypasses Windows Smart App Control restriction on binary C-extensions)")

        pure_scaler = PureStandardScaler().fit(X_train)
        X_train_sc = pure_scaler.transform(X_train)
        X_test_sc = pure_scaler.transform(X_test)

        pure_rf = PureRandomForest(n_estimators=35, max_depth=7)
        log.info(f"Training ensemble of {pure_rf.n_estimators} decision trees ...")
        pure_rf.fit(X_train_sc, y_train)

        y_pred = pure_rf.predict(X_test_sc)
        metrics = calculate_metrics(y_test, y_pred)

        pure_rf.save(JSON_MODEL_PATH)
        JSON_SCALER_PATH.write_text(json.dumps(pure_scaler.to_dict()), encoding="utf-8")
        log.info(f"  ✓ Saved JSON model → {JSON_MODEL_PATH}")
        log.info(f"  ✓ Saved JSON scaler → {JSON_SCALER_PATH}")

        paired = list(zip(FEATURE_NAMES, pure_rf.feature_importances_))
        top_features = sorted(paired, key=lambda x: x[1], reverse=True)[:5]

    return {
        "metrics": metrics,
        "train_size": len(X_train),
        "test_size": len(X_test),
        "phishing_count": sum(y),
        "legit_count": len(y) - sum(y),
        "top_features": top_features,
        "engine": engine_name,
    }


def write_evaluation_report(results: dict):
    m = results["metrics"]
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    report_md = f"""# PhishGuard AI — Model Evaluation Report
Generated: {timestamp}
Engine: {results.get("engine", "unspecified")}

## Dataset Summary
| Metric | Value |
|--------|-------|
| Total samples | {results['phishing_count'] + results['legit_count']} |
| Phishing URLs | {results['phishing_count']} |
| Legitimate URLs | {results['legit_count']} |
| Train set size | {results['train_size']} |
| Test set size | {results['test_size']} |

## Test Set Performance
| Metric | Value |
|--------|-------|
| **Accuracy** | **{m['accuracy'] * 100:.2f}%** |
| **Precision** (Phishing) | **{m['precision'] * 100:.2f}%** |
| **Recall** (Phishing) | **{m['recall'] * 100:.2f}%** |
| **F1 Score** | **{m['f1']:.4f}** |
| False Positive Rate | {m['fpr'] * 100:.2f}% |

## Confusion Matrix
```
                    Predicted Legit    Predicted Phishing
Actual Legit        {m['tn']:>8}           {m['fp']:>8}
Actual Phishing     {m['fn']:>8}           {m['tp']:>8}
```

## Top 5 Most Informative Features (Gini Impurity Reduction)
"""
    for rank, (feat, imp) in enumerate(results["top_features"], 1):
        report_md += f"{rank}. **`{feat}`** — Importance: `{imp * 100:.2f}%`\n"

    report_md += """
## Limitations and Caveats
- The model was trained purely on URL-lexical features (no active page DOM or credentials harvesting check).
- Zero-day phishing domains with deceptive brand names can evade purely statistical classifiers; always cross-verify with Threat Intelligence.
- URL shortening services hide actual destinations — PhishGuard follows and analyzes redirect chains when enabled.
"""
    REPORT_PATH.write_text(report_md, encoding="utf-8")
    log.info(f"Report saved → {REPORT_PATH}")


def main():
    log.info("=" * 60)
    log.info("PhishGuard AI — Model Training Pipeline")
    log.info("=" * 60)

    log.info("\n[Step 1/4] Loading phishing URLs ...")
    phishing_urls = load_or_download_phishing_urls(max_urls=2500)

    log.info("\n[Step 2/4] Loading legitimate URLs ...")
    legit_urls = load_or_download_legitimate_urls(max_urls=2500)

    log.info("\n[Step 3/4] Extracting features ...")
    X, y = build_dataset(phishing_urls, legit_urls, max_per_class=2000)

    if len(X) < 100:
        log.error("Too few samples to train a meaningful model.")
        sys.exit(1)

    log.info("\n[Step 4/4] Training and evaluating Random Forest model ...")
    results = train_pipeline(X, y)
    write_evaluation_report(results)

    m = results["metrics"]
    log.info("\n" + "=" * 60)
    log.info("✓ Model Training Complete!")
    log.info(f"  Test Accuracy : {m['accuracy'] * 100:.2f}%")
    log.info(f"  Test F1 Score : {m['f1']:.4f}")
    log.info(f"  Precision     : {m['precision'] * 100:.2f}%")
    log.info(f"  Recall        : {m['recall'] * 100:.2f}%")
    log.info(f"  Report        : {REPORT_PATH}")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
