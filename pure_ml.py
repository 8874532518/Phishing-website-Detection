"""
pure_ml.py — PhishGuard AI
===========================
Pure-Python Machine Learning Engine (Random Forest & Scaler).

Why this exists:
    On Windows 11 systems with Smart App Control (SAC) or WDAC (Application Control)
    policies enabled, unsigned binary .pyd / DLL C-extensions (like numpy and scipy)
    can be blocked by the Windows kernel (WinError 4551).
    
    This module provides a 100% pure-Python implementation of:
      1. StandardScaler (mean & variance normalization)
      2. DecisionTree (recursive Gini impurity binary tree)
      3. PureRandomForest (ensemble with bootstrap bagging, sub-feature sampling,
         Gini-based feature importances, and calibrated predict_proba)
      4. Fast JSON serialization / deserialization

It adheres strictly to the scikit-learn estimator interface:
    - fit(X, y)
    - predict(X) -> list[int]
    - predict_proba(X) -> list[list[float]]  (shape: [N, 2])
    - feature_importances_ -> list[float]    (sums to 1.0)
"""

import math
import random
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


class PureStandardScaler:
    """Standardizes features by removing the mean and scaling to unit variance."""

    def __init__(self):
        self.mean_: List[float] = []
        self.scale_: List[float] = []

    def fit(self, X: List[List[float]]) -> "PureStandardScaler":
        if not X or not X[0]:
            return self
        n_samples = len(X)
        n_features = len(X[0])

        self.mean_ = [0.0] * n_features
        for row in X:
            for j in range(n_features):
                self.mean_[j] += row[j]
        self.mean_ = [m / n_samples for m in self.mean_]

        variances = [0.0] * n_features
        for row in X:
            for j in range(n_features):
                diff = row[j] - self.mean_[j]
                variances[j] += diff * diff

        self.scale_ = []
        for v in variances:
            std = math.sqrt(v / n_samples)
            self.scale_.append(std if std > 1e-8 else 1.0)

        return self

    def transform(self, X: List[List[float]]) -> List[List[float]]:
        if not self.mean_:
            return X
        scaled = []
        for row in X:
            scaled_row = [
                (val - self.mean_[j]) / self.scale_[j]
                for j, val in enumerate(row)
            ]
            scaled.append(scaled_row)
        return scaled

    def fit_transform(self, X: List[List[float]]) -> List[List[float]]:
        return self.fit(X).transform(X)

    def to_dict(self) -> Dict[str, Any]:
        return {"mean": self.mean_, "scale": self.scale_}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PureStandardScaler":
        scaler = cls()
        scaler.mean_ = data.get("mean", [])
        scaler.scale_ = data.get("scale", [])
        return scaler


class PureNode:
    """A single decision tree node."""

    def __init__(
        self,
        feature_index: int = -1,
        threshold: float = 0.0,
        prob_positive: float = 0.5,
        left: Optional["PureNode"] = None,
        right: Optional["PureNode"] = None,
        is_leaf: bool = False,
    ):
        self.feature_index = feature_index
        self.threshold = threshold
        self.prob_positive = prob_positive
        self.left = left
        self.right = right
        self.is_leaf = is_leaf

    def to_dict(self) -> Dict[str, Any]:
        if self.is_leaf:
            return {"leaf": True, "prob": round(self.prob_positive, 4)}
        return {
            "feat": self.feature_index,
            "thresh": round(self.threshold, 6),
            "left": self.left.to_dict() if self.left else None,
            "right": self.right.to_dict() if self.right else None,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PureNode":
        if d.get("leaf"):
            return cls(prob_positive=d["prob"], is_leaf=True)
        return cls(
            feature_index=d["feat"],
            threshold=d["thresh"],
            left=cls.from_dict(d["left"]) if d.get("left") else None,
            right=cls.from_dict(d["right"]) if d.get("right") else None,
            is_leaf=False,
        )


def _gini(pos: int, total: int) -> float:
    if total == 0:
        return 0.0
    p1 = pos / total
    p0 = 1.0 - p1
    return 1.0 - (p0 * p0 + p1 * p1)


class PureDecisionTree:
    """Fast binary classification decision tree in pure Python."""

    def __init__(self, max_depth: int = 7, min_samples_split: int = 4, max_features: int = 5):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.max_features = max_features
        self.root: Optional[PureNode] = None
        self.feature_importances: List[float] = []

    def fit(self, X: List[List[float]], y: List[int], n_total_features: int) -> "PureDecisionTree":
        self.feature_importances = [0.0] * n_total_features
        self.root = self._build_tree(X, y, depth=0, n_total_features=n_total_features)
        return self

    def _build_tree(
        self, X: List[List[float]], y: List[int], depth: int, n_total_features: int
    ) -> PureNode:
        n_samples = len(y)
        pos_count = sum(y)

        # Base conditions: pure node, max depth reached, or too few samples
        if n_samples == 0:
            return PureNode(prob_positive=0.5, is_leaf=True)
        prob = pos_count / n_samples
        if depth >= self.max_depth or n_samples < self.min_samples_split or pos_count == 0 or pos_count == n_samples:
            return PureNode(prob_positive=prob, is_leaf=True)

        current_gini = _gini(pos_count, n_samples)
        best_gain = 0.0
        best_feat = -1
        best_thresh = 0.0
        best_left_idx: List[int] = []
        best_right_idx: List[int] = []

        # Feature subsampling (Random Forest random feature selection)
        feature_candidates = list(range(n_total_features))
        random.shuffle(feature_candidates)
        chosen_features = feature_candidates[: min(self.max_features, n_total_features)]

        for feat in chosen_features:
            # Extract feature values and unique thresholds
            vals = [X[i][feat] for i in range(n_samples)]
            unique_vals = sorted(set(vals))
            if len(unique_vals) <= 1:
                continue

            # Pick candidate thresholds (up to 12 evenly spaced)
            if len(unique_vals) > 12:
                step = len(unique_vals) // 12
                thresholds = [unique_vals[k] for k in range(0, len(unique_vals), step)]
            else:
                thresholds = unique_vals

            for thresh in thresholds:
                left_y_pos = 0
                left_count = 0
                right_y_pos = 0
                right_count = 0

                left_idx = []
                right_idx = []

                for i in range(n_samples):
                    if vals[i] <= thresh:
                        left_idx.append(i)
                        left_count += 1
                        if y[i] == 1:
                            left_y_pos += 1
                    else:
                        right_idx.append(i)
                        right_count += 1
                        if y[i] == 1:
                            right_y_pos += 1

                if left_count == 0 or right_count == 0:
                    continue

                left_gini = _gini(left_y_pos, left_count)
                right_gini = _gini(right_y_pos, right_count)
                weighted_gini = (left_count / n_samples) * left_gini + (right_count / n_samples) * right_gini
                gain = current_gini - weighted_gini

                if gain > best_gain:
                    best_gain = gain
                    best_feat = feat
                    best_thresh = thresh
                    best_left_idx = left_idx
                    best_right_idx = right_idx

        # If no split improves Gini, turn into leaf
        if best_gain <= 1e-7 or best_feat == -1:
            return PureNode(prob_positive=prob, is_leaf=True)

        # Record feature importance gain
        self.feature_importances[best_feat] += best_gain * n_samples

        left_X = [X[i] for i in best_left_idx]
        left_y = [y[i] for i in best_left_idx]
        right_X = [X[i] for i in best_right_idx]
        right_y = [y[i] for i in best_right_idx]

        left_node = self._build_tree(left_X, left_y, depth + 1, n_total_features)
        right_node = self._build_tree(right_X, right_y, depth + 1, n_total_features)

        return PureNode(
            feature_index=best_feat,
            threshold=best_thresh,
            prob_positive=prob,
            left=left_node,
            right=right_node,
            is_leaf=False,
        )

    def predict_one(self, x: List[float]) -> float:
        node = self.root
        while node and not node.is_leaf:
            if x[node.feature_index] <= node.threshold:
                node = node.left
            else:
                node = node.right
        return node.prob_positive if node else 0.5


class PureRandomForest:
    """
    Pure-Python Random Forest Classifier.
    Bagging ensemble of decision trees with feature subsampling.
    """

    def __init__(self, n_estimators: int = 30, max_depth: int = 7, max_features: Optional[int] = None):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.max_features = max_features
        self.trees: List[PureDecisionTree] = []
        self.feature_importances_: List[float] = []

    def fit(self, X: List[List[float]], y: List[int]) -> "PureRandomForest":
        n_samples = len(X)
        if n_samples == 0:
            return self
        n_features = len(X[0])
        max_feat = self.max_features or max(1, int(math.isqrt(n_features)))

        self.trees = []
        raw_importances = [0.0] * n_features

        for _ in range(self.n_estimators):
            # Bootstrap sample (sample with replacement)
            indices = [random.randint(0, n_samples - 1) for _ in range(n_samples)]
            boot_X = [X[i] for i in indices]
            boot_y = [y[i] for i in indices]

            tree = PureDecisionTree(
                max_depth=self.max_depth,
                min_samples_split=4,
                max_features=max_feat,
            )
            tree.fit(boot_X, boot_y, n_total_features=n_features)
            self.trees.append(tree)

            for j in range(n_features):
                raw_importances[j] += tree.feature_importances[j]

        # Normalize feature importances to sum to 1.0
        total_imp = sum(raw_importances)
        if total_imp > 0:
            self.feature_importances_ = [imp / total_imp for imp in raw_importances]
        else:
            self.feature_importances_ = [1.0 / n_features] * n_features

        return self

    def predict_proba(self, X: List[List[float]]) -> List[List[float]]:
        """Return list of [P(benign), P(phishing)] for each row."""
        if not self.trees:
            return [[0.5, 0.5] for _ in X]

        results = []
        n_trees = len(self.trees)
        for row in X:
            pos_sum = sum(tree.predict_one(row) for tree in self.trees)
            prob_phish = max(0.0, min(1.0, pos_sum / n_trees))
            results.append([round(1.0 - prob_phish, 4), round(prob_phish, 4)])
        return results

    def predict(self, X: List[List[float]], threshold: float = 0.5) -> List[int]:
        probs = self.predict_proba(X)
        return [1 if p[1] >= threshold else 0 for p in probs]

    def save(self, filepath: Path):
        """Save model trees and feature importances to JSON."""
        data = {
            "n_estimators": len(self.trees),
            "feature_importances": self.feature_importances_,
            "trees": [t.root.to_dict() if t.root else None for t in self.trees],
        }
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(json.dumps(data), encoding="utf-8")

    @classmethod
    def load(cls, filepath: Path) -> "PureRandomForest":
        """Load model trees and feature importances from JSON."""
        data = json.loads(filepath.read_text(encoding="utf-8"))
        rf = cls(n_estimators=data.get("n_estimators", 30))
        rf.feature_importances_ = data.get("feature_importances", [])
        rf.trees = []
        for tree_dict in data.get("trees", []):
            if tree_dict:
                tree = PureDecisionTree()
                tree.root = PureNode.from_dict(tree_dict)
                rf.trees.append(tree)
        return rf
