"""Tests for threshold optimization and evaluation metrics (src/models/train.py).

A tiny stub model with a fixed predict_proba is used so the metric/threshold
logic is tested without training anything.
"""

import numpy as np
import pytest

# src.models.train hard-imports xgboost and lightgbm at module load; skip the
# whole module cleanly in environments where those wheels are not installed.
pytest.importorskip("xgboost")
pytest.importorskip("lightgbm")

from src.models.train import ModelTrainer


class _StubModel:
    """Returns pre-baked positive-class probabilities, in order."""

    def __init__(self, probs):
        self._probs = np.asarray(probs, dtype=float)

    def predict_proba(self, X):
        p = self._probs[: len(X)]
        return np.column_stack([1 - p, p])


def _trainer_with(model, model_type='xgboost'):
    t = ModelTrainer.__new__(ModelTrainer)   # skip config loading
    t.model = model
    t.model_type = model_type
    t.threshold = 0.5
    return t


def test_optimize_threshold_selects_f1_maximizing_value():
    # Labels perfectly separable at 0.5; a low threshold would add false positives.
    y = np.array([0, 0, 0, 1, 1, 1])
    probs = np.array([0.05, 0.10, 0.20, 0.80, 0.85, 0.90])
    t = _trainer_with(_StubModel(probs))

    thr = t.optimize_threshold(probs_X := np.zeros((6, 1)), y, metric='f1')

    # Perfect separation -> F1 == 1.0 achievable; chosen threshold sits in the gap.
    assert 0.20 < thr <= 0.80
    assert t.threshold == thr
    preds = (probs >= thr).astype(int)
    from sklearn.metrics import f1_score
    assert f1_score(y, preds) == pytest.approx(1.0)


def test_optimize_threshold_defaults_when_no_signal():
    y = np.array([0, 0, 0, 0])            # only one class present
    probs = np.array([0.4, 0.5, 0.6, 0.7])
    t = _trainer_with(_StubModel(probs))
    thr = t.optimize_threshold(np.zeros((4, 1)), y, metric='f1')
    assert thr == 0.5   # falls back to default when no positive F1 is found


def test_evaluate_reports_consistent_metrics():
    y = np.array([0, 0, 1, 1])
    probs = np.array([0.1, 0.4, 0.6, 0.9])
    t = _trainer_with(_StubModel(probs))
    t.threshold = 0.5

    metrics = t.evaluate(np.zeros((4, 1)), y)

    expected_preds = (probs >= 0.5).astype(int)
    assert metrics['accuracy'] == pytest.approx((expected_preds == y).mean())
    assert 0.0 <= metrics['pr_auc'] <= 1.0
    assert 0.0 <= metrics['roc_auc'] <= 1.0
    assert metrics['threshold'] == 0.5
    cm = np.array(metrics['confusion_matrix'])
    assert cm.shape == (2, 2)
    assert cm.sum() == len(y)


def test_evaluate_threshold_argument_overrides_attribute():
    y = np.array([0, 1, 1])
    probs = np.array([0.3, 0.55, 0.7])
    t = _trainer_with(_StubModel(probs))
    t.threshold = 0.5
    strict = t.evaluate(np.zeros((3, 1)), y, threshold=0.6)
    assert strict['threshold'] == 0.6
    # At 0.6 only the 0.7 sample is positive -> one of the two positives missed.
    assert strict['accuracy'] == pytest.approx(2 / 3)
