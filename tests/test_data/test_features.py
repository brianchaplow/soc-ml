"""Tests for FeatureEngineer (src/data/features.py).

Uses tiny synthetic DataFrames only, with no OpenSearch or disk I/O.
Focus: the fit/transform contract and the leakage guards the pipeline
depends on (scaler/encoders fit on train only, no label-leaking features).
"""

import numpy as np
import pandas as pd
import pytest

from src.data.features import FeatureEngineer


def _sample_df(n_rows=6):
    """Small behavioral DataFrame resembling Suricata+flow records."""
    return pd.DataFrame({
        'src_ip': ['10.10.20.5', '8.8.8.8', '10.10.40.9', '10.10.20.5',
                   '1.1.1.1', '10.10.30.40'][:n_rows],
        'dest_ip': ['10.10.40.5', '10.10.20.5', '10.10.40.10', '8.8.8.8',
                    '10.10.20.5', '10.10.30.41'][:n_rows],
        'src_port': [44000, 53, 50100, 44001, 40000, 49200][:n_rows],
        'dest_port': [445, 44000, 80, 443, 22, 3389][:n_rows],
        'proto': ['TCP', 'UDP', 'TCP', 'TCP', 'TCP', 'TCP'][:n_rows],
        'direction': ['to_server', 'to_client', 'to_server', 'to_server',
                      'to_server', 'to_server'][:n_rows],
        'vlan': [[20], [40], [40], [20], [20], [30]][:n_rows],
        'flow.bytes_toserver': [100, 200, 5000, 60, 40, 9000][:n_rows],
        'flow.bytes_toclient': [50, 80, 100, 120, 20, 300][:n_rows],
        'flow.pkts_toserver': [2, 3, 50, 1, 1, 80][:n_rows],
        'flow.pkts_toclient': [1, 1, 5, 2, 1, 6][:n_rows],
        '@timestamp': pd.to_datetime([
            '2026-01-01T10:00:00', '2026-01-01T23:00:00', '2026-01-02T03:00:00',
            '2026-01-02T14:00:00', '2026-01-03T09:30:00', '2026-01-03T22:15:00',
        ][:n_rows]),
    })


def test_fit_transform_shape_and_names():
    eng = FeatureEngineer()
    df = _sample_df()
    X, names = eng.fit_transform(df)
    assert X.shape[0] == len(df)
    assert X.shape[1] == len(names)
    assert len(names) == len(set(names)), "feature names must be unique"
    assert np.isfinite(X).all(), "no NaN/inf should remain in feature matrix"


def test_no_label_leaking_features():
    """severity / signature_id / signature / category must never be features."""
    eng = FeatureEngineer()
    _, names = eng.fit_transform(_sample_df())
    joined = " ".join(names).lower()
    for leak in ('severity', 'signature', 'category'):
        assert leak not in joined, f"leaky feature '{leak}' present"


def test_transform_matches_fit_columns_and_order():
    eng = FeatureEngineer()
    _, names = eng.fit_transform(_sample_df())
    # Different rows, and a column missing entirely (dest_port) -> still aligns.
    other = _sample_df(n_rows=3).drop(columns=['dest_port'])
    Xt = eng.transform(other)
    assert Xt.shape == (3, len(names))
    assert np.isfinite(Xt).all()


def test_transform_before_fit_raises():
    with pytest.raises(ValueError):
        FeatureEngineer().transform(_sample_df())


def test_scaler_fit_on_train_only_no_test_leakage():
    """Leakage guard: with scale=True the StandardScaler must be fit on the
    training frame, and calling transform() on held-out data must NOT refit it.

    This locks in that scaling statistics never see test data.
    """
    eng = FeatureEngineer()
    train = _sample_df()
    eng.fit_transform(train, scale=True)
    assert eng.scaler is not None
    mean_before = eng.scaler.mean_.copy()
    scale_before = eng.scaler.scale_.copy()

    # Transform a very different distribution; scaler params must be frozen.
    test = _sample_df(n_rows=3)
    test['flow.bytes_toserver'] = [10 ** 7, 10 ** 7, 10 ** 7]
    eng.transform(test)

    np.testing.assert_array_equal(eng.scaler.mean_, mean_before)
    np.testing.assert_array_equal(eng.scaler.scale_, scale_before)


def test_unseen_categorical_falls_back_to_known_class():
    """An unseen protocol must map to OTHER instead of raising at transform."""
    eng = FeatureEngineer()
    eng.fit_transform(_sample_df())
    odd = _sample_df(n_rows=2)
    odd['proto'] = ['SCTP', 'GRE']  # never seen during fit
    Xt = eng.transform(odd)  # must not raise
    assert Xt.shape[0] == 2


def test_ip_direction_features_are_correct():
    eng = FeatureEngineer()
    df = pd.DataFrame({
        'src_ip': ['10.10.20.5', '8.8.8.8', '10.10.20.5'],
        'dest_ip': ['10.10.40.5', '10.10.20.5', '9.9.9.9'],
        'src_port': [1000, 53, 1000], 'dest_port': [445, 1000, 443],
        'proto': ['TCP', 'TCP', 'TCP'],
    })
    feats = eng._extract_ip_features(df)
    # row0: internal->internal ; row1: external->internal (inbound) ; row2: internal->external (outbound)
    assert feats['is_internal_traffic'].tolist() == [1, 0, 0]
    assert feats['is_inbound'].tolist() == [0, 1, 0]
    assert feats['is_outbound'].tolist() == [0, 0, 1]


def test_fit_transform_is_deterministic():
    df = _sample_df()
    X1, _ = FeatureEngineer().fit_transform(df)
    X2, _ = FeatureEngineer().fit_transform(df)
    np.testing.assert_array_equal(X1, X2)
