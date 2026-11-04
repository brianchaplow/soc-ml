"""Tests for DataExtractor (src/data/extract.py).

No OpenSearch connection: get_client is monkeypatched to a dummy so we can
exercise the pure data-shaping logic (labeling, temporal split, balancing).
"""

import numpy as np
import pandas as pd
import pytest

from src.data import extract as extract_mod
from src.data.extract import DataExtractor


class _DummyClient:
    config = {'zeek': {'enabled': False}}


@pytest.fixture
def extractor(monkeypatch):
    monkeypatch.setattr(extract_mod, 'get_client', lambda *a, **k: _DummyClient())
    ex = DataExtractor()
    # Controlled label config so the test does not depend on config/features.yaml.
    ex.features_config = {
        'labels': {'binary': {
            'attack': {'signature_patterns': ['HOMELAB'], 'categories': ['Attack']},
            'noise': {'signatures': ['ET SCAN Nmap'], 'categories': ['Noise']},
            'info': {'signature_patterns': ['ET INFO'], 'categories': ['Info']},
        }},
        'sampling': {'target_samples': {'attack': None, 'noise': 2, 'benign': 2},
                     'min_samples': 1},
    }
    return ex


def test_classify_alert_attack_noise_info_default(extractor):
    rows = [
        ({'alert.signature': 'HOMELAB SQLi detected', 'alert.category': ''}, 'attack'),
        ({'alert.signature': 'x', 'alert.category': 'Attack'}, 'attack'),
        ({'alert.signature': 'ET SCAN Nmap', 'alert.category': ''}, 'noise'),
        ({'alert.signature': 'ET INFO Observed DNS', 'alert.category': ''}, 'info'),
        ({'alert.signature': 'totally unknown', 'alert.category': ''}, 'noise'),  # conservative default
    ]
    for payload, expected in rows:
        assert extractor._classify_alert(pd.Series(payload)) == expected


def test_temporal_split_has_no_future_leakage(extractor):
    df = pd.DataFrame({
        '@timestamp': pd.to_datetime([
            '2026-01-01', '2026-01-10', '2026-01-15',
            '2026-01-16', '2026-01-20', '2026-01-27',
        ]),
        'label_binary': ['attack', 'noise', 'benign', 'attack', 'noise', 'benign'],
    })
    train, test = extractor.temporal_split(df, split_date='2026-01-16')
    assert len(train) == 3 and len(test) == 3
    # The defining property: train is strictly before the split, test is on/after.
    assert train['@timestamp'].max() < pd.Timestamp('2026-01-16')
    assert test['@timestamp'].min() >= pd.Timestamp('2026-01-16')


def test_balanced_dataset_undersamples_and_is_reproducible(extractor):
    rng = np.random.default_rng(0)
    alerts = pd.DataFrame({
        'label_binary': ['attack'] * 3 + ['noise'] * 10,
        'val': rng.integers(0, 100, 13),
    })
    flows = pd.DataFrame({'label_binary': ['benign'] * 10, 'val': rng.integers(0, 100, 10)})

    out1 = extractor.create_balanced_dataset(alerts, flows, random_state=42)
    out2 = extractor.create_balanced_dataset(alerts, flows, random_state=42)

    counts = out1['label_binary'].value_counts()
    assert counts.get('attack', 0) == 3      # target None -> keep all
    assert counts.get('noise', 0) == 2       # undersampled to target
    assert counts.get('benign', 0) == 2
    # Deterministic for a fixed seed.
    pd.testing.assert_frame_equal(
        out1.sort_index(axis=1).reset_index(drop=True),
        out2.sort_index(axis=1).reset_index(drop=True),
    )
