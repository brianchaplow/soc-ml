"""Shared test fixtures for soc-ml."""

import pytest
import numpy as np
import pandas as pd
from sklearn.datasets import make_classification


@pytest.fixture
def synthetic_binary_data():
    """Generate synthetic binary classification data matching SOC-ML feature shape."""
    X, y = make_classification(
        n_samples=500,
        n_features=70,
        n_informative=30,
        n_classes=2,
        weights=[0.85, 0.15],
        random_state=42
    )
    feature_names = [f'feature_{i}' for i in range(70)]
    return X, y, feature_names


@pytest.fixture
def train_val_test_split(synthetic_binary_data):
    """Pre-split data into train/val/test."""
    from sklearn.model_selection import train_test_split

    X, y, feature_names = synthetic_binary_data

    X_train, X_tmp, y_train, y_tmp = train_test_split(
        X, y, test_size=0.3, stratify=y, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_tmp, y_tmp, test_size=0.5, stratify=y_tmp, random_state=42
    )

    return {
        'X_train': X_train, 'y_train': y_train,
        'X_val': X_val, 'y_val': y_val,
        'X_test': X_test, 'y_test': y_test,
        'feature_names': feature_names,
    }


@pytest.fixture
def ground_truth_df():
    """Generate a DataFrame mimicking ground-truth labeled data for detection comparison."""
    np.random.seed(42)
    n = 200

    df = pd.DataFrame({
        'attack_confirmed': np.random.choice([True, False], n, p=[0.2, 0.8]),
        'alert.signature_id': np.where(
            np.random.random(n) > 0.4,
            np.random.choice([9000001, 9000002, 9000010, 2100498], n),
            np.nan
        ),
        'alert.signature': np.where(
            np.random.random(n) > 0.4,
            np.random.choice(['HOMELAB SQLi', 'HOMELAB XSS', 'ET SCAN', 'ET MALWARE'], n),
            None
        ),
        'alert.severity': np.random.choice([1, 2, 3, 4], n, p=[0.1, 0.3, 0.4, 0.2]),
        'attack_category': np.where(
            np.random.random(n) > 0.3,
            np.random.choice(['sql_injection', 'xss', 'brute_force', 'recon', 'c2_simulation'], n),
            None
        ),
        'attack_tool': np.random.choice(['sqlmap', 'nmap', 'hydra', 'nikto', None], n),
        'src_ip': [f'10.10.20.{np.random.randint(1,254)}' for _ in range(n)],
        'dest_ip': [f'10.10.40.{np.random.randint(1,254)}' for _ in range(n)],
    })

    return df
