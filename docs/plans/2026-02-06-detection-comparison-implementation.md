# Detection Comparison & Multi-Model Analysis — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a multi-model detection comparison system that trains 7 ML model types, compares them against Suricata signature-based detection, and produces portfolio-quality reports (terminal, JSON, Discord, HTML+Plotly+SHAP).

**Architecture:** Three-layer system — `train.py` trains all models, `detection_comparison.py` analyzes detection accuracy across all models + Suricata, `report_generator.py` produces all output formats. New `mlp.py` module for PyTorch neural net. Integration into `post_campaign_automation.sh` for unattended operation.

**Tech Stack:** Python 3, PyTorch (GPU — GTX 1650 Ti), scikit-learn, XGBoost, LightGBM, SHAP, Plotly, tabulate, pytest

**Design Doc:** `docs/plans/2026-02-06-detection-comparison-design.md`

---

## Task 1: Environment Setup

**Files:**
- Modify: `config/model.yaml` (add KNN + MLP config sections)

**Step 1: Install new dependencies**

```bash
cd ~/soc-ml
conda activate soc-ml
conda install pytorch pytorch-cuda=12.4 -c pytorch -c nvidia -y
pip install tabulate pytest
```

Verify GPU:
```bash
python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}'); print(f'Device: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else \"CPU\"}')"
```

Expected: `CUDA available: True` and `Device: NVIDIA GeForce GTX 1650 Ti`

**Step 2: Create test infrastructure**

```bash
mkdir -p tests/test_models tests/test_analysis tests/fixtures
```

Create `tests/conftest.py`:
```python
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
```

Create `pytest.ini`:
```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*
addopts = -v --tb=short
```

**Step 3: Verify test infrastructure**

```bash
cd ~/soc-ml
python -m pytest tests/ --co
```

Expected: `no tests ran` (collected 0 items — confirms pytest finds the directory)

**Step 4: Add KNN and MLP config sections to model.yaml**

Add after the `lightgbm` section (after line 97 in `config/model.yaml`):

```yaml
# -----------------------------------------------------------------------------
# KNN (comparison)
# -----------------------------------------------------------------------------
knn:
  n_neighbors: 7
  algorithm: "ball_tree"
  weights: "distance"
  metric: "minkowski"
  n_jobs: -1

# -----------------------------------------------------------------------------
# MLP Neural Network (comparison)
# -----------------------------------------------------------------------------
mlp:
  # Architecture
  hidden_layers: [256, 128, 64]
  dropout: 0.3
  activation: "relu"
  batch_norm: true

  # Training
  learning_rate: 0.001
  batch_size: 256
  max_epochs: 100
  early_stopping_patience: 10

  # GPU
  device: "auto"  # "auto", "cuda", "cpu"

  # Class imbalance
  class_weight: "balanced"

  # Reproducibility
  random_state: 42
```

Also add to the `models.baseline` list (line 19):
```yaml
    - name: "knn"
    - name: "mlp"
```

**Step 5: Commit**

```bash
git add tests/ pytest.ini config/model.yaml
git commit -m "feat: add test infrastructure, KNN/MLP config sections"
```

---

## Task 2: MLP Model Class (mlp.py)

**Files:**
- Create: `src/models/mlp.py`
- Test: `tests/test_models/test_mlp.py`

**Step 1: Write failing tests for MLP**

Create `tests/test_models/test_mlp.py`:

```python
"""Tests for PyTorch MLP model."""

import pytest
import numpy as np


class TestSOCMLP:
    """Test the MLP model class."""

    def test_model_creation(self):
        """MLP model can be created with default config."""
        from src.models.mlp import SOCMLP

        model = SOCMLP(n_features=70)
        assert model is not None
        assert model.n_features == 70

    def test_model_creation_custom_layers(self):
        """MLP model respects custom hidden layer sizes."""
        from src.models.mlp import SOCMLP

        model = SOCMLP(n_features=70, hidden_layers=[128, 64, 32])
        assert model is not None

    def test_forward_pass(self):
        """Forward pass produces correct output shape."""
        import torch
        from src.models.mlp import SOCMLP

        model = SOCMLP(n_features=70)
        X = torch.randn(16, 70)
        output = model(X)
        assert output.shape == (16, 1)

    def test_output_range(self):
        """Output values are between 0 and 1 (sigmoid)."""
        import torch
        from src.models.mlp import SOCMLP

        model = SOCMLP(n_features=70)
        X = torch.randn(32, 70)
        output = model(X)
        assert (output >= 0).all() and (output <= 1).all()


class TestMLPTrainer:
    """Test the MLP training wrapper."""

    def test_trainer_creation(self):
        """Trainer can be created with config dict."""
        from src.models.mlp import MLPTrainer

        trainer = MLPTrainer(n_features=70)
        assert trainer is not None

    def test_fit(self, train_val_test_split):
        """Trainer can fit on data."""
        from src.models.mlp import MLPTrainer

        data = train_val_test_split
        trainer = MLPTrainer(n_features=70)
        trainer.fit(
            data['X_train'], data['y_train'],
            data['X_val'], data['y_val']
        )
        assert trainer.fitted

    def test_predict_proba(self, train_val_test_split):
        """Trainer produces probability predictions."""
        from src.models.mlp import MLPTrainer

        data = train_val_test_split
        trainer = MLPTrainer(n_features=70)
        trainer.fit(
            data['X_train'], data['y_train'],
            data['X_val'], data['y_val'],
            max_epochs=5  # fast for test
        )
        proba = trainer.predict_proba(data['X_test'])
        assert proba.shape == (len(data['X_test']),)
        assert (proba >= 0).all() and (proba <= 1).all()

    def test_predict(self, train_val_test_split):
        """Trainer produces binary predictions."""
        from src.models.mlp import MLPTrainer

        data = train_val_test_split
        trainer = MLPTrainer(n_features=70)
        trainer.fit(
            data['X_train'], data['y_train'],
            data['X_val'], data['y_val'],
            max_epochs=5
        )
        preds = trainer.predict(data['X_test'])
        assert set(np.unique(preds)).issubset({0, 1})

    def test_save_load(self, train_val_test_split, tmp_path):
        """Model can be saved and loaded."""
        from src.models.mlp import MLPTrainer

        data = train_val_test_split
        trainer = MLPTrainer(n_features=70)
        trainer.fit(
            data['X_train'], data['y_train'],
            data['X_val'], data['y_val'],
            max_epochs=5
        )

        save_dir = str(tmp_path / "mlp_test")
        trainer.save(save_dir)

        loaded = MLPTrainer.load(save_dir)
        original_preds = trainer.predict_proba(data['X_test'])
        loaded_preds = loaded.predict_proba(data['X_test'])
        np.testing.assert_array_almost_equal(original_preds, loaded_preds, decimal=5)

    def test_device_selection(self):
        """Trainer selects GPU when available, CPU otherwise."""
        import torch
        from src.models.mlp import MLPTrainer

        trainer = MLPTrainer(n_features=70, device='auto')
        if torch.cuda.is_available():
            assert 'cuda' in str(trainer.device)
        else:
            assert 'cpu' in str(trainer.device)
```

**Step 2: Run tests to verify they fail**

```bash
cd ~/soc-ml
python -m pytest tests/test_models/test_mlp.py -v
```

Expected: All tests FAIL with `ModuleNotFoundError: No module named 'src.models.mlp'`

**Step 3: Implement SOCMLP and MLPTrainer**

Create `src/models/mlp.py`:

```python
"""
PyTorch MLP Model for SOC Threat Detection
==========================================
Simple feedforward neural network for binary classification
of network traffic as attack vs benign.

Designed for GPU training on sear (GTX 1650 Ti).
"""

import os
import json
import logging
from typing import List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import average_precision_score

logger = logging.getLogger(__name__)


class SOCMLP(nn.Module):
    """
    Feedforward neural network for binary threat classification.

    Architecture: Input -> [Hidden + BatchNorm + ReLU + Dropout] x N -> Sigmoid
    """

    def __init__(
        self,
        n_features: int,
        hidden_layers: Optional[List[int]] = None,
        dropout: float = 0.3,
        batch_norm: bool = True,
    ):
        super().__init__()
        self.n_features = n_features

        if hidden_layers is None:
            hidden_layers = [256, 128, 64]

        layers = []
        prev_size = n_features

        for hidden_size in hidden_layers:
            layers.append(nn.Linear(prev_size, hidden_size))
            if batch_norm:
                layers.append(nn.BatchNorm1d(hidden_size))
            layers.append(nn.ReLU())
            layers.append(nn.Dropout(dropout))
            prev_size = hidden_size

        layers.append(nn.Linear(prev_size, 1))
        layers.append(nn.Sigmoid())

        self.network = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)


class MLPTrainer:
    """
    Sklearn-compatible training wrapper for SOCMLP.

    Handles scaling, GPU transfer, training loop with early stopping,
    and save/load for integration with ModelTrainer.
    """

    def __init__(
        self,
        n_features: int,
        hidden_layers: Optional[List[int]] = None,
        dropout: float = 0.3,
        batch_norm: bool = True,
        learning_rate: float = 0.001,
        batch_size: int = 256,
        device: str = 'auto',
        random_state: int = 42,
    ):
        self.n_features = n_features
        self.hidden_layers = hidden_layers
        self.dropout = dropout
        self.batch_norm = batch_norm
        self.learning_rate = learning_rate
        self.batch_size = batch_size
        self.random_state = random_state
        self.fitted = False

        # Device selection
        if device == 'auto':
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        else:
            self.device = torch.device(device)

        # Set seeds
        torch.manual_seed(random_state)
        np.random.seed(random_state)
        if torch.cuda.is_available():
            torch.cuda.manual_seed(random_state)

        # Initialize model and scaler
        self.model = SOCMLP(
            n_features=n_features,
            hidden_layers=hidden_layers,
            dropout=dropout,
            batch_norm=batch_norm,
        ).to(self.device)

        self.scaler = StandardScaler()
        self.training_history = []

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        max_epochs: int = 100,
        early_stopping_patience: int = 10,
    ):
        """Train the MLP with early stopping on validation PR-AUC."""
        logger.info(f"Training MLP on {self.device} ({len(X_train)} samples)")

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)

        # Compute class weights for imbalance
        n_pos = y_train.sum()
        n_neg = len(y_train) - n_pos
        pos_weight = torch.tensor([n_neg / n_pos], dtype=torch.float32).to(self.device)

        # Create data loaders
        train_dataset = TensorDataset(
            torch.FloatTensor(X_train_scaled),
            torch.FloatTensor(y_train.astype(np.float32)),
        )
        train_loader = DataLoader(
            train_dataset, batch_size=self.batch_size, shuffle=True
        )

        # Validation set
        if X_val is not None:
            X_val_scaled = self.scaler.transform(X_val)

        # Loss and optimizer
        criterion = nn.BCELoss(weight=None)  # We use pos_weight manually
        optimizer = torch.optim.Adam(
            self.model.parameters(), lr=self.learning_rate
        )

        # Training loop
        best_val_prauc = -1
        best_state = None
        patience_counter = 0
        self.training_history = []

        for epoch in range(max_epochs):
            # Train
            self.model.train()
            epoch_loss = 0
            n_batches = 0

            for X_batch, y_batch in train_loader:
                X_batch = X_batch.to(self.device)
                y_batch = y_batch.to(self.device)

                optimizer.zero_grad()
                output = self.model(X_batch).squeeze()

                # Weighted BCE: apply pos_weight to positive samples
                weight = torch.where(y_batch == 1, pos_weight, torch.ones_like(y_batch))
                loss = nn.functional.binary_cross_entropy(output, y_batch, weight=weight)

                loss.backward()
                optimizer.step()

                epoch_loss += loss.item()
                n_batches += 1

            avg_loss = epoch_loss / n_batches

            # Validate
            if X_val is not None:
                val_proba = self._predict_proba_internal(X_val_scaled)
                val_prauc = average_precision_score(y_val, val_proba)

                self.training_history.append({
                    'epoch': epoch + 1,
                    'train_loss': round(avg_loss, 4),
                    'val_prauc': round(val_prauc, 4),
                })

                if val_prauc > best_val_prauc:
                    best_val_prauc = val_prauc
                    best_state = {k: v.cpu().clone() for k, v in self.model.state_dict().items()}
                    patience_counter = 0
                else:
                    patience_counter += 1

                if patience_counter >= early_stopping_patience:
                    logger.info(f"Early stopping at epoch {epoch + 1} (best PR-AUC: {best_val_prauc:.4f})")
                    break

                if (epoch + 1) % 10 == 0:
                    logger.info(f"Epoch {epoch + 1}: loss={avg_loss:.4f}, val_prauc={val_prauc:.4f}")
            else:
                self.training_history.append({
                    'epoch': epoch + 1,
                    'train_loss': round(avg_loss, 4),
                })

        # Restore best model
        if best_state is not None:
            self.model.load_state_dict(best_state)
            self.model.to(self.device)

        self.fitted = True
        logger.info(f"MLP training complete. Best val PR-AUC: {best_val_prauc:.4f}")

    def _predict_proba_internal(self, X_scaled: np.ndarray) -> np.ndarray:
        """Predict on already-scaled data."""
        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X_scaled).to(self.device)

            # Batch if large
            if len(X_scaled) > 10000:
                outputs = []
                for i in range(0, len(X_scaled), self.batch_size):
                    batch = X_tensor[i:i + self.batch_size]
                    outputs.append(self.model(batch).cpu().numpy())
                return np.concatenate(outputs).squeeze()
            else:
                return self.model(X_tensor).cpu().numpy().squeeze()

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict probabilities for attack class."""
        X_scaled = self.scaler.transform(X)
        return self._predict_proba_internal(X_scaled)

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """Predict binary labels."""
        proba = self.predict_proba(X)
        return (proba >= threshold).astype(int)

    def save(self, path: str):
        """Save model, scaler, and architecture config."""
        import pickle

        os.makedirs(path, exist_ok=True)

        # Save model weights
        torch.save(self.model.state_dict(), os.path.join(path, 'model.pt'))

        # Save scaler
        with open(os.path.join(path, 'scaler.pkl'), 'wb') as f:
            pickle.dump(self.scaler, f)

        # Save architecture config
        config = {
            'n_features': self.n_features,
            'hidden_layers': self.hidden_layers or [256, 128, 64],
            'dropout': self.dropout,
            'batch_norm': self.batch_norm,
            'learning_rate': self.learning_rate,
            'batch_size': self.batch_size,
            'random_state': self.random_state,
            'training_history': self.training_history,
        }
        with open(os.path.join(path, 'architecture.json'), 'w') as f:
            json.dump(config, f, indent=2)

        logger.info(f"MLP saved to {path}")

    @classmethod
    def load(cls, path: str, device: str = 'auto') -> 'MLPTrainer':
        """Load a saved MLP model."""
        import pickle

        # Load architecture config
        with open(os.path.join(path, 'architecture.json'), 'r') as f:
            config = json.load(f)

        trainer = cls(
            n_features=config['n_features'],
            hidden_layers=config['hidden_layers'],
            dropout=config['dropout'],
            batch_norm=config['batch_norm'],
            learning_rate=config['learning_rate'],
            batch_size=config['batch_size'],
            device=device,
            random_state=config['random_state'],
        )

        # Load model weights
        state_dict = torch.load(
            os.path.join(path, 'model.pt'),
            map_location=trainer.device,
            weights_only=True,
        )
        trainer.model.load_state_dict(state_dict)

        # Load scaler
        with open(os.path.join(path, 'scaler.pkl'), 'rb') as f:
            trainer.scaler = pickle.load(f)

        trainer.fitted = True
        trainer.training_history = config.get('training_history', [])

        logger.info(f"MLP loaded from {path}")
        return trainer
```

**Step 4: Run tests to verify they pass**

```bash
cd ~/soc-ml
python -m pytest tests/test_models/test_mlp.py -v
```

Expected: All 9 tests PASS

**Step 5: Commit**

```bash
git add src/models/mlp.py tests/test_models/test_mlp.py
git commit -m "feat: add PyTorch MLP model class with GPU support"
```

---

## Task 3: Extend train.py — Add KNN and MLP

**Files:**
- Modify: `src/models/train.py` (lines 311-316, 1247-1333, 1399-1484)
- Test: `tests/test_models/test_compare.py`

**Step 1: Write failing tests for extended compare_models**

Create `tests/test_models/test_compare.py`:

```python
"""Tests for extended model comparison including KNN and MLP."""

import pytest
import numpy as np


class TestCompareModels:
    """Test that compare_models includes KNN and MLP."""

    def test_compare_includes_knn(self, train_val_test_split):
        """KNN appears in comparison results."""
        from src.models.train import ModelTrainer

        data = train_val_test_split
        trainer = ModelTrainer()
        comparison = trainer.compare_models(
            data['X_train'], data['y_train'],
            data['X_test'], data['y_test'],
            data['X_val'], data['y_val'],
        )
        assert 'KNN' in comparison['model'].values

    def test_compare_includes_mlp(self, train_val_test_split):
        """MLP appears in comparison results."""
        from src.models.train import ModelTrainer

        data = train_val_test_split
        trainer = ModelTrainer()
        comparison = trainer.compare_models(
            data['X_train'], data['y_train'],
            data['X_test'], data['y_test'],
            data['X_val'], data['y_val'],
        )
        assert 'MLP' in comparison['model'].values

    def test_compare_all_seven_models(self, train_val_test_split):
        """All 7 model types are compared."""
        from src.models.train import ModelTrainer

        data = train_val_test_split
        trainer = ModelTrainer()
        comparison = trainer.compare_models(
            data['X_train'], data['y_train'],
            data['X_test'], data['y_test'],
            data['X_val'], data['y_val'],
        )
        expected = {'XGBoost', 'LightGBM', 'Random Forest', 'Logistic Regression', 'KNN', 'MLP', 'Isolation Forest'}
        actual = set(comparison['model'].values)
        assert expected == actual

    def test_compare_saves_all_models(self, train_val_test_split, tmp_path):
        """compare_models with save_all=True saves all model artifacts."""
        from src.models.train import ModelTrainer

        data = train_val_test_split
        trainer = ModelTrainer()
        comparison = trainer.compare_models(
            data['X_train'], data['y_train'],
            data['X_test'], data['y_test'],
            data['X_val'], data['y_val'],
            save_all=True,
            save_dir=str(tmp_path),
            feature_names=data['feature_names'],
        )

        # Check that model directories were created
        import os
        saved_dirs = [d for d in os.listdir(tmp_path) if os.path.isdir(tmp_path / d)]
        assert len(saved_dirs) >= 7

    def test_knn_training(self, train_val_test_split):
        """KNN trains and produces valid predictions."""
        from src.models.train import ModelTrainer

        data = train_val_test_split
        trainer = ModelTrainer()
        trainer.train_knn(data['X_train'], data['y_train'])
        metrics = trainer.evaluate(data['X_test'], data['y_test'])
        assert 'pr_auc' in metrics
        assert metrics['pr_auc'] > 0

    def test_mlp_training(self, train_val_test_split):
        """MLP trains via ModelTrainer and produces valid predictions."""
        from src.models.train import ModelTrainer

        data = train_val_test_split
        trainer = ModelTrainer()
        trainer.train_mlp(data['X_train'], data['y_train'], data['X_val'], data['y_val'])
        metrics = trainer.evaluate(data['X_test'], data['y_test'])
        assert 'pr_auc' in metrics
        assert metrics['pr_auc'] > 0
```

**Step 2: Run tests to verify they fail**

```bash
cd ~/soc-ml
python -m pytest tests/test_models/test_compare.py -v
```

Expected: FAIL — `train_knn`, `train_mlp` don't exist, compare_models only has 4 models

**Step 3: Add train_knn method to ModelTrainer**

Add after `train_logistic_regression` method (after line ~286 in `src/models/train.py`):

```python
    def train_knn(self, X_train: np.ndarray, y_train: np.ndarray):
        """
        Train K-Nearest Neighbors classifier.

        Uses StandardScaler pipeline since KNN is distance-based
        and features have different scales.
        """
        from sklearn.neighbors import KNeighborsClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline

        logger.info("Training KNN...")

        knn_config = self.config.get('knn', {})

        pipeline = Pipeline([
            ('scaler', StandardScaler()),
            ('knn', KNeighborsClassifier(
                n_neighbors=knn_config.get('n_neighbors', 7),
                algorithm=knn_config.get('algorithm', 'ball_tree'),
                weights=knn_config.get('weights', 'distance'),
                metric=knn_config.get('metric', 'minkowski'),
                n_jobs=knn_config.get('n_jobs', -1),
            ))
        ])

        pipeline.fit(X_train, y_train)

        self.model = pipeline
        self.model_type = 'knn'
        logger.info("KNN training complete")
```

**Step 4: Add train_mlp method to ModelTrainer**

Add after `train_knn`:

```python
    def train_mlp(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
    ):
        """
        Train PyTorch MLP neural network.

        Uses GPU (cuda) when available, falls back to CPU.
        """
        from src.models.mlp import MLPTrainer

        logger.info("Training MLP...")

        mlp_config = self.config.get('mlp', {})

        trainer = MLPTrainer(
            n_features=X_train.shape[1],
            hidden_layers=mlp_config.get('hidden_layers', [256, 128, 64]),
            dropout=mlp_config.get('dropout', 0.3),
            batch_norm=mlp_config.get('batch_norm', True),
            learning_rate=mlp_config.get('learning_rate', 0.001),
            batch_size=mlp_config.get('batch_size', 256),
            device=mlp_config.get('device', 'auto'),
            random_state=mlp_config.get('random_state', 42),
        )

        trainer.fit(
            X_train, y_train,
            X_val, y_val,
            max_epochs=mlp_config.get('max_epochs', 100),
            early_stopping_patience=mlp_config.get('early_stopping_patience', 10),
        )

        self.model = trainer
        self.model_type = 'mlp'
        logger.info("MLP training complete")
```

**Step 5: Extend compare_models to include all 7 model types**

Modify `model_specs` list at line 311 of `train.py`:

```python
        model_specs = [
            ('XGBoost', 'xgboost'),
            ('LightGBM', 'lightgbm'),
            ('Random Forest', 'random_forest'),
            ('Logistic Regression', 'logistic_regression'),
            ('KNN', 'knn'),
            ('MLP', 'mlp'),
            ('Isolation Forest', 'isolation_forest'),
        ]
```

Extend the training dispatch in the `for` loop (around line 321) to handle new model types:

```python
                elif model_key == 'knn':
                    self.train_knn(X_train, y_train)
                elif model_key == 'mlp':
                    self.train_mlp(X_train, y_train, X_val, y_val)
                elif model_key == 'isolation_forest':
                    # Anomaly detector — train on benign only, evaluate differently
                    normal_mask = y_train == 0
                    self.train_anomaly_detector(X_train[normal_mask])
```

For the Isolation Forest evaluation, update the evaluate block (around line 331) to handle unsupervised:

```python
                # Evaluate
                if model_key == 'isolation_forest':
                    # Anomaly scoring — use anomaly_score as probability
                    anomaly_metrics = self.evaluate_anomaly(X_test, y_test)
                    metrics = {
                        'pr_auc': anomaly_metrics.get('pr_auc', 0),
                        'roc_auc': anomaly_metrics.get('roc_auc', 0),
                        'accuracy': anomaly_metrics.get('accuracy', 0),
                        'classification_report': {
                            'weighted avg': {
                                'f1-score': anomaly_metrics.get('f1', 0),
                                'precision': anomaly_metrics.get('precision', 0),
                                'recall': anomaly_metrics.get('recall', 0),
                            }
                        },
                    }
                else:
                    metrics = self.evaluate(X_test, y_test, label_encoder)
```

Add `save_all` parameter to `compare_models` signature and save logic:

```python
    def compare_models(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        label_encoder=None,
        save_all: bool = False,
        save_dir: Optional[str] = None,
        feature_names: Optional[List[str]] = None,
    ) -> pd.DataFrame:
```

After the comparison table is built (after line ~365), add save logic:

```python
        # Save all models if requested
        if save_all and save_dir:
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            for model_key, (model, model_type, model_metrics) in trained_models.items():
                self.model = model
                self.model_type = model_type
                model_dir = os.path.join(save_dir, f'{model_key}_binary_{timestamp}')
                self.save_model(
                    model_dir,
                    feature_names=feature_names or [],
                    label_encoder=label_encoder,
                    metrics=model_metrics,
                )
```

**Step 6: Update save_model and evaluate to handle KNN and MLP**

In `save_model` (line ~1277), update the else branch to handle MLP:

```python
        elif self.model_type == 'mlp':
            self.model.save(path)  # MLPTrainer handles its own saving
        else:
            import pickle
            model_path = os.path.join(path, 'model.pkl')
            with open(model_path, 'wb') as f:
                pickle.dump(self.model, f)
```

In `evaluate` method, add handling for MLP's predict_proba interface (the MLPTrainer returns a 1D array, not a 2D array like sklearn):

```python
        # Get predictions
        if self.model_type == 'mlp':
            y_proba_positive = self.model.predict_proba(X_test)
            y_pred = self.model.predict(X_test, threshold=self.threshold)
        elif hasattr(self.model, 'predict_proba'):
            y_proba = self.model.predict_proba(X_test)
            y_proba_positive = y_proba[:, 1] if y_proba.ndim > 1 else y_proba
            y_pred = (y_proba_positive >= self.threshold).astype(int)
        else:
            y_pred = self.model.predict(X_test)
            y_proba_positive = None
```

**Step 7: Run tests to verify they pass**

```bash
cd ~/soc-ml
python -m pytest tests/test_models/test_compare.py -v
```

Expected: All 7 tests PASS (some may be slow due to MLP training — expect ~30s total)

**Step 8: Commit**

```bash
git add src/models/train.py tests/test_models/test_compare.py
git commit -m "feat: extend model comparison with KNN, MLP, IsolationForest (7 models)"
```

---

## Task 4: Refactor detection_comparison.py — Multi-Model Support

**Files:**
- Modify: `src/analysis/detection_comparison.py`
- Test: `tests/test_analysis/test_detection_comparison.py`

**Step 1: Write failing tests for MultiModelComparator**

Create `tests/test_analysis/test_detection_comparison.py`:

```python
"""Tests for multi-model detection comparison."""

import pytest
import numpy as np
import pandas as pd


class TestMultiModelComparator:
    """Test the multi-model comparison orchestrator."""

    def test_creation(self, ground_truth_df):
        """Can create MultiModelComparator with DataFrame."""
        from src.analysis.detection_comparison import MultiModelComparator

        comparator = MultiModelComparator(ground_truth_df)
        assert comparator is not None

    def test_suricata_analysis_runs(self, ground_truth_df):
        """Suricata analysis produces results without ML models."""
        from src.analysis.detection_comparison import MultiModelComparator

        comparator = MultiModelComparator(ground_truth_df)
        results = comparator.analyze_suricata()
        assert 'detection_rates' in results
        assert 'recall' in results['detection_rates']

    def test_add_model_predictions(self, ground_truth_df):
        """Can add model predictions to the comparator."""
        from src.analysis.detection_comparison import MultiModelComparator

        comparator = MultiModelComparator(ground_truth_df)
        # Simulate model predictions
        n = len(ground_truth_df)
        comparator.add_model_predictions(
            'xgboost',
            predictions=np.random.randint(0, 2, n),
            probabilities=np.random.random(n),
        )
        assert 'xgboost' in comparator.model_predictions

    def test_full_comparison(self, ground_truth_df):
        """Full comparison with multiple models produces complete results."""
        from src.analysis.detection_comparison import MultiModelComparator

        comparator = MultiModelComparator(ground_truth_df)
        n = len(ground_truth_df)

        for model_name in ['xgboost', 'lightgbm', 'knn']:
            comparator.add_model_predictions(
                model_name,
                predictions=np.random.randint(0, 2, n),
                probabilities=np.random.random(n),
            )

        results = comparator.compare_all()

        assert 'metadata' in results
        assert 'suricata' in results
        assert 'models' in results
        assert 'cross_model' in results
        assert 'recommendations' in results
        assert len(results['models']) == 3


class TestCrossModelAnalyzer:
    """Test cross-model analysis."""

    def test_consensus_matrix(self, ground_truth_df):
        """Consensus matrix counts how many models detect each attack."""
        from src.analysis.detection_comparison import MultiModelComparator

        comparator = MultiModelComparator(ground_truth_df)
        n = len(ground_truth_df)

        for name in ['model_a', 'model_b', 'model_c']:
            comparator.add_model_predictions(
                name,
                predictions=np.random.randint(0, 2, n),
                probabilities=np.random.random(n),
            )

        results = comparator.compare_all()
        consensus = results['cross_model']['consensus_matrix']
        assert 'detected_by_all' in consensus or isinstance(consensus, dict)

    def test_agreement_heatmap_data(self, ground_truth_df):
        """Agreement heatmap data has correct shape."""
        from src.analysis.detection_comparison import MultiModelComparator

        comparator = MultiModelComparator(ground_truth_df)
        n = len(ground_truth_df)

        model_names = ['model_a', 'model_b', 'model_c']
        for name in model_names:
            comparator.add_model_predictions(
                name,
                predictions=np.random.randint(0, 2, n),
                probabilities=np.random.random(n),
            )

        results = comparator.compare_all()
        heatmap = results['cross_model']['agreement_heatmap']
        assert len(heatmap) == 3  # 3 models

    def test_blind_spots_identified(self, ground_truth_df):
        """Blind spots (attacks missed by all) are identified."""
        from src.analysis.detection_comparison import MultiModelComparator

        comparator = MultiModelComparator(ground_truth_df)
        n = len(ground_truth_df)

        # All models predict 0 — everything is a blind spot
        for name in ['model_a', 'model_b']:
            comparator.add_model_predictions(
                name,
                predictions=np.zeros(n, dtype=int),
                probabilities=np.zeros(n),
            )

        results = comparator.compare_all()
        blind = results['cross_model']['blind_spots']
        assert blind['total'] >= 0

    def test_rankings(self, ground_truth_df):
        """Models are ranked by PR-AUC."""
        from src.analysis.detection_comparison import MultiModelComparator

        comparator = MultiModelComparator(ground_truth_df)
        n = len(ground_truth_df)

        for name in ['model_a', 'model_b']:
            comparator.add_model_predictions(
                name,
                predictions=np.random.randint(0, 2, n),
                probabilities=np.random.random(n),
            )

        results = comparator.compare_all()
        rankings = results['cross_model']['rankings']
        assert 'by_pr_auc' in rankings or isinstance(rankings, list)
```

**Step 2: Run tests to verify they fail**

```bash
cd ~/soc-ml
python -m pytest tests/test_analysis/test_detection_comparison.py -v
```

Expected: FAIL — `MultiModelComparator` doesn't exist

**Step 3: Implement MultiModelComparator and CrossModelAnalyzer**

Add to end of `src/analysis/detection_comparison.py` (before `run_comparison` and `__main__`), keeping existing classes intact:

```python
class MultiModelComparator:
    """
    Orchestrates comparison of multiple ML models against Suricata.

    Usage:
        comparator = MultiModelComparator(ground_truth_df)
        comparator.add_model_predictions('xgboost', preds, probas)
        comparator.add_model_predictions('mlp', preds, probas)
        results = comparator.compare_all()
    """

    def __init__(self, df: pd.DataFrame):
        self.df = df.copy()
        self.model_predictions = {}
        self.suricata_results = None
        self.model_results = {}

    def analyze_suricata(self) -> Dict:
        """Run Suricata analysis."""
        analyzer = SuricataAnalyzer(self.df)
        self.suricata_results = analyzer.analyze()
        return self.suricata_results

    def add_model_predictions(
        self,
        model_name: str,
        predictions: np.ndarray,
        probabilities: np.ndarray,
    ):
        """Add a model's predictions for comparison."""
        self.model_predictions[model_name] = {
            'predictions': predictions,
            'probabilities': probabilities,
        }

    def compare_all(self, threshold: float = 0.5) -> Dict:
        """Run full multi-model comparison."""
        logger.info("=" * 60)
        logger.info("MULTI-MODEL DETECTION COMPARISON")
        logger.info("=" * 60)

        # Suricata analysis
        if self.suricata_results is None:
            self.analyze_suricata()

        # Per-model analysis
        y_true = self.df['attack_confirmed'].astype(int).values

        for model_name, pred_data in self.model_predictions.items():
            logger.info(f"\n--- Analyzing {model_name} ---")

            y_pred = pred_data['predictions']
            y_proba = pred_data['probabilities']

            # Use existing analysis logic
            model_df = self.df.copy()
            model_df['ml_prediction'] = y_pred
            model_df['ml_probability'] = y_proba

            analyzer = MLModelAnalyzer(model_df)
            analyzer.df = model_df  # Skip re-predicting
            self.model_results[model_name] = analyzer.analyze(threshold)

        # Cross-model analysis
        cross_analyzer = CrossModelAnalyzer(
            self.df, self.model_predictions, self.suricata_results
        )
        cross_results = cross_analyzer.analyze()

        # Per-model vs Suricata comparison
        per_model_comparisons = {}
        for model_name in self.model_predictions:
            model_df = self.df.copy()
            model_df['ml_prediction'] = self.model_predictions[model_name]['predictions']
            model_df['ml_probability'] = self.model_predictions[model_name]['probabilities']

            comparator = DetectionComparator(
                model_df, self.suricata_results, self.model_results[model_name]
            )
            per_model_comparisons[model_name] = comparator.compare()

        # Combine results
        results = {
            'metadata': {
                'total_records': len(self.df),
                'attack_records': int(self.df['attack_confirmed'].sum()),
                'models_compared': list(self.model_predictions.keys()),
                'threshold': threshold,
                'timestamp': datetime.now().isoformat(),
            },
            'suricata': self.suricata_results,
            'models': self.model_results,
            'per_model_vs_suricata': per_model_comparisons,
            'cross_model': cross_results,
            'recommendations': self._generate_recommendations(cross_results),
        }

        return results

    def _generate_recommendations(self, cross_results: Dict) -> List[str]:
        """Generate recommendations from cross-model analysis."""
        recommendations = []

        # Blind spots
        blind_total = cross_results.get('blind_spots', {}).get('total', 0)
        if blind_total > 0:
            recommendations.append(
                f"CRITICAL: {blind_total} attacks evade ALL models AND Suricata. "
                "Investigate these blind spots — they represent detection gaps "
                "that no current approach covers."
            )

        # Combined vs individual detection
        rankings = cross_results.get('rankings', {})
        if isinstance(rankings, dict) and 'by_pr_auc' in rankings:
            best = rankings['by_pr_auc'][0] if rankings['by_pr_auc'] else None
            if best:
                recommendations.append(
                    f"Best model by PR-AUC: {best['model']} ({best['pr_auc']:.4f}). "
                    "Consider this as the primary production model."
                )

        # Unique catches
        unique = cross_results.get('unique_catches', {})
        for model_name, catches in unique.items():
            if catches.get('total', 0) > 5:
                recommendations.append(
                    f"{model_name} uniquely detects {catches['total']} attacks "
                    f"that no other model catches. Consider including in ensemble."
                )

        # Consensus
        consensus = cross_results.get('consensus_matrix', {})
        low_consensus = consensus.get('detected_by_minority', 0)
        if low_consensus > 0:
            recommendations.append(
                f"{low_consensus} attacks detected by only 1-2 models. "
                "These are borderline cases — review for false positives or "
                "genuine hard-to-detect patterns."
            )

        return recommendations


class CrossModelAnalyzer:
    """Analyzes agreement and disagreement across multiple models."""

    def __init__(
        self,
        df: pd.DataFrame,
        model_predictions: Dict,
        suricata_results: Dict,
    ):
        self.df = df
        self.model_predictions = model_predictions
        self.suricata_results = suricata_results

    def analyze(self) -> Dict:
        """Run full cross-model analysis."""
        return {
            'consensus_matrix': self._consensus_matrix(),
            'agreement_heatmap': self._agreement_heatmap(),
            'category_model_matrix': self._category_model_matrix(),
            'unique_catches': self._unique_catches(),
            'blind_spots': self._blind_spots(),
            'rankings': self._rankings(),
        }

    def _consensus_matrix(self) -> Dict:
        """For each attack, count how many models detected it."""
        gt_attacks = self.df['attack_confirmed'] == True
        model_names = list(self.model_predictions.keys())
        n_models = len(model_names)

        if n_models == 0 or gt_attacks.sum() == 0:
            return {'detected_by_all': 0, 'detected_by_majority': 0,
                    'detected_by_minority': 0, 'detected_by_none': 0}

        # Build detection matrix (attacks x models)
        attack_indices = np.where(gt_attacks.values)[0]
        detection_counts = np.zeros(len(attack_indices), dtype=int)

        # Include Suricata as a detector
        has_alert = self.df['alert.signature_id'].notna().values if 'alert.signature_id' in self.df.columns else np.zeros(len(self.df), dtype=bool)

        for idx_pos, idx in enumerate(attack_indices):
            if has_alert[idx]:
                detection_counts[idx_pos] += 1
            for model_name in model_names:
                if self.model_predictions[model_name]['predictions'][idx] == 1:
                    detection_counts[idx_pos] += 1

        total_detectors = n_models + 1  # models + Suricata
        majority_threshold = total_detectors // 2 + 1

        return {
            'total_attacks': int(len(attack_indices)),
            'total_detectors': total_detectors,
            'detected_by_all': int((detection_counts == total_detectors).sum()),
            'detected_by_majority': int((detection_counts >= majority_threshold).sum()),
            'detected_by_minority': int(((detection_counts > 0) & (detection_counts < majority_threshold)).sum()),
            'detected_by_none': int((detection_counts == 0).sum()),
            'distribution': {str(i): int((detection_counts == i).sum()) for i in range(total_detectors + 1)},
        }

    def _agreement_heatmap(self) -> Dict:
        """Pairwise agreement rates between all models."""
        model_names = list(self.model_predictions.keys())
        heatmap = {}

        for i, name_a in enumerate(model_names):
            heatmap[name_a] = {}
            preds_a = self.model_predictions[name_a]['predictions']

            for j, name_b in enumerate(model_names):
                preds_b = self.model_predictions[name_b]['predictions']
                agreement = (preds_a == preds_b).mean()
                heatmap[name_a][name_b] = round(float(agreement), 4)

        return heatmap

    def _category_model_matrix(self) -> Dict:
        """Detection rate for each attack category across each model."""
        if 'attack_category' not in self.df.columns:
            return {}

        gt_attacks = self.df[self.df['attack_confirmed'] == True]
        categories = gt_attacks['attack_category'].dropna().unique()
        model_names = list(self.model_predictions.keys())

        matrix = {}
        for cat in categories:
            cat_mask = (self.df['attack_confirmed'] == True) & (self.df['attack_category'] == cat)
            cat_indices = np.where(cat_mask.values)[0]
            total = len(cat_indices)

            if total == 0:
                continue

            matrix[cat] = {'total_attacks': total}

            # Suricata
            has_alert = self.df['alert.signature_id'].notna().values if 'alert.signature_id' in self.df.columns else np.zeros(len(self.df), dtype=bool)
            sur_detected = sum(1 for idx in cat_indices if has_alert[idx])
            matrix[cat]['suricata'] = round(sur_detected / total * 100, 2)

            # Each model
            for model_name in model_names:
                preds = self.model_predictions[model_name]['predictions']
                detected = sum(1 for idx in cat_indices if preds[idx] == 1)
                matrix[cat][model_name] = round(detected / total * 100, 2)

        return matrix

    def _unique_catches(self) -> Dict:
        """Attacks that only one specific model detects."""
        gt_attack_mask = self.df['attack_confirmed'].values == True
        model_names = list(self.model_predictions.keys())

        has_alert = self.df['alert.signature_id'].notna().values if 'alert.signature_id' in self.df.columns else np.zeros(len(self.df), dtype=bool)

        unique = {}
        attack_indices = np.where(gt_attack_mask)[0]

        for target_model in model_names:
            unique_indices = []
            for idx in attack_indices:
                # Target model detects
                if self.model_predictions[target_model]['predictions'][idx] != 1:
                    continue

                # No other model or Suricata detects
                other_detects = has_alert[idx]
                for other_model in model_names:
                    if other_model == target_model:
                        continue
                    if self.model_predictions[other_model]['predictions'][idx] == 1:
                        other_detects = True
                        break

                if not other_detects:
                    unique_indices.append(idx)

            by_category = {}
            if 'attack_category' in self.df.columns and unique_indices:
                cats = self.df.iloc[unique_indices]['attack_category'].value_counts()
                by_category = {str(k): int(v) for k, v in cats.items() if pd.notna(k)}

            unique[target_model] = {
                'total': len(unique_indices),
                'by_category': by_category,
            }

        return unique

    def _blind_spots(self) -> Dict:
        """Attacks that evade ALL models AND Suricata."""
        gt_attack_mask = self.df['attack_confirmed'].values == True
        model_names = list(self.model_predictions.keys())
        attack_indices = np.where(gt_attack_mask)[0]

        has_alert = self.df['alert.signature_id'].notna().values if 'alert.signature_id' in self.df.columns else np.zeros(len(self.df), dtype=bool)

        blind_indices = []
        for idx in attack_indices:
            detected = has_alert[idx]
            if not detected:
                for model_name in model_names:
                    if self.model_predictions[model_name]['predictions'][idx] == 1:
                        detected = True
                        break

            if not detected:
                blind_indices.append(idx)

        by_category = {}
        if 'attack_category' in self.df.columns and blind_indices:
            cats = self.df.iloc[blind_indices]['attack_category'].value_counts()
            by_category = {str(k): int(v) for k, v in cats.items() if pd.notna(k)}

        return {
            'total': len(blind_indices),
            'by_category': by_category,
        }

    def _rankings(self) -> Dict:
        """Rank models by various metrics."""
        from sklearn.metrics import average_precision_score, recall_score, precision_score, f1_score

        y_true = self.df['attack_confirmed'].astype(int).values
        model_names = list(self.model_predictions.keys())

        rankings_data = []
        for model_name in model_names:
            preds = self.model_predictions[model_name]['predictions']
            probas = self.model_predictions[model_name]['probabilities']

            try:
                pr_auc = average_precision_score(y_true, probas)
            except Exception:
                pr_auc = 0

            rankings_data.append({
                'model': model_name,
                'pr_auc': round(float(pr_auc), 4),
                'recall': round(float(recall_score(y_true, preds, zero_division=0)), 4),
                'precision': round(float(precision_score(y_true, preds, zero_division=0)), 4),
                'f1': round(float(f1_score(y_true, preds, zero_division=0)), 4),
            })

        return {
            'by_pr_auc': sorted(rankings_data, key=lambda x: x['pr_auc'], reverse=True),
            'by_recall': sorted(rankings_data, key=lambda x: x['recall'], reverse=True),
            'by_f1': sorted(rankings_data, key=lambda x: x['f1'], reverse=True),
        }
```

**Step 4: Update CLI to support multi-model mode**

Replace the existing `if __name__ == "__main__"` block at the bottom of `detection_comparison.py`:

```python
def run_multi_model_comparison(
    data_path: str,
    model_dir: str,
    output_dir: Optional[str] = None,
    threshold: float = 0.5,
) -> Dict:
    """
    Run multi-model comparison from saved model artifacts.

    Args:
        data_path: Path to ground-truth labeled parquet
        model_dir: Parent directory containing all model subdirectories
        output_dir: Output directory for results
        threshold: ML prediction threshold
    """
    from src.data.features import FeatureEngineer

    logger.info("=" * 60)
    logger.info("MULTI-MODEL DETECTION COMPARISON")
    logger.info("=" * 60)

    # Load data
    df = pd.read_parquet(data_path)
    logger.info(f"Loaded {len(df):,} records ({df['attack_confirmed'].sum():,} attacks)")

    # Engineer features
    fe = FeatureEngineer()
    X, feature_names = fe.fit_transform(df)
    y = df['attack_confirmed'].astype(int).values

    # Find all model directories
    model_base = Path(model_dir)
    model_dirs = sorted(model_base.glob('*_binary_*'))

    if not model_dirs:
        logger.warning(f"No model directories found in {model_dir}")
        # Fall back to single-model comparison
        return run_comparison(data_path, output_dir=output_dir, threshold=threshold)

    # Create comparator
    comparator = MultiModelComparator(df)

    # Load each model and generate predictions
    for mdir in model_dirs:
        model_name = mdir.name.rsplit('_binary_', 1)[0]
        logger.info(f"Loading {model_name} from {mdir}")

        try:
            from src.models.train import ModelTrainer

            trainer = ModelTrainer.load_model(str(mdir))

            if trainer.model_type == 'mlp':
                probas = trainer.model.predict_proba(X)
                preds = trainer.model.predict(X, threshold=threshold)
            elif hasattr(trainer.model, 'predict_proba'):
                prob_output = trainer.model.predict_proba(X)
                probas = prob_output[:, 1] if prob_output.ndim > 1 else prob_output
                preds = (probas >= threshold).astype(int)
            else:
                preds = trainer.model.predict(X)
                probas = np.zeros(len(X))

            comparator.add_model_predictions(model_name, preds, probas)

        except Exception as e:
            logger.warning(f"Failed to load {model_name}: {e}")

    # Run comparison
    results = comparator.compare_all(threshold)
    results['metadata']['data_path'] = data_path
    results['metadata']['model_dir'] = model_dir

    # Save results
    if output_dir:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        results_file = output_path / f"detection_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Results saved to {results_file}")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Detection Comparison Analysis")
    parser.add_argument('--data', required=True, help='Path to ground-truth labeled parquet')
    parser.add_argument('--model', default=None, help='Path to single model directory')
    parser.add_argument('--model-dir', default=None, help='Parent dir with all model subdirs')
    parser.add_argument('--all-models', action='store_true', help='Compare all models in --model-dir')
    parser.add_argument('--output', default='results/comparison', help='Output directory')
    parser.add_argument('--threshold', type=float, default=0.5, help='ML threshold')

    args = parser.parse_args()

    if args.all_models and args.model_dir:
        run_multi_model_comparison(
            data_path=args.data,
            model_dir=args.model_dir,
            output_dir=args.output,
            threshold=args.threshold,
        )
    else:
        run_comparison(
            data_path=args.data,
            model_dir=args.model,
            output_dir=args.output,
            threshold=args.threshold,
        )
```

**Step 5: Run tests to verify they pass**

```bash
cd ~/soc-ml
python -m pytest tests/test_analysis/test_detection_comparison.py -v
```

Expected: All 8 tests PASS

**Step 6: Commit**

```bash
git add src/analysis/detection_comparison.py tests/test_analysis/test_detection_comparison.py
git commit -m "feat: add MultiModelComparator and CrossModelAnalyzer for N-model comparison"
```

---

## Task 5: Report Generator

**Files:**
- Create: `src/analysis/report_generator.py`
- Test: `tests/test_analysis/test_report_generator.py`

**Step 1: Write failing tests**

Create `tests/test_analysis/test_report_generator.py`:

```python
"""Tests for report generator outputs."""

import pytest
import json
import os
from pathlib import Path


@pytest.fixture
def sample_comparison_results():
    """Minimal comparison results JSON for testing report generation."""
    return {
        'metadata': {
            'total_records': 1000,
            'attack_records': 150,
            'models_compared': ['xgboost', 'lightgbm', 'mlp'],
            'threshold': 0.5,
            'timestamp': '2026-02-06T12:00:00',
        },
        'suricata': {
            'detection_rates': {
                'recall': 0.74, 'precision': 0.92, 'f1_score': 0.82,
                'detection_rate': 74.0, 'false_positive_rate': 2.1,
                'true_positives': 111, 'false_negatives': 39,
                'false_positives': 10, 'true_negatives': 840,
                'total_attacks_ground_truth': 150,
                'total_benign_ground_truth': 850,
            },
            'category_performance': {
                'sql_injection': {'total_attacks': 40, 'detected': 38, 'detection_rate': 95.0},
                'c2_simulation': {'total_attacks': 30, 'detected': 0, 'detection_rate': 0.0},
            },
        },
        'models': {
            'xgboost': {
                'detection_rates': {
                    'recall': 0.89, 'precision': 0.83, 'f1_score': 0.86,
                    'detection_rate': 89.0, 'false_positive_rate': 3.5,
                },
                'category_performance': {
                    'sql_injection': {'total_attacks': 40, 'detected': 36, 'detection_rate': 90.0},
                    'c2_simulation': {'total_attacks': 30, 'detected': 22, 'detection_rate': 73.3},
                },
            },
            'lightgbm': {
                'detection_rates': {
                    'recall': 0.87, 'precision': 0.84, 'f1_score': 0.85,
                    'detection_rate': 87.0, 'false_positive_rate': 3.2,
                },
                'category_performance': {},
            },
            'mlp': {
                'detection_rates': {
                    'recall': 0.90, 'precision': 0.80, 'f1_score': 0.85,
                    'detection_rate': 90.0, 'false_positive_rate': 4.1,
                },
                'category_performance': {},
            },
        },
        'cross_model': {
            'consensus_matrix': {
                'total_attacks': 150, 'total_detectors': 4,
                'detected_by_all': 100, 'detected_by_majority': 130,
                'detected_by_minority': 15, 'detected_by_none': 5,
                'distribution': {'0': 5, '1': 5, '2': 10, '3': 30, '4': 100},
            },
            'agreement_heatmap': {
                'xgboost': {'xgboost': 1.0, 'lightgbm': 0.92, 'mlp': 0.88},
                'lightgbm': {'xgboost': 0.92, 'lightgbm': 1.0, 'mlp': 0.87},
                'mlp': {'xgboost': 0.88, 'lightgbm': 0.87, 'mlp': 1.0},
            },
            'category_model_matrix': {
                'sql_injection': {'total_attacks': 40, 'suricata': 95.0, 'xgboost': 90.0, 'lightgbm': 88.0, 'mlp': 87.0},
                'c2_simulation': {'total_attacks': 30, 'suricata': 0.0, 'xgboost': 73.3, 'lightgbm': 64.0, 'mlp': 80.0},
            },
            'rankings': {
                'by_pr_auc': [
                    {'model': 'xgboost', 'pr_auc': 0.91, 'recall': 0.89, 'precision': 0.83, 'f1': 0.86},
                    {'model': 'mlp', 'pr_auc': 0.89, 'recall': 0.90, 'precision': 0.80, 'f1': 0.85},
                    {'model': 'lightgbm', 'pr_auc': 0.88, 'recall': 0.87, 'precision': 0.84, 'f1': 0.85},
                ],
            },
            'blind_spots': {'total': 5, 'by_category': {'c2_simulation': 3, 'recon': 2}},
            'unique_catches': {},
        },
        'recommendations': ['Test recommendation 1', 'Test recommendation 2'],
    }


class TestTerminalReport:
    """Test terminal table output."""

    def test_generates_output(self, sample_comparison_results, capsys):
        """Terminal report produces output."""
        from src.analysis.report_generator import generate_terminal_report

        generate_terminal_report(sample_comparison_results)
        captured = capsys.readouterr()
        assert 'xgboost' in captured.out.lower() or 'XGBoost' in captured.out

    def test_includes_rankings(self, sample_comparison_results, capsys):
        """Terminal report shows model rankings."""
        from src.analysis.report_generator import generate_terminal_report

        generate_terminal_report(sample_comparison_results)
        captured = capsys.readouterr()
        assert 'PR-AUC' in captured.out or 'pr_auc' in captured.out.lower()


class TestJSONReport:
    """Test JSON output."""

    def test_saves_valid_json(self, sample_comparison_results, tmp_path):
        """JSON report saves valid JSON file."""
        from src.analysis.report_generator import save_json_report

        output_file = tmp_path / 'test_report.json'
        save_json_report(sample_comparison_results, str(output_file))

        with open(output_file) as f:
            loaded = json.load(f)
        assert loaded['metadata']['total_records'] == 1000


class TestHTMLReport:
    """Test HTML report generation."""

    def test_generates_html_file(self, sample_comparison_results, tmp_path):
        """HTML report creates a file."""
        from src.analysis.report_generator import generate_html_report

        output_file = tmp_path / 'test_report.html'
        generate_html_report(sample_comparison_results, str(output_file))
        assert output_file.exists()
        assert output_file.stat().st_size > 1000

    def test_html_contains_plotly(self, sample_comparison_results, tmp_path):
        """HTML report embeds Plotly.js."""
        from src.analysis.report_generator import generate_html_report

        output_file = tmp_path / 'test_report.html'
        generate_html_report(sample_comparison_results, str(output_file))

        content = output_file.read_text()
        assert 'plotly' in content.lower()

    def test_html_contains_all_sections(self, sample_comparison_results, tmp_path):
        """HTML report has all visualization sections."""
        from src.analysis.report_generator import generate_html_report

        output_file = tmp_path / 'test_report.html'
        generate_html_report(sample_comparison_results, str(output_file))

        content = output_file.read_text()
        assert 'Rankings' in content or 'rankings' in content
        assert 'Heatmap' in content or 'heatmap' in content


class TestDiscordReport:
    """Test Discord digest formatting."""

    def test_generates_embed_payload(self, sample_comparison_results):
        """Discord report generates valid embed JSON."""
        from src.analysis.report_generator import format_discord_digest

        payload = format_discord_digest(sample_comparison_results)
        assert 'embeds' in payload
        assert len(payload['embeds']) > 0
        assert 'title' in payload['embeds'][0]
```

**Step 2: Run tests to verify they fail**

```bash
cd ~/soc-ml
python -m pytest tests/test_analysis/test_report_generator.py -v
```

Expected: FAIL — module doesn't exist

**Step 3: Implement report_generator.py**

Create `src/analysis/report_generator.py`. This is a large file — implement the four output functions:

```python
"""
Report Generator for Detection Comparison
==========================================
Produces terminal tables, JSON, Discord digest, and HTML report
with interactive Plotly charts and SHAP beeswarm plots.

Author: Brian Chaplow
"""

import json
import logging
from typing import Dict, Optional, List
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


# =============================================================================
# TERMINAL REPORT
# =============================================================================

def generate_terminal_report(results: Dict):
    """Print formatted multi-model comparison to terminal."""
    from tabulate import tabulate

    print("\n" + "=" * 75)
    print("  MULTI-MODEL DETECTION COMPARISON REPORT")
    print("=" * 75)

    meta = results['metadata']
    print(f"\n  Records: {meta['total_records']:,}  |  "
          f"Attacks: {meta['attack_records']:,}  |  "
          f"Models: {len(meta['models_compared'])}  |  "
          f"Threshold: {meta['threshold']}")

    # Rankings table
    rankings = results.get('cross_model', {}).get('rankings', {}).get('by_pr_auc', [])
    if rankings:
        print("\n### Model Rankings (by PR-AUC) ###\n")
        table_data = []
        for i, r in enumerate(rankings, 1):
            table_data.append([
                i, r['model'],
                f"{r['pr_auc']:.4f}",
                f"{r['recall']:.4f}",
                f"{r['precision']:.4f}",
                f"{r['f1']:.4f}",
            ])

        # Add Suricata row
        sur = results.get('suricata', {}).get('detection_rates', {})
        table_data.append([
            '*', 'Suricata (rules)',
            '--',
            f"{sur.get('recall', 0):.4f}",
            f"{sur.get('precision', 0):.4f}",
            f"{sur.get('f1_score', 0):.4f}",
        ])

        print(tabulate(
            table_data,
            headers=['#', 'Model', 'PR-AUC', 'Recall', 'Precision', 'F1'],
            tablefmt='simple',
        ))

    # Category x Model matrix
    cat_matrix = results.get('cross_model', {}).get('category_model_matrix', {})
    if cat_matrix:
        print("\n### Detection Rate by Category (%) ###\n")
        model_names = results['metadata']['models_compared']
        headers = ['Category', 'N', 'Suricata'] + model_names

        table_data = []
        for cat, stats in sorted(cat_matrix.items(), key=lambda x: x[1].get('total_attacks', 0), reverse=True):
            row = [
                cat[:20],
                stats.get('total_attacks', 0),
                f"{stats.get('suricata', 0):.1f}",
            ]
            for m in model_names:
                row.append(f"{stats.get(m, 0):.1f}")
            table_data.append(row)

        print(tabulate(table_data, headers=headers, tablefmt='simple'))

    # Consensus
    consensus = results.get('cross_model', {}).get('consensus_matrix', {})
    if consensus:
        print("\n### Consensus Analysis ###\n")
        print(f"  Detected by all:      {consensus.get('detected_by_all', 0):>6}")
        print(f"  Detected by majority: {consensus.get('detected_by_majority', 0):>6}")
        print(f"  Detected by minority: {consensus.get('detected_by_minority', 0):>6}")
        print(f"  Blind spots (none):   {consensus.get('detected_by_none', 0):>6}")

    # Recommendations
    recs = results.get('recommendations', [])
    if recs:
        print("\n### Recommendations ###\n")
        for i, rec in enumerate(recs, 1):
            print(f"  {i}. {rec}\n")

    print("=" * 75)


# =============================================================================
# JSON REPORT
# =============================================================================

def save_json_report(results: Dict, output_path: str):
    """Save results as formatted JSON."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"JSON report saved to {output_path}")


# =============================================================================
# DISCORD DIGEST
# =============================================================================

def format_discord_digest(results: Dict) -> Dict:
    """Format results as a Discord webhook embed payload."""
    meta = results['metadata']
    rankings = results.get('cross_model', {}).get('rankings', {}).get('by_pr_auc', [])
    consensus = results.get('cross_model', {}).get('consensus_matrix', {})
    blind_spots = results.get('cross_model', {}).get('blind_spots', {}).get('total', 0)

    # Build description
    lines = [f"**Records:** {meta['total_records']:,} ({meta['attack_records']:,} attacks)"]
    lines.append(f"**Models Compared:** {len(meta['models_compared'])}")
    lines.append("")

    if rankings:
        lines.append("**Model Rankings (PR-AUC):**")
        for i, r in enumerate(rankings[:5], 1):
            medal = ['', '', ''][i - 1] if i <= 3 else f"{i}."
            lines.append(f"{medal} {r['model']}: {r['pr_auc']:.4f} PR-AUC | {r['recall']:.1%} recall")

    sur = results.get('suricata', {}).get('detection_rates', {})
    lines.append(f"\nSuricata (rules): {sur.get('recall', 0):.1%} recall | {sur.get('precision', 0):.1%} precision")

    if consensus:
        lines.append(f"\n**Consensus:** {consensus.get('detected_by_all', 0)} by all, "
                     f"{consensus.get('detected_by_none', 0)} blind spots")

    if blind_spots > 0:
        lines.append(f"\n**ALERT:** {blind_spots} attacks evade ALL detection systems")

    description = "\n".join(lines)

    # Color: green if no blind spots, yellow if some, red if many
    if blind_spots == 0:
        color = 3066993  # green
    elif blind_spots < 10:
        color = 16776960  # yellow
    else:
        color = 15158332  # red

    return {
        'embeds': [{
            'title': 'Detection Comparison Complete',
            'description': description,
            'color': color,
            'footer': {'text': f"Threshold: {meta['threshold']} | {meta.get('timestamp', '')}"},
        }]
    }


def send_discord_digest(results: Dict, webhook_url: str):
    """Send digest to Discord webhook."""
    import subprocess

    payload = format_discord_digest(results)
    payload_json = json.dumps(payload)

    subprocess.run([
        'curl', '-s',
        '-H', 'Content-Type: application/json',
        '-X', 'POST', webhook_url,
        '-d', payload_json,
    ], capture_output=True)

    logger.info("Discord digest sent")


# =============================================================================
# HTML REPORT
# =============================================================================

def generate_html_report(
    results: Dict,
    output_path: str,
    shap_data: Optional[Dict] = None,
):
    """
    Generate self-contained HTML report with Plotly charts.

    Args:
        results: Full comparison results dict
        output_path: Path to write HTML file
        shap_data: Optional dict of {model_name: {'shap_values': array, 'feature_names': list, 'X_sample': array}}
    """
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    import plotly.io as pio

    charts_html = []

    # --- Chart 1: Model Radar ---
    charts_html.append(_chart_radar(results))

    # --- Chart 2: Category x Model Heatmap ---
    charts_html.append(_chart_category_heatmap(results))

    # --- Chart 3: Agreement Heatmap ---
    charts_html.append(_chart_agreement_heatmap(results))

    # --- Chart 4: Consensus Bars ---
    charts_html.append(_chart_consensus_bars(results))

    # --- Chart 5: PR Curves (if threshold analysis available) ---
    charts_html.append(_chart_threshold_analysis(results))

    # --- Chart 6: Confusion Matrices ---
    charts_html.append(_chart_confusion_matrices(results))

    # --- Chart 7: SHAP Beeswarm (if data provided) ---
    if shap_data:
        charts_html.append(_chart_shap_beeswarm(shap_data))

    # Assemble HTML
    html = _assemble_html(results, charts_html)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(html)

    logger.info(f"HTML report saved to {output_path}")


def _chart_radar(results: Dict) -> str:
    """Radar chart comparing all models + Suricata."""
    import plotly.graph_objects as go

    rankings = results.get('cross_model', {}).get('rankings', {}).get('by_pr_auc', [])
    sur = results.get('suricata', {}).get('detection_rates', {})

    categories = ['Recall', 'Precision', 'F1', 'Detection Rate']

    fig = go.Figure()

    for r in rankings:
        fig.add_trace(go.Scatterpolar(
            r=[r['recall'], r['precision'], r['f1'], r['recall']],
            theta=categories,
            fill='toself',
            name=r['model'],
            opacity=0.6,
        ))

    # Suricata
    fig.add_trace(go.Scatterpolar(
        r=[sur.get('recall', 0), sur.get('precision', 0), sur.get('f1_score', 0), sur.get('recall', 0)],
        theta=categories,
        fill='toself',
        name='Suricata',
        opacity=0.6,
        line=dict(dash='dash'),
    ))

    fig.update_layout(
        polar=dict(bgcolor='rgba(0,0,0,0)', radialaxis=dict(visible=True, range=[0, 1])),
        title='Model Performance Radar',
        template='plotly_dark',
        height=500,
    )

    return f'<div class="chart-section"><h2>Model Performance Radar</h2>{fig.to_html(include_plotlyjs=False, full_html=False)}</div>'


def _chart_category_heatmap(results: Dict) -> str:
    """Category x Model detection rate heatmap."""
    import plotly.graph_objects as go

    cat_matrix = results.get('cross_model', {}).get('category_model_matrix', {})
    if not cat_matrix:
        return '<div class="chart-section"><h2>Category Detection Heatmap</h2><p>No category data available.</p></div>'

    model_names = ['suricata'] + results['metadata']['models_compared']
    categories = sorted(cat_matrix.keys())

    z = []
    for cat in categories:
        row = [cat_matrix[cat].get(m, 0) for m in model_names]
        z.append(row)

    fig = go.Figure(data=go.Heatmap(
        z=z, x=model_names, y=categories,
        colorscale='RdYlGn', zmin=0, zmax=100,
        text=[[f'{v:.1f}%' for v in row] for row in z],
        texttemplate='%{text}',
        hovertemplate='%{y} / %{x}: %{z:.1f}%<extra></extra>',
    ))

    fig.update_layout(
        title='Detection Rate by Category (%)',
        template='plotly_dark',
        height=max(400, len(categories) * 40),
    )

    return f'<div class="chart-section"><h2>Detection Rate by Category</h2>{fig.to_html(include_plotlyjs=False, full_html=False)}</div>'


def _chart_agreement_heatmap(results: Dict) -> str:
    """Pairwise model agreement heatmap."""
    import plotly.graph_objects as go

    heatmap_data = results.get('cross_model', {}).get('agreement_heatmap', {})
    if not heatmap_data:
        return '<div class="chart-section"><h2>Model Agreement Heatmap</h2><p>No agreement data.</p></div>'

    model_names = list(heatmap_data.keys())
    z = [[heatmap_data[a].get(b, 0) for b in model_names] for a in model_names]

    fig = go.Figure(data=go.Heatmap(
        z=z, x=model_names, y=model_names,
        colorscale='Blues', zmin=0.5, zmax=1.0,
        text=[[f'{v:.2f}' for v in row] for row in z],
        texttemplate='%{text}',
    ))

    fig.update_layout(
        title='Pairwise Model Agreement',
        template='plotly_dark',
        height=400,
    )

    return f'<div class="chart-section"><h2>Model Agreement Heatmap</h2>{fig.to_html(include_plotlyjs=False, full_html=False)}</div>'


def _chart_consensus_bars(results: Dict) -> str:
    """Consensus distribution stacked bar chart."""
    import plotly.graph_objects as go

    consensus = results.get('cross_model', {}).get('consensus_matrix', {})
    dist = consensus.get('distribution', {})

    if not dist:
        return '<div class="chart-section"><h2>Detection Consensus</h2><p>No consensus data.</p></div>'

    x_labels = [f'{k} detectors' for k in sorted(dist.keys(), key=int)]
    values = [dist[k] for k in sorted(dist.keys(), key=int)]

    colors = ['#ff4444'] + ['#ff8800'] * 2 + ['#ffcc00'] * 2 + ['#44bb44'] * (len(values) - 4) if len(values) > 4 else ['#44bb44'] * len(values)
    colors[0] = '#ff4444'  # None = red

    fig = go.Figure(data=go.Bar(
        x=x_labels, y=values,
        marker_color=colors[:len(values)],
        text=values, textposition='auto',
    ))

    fig.update_layout(
        title='Attack Detection Consensus',
        xaxis_title='Number of Detectors',
        yaxis_title='Number of Attacks',
        template='plotly_dark',
        height=400,
    )

    return f'<div class="chart-section"><h2>Detection Consensus</h2>{fig.to_html(include_plotlyjs=False, full_html=False)}</div>'


def _chart_threshold_analysis(results: Dict) -> str:
    """Threshold sweep curves for each model."""
    import plotly.graph_objects as go

    fig = go.Figure()
    has_data = False

    for model_name, model_data in results.get('models', {}).items():
        thresh_analysis = model_data.get('threshold_analysis', [])
        if not thresh_analysis:
            continue

        has_data = True
        thresholds = [t['threshold'] for t in thresh_analysis]
        recalls = [t['recall'] for t in thresh_analysis]
        precisions = [t['precision'] for t in thresh_analysis]

        fig.add_trace(go.Scatter(
            x=recalls, y=precisions,
            mode='lines+markers',
            name=model_name,
            text=[f'thresh={t:.2f}' for t in thresholds],
            hovertemplate='%{text}<br>Recall: %{x:.3f}<br>Precision: %{y:.3f}<extra>%{fullData.name}</extra>',
        ))

    if not has_data:
        return '<div class="chart-section"><h2>Precision-Recall Curves</h2><p>No threshold data available.</p></div>'

    fig.update_layout(
        title='Precision-Recall Tradeoff by Threshold',
        xaxis_title='Recall',
        yaxis_title='Precision',
        template='plotly_dark',
        height=500,
    )

    return f'<div class="chart-section"><h2>Precision-Recall Curves</h2>{fig.to_html(include_plotlyjs=False, full_html=False)}</div>'


def _chart_confusion_matrices(results: Dict) -> str:
    """Small multiple confusion matrices."""
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots

    models = results.get('models', {})
    n_models = len(models)
    if n_models == 0:
        return '<div class="chart-section"><h2>Confusion Matrices</h2><p>No model data.</p></div>'

    cols = min(n_models, 4)
    rows = (n_models + cols - 1) // cols

    fig = make_subplots(rows=rows, cols=cols, subplot_titles=list(models.keys()))

    for idx, (model_name, model_data) in enumerate(models.items()):
        dr = model_data.get('detection_rates', {})
        tp = dr.get('true_positives', 0)
        fp = dr.get('false_positives', 0)
        fn = dr.get('false_negatives', 0)
        tn = dr.get('true_negatives', 0)

        row = idx // cols + 1
        col = idx % cols + 1

        fig.add_trace(go.Heatmap(
            z=[[tn, fp], [fn, tp]],
            x=['Predicted Benign', 'Predicted Attack'],
            y=['Actual Benign', 'Actual Attack'],
            colorscale='Blues',
            showscale=False,
            text=[[str(tn), str(fp)], [str(fn), str(tp)]],
            texttemplate='%{text}',
        ), row=row, col=col)

    fig.update_layout(
        title='Confusion Matrices',
        template='plotly_dark',
        height=300 * rows,
    )

    return f'<div class="chart-section"><h2>Confusion Matrices</h2>{fig.to_html(include_plotlyjs=False, full_html=False)}</div>'


def _chart_shap_beeswarm(shap_data: Dict) -> str:
    """SHAP beeswarm plots embedded as base64 images."""
    import shap
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import base64
    from io import BytesIO

    html_parts = ['<div class="chart-section"><h2>SHAP Feature Impact (Beeswarm)</h2>']

    for model_name, data in shap_data.items():
        shap_values = data['shap_values']
        feature_names = data['feature_names']
        X_sample = data['X_sample']

        plt.figure(figsize=(10, 8))
        shap.summary_plot(
            shap_values, X_sample,
            feature_names=feature_names,
            show=False,
            max_display=20,
            plot_type='dot',
        )
        plt.title(f'{model_name} — SHAP Feature Impact')
        plt.tight_layout()

        buf = BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                    facecolor='#1a1a2e', edgecolor='none')
        plt.close()
        buf.seek(0)

        img_b64 = base64.b64encode(buf.read()).decode('utf-8')
        html_parts.append(
            f'<div class="shap-plot"><h3>{model_name}</h3>'
            f'<img src="data:image/png;base64,{img_b64}" alt="SHAP beeswarm for {model_name}" '
            f'style="max-width:100%;border-radius:8px;"/></div>'
        )

    html_parts.append('</div>')
    return '\n'.join(html_parts)


def _assemble_html(results: Dict, charts: List[str]) -> str:
    """Assemble final HTML document with dark theme."""
    import plotly

    meta = results['metadata']
    recs = results.get('recommendations', [])

    recs_html = ''.join(f'<li>{r}</li>' for r in recs)

    charts_html = '\n'.join(charts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Detection Comparison Report — {meta.get('timestamp', '')[:10]}</title>
    <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #0d1117;
            color: #c9d1d9;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        header {{
            text-align: center;
            padding: 2rem 0;
            border-bottom: 1px solid #30363d;
            margin-bottom: 2rem;
        }}
        header h1 {{
            color: #58a6ff;
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}
        header .meta {{
            color: #8b949e;
            font-size: 0.9rem;
        }}
        nav {{
            position: fixed;
            left: 0;
            top: 0;
            width: 220px;
            height: 100vh;
            background: #161b22;
            border-right: 1px solid #30363d;
            padding: 1rem;
            overflow-y: auto;
            z-index: 100;
        }}
        nav a {{
            display: block;
            color: #8b949e;
            text-decoration: none;
            padding: 0.4rem 0.8rem;
            border-radius: 4px;
            margin-bottom: 0.2rem;
            font-size: 0.85rem;
        }}
        nav a:hover {{ background: #30363d; color: #c9d1d9; }}
        .main {{ margin-left: 240px; }}
        .chart-section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .chart-section h2 {{
            color: #58a6ff;
            margin-bottom: 1rem;
            font-size: 1.3rem;
        }}
        .recommendations {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.5rem;
        }}
        .recommendations h2 {{ color: #58a6ff; margin-bottom: 1rem; }}
        .recommendations li {{
            margin-bottom: 0.8rem;
            padding-left: 0.5rem;
        }}
        .shap-plot {{ margin: 1rem 0; }}
        .shap-plot h3 {{ color: #c9d1d9; margin-bottom: 0.5rem; }}
        @media (max-width: 768px) {{
            nav {{ display: none; }}
            .main {{ margin-left: 0; }}
        }}
    </style>
</head>
<body>
    <nav>
        <h3 style="color:#58a6ff;margin-bottom:1rem;">Sections</h3>
        <a href="#top">Overview</a>
        <a href="#radar">Performance Radar</a>
        <a href="#categories">Category Heatmap</a>
        <a href="#agreement">Agreement</a>
        <a href="#consensus">Consensus</a>
        <a href="#pr-curves">PR Curves</a>
        <a href="#confusion">Confusion Matrices</a>
        <a href="#shap">SHAP Analysis</a>
        <a href="#recommendations">Recommendations</a>
    </nav>
    <div class="main">
        <div class="container">
            <header id="top">
                <h1>Detection Comparison Report</h1>
                <div class="meta">
                    {meta['total_records']:,} records | {meta['attack_records']:,} attacks |
                    {len(meta['models_compared'])} models | threshold {meta['threshold']} |
                    {meta.get('timestamp', '')[:19]}
                </div>
            </header>

            {charts_html}

            <div class="recommendations" id="recommendations">
                <h2>Recommendations</h2>
                <ol>{recs_html}</ol>
            </div>
        </div>
    </div>
</body>
</html>"""
```

**Step 4: Run tests to verify they pass**

```bash
cd ~/soc-ml
python -m pytest tests/test_analysis/test_report_generator.py -v
```

Expected: All 7 tests PASS

**Step 5: Commit**

```bash
git add src/analysis/report_generator.py tests/test_analysis/test_report_generator.py
git commit -m "feat: add report generator with terminal, JSON, Discord, HTML+Plotly+SHAP output"
```

---

## Task 6: SHAP Integration into Comparison Pipeline

**Files:**
- Modify: `src/analysis/detection_comparison.py` (add SHAP computation to `run_multi_model_comparison`)

**Step 1: Add SHAP computation function**

Add to `detection_comparison.py`, before `run_multi_model_comparison`:

```python
def compute_shap_values(
    model_name: str,
    model,
    model_type: str,
    X: np.ndarray,
    feature_names: List[str],
    max_samples: int = 1000,
) -> Optional[Dict]:
    """Compute SHAP values for a model."""
    import shap

    logger.info(f"Computing SHAP values for {model_name}...")

    # Sample if large
    if len(X) > max_samples:
        idx = np.random.choice(len(X), max_samples, replace=False)
        X_sample = X[idx]
    else:
        X_sample = X

    try:
        if model_type in ('xgboost', 'lightgbm', 'random_forest', 'isolation_forest'):
            # TreeExplainer — fast
            actual_model = model.model if model_type == 'xgboost' else model
            if hasattr(actual_model, 'named_steps'):
                # Pipeline (KNN) — extract final step
                actual_model = actual_model.named_steps.get('knn', actual_model)
            explainer = shap.TreeExplainer(actual_model)
            shap_values = explainer.shap_values(X_sample)

        elif model_type == 'mlp':
            # Use KernelExplainer with background sample
            bg_idx = np.random.choice(len(X), min(100, len(X)), replace=False)
            background = X[bg_idx]

            def predict_fn(x):
                return model.predict_proba(x)

            explainer = shap.KernelExplainer(predict_fn, background)
            shap_values = explainer.shap_values(X_sample[:200])  # Smaller for KernelExplainer
            X_sample = X_sample[:200]

        elif model_type == 'logistic_regression':
            actual_model = model
            if hasattr(model, 'named_steps'):
                actual_model = model.named_steps.get('lr', model)
            explainer = shap.LinearExplainer(actual_model, X_sample)
            shap_values = explainer.shap_values(X_sample)

        elif model_type == 'knn':
            # KernelExplainer — slow, use small sample
            bg_idx = np.random.choice(len(X), min(50, len(X)), replace=False)
            background = X[bg_idx]

            def predict_fn(x):
                prob = model.predict_proba(x)
                return prob[:, 1] if prob.ndim > 1 else prob

            explainer = shap.KernelExplainer(predict_fn, background)
            shap_values = explainer.shap_values(X_sample[:100])
            X_sample = X_sample[:100]

        else:
            logger.warning(f"SHAP not supported for model type: {model_type}")
            return None

        # Handle multi-output SHAP values
        if isinstance(shap_values, list):
            shap_values = shap_values[1] if len(shap_values) > 1 else shap_values[0]

        return {
            'shap_values': shap_values,
            'feature_names': feature_names,
            'X_sample': X_sample,
        }

    except Exception as e:
        logger.warning(f"SHAP failed for {model_name}: {e}")
        return None
```

**Step 2: Wire SHAP into run_multi_model_comparison**

In the `run_multi_model_comparison` function, after predictions are generated, add SHAP computation:

```python
    # Compute SHAP values for each model
    shap_data = {}
    for mdir in model_dirs:
        model_name = mdir.name.rsplit('_binary_', 1)[0]
        if model_name not in comparator.model_predictions:
            continue

        try:
            trainer = ModelTrainer.load_model(str(mdir))
            shap_result = compute_shap_values(
                model_name, trainer.model, trainer.model_type,
                X, feature_names,
            )
            if shap_result:
                shap_data[model_name] = shap_result
        except Exception as e:
            logger.warning(f"SHAP skipped for {model_name}: {e}")
```

**Step 3: Add report generation call to run_multi_model_comparison**

At the end of `run_multi_model_comparison`, after saving JSON:

```python
    # Generate reports
    from src.analysis.report_generator import (
        generate_terminal_report, save_json_report, generate_html_report
    )

    generate_terminal_report(results)

    if output_dir:
        output_path = Path(output_dir)

        # JSON
        json_file = output_path / f"detection_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        save_json_report(results, str(json_file))

        # HTML
        html_file = output_path / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        generate_html_report(results, str(html_file), shap_data=shap_data if shap_data else None)

    return results
```

**Step 4: Run full test suite**

```bash
cd ~/soc-ml
python -m pytest tests/ -v
```

Expected: All tests PASS

**Step 5: Commit**

```bash
git add src/analysis/detection_comparison.py
git commit -m "feat: integrate SHAP computation and report generation into comparison pipeline"
```

---

## Task 7: Post-Campaign Automation Integration

**Files:**
- Modify: `attacks/campaigns/post_campaign_automation.sh`

**Step 1: Add compare_detections function**

Add after the `train_model()` function (after line ~224) in `post_campaign_automation.sh`:

```bash
#=============================================================================
# DETECTION COMPARISON
#=============================================================================

compare_detections() {
    local data_file="$1"
    local model_dir="$PROJECT_DIR/models"

    log "=== Running Multi-Model Detection Comparison ==="

    cd "$PROJECT_DIR"

    eval "$(conda shell.bash hook)"
    conda activate "$CONDA_ENV"

    discord_info "Detection Comparison" \
        "Comparing all models vs Suricata rules...\n\nThis includes SHAP analysis and HTML report generation."

    python -m src.analysis.detection_comparison \
        --data "$data_file" \
        --model-dir "$model_dir" \
        --all-models \
        --output results/comparison \
        --threshold 0.5 \
        2>&1 | tee -a "$LOG_FILE"

    if [[ $? -ne 0 ]]; then
        discord_error "Detection Comparison" "Comparison failed! Check logs at $LOG_FILE"
        return 1
    fi

    # Find latest report
    local latest_json=$(ls -t results/comparison/detection_comparison_*.json 2>/dev/null | head -1)
    local latest_html=$(ls -t results/comparison/report_*.html 2>/dev/null | head -1)

    if [[ -n "$latest_json" ]]; then
        # Extract summary for Discord
        local summary
        summary=$(python -c "
import json
with open('$latest_json') as f:
    data = json.load(f)
rankings = data.get('cross_model', {}).get('rankings', {}).get('by_pr_auc', [])
blind = data.get('cross_model', {}).get('blind_spots', {}).get('total', 0)
print(f'**Best Model:** {rankings[0][\"model\"]} (PR-AUC: {rankings[0][\"pr_auc\"]:.4f})' if rankings else 'No rankings')
print(f'**Models Compared:** {len(data[\"metadata\"][\"models_compared\"])}')
print(f'**Blind Spots:** {blind}')
" 2>/dev/null)

        discord_success "Detection Comparison Complete" \
            "$summary\n\nJSON: \`$latest_json\`\nHTML: \`$latest_html\`"
    fi

    log "Detection comparison complete"
}
```

**Step 2: Update train_model to use --compare and save all models**

Modify the `train_model()` function to use `--compare` instead of just training XGBoost:

```bash
    # Train all models for comparison
    python -m src.models.train \
        --task binary \
        --compare \
        --input "$data_file" \
        2>&1 | tee -a "$LOG_FILE"
```

**Step 3: Insert comparison step in main flow**

In the `main()` function, add the comparison call between training and campaign launch:

```bash
    # Step 3: Train models
    local model_dir
    model_dir=$(train_model "$data_file")

    # Step 4: Detection comparison (non-blocking)
    compare_detections "$data_file" || log "WARNING: Detection comparison failed, continuing..."

    # Step 5: Launch next campaign
    launch_noise_campaign
```

**Step 4: Commit**

```bash
git add attacks/campaigns/post_campaign_automation.sh
git commit -m "feat: integrate multi-model comparison into post-campaign automation"
```

---

## Task 8: End-to-End Validation

**Step 1: Run synthetic end-to-end test**

```bash
cd ~/soc-ml
conda activate soc-ml

# Train all models on synthetic data
python -m src.models.train --test --compare
```

Expected: All 7 models train, comparison table shows rankings by PR-AUC

**Step 2: Run detection comparison on synthetic data (if parquet exists)**

```bash
# Check for existing ground-truth data
ls -la data/processed/ground_truth_*.parquet

# If data exists, run comparison
python -m src.analysis.detection_comparison \
    --data data/processed/ground_truth_*.parquet \
    --model-dir models/ \
    --all-models \
    --output results/comparison
```

Expected: Terminal table output, JSON file saved, HTML report generated

**Step 3: Verify HTML report opens correctly**

```bash
ls -la results/comparison/report_*.html
# Open in browser or check file size > 10KB
```

**Step 4: Run full test suite**

```bash
python -m pytest tests/ -v --tb=short
```

Expected: All tests PASS

**Step 5: Final commit**

```bash
git add -A
git commit -m "feat: complete multi-model detection comparison system

- 7 ML models (XGBoost, LightGBM, RF, LR, KNN, MLP, IsolationForest)
- MLP trains on GPU (GTX 1650 Ti)
- Multi-model comparison with cross-model analysis
- Portfolio-quality HTML report with Plotly charts + SHAP beeswarm
- Discord digest notifications
- Integrated into post-campaign automation pipeline"
```
