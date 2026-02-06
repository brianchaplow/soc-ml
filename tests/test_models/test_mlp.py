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
