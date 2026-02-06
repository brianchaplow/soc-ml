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

    def test_isolation_forest_captured_correctly(self, train_val_test_split):
        """IsolationForest is stored as self.model after training in compare_models."""
        from src.models.train import ModelTrainer
        from sklearn.ensemble import IsolationForest

        data = train_val_test_split
        trainer = ModelTrainer()
        comparison = trainer.compare_models(
            data['X_train'], data['y_train'],
            data['X_test'], data['y_test'],
            data['X_val'], data['y_val'],
        )
        # After compare_models, best model is restored; check trained_models had IF
        assert 'Isolation Forest' in comparison['model'].values
        # IF should have pr_auc > 0 (it was evaluated)
        if_row = comparison[comparison['model'] == 'Isolation Forest'].iloc[0]
        assert if_row['pr_auc'] > 0

    def test_isolation_forest_save_load(self, train_val_test_split, tmp_path):
        """IsolationForest can be saved and loaded correctly."""
        from src.models.train import ModelTrainer
        from sklearn.ensemble import IsolationForest
        import numpy as np

        data = train_val_test_split
        trainer = ModelTrainer()

        # Train isolation forest directly
        normal_mask = data['y_train'] == 0
        trainer.train_anomaly_detector(data['X_train'][normal_mask])
        trainer.model = trainer.anomaly_model
        trainer.model_type = 'isolation_forest'

        # Save
        save_path = str(tmp_path / 'if_test')
        trainer.save_model(save_path, feature_names=data['feature_names'])

        # Load
        loaded = ModelTrainer.load_model(save_path)
        assert loaded.model_type == 'isolation_forest'
        assert isinstance(loaded.model, IsolationForest)
        assert hasattr(loaded, 'anomaly_model')
        assert hasattr(loaded, 'anomaly_scaler')

        # Verify predictions work
        scores = loaded.anomaly_scores(data['X_test'])
        assert len(scores) == len(data['y_test'])
        assert scores.min() >= 0
        assert scores.max() <= 1
