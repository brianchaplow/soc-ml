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
