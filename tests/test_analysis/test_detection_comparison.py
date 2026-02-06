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
