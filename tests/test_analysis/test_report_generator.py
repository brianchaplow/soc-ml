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
        assert 'Radar' in content or 'radar' in content
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
