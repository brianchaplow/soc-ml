"""
Detection Comparison Analysis
=============================
Compares Suricata signature-based detection vs ML model detection
against ground-truth labeled attack data.

Author: Brian Chaplow
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path

import pandas as pd
import numpy as np
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SuricataAnalyzer:
    """Analyzes Suricata signature detection accuracy."""

    def __init__(self, df: pd.DataFrame):
        """
        Initialize with ground-truth labeled data.

        Args:
            df: DataFrame with columns:
                - attack_confirmed: bool (ground truth)
                - alert.signature_id: Suricata SID
                - alert.signature: Signature name
                - alert.category: Alert category
                - alert.severity: 1-4
                - attack_category: Ground truth category
        """
        self.df = df.copy()
        self.results = {}

    def analyze(self) -> Dict:
        """Run full Suricata analysis."""
        logger.info("=== Suricata Signature Analysis ===")

        self.results = {
            'timestamp': datetime.now().isoformat(),
            'total_records': len(self.df),
            'detection_rates': self._calculate_detection_rates(),
            'signature_performance': self._analyze_signatures(),
            'category_performance': self._analyze_categories(),
            'false_positives': self._analyze_false_positives(),
            'missed_attacks': self._analyze_missed_attacks(),
        }

        return self.results

    def _calculate_detection_rates(self) -> Dict:
        """Calculate overall detection rates."""
        # Ground truth attacks
        gt_attacks = self.df[self.df['attack_confirmed'] == True]
        gt_benign = self.df[self.df['attack_confirmed'] == False]

        # Suricata considers severity 1-2 as attacks (not noise/info)
        # Or we can use specific attack signature patterns
        attack_sigs = self.df['alert.severity'].isin([1, 2]) if 'alert.severity' in self.df.columns else pd.Series([False] * len(self.df))

        # Alternative: check if signature exists (any alert = detection)
        has_alert = self.df['alert.signature_id'].notna() if 'alert.signature_id' in self.df.columns else pd.Series([False] * len(self.df))

        # True positives: attack_confirmed AND has alert
        tp = ((self.df['attack_confirmed'] == True) & has_alert).sum()

        # False negatives: attack_confirmed but NO alert
        fn = ((self.df['attack_confirmed'] == True) & ~has_alert).sum()

        # False positives: NOT attack but HAS alert (severity 1-2)
        fp = ((self.df['attack_confirmed'] == False) & attack_sigs).sum()

        # True negatives: NOT attack and NO alert (or noise/info alert)
        tn = ((self.df['attack_confirmed'] == False) & ~attack_sigs).sum()

        total_attacks = len(gt_attacks)
        total_benign = len(gt_benign)

        recall = tp / total_attacks if total_attacks > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        return {
            'total_attacks_ground_truth': int(total_attacks),
            'total_benign_ground_truth': int(total_benign),
            'true_positives': int(tp),
            'false_negatives': int(fn),
            'false_positives': int(fp),
            'true_negatives': int(tn),
            'recall': round(recall, 4),
            'precision': round(precision, 4),
            'f1_score': round(f1, 4),
            'detection_rate': round(recall * 100, 2),
            'false_positive_rate': round(fp / total_benign * 100, 2) if total_benign > 0 else 0,
        }

    def _analyze_signatures(self) -> List[Dict]:
        """Analyze performance by signature."""
        if 'alert.signature_id' not in self.df.columns:
            return []

        sig_stats = []

        for sid in self.df['alert.signature_id'].dropna().unique():
            sig_df = self.df[self.df['alert.signature_id'] == sid]

            tp = (sig_df['attack_confirmed'] == True).sum()
            fp = (sig_df['attack_confirmed'] == False).sum()
            total = len(sig_df)

            sig_name = sig_df['alert.signature'].iloc[0] if 'alert.signature' in sig_df.columns else 'Unknown'

            sig_stats.append({
                'signature_id': int(sid) if pd.notna(sid) else None,
                'signature_name': str(sig_name),
                'total_alerts': int(total),
                'true_positives': int(tp),
                'false_positives': int(fp),
                'precision': round(tp / total, 4) if total > 0 else 0,
            })

        # Sort by total alerts
        sig_stats.sort(key=lambda x: x['total_alerts'], reverse=True)

        return sig_stats[:50]  # Top 50 signatures

    def _analyze_categories(self) -> Dict:
        """Analyze detection rates by attack category."""
        if 'attack_category' not in self.df.columns:
            return {}

        category_stats = {}

        for category in self.df[self.df['attack_confirmed']]['attack_category'].dropna().unique():
            cat_attacks = self.df[
                (self.df['attack_confirmed'] == True) &
                (self.df['attack_category'] == category)
            ]

            # Check if Suricata alerted on these
            has_alert = cat_attacks['alert.signature_id'].notna() if 'alert.signature_id' in cat_attacks.columns else pd.Series([False] * len(cat_attacks))

            detected = has_alert.sum()
            total = len(cat_attacks)

            category_stats[category] = {
                'total_attacks': int(total),
                'detected': int(detected),
                'missed': int(total - detected),
                'detection_rate': round(detected / total * 100, 2) if total > 0 else 0,
            }

        return category_stats

    def _analyze_false_positives(self) -> Dict:
        """Analyze false positive patterns."""
        if 'alert.signature_id' not in self.df.columns:
            return {}

        # False positives: alerts on non-attack traffic
        fp_df = self.df[
            (self.df['attack_confirmed'] == False) &
            (self.df['alert.signature_id'].notna()) &
            (self.df['alert.severity'].isin([1, 2]) if 'alert.severity' in self.df.columns else True)
        ]

        if len(fp_df) == 0:
            return {'total': 0, 'by_signature': []}

        # Group by signature
        fp_by_sig = fp_df.groupby('alert.signature_id').size().sort_values(ascending=False)

        top_fp_sigs = []
        for sid, count in fp_by_sig.head(20).items():
            sig_name = fp_df[fp_df['alert.signature_id'] == sid]['alert.signature'].iloc[0] if 'alert.signature' in fp_df.columns else 'Unknown'
            top_fp_sigs.append({
                'signature_id': int(sid) if pd.notna(sid) else None,
                'signature_name': str(sig_name),
                'false_positive_count': int(count),
            })

        return {
            'total': int(len(fp_df)),
            'by_signature': top_fp_sigs,
        }

    def _analyze_missed_attacks(self) -> Dict:
        """Analyze attacks that Suricata missed."""
        # Attacks with no alert
        missed = self.df[
            (self.df['attack_confirmed'] == True) &
            (self.df['alert.signature_id'].isna() if 'alert.signature_id' in self.df.columns else True)
        ]

        if len(missed) == 0:
            return {'total': 0, 'by_category': {}, 'by_tool': {}}

        # By category
        by_category = {}
        if 'attack_category' in missed.columns:
            for cat, count in missed['attack_category'].value_counts().items():
                by_category[cat] = int(count)

        # By tool
        by_tool = {}
        if 'attack_tool' in missed.columns:
            for tool, count in missed['attack_tool'].value_counts().items():
                by_tool[tool] = int(count)

        return {
            'total': int(len(missed)),
            'by_category': by_category,
            'by_tool': by_tool,
        }


class MLModelAnalyzer:
    """Analyzes ML model detection accuracy."""

    def __init__(self, df: pd.DataFrame, model_dir: Optional[str] = None):
        """
        Initialize with ground-truth labeled data.

        Args:
            df: DataFrame with ground-truth labels
            model_dir: Path to trained model directory
        """
        self.df = df.copy()
        self.model_dir = model_dir
        self.model = None
        self.feature_engineer = None
        self.results = {}

    def load_model(self):
        """Load the trained model and feature engineer."""
        import pickle
        import xgboost as xgb

        if self.model_dir is None:
            # Find latest model
            models_dir = Path(__file__).parent.parent.parent / 'models'
            model_dirs = sorted(models_dir.glob('xgboost_binary_*'), reverse=True)
            if not model_dirs:
                raise FileNotFoundError("No trained models found")
            self.model_dir = str(model_dirs[0])

        logger.info(f"Loading model from {self.model_dir}")

        # Load XGBoost model
        model_path = Path(self.model_dir) / 'model.json'
        if model_path.exists():
            self.model = xgb.XGBClassifier()
            self.model.load_model(str(model_path))
        else:
            raise FileNotFoundError(f"Model not found at {model_path}")

        # Load feature engineer
        fe_path = Path(self.model_dir) / 'feature_engineer.pkl'
        if fe_path.exists():
            with open(fe_path, 'rb') as f:
                self.feature_engineer = pickle.load(f)

        logger.info("Model loaded successfully")

    def predict(self, threshold: float = 0.5) -> pd.DataFrame:
        """Generate predictions on the dataset."""
        from src.data.features import FeatureEngineer

        if self.model is None:
            self.load_model()

        # Engineer features
        if self.feature_engineer is None:
            self.feature_engineer = FeatureEngineer()
            X = self.feature_engineer.fit_transform(self.df)
        else:
            # Use loaded feature engineer
            if hasattr(self.feature_engineer, 'transform'):
                X = self.feature_engineer.transform(self.df)
            else:
                # Handle dict-based feature engineer
                fe = FeatureEngineer()
                fe.feature_names = self.feature_engineer.get('feature_names', [])
                X = fe.transform(self.df)

        # Get predictions
        y_proba = self.model.predict_proba(X)[:, 1]
        y_pred = (y_proba >= threshold).astype(int)

        self.df['ml_probability'] = y_proba
        self.df['ml_prediction'] = y_pred

        return self.df

    def analyze(self, threshold: float = 0.5) -> Dict:
        """Run full ML model analysis."""
        logger.info("=== ML Model Analysis ===")

        # Generate predictions if not already done
        if 'ml_prediction' not in self.df.columns:
            self.predict(threshold)

        # Ground truth
        y_true = self.df['attack_confirmed'].astype(int)
        y_pred = self.df['ml_prediction']
        y_proba = self.df['ml_probability']

        # Confusion matrix
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

        self.results = {
            'timestamp': datetime.now().isoformat(),
            'model_dir': self.model_dir,
            'threshold': threshold,
            'total_records': len(self.df),
            'detection_rates': {
                'total_attacks_ground_truth': int(y_true.sum()),
                'total_benign_ground_truth': int((1 - y_true).sum()),
                'true_positives': int(tp),
                'false_negatives': int(fn),
                'false_positives': int(fp),
                'true_negatives': int(tn),
                'recall': round(recall_score(y_true, y_pred), 4),
                'precision': round(precision_score(y_true, y_pred), 4),
                'f1_score': round(f1_score(y_true, y_pred), 4),
                'detection_rate': round(recall_score(y_true, y_pred) * 100, 2),
                'false_positive_rate': round(fp / (fp + tn) * 100, 2) if (fp + tn) > 0 else 0,
            },
            'category_performance': self._analyze_by_category(y_true, y_pred),
            'confidence_distribution': self._analyze_confidence(y_proba, y_true),
            'threshold_analysis': self._analyze_thresholds(y_proba, y_true),
            'missed_attacks': self._analyze_missed(y_true, y_pred, y_proba),
            'false_positives': self._analyze_fp(y_true, y_pred, y_proba),
        }

        return self.results

    def _analyze_by_category(self, y_true, y_pred) -> Dict:
        """Analyze performance by attack category."""
        if 'attack_category' not in self.df.columns:
            return {}

        category_stats = {}

        for category in self.df[self.df['attack_confirmed']]['attack_category'].dropna().unique():
            mask = (self.df['attack_confirmed'] == True) & (self.df['attack_category'] == category)

            cat_true = y_true[mask]
            cat_pred = y_pred[mask]

            tp = ((cat_true == 1) & (cat_pred == 1)).sum()
            fn = ((cat_true == 1) & (cat_pred == 0)).sum()

            category_stats[category] = {
                'total_attacks': int(len(cat_true)),
                'detected': int(tp),
                'missed': int(fn),
                'detection_rate': round(tp / len(cat_true) * 100, 2) if len(cat_true) > 0 else 0,
            }

        return category_stats

    def _analyze_confidence(self, y_proba, y_true) -> Dict:
        """Analyze confidence score distribution."""
        attacks = y_proba[y_true == 1]
        benign = y_proba[y_true == 0]

        return {
            'attacks': {
                'mean': round(float(attacks.mean()), 4) if len(attacks) > 0 else 0,
                'median': round(float(np.median(attacks)), 4) if len(attacks) > 0 else 0,
                'std': round(float(attacks.std()), 4) if len(attacks) > 0 else 0,
                'min': round(float(attacks.min()), 4) if len(attacks) > 0 else 0,
                'max': round(float(attacks.max()), 4) if len(attacks) > 0 else 0,
            },
            'benign': {
                'mean': round(float(benign.mean()), 4) if len(benign) > 0 else 0,
                'median': round(float(np.median(benign)), 4) if len(benign) > 0 else 0,
                'std': round(float(benign.std()), 4) if len(benign) > 0 else 0,
                'min': round(float(benign.min()), 4) if len(benign) > 0 else 0,
                'max': round(float(benign.max()), 4) if len(benign) > 0 else 0,
            },
        }

    def _analyze_thresholds(self, y_proba, y_true) -> List[Dict]:
        """Analyze performance at different thresholds."""
        thresholds = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]
        results = []

        for thresh in thresholds:
            y_pred = (y_proba >= thresh).astype(int)

            if y_pred.sum() == 0:
                continue

            results.append({
                'threshold': thresh,
                'precision': round(precision_score(y_true, y_pred, zero_division=0), 4),
                'recall': round(recall_score(y_true, y_pred, zero_division=0), 4),
                'f1': round(f1_score(y_true, y_pred, zero_division=0), 4),
            })

        return results

    def _analyze_missed(self, y_true, y_pred, y_proba) -> Dict:
        """Analyze attacks the model missed."""
        missed_mask = (y_true == 1) & (y_pred == 0)
        missed = self.df[missed_mask]

        if len(missed) == 0:
            return {'total': 0, 'by_category': {}, 'confidence_stats': {}}

        by_category = {}
        if 'attack_category' in missed.columns:
            for cat, count in missed['attack_category'].value_counts().items():
                by_category[cat] = int(count)

        return {
            'total': int(len(missed)),
            'by_category': by_category,
            'confidence_stats': {
                'mean': round(float(y_proba[missed_mask].mean()), 4),
                'max': round(float(y_proba[missed_mask].max()), 4),
            },
        }

    def _analyze_fp(self, y_true, y_pred, y_proba) -> Dict:
        """Analyze false positives."""
        fp_mask = (y_true == 0) & (y_pred == 1)
        fp = self.df[fp_mask]

        if len(fp) == 0:
            return {'total': 0, 'confidence_stats': {}}

        return {
            'total': int(len(fp)),
            'confidence_stats': {
                'mean': round(float(y_proba[fp_mask].mean()), 4),
                'min': round(float(y_proba[fp_mask].min()), 4),
            },
        }


class DetectionComparator:
    """Compares Suricata and ML detection performance."""

    def __init__(
        self,
        df: pd.DataFrame,
        suricata_results: Dict,
        ml_results: Dict
    ):
        self.df = df
        self.suricata = suricata_results
        self.ml = ml_results
        self.results = {}

    def compare(self) -> Dict:
        """Run comparison analysis."""
        logger.info("=== Detection Comparison Analysis ===")

        self.results = {
            'timestamp': datetime.now().isoformat(),
            'summary': self._compare_summary(),
            'by_category': self._compare_by_category(),
            'agreement_analysis': self._analyze_agreement(),
            'unique_detections': self._analyze_unique_detections(),
            'recommendations': self._generate_recommendations(),
        }

        return self.results

    def _compare_summary(self) -> Dict:
        """Compare overall metrics."""
        sur = self.suricata.get('detection_rates', {})
        ml = self.ml.get('detection_rates', {})

        return {
            'suricata': {
                'recall': sur.get('recall', 0),
                'precision': sur.get('precision', 0),
                'f1_score': sur.get('f1_score', 0),
                'detection_rate': sur.get('detection_rate', 0),
                'false_positive_rate': sur.get('false_positive_rate', 0),
            },
            'ml_model': {
                'recall': ml.get('recall', 0),
                'precision': ml.get('precision', 0),
                'f1_score': ml.get('f1_score', 0),
                'detection_rate': ml.get('detection_rate', 0),
                'false_positive_rate': ml.get('false_positive_rate', 0),
            },
            'winner': {
                'recall': 'ml' if ml.get('recall', 0) > sur.get('recall', 0) else 'suricata',
                'precision': 'ml' if ml.get('precision', 0) > sur.get('precision', 0) else 'suricata',
                'f1': 'ml' if ml.get('f1_score', 0) > sur.get('f1_score', 0) else 'suricata',
            },
        }

    def _compare_by_category(self) -> Dict:
        """Compare detection rates by attack category."""
        sur_cat = self.suricata.get('category_performance', {})
        ml_cat = self.ml.get('category_performance', {})

        all_categories = set(sur_cat.keys()) | set(ml_cat.keys())

        comparison = {}
        for cat in all_categories:
            sur_rate = sur_cat.get(cat, {}).get('detection_rate', 0)
            ml_rate = ml_cat.get(cat, {}).get('detection_rate', 0)

            comparison[cat] = {
                'suricata_rate': sur_rate,
                'ml_rate': ml_rate,
                'difference': round(ml_rate - sur_rate, 2),
                'winner': 'ml' if ml_rate > sur_rate else 'suricata' if sur_rate > ml_rate else 'tie',
                'total_attacks': sur_cat.get(cat, ml_cat.get(cat, {})).get('total_attacks', 0),
            }

        return comparison

    def _analyze_agreement(self) -> Dict:
        """Analyze where Suricata and ML agree/disagree."""
        if 'ml_prediction' not in self.df.columns:
            return {}

        # Suricata detection (has alert)
        has_alert = self.df['alert.signature_id'].notna() if 'alert.signature_id' in self.df.columns else pd.Series([False] * len(self.df))

        ml_pred = self.df['ml_prediction'] == 1
        gt_attack = self.df['attack_confirmed'] == True

        # Agreement matrix
        both_detect = (has_alert & ml_pred).sum()
        both_miss = (~has_alert & ~ml_pred & gt_attack).sum()
        sur_only = (has_alert & ~ml_pred & gt_attack).sum()
        ml_only = (~has_alert & ml_pred & gt_attack).sum()

        # False positive agreement
        both_fp = (has_alert & ml_pred & ~gt_attack).sum()
        sur_fp_only = (has_alert & ~ml_pred & ~gt_attack).sum()
        ml_fp_only = (~has_alert & ml_pred & ~gt_attack).sum()

        total_attacks = gt_attack.sum()

        return {
            'true_positives': {
                'both_detect': int(both_detect),
                'suricata_only': int(sur_only),
                'ml_only': int(ml_only),
                'both_miss': int(both_miss),
            },
            'false_positives': {
                'both_fp': int(both_fp),
                'suricata_only': int(sur_fp_only),
                'ml_only': int(ml_fp_only),
            },
            'agreement_rate': round(both_detect / total_attacks * 100, 2) if total_attacks > 0 else 0,
            'combined_detection_rate': round((both_detect + sur_only + ml_only) / total_attacks * 100, 2) if total_attacks > 0 else 0,
        }

    def _analyze_unique_detections(self) -> Dict:
        """Analyze what each system uniquely detects."""
        if 'ml_prediction' not in self.df.columns:
            return {}

        has_alert = self.df['alert.signature_id'].notna() if 'alert.signature_id' in self.df.columns else pd.Series([False] * len(self.df))
        ml_pred = self.df['ml_prediction'] == 1
        gt_attack = self.df['attack_confirmed'] == True

        # ML catches but Suricata misses
        ml_unique = self.df[(~has_alert) & ml_pred & gt_attack]

        # Suricata catches but ML misses
        sur_unique = self.df[has_alert & (~ml_pred) & gt_attack]

        ml_unique_by_cat = {}
        sur_unique_by_cat = {}

        if 'attack_category' in self.df.columns:
            if len(ml_unique) > 0:
                for cat, count in ml_unique['attack_category'].value_counts().items():
                    ml_unique_by_cat[cat] = int(count)

            if len(sur_unique) > 0:
                for cat, count in sur_unique['attack_category'].value_counts().items():
                    sur_unique_by_cat[cat] = int(count)

        return {
            'ml_unique_detections': {
                'total': int(len(ml_unique)),
                'by_category': ml_unique_by_cat,
            },
            'suricata_unique_detections': {
                'total': int(len(sur_unique)),
                'by_category': sur_unique_by_cat,
            },
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []

        summary = self._compare_summary()
        categories = self._compare_by_category()
        agreement = self._analyze_agreement()
        unique = self._analyze_unique_detections()

        # Overall performance
        sur_f1 = summary['suricata']['f1_score']
        ml_f1 = summary['ml_model']['f1_score']

        if ml_f1 > sur_f1 + 0.1:
            recommendations.append(
                f"ML model significantly outperforms Suricata (F1: {ml_f1:.2f} vs {sur_f1:.2f}). "
                "Consider using ML as primary detection with Suricata for signature-based alerts."
            )
        elif sur_f1 > ml_f1 + 0.1:
            recommendations.append(
                f"Suricata outperforms ML model (F1: {sur_f1:.2f} vs {ml_f1:.2f}). "
                "Review ML training data for gaps in attack coverage."
            )

        # Category-specific recommendations
        for cat, stats in categories.items():
            if stats['ml_rate'] > stats['suricata_rate'] + 20:
                recommendations.append(
                    f"ML excels at detecting {cat} ({stats['ml_rate']}% vs {stats['suricata_rate']}%). "
                    f"Consider adding Suricata rules for this category."
                )
            elif stats['suricata_rate'] > stats['ml_rate'] + 20:
                recommendations.append(
                    f"Suricata excels at detecting {cat} ({stats['suricata_rate']}% vs {stats['ml_rate']}%). "
                    f"Add more {cat} samples to ML training data."
                )

        # Combined detection
        combined = agreement.get('combined_detection_rate', 0)
        sur_only = agreement.get('true_positives', {}).get('suricata_only', 0)
        ml_only = agreement.get('true_positives', {}).get('ml_only', 0)

        if sur_only > 0 or ml_only > 0:
            recommendations.append(
                f"Combined detection ({combined:.1f}%) exceeds either system alone. "
                f"Use both systems: Suricata catches {sur_only} attacks ML misses, "
                f"ML catches {ml_only} attacks Suricata misses."
            )

        # Blind spots
        both_miss = agreement.get('true_positives', {}).get('both_miss', 0)
        if both_miss > 0:
            recommendations.append(
                f"CRITICAL: {both_miss} attacks evade BOTH systems. "
                "Investigate these blind spots and update detection strategies."
            )

        return recommendations


def run_comparison(
    data_path: str,
    model_dir: Optional[str] = None,
    output_dir: Optional[str] = None,
    threshold: float = 0.5
) -> Dict:
    """
    Run full detection comparison analysis.

    Args:
        data_path: Path to ground-truth labeled parquet file
        model_dir: Path to trained model directory
        output_dir: Directory for output files
        threshold: ML prediction threshold

    Returns:
        Dict with all analysis results
    """
    logger.info("=" * 60)
    logger.info("DETECTION COMPARISON ANALYSIS")
    logger.info("=" * 60)

    # Load data
    logger.info(f"Loading data from {data_path}")
    df = pd.read_parquet(data_path)
    logger.info(f"Loaded {len(df):,} records")
    logger.info(f"Ground-truth attacks: {df['attack_confirmed'].sum():,}")

    # Suricata analysis
    sur_analyzer = SuricataAnalyzer(df)
    sur_results = sur_analyzer.analyze()

    # ML analysis
    ml_analyzer = MLModelAnalyzer(df, model_dir)
    ml_results = ml_analyzer.analyze(threshold)

    # Get predictions for comparison
    df = ml_analyzer.df

    # Comparison
    comparator = DetectionComparator(df, sur_results, ml_results)
    comparison = comparator.compare()

    # Combine results
    results = {
        'metadata': {
            'data_path': data_path,
            'model_dir': model_dir,
            'threshold': threshold,
            'total_records': len(df),
            'attack_records': int(df['attack_confirmed'].sum()),
        },
        'suricata': sur_results,
        'ml_model': ml_results,
        'comparison': comparison,
    }

    # Save results
    if output_dir:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        results_file = output_path / f"detection_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(f"Results saved to {results_file}")

    # Print summary
    _print_summary(results)

    return results


def _print_summary(results: Dict):
    """Print a formatted summary."""
    print("\n" + "=" * 70)
    print("DETECTION COMPARISON SUMMARY")
    print("=" * 70)

    summary = results['comparison']['summary']

    print("\n### Overall Metrics ###\n")
    print(f"{'Metric':<20} {'Suricata':>12} {'ML Model':>12} {'Winner':>12}")
    print("-" * 60)

    for metric in ['recall', 'precision', 'f1_score']:
        sur_val = summary['suricata'].get(metric, 0)
        ml_val = summary['ml_model'].get(metric, 0)
        winner = summary['winner'].get(metric.replace('_score', ''), 'tie')
        print(f"{metric:<20} {sur_val:>12.4f} {ml_val:>12.4f} {winner:>12}")

    print("\n### Detection by Category ###\n")
    categories = results['comparison']['by_category']
    print(f"{'Category':<20} {'Suricata':>10} {'ML Model':>10} {'Diff':>10} {'Winner':>10}")
    print("-" * 65)

    for cat, stats in sorted(categories.items(), key=lambda x: x[1]['total_attacks'], reverse=True):
        print(f"{cat[:20]:<20} {stats['suricata_rate']:>9.1f}% {stats['ml_rate']:>9.1f}% {stats['difference']:>+9.1f}% {stats['winner']:>10}")

    print("\n### Agreement Analysis ###\n")
    agreement = results['comparison']['agreement_analysis']
    tp = agreement.get('true_positives', {})
    print(f"Both detect:      {tp.get('both_detect', 0):>6}")
    print(f"Suricata only:    {tp.get('suricata_only', 0):>6}")
    print(f"ML only:          {tp.get('ml_only', 0):>6}")
    print(f"Both miss:        {tp.get('both_miss', 0):>6}")
    print(f"\nCombined rate:    {agreement.get('combined_detection_rate', 0):.1f}%")

    print("\n### Recommendations ###\n")
    for i, rec in enumerate(results['comparison']['recommendations'], 1):
        print(f"{i}. {rec}\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Detection Comparison Analysis")
    parser.add_argument('--data', required=True, help='Path to ground-truth labeled parquet')
    parser.add_argument('--model', default=None, help='Path to model directory')
    parser.add_argument('--output', default='results/comparison', help='Output directory')
    parser.add_argument('--threshold', type=float, default=0.5, help='ML threshold')

    args = parser.parse_args()

    run_comparison(
        data_path=args.data,
        model_dir=args.model,
        output_dir=args.output,
        threshold=args.threshold
    )
