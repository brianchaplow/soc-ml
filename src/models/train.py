"""
SOC-ML Model Training Module
============================
Trains and evaluates threat detection models.

Author: Brian Chaplow (Chappy McNasty)
"""

import os
import json
import logging
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

import numpy as np
import pandas as pd
import yaml
import xgboost as xgb
import lightgbm as lgb
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.semi_supervised import SelfTrainingClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_recall_curve, average_precision_score,
    roc_auc_score, f1_score, precision_score, recall_score
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ModelTrainer:
    """
    Trains and evaluates threat detection models.
    
    Supports:
    - XGBoost (primary)
    - Random Forest (baseline)
    - Logistic Regression (simple baseline)
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the trainer.
        
        Args:
            config_path: Path to model.yaml
        """
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__), '..', '..', 'config', 'model.yaml'
            )
        
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.model = None
        self.model_type = None
        self.label_encoder = None
        self.threshold = 0.5
        self.training_history: Dict[str, Any] = {}
    
    def _compute_class_weights(self, y: np.ndarray) -> float:
        """Compute scale_pos_weight for XGBoost."""
        n_neg = np.sum(y == 0)
        n_pos = np.sum(y == 1)
        
        if n_pos == 0:
            return 1.0
        
        return n_neg / n_pos
    
    def train_xgboost(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        task: str = 'binary'
    ) -> xgb.XGBClassifier:
        """
        Train an XGBoost model.
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features (optional)
            y_val: Validation labels (optional)
            task: 'binary' or 'multiclass'
            
        Returns:
            Trained XGBoost model
        """
        logger.info(f"Training XGBoost ({task})...")
        
        # Get config
        xgb_config = self.config.get('xgboost', {}).get(task, {})
        
        # Build parameters
        params = {
            'objective': xgb_config.get('objective', 'binary:logistic'),
            'n_estimators': xgb_config.get('n_estimators', 500),
            'max_depth': xgb_config.get('max_depth', 8),
            'min_child_weight': xgb_config.get('min_child_weight', 5),
            'learning_rate': xgb_config.get('learning_rate', 0.05),
            'subsample': xgb_config.get('subsample', 0.8),
            'colsample_bytree': xgb_config.get('colsample_bytree', 0.8),
            'reg_alpha': xgb_config.get('reg_alpha', 0.1),
            'reg_lambda': xgb_config.get('reg_lambda', 1.0),
            'tree_method': xgb_config.get('tree_method', 'hist'),
            'random_state': xgb_config.get('random_state', 42),
            'n_jobs': -1,
            'verbosity': 1
        }
        
        # Handle class imbalance for binary
        if task == 'binary':
            scale_pos_weight = xgb_config.get('scale_pos_weight', 'auto')
            if scale_pos_weight == 'auto':
                params['scale_pos_weight'] = self._compute_class_weights(y_train)
                logger.info(f"Computed scale_pos_weight: {params['scale_pos_weight']:.2f}")
            else:
                params['scale_pos_weight'] = scale_pos_weight
        
        # Multiclass setup
        if task == 'multiclass':
            n_classes = len(np.unique(y_train))
            params['num_class'] = n_classes
            logger.info(f"Multiclass with {n_classes} classes")
        
        # Create model
        model = xgb.XGBClassifier(**params)
        
        # Early stopping setup
        early_stopping_rounds = xgb_config.get('early_stopping_rounds', 50)
        
        if X_val is not None and y_val is not None:
            # Train with validation
            eval_set = [(X_train, y_train), (X_val, y_val)]
            model.fit(
                X_train, y_train,
                eval_set=eval_set,
                verbose=True
            )
        else:
            # Train without validation
            model.fit(X_train, y_train, verbose=True)
        
        self.model = model
        self.model_type = 'xgboost'
        
        logger.info("XGBoost training complete")
        return model
    
    def train_random_forest(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray
    ) -> RandomForestClassifier:
        """Train a Random Forest baseline."""
        logger.info("Training Random Forest baseline...")
        
        rf_config = self.config.get('random_forest', {})
        
        model = RandomForestClassifier(
            n_estimators=rf_config.get('n_estimators', 300),
            max_depth=rf_config.get('max_depth', 15),
            min_samples_split=rf_config.get('min_samples_split', 5),
            min_samples_leaf=rf_config.get('min_samples_leaf', 2),
            class_weight=rf_config.get('class_weight', 'balanced'),
            n_jobs=-1,
            random_state=rf_config.get('random_state', 42)
        )
        
        model.fit(X_train, y_train)

        self.model = model
        self.model_type = 'random_forest'

        logger.info("Random Forest training complete")
        return model

    def train_lightgbm(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        task: str = 'binary'
    ) -> lgb.LGBMClassifier:
        """
        Train a LightGBM model.

        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features (optional)
            y_val: Validation labels (optional)
            task: 'binary' or 'multiclass'

        Returns:
            Trained LightGBM model
        """
        logger.info(f"Training LightGBM ({task})...")

        lgb_config = self.config.get('lightgbm', {})

        params = {
            'n_estimators': lgb_config.get('n_estimators', 500),
            'max_depth': lgb_config.get('max_depth', 8),
            'num_leaves': lgb_config.get('num_leaves', 64),
            'learning_rate': lgb_config.get('learning_rate', 0.05),
            'subsample': lgb_config.get('subsample', 0.8),
            'colsample_bytree': lgb_config.get('colsample_bytree', 0.8),
            'random_state': lgb_config.get('random_state', 42),
            'n_jobs': -1,
            'verbose': -1,
        }

        if task == 'binary':
            params['objective'] = 'binary'
            params['metric'] = 'binary_logloss'
            params['is_unbalance'] = lgb_config.get('is_unbalance', True)
        else:
            params['objective'] = 'multiclass'
            params['metric'] = 'multi_logloss'
            params['num_class'] = len(np.unique(y_train))

        model = lgb.LGBMClassifier(**params)

        callbacks = [lgb.log_evaluation(period=50)]

        if X_val is not None and y_val is not None:
            callbacks.append(lgb.early_stopping(stopping_rounds=50, verbose=True))
            model.fit(
                X_train, y_train,
                eval_set=[(X_val, y_val)],
                callbacks=callbacks
            )
        else:
            model.fit(X_train, y_train, callbacks=callbacks)

        self.model = model
        self.model_type = 'lightgbm'

        logger.info("LightGBM training complete")
        return model

    def train_logistic_regression(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray
    ) -> Pipeline:
        """
        Train a Logistic Regression baseline (with standard scaling).

        Returns:
            Trained sklearn Pipeline (scaler + LR)
        """
        logger.info("Training Logistic Regression baseline...")

        model = Pipeline([
            ('scaler', StandardScaler()),
            ('lr', LogisticRegression(
                class_weight='balanced',
                max_iter=1000,
                solver='lbfgs',
                random_state=42,
            ))
        ])

        model.fit(X_train, y_train)

        self.model = model
        self.model_type = 'logistic_regression'

        logger.info("Logistic Regression training complete")
        return model

    def compare_models(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        label_encoder=None
    ) -> pd.DataFrame:
        """
        Train and compare all available models on the same data.

        Returns:
            DataFrame with model comparison ranked by PR-AUC
        """
        logger.info("=" * 60)
        logger.info("Model Comparison")
        logger.info("=" * 60)

        results = []
        trained_models = {}

        model_specs = [
            ('XGBoost', 'xgboost'),
            ('LightGBM', 'lightgbm'),
            ('Random Forest', 'random_forest'),
            ('Logistic Regression', 'logistic_regression'),
        ]

        for display_name, model_key in model_specs:
            logger.info(f"\n--- {display_name} ---")
            try:
                if model_key == 'xgboost':
                    self.train_xgboost(X_train, y_train, X_val, y_val)
                elif model_key == 'lightgbm':
                    self.train_lightgbm(X_train, y_train, X_val, y_val)
                elif model_key == 'random_forest':
                    self.train_random_forest(X_train, y_train)
                elif model_key == 'logistic_regression':
                    self.train_logistic_regression(X_train, y_train)

                # Evaluate
                metrics = self.evaluate(X_test, y_test, label_encoder)

                row = {
                    'model': display_name,
                    'pr_auc': metrics.get('pr_auc', 0),
                    'roc_auc': metrics.get('roc_auc', 0),
                    'accuracy': metrics.get('accuracy', 0),
                    'f1': metrics.get('classification_report', {}).get('weighted avg', {}).get('f1-score', 0),
                    'precision': metrics.get('classification_report', {}).get('weighted avg', {}).get('precision', 0),
                    'recall': metrics.get('classification_report', {}).get('weighted avg', {}).get('recall', 0),
                }
                results.append(row)

                # Store trained model
                trained_models[model_key] = (self.model, self.model_type, metrics)

            except Exception as e:
                logger.warning(f"Failed to train {display_name}: {e}")
                results.append({
                    'model': display_name,
                    'pr_auc': 0, 'roc_auc': 0, 'accuracy': 0,
                    'f1': 0, 'precision': 0, 'recall': 0,
                })

        # Build comparison table
        comparison = pd.DataFrame(results)
        comparison = comparison.sort_values('pr_auc', ascending=False)
        comparison = comparison.reset_index(drop=True)
        comparison.index = comparison.index + 1  # 1-indexed rank
        comparison.index.name = 'rank'

        logger.info("\n" + "=" * 60)
        logger.info("Model Comparison (ranked by PR-AUC)")
        logger.info("=" * 60)
        print(comparison.to_string())

        # Restore the best model
        best_key = comparison.iloc[0]['model']
        for key, display in model_specs:
            if key == best_key:
                best_model_key = display
                break
        else:
            best_model_key = model_specs[0][1]

        # Map display name back to key
        name_to_key = {display: key for display, key in model_specs}
        best_key = name_to_key.get(comparison.iloc[0]['model'], 'xgboost')

        if best_key in trained_models:
            self.model, self.model_type, _ = trained_models[best_key]
            logger.info(f"\nBest model set as active: {comparison.iloc[0]['model']}")

        self.training_history['comparison'] = comparison.to_dict('records')

        return comparison

    def tune_xgboost(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        n_trials: int = 50,
        task: str = 'binary'
    ) -> Dict[str, Any]:
        """
        Hyperparameter tuning for XGBoost using Optuna.

        Optimizes for PR-AUC using stratified cross-validation.

        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features
            y_val: Validation labels
            n_trials: Number of Optuna trials
            task: 'binary' or 'multiclass'

        Returns:
            Dict with best params and score
        """
        try:
            import optuna
            optuna.logging.set_verbosity(optuna.logging.WARNING)
        except ImportError:
            logger.error("Optuna not installed. Run: pip install optuna")
            return {}

        logger.info(f"Tuning XGBoost with Optuna ({n_trials} trials)...")

        tuning_config = self.config.get('tuning', {})
        search_space = tuning_config.get('xgboost_search_space', {})

        def objective(trial):
            params = {
                'objective': 'binary:logistic' if task == 'binary' else 'multi:softprob',
                'tree_method': 'hist',
                'n_jobs': -1,
                'verbosity': 0,
                'random_state': 42,
                'n_estimators': trial.suggest_int(
                    'n_estimators',
                    search_space.get('n_estimators', [100, 1000])[0],
                    search_space.get('n_estimators', [100, 1000])[1],
                ),
                'max_depth': trial.suggest_int(
                    'max_depth',
                    search_space.get('max_depth', [4, 12])[0],
                    search_space.get('max_depth', [4, 12])[1],
                ),
                'min_child_weight': trial.suggest_int(
                    'min_child_weight',
                    search_space.get('min_child_weight', [1, 10])[0],
                    search_space.get('min_child_weight', [1, 10])[1],
                ),
                'learning_rate': trial.suggest_float(
                    'learning_rate',
                    search_space.get('learning_rate', [0.01, 0.3])[0],
                    search_space.get('learning_rate', [0.01, 0.3])[1],
                    log=True,
                ),
                'subsample': trial.suggest_float(
                    'subsample',
                    search_space.get('subsample', [0.6, 1.0])[0],
                    search_space.get('subsample', [0.6, 1.0])[1],
                ),
                'colsample_bytree': trial.suggest_float(
                    'colsample_bytree',
                    search_space.get('colsample_bytree', [0.6, 1.0])[0],
                    search_space.get('colsample_bytree', [0.6, 1.0])[1],
                ),
                'reg_alpha': trial.suggest_float(
                    'reg_alpha',
                    search_space.get('reg_alpha', [0, 1.0])[0],
                    search_space.get('reg_alpha', [0, 1.0])[1],
                ),
                'reg_lambda': trial.suggest_float(
                    'reg_lambda',
                    search_space.get('reg_lambda', [0.5, 2.0])[0],
                    search_space.get('reg_lambda', [0.5, 2.0])[1],
                ),
            }

            if task == 'binary':
                params['scale_pos_weight'] = self._compute_class_weights(y_train)

            model = xgb.XGBClassifier(**params)
            model.fit(
                X_train, y_train,
                eval_set=[(X_val, y_val)],
                verbose=False,
            )

            y_prob = model.predict_proba(X_val)[:, 1]
            return average_precision_score(y_val, y_prob)

        study = optuna.create_study(direction='maximize')
        study.optimize(objective, n_trials=n_trials, show_progress_bar=True)

        best = study.best_trial
        logger.info(f"Best PR-AUC: {best.value:.4f}")
        logger.info(f"Best params: {best.params}")

        # Retrain with best params
        logger.info("Retraining with best parameters...")
        best_params = best.params.copy()
        best_params['objective'] = 'binary:logistic' if task == 'binary' else 'multi:softprob'
        best_params['tree_method'] = 'hist'
        best_params['n_jobs'] = -1
        best_params['random_state'] = 42
        if task == 'binary':
            best_params['scale_pos_weight'] = self._compute_class_weights(y_train)

        model = xgb.XGBClassifier(**best_params)
        model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=True,
        )

        self.model = model
        self.model_type = 'xgboost'

        result = {
            'best_pr_auc': best.value,
            'best_params': best.params,
            'n_trials': n_trials,
            'all_trials': [
                {'number': t.number, 'value': t.value, 'params': t.params}
                for t in study.trials
            ]
        }
        self.training_history['xgboost_tuning'] = result

        return result

    def tune_lightgbm(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        n_trials: int = 50,
        task: str = 'binary'
    ) -> Dict[str, Any]:
        """
        Hyperparameter tuning for LightGBM using Optuna.

        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features
            y_val: Validation labels
            n_trials: Number of Optuna trials
            task: 'binary' or 'multiclass'

        Returns:
            Dict with best params and score
        """
        try:
            import optuna
            optuna.logging.set_verbosity(optuna.logging.WARNING)
        except ImportError:
            logger.error("Optuna not installed. Run: pip install optuna")
            return {}

        logger.info(f"Tuning LightGBM with Optuna ({n_trials} trials)...")

        def objective(trial):
            params = {
                'objective': 'binary' if task == 'binary' else 'multiclass',
                'verbose': -1,
                'n_jobs': -1,
                'random_state': 42,
                'n_estimators': trial.suggest_int('n_estimators', 100, 1000),
                'max_depth': trial.suggest_int('max_depth', 3, 12),
                'num_leaves': trial.suggest_int('num_leaves', 16, 128),
                'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3, log=True),
                'subsample': trial.suggest_float('subsample', 0.6, 1.0),
                'colsample_bytree': trial.suggest_float('colsample_bytree', 0.6, 1.0),
                'min_child_samples': trial.suggest_int('min_child_samples', 5, 100),
                'reg_alpha': trial.suggest_float('reg_alpha', 1e-8, 1.0, log=True),
                'reg_lambda': trial.suggest_float('reg_lambda', 1e-8, 1.0, log=True),
            }

            if task == 'binary':
                params['is_unbalance'] = True

            model = lgb.LGBMClassifier(**params)
            model.fit(
                X_train, y_train,
                eval_set=[(X_val, y_val)],
                callbacks=[
                    lgb.early_stopping(stopping_rounds=50, verbose=False),
                    lgb.log_evaluation(period=0),
                ],
            )

            y_prob = model.predict_proba(X_val)[:, 1]
            return average_precision_score(y_val, y_prob)

        study = optuna.create_study(direction='maximize')
        study.optimize(objective, n_trials=n_trials, show_progress_bar=True)

        best = study.best_trial
        logger.info(f"Best PR-AUC: {best.value:.4f}")
        logger.info(f"Best params: {best.params}")

        # Retrain with best params
        logger.info("Retraining with best parameters...")
        best_params = best.params.copy()
        best_params['objective'] = 'binary' if task == 'binary' else 'multiclass'
        best_params['verbose'] = -1
        best_params['n_jobs'] = -1
        best_params['random_state'] = 42
        if task == 'binary':
            best_params['is_unbalance'] = True

        model = lgb.LGBMClassifier(**best_params)
        model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            callbacks=[
                lgb.early_stopping(stopping_rounds=50, verbose=True),
                lgb.log_evaluation(period=50),
            ],
        )

        self.model = model
        self.model_type = 'lightgbm'

        result = {
            'best_pr_auc': best.value,
            'best_params': best.params,
            'n_trials': n_trials,
        }
        self.training_history['lightgbm_tuning'] = result

        return result

    # =========================================================================
    # Anomaly Detection (Unsupervised — Zero-Day Coverage)
    # =========================================================================

    def train_anomaly_detector(
        self,
        X_normal: np.ndarray,
        contamination: float = 0.05,
    ) -> IsolationForest:
        """
        Train an Isolation Forest on normal/benign traffic.

        The model learns what normal looks like. Anything that deviates
        significantly is flagged as anomalous — catches zero-days that
        supervised models miss because they've never seen the pattern.

        Args:
            X_normal: Feature matrix of known-normal traffic only
            contamination: Expected fraction of anomalies in training data

        Returns:
            Trained IsolationForest
        """
        logger.info("Training Isolation Forest anomaly detector...")
        logger.info(f"  Normal samples: {len(X_normal):,}")
        logger.info(f"  Contamination: {contamination}")

        anomaly_config = self.config.get('anomaly_detection', {})

        self.anomaly_model = IsolationForest(
            n_estimators=anomaly_config.get('n_estimators', 300),
            max_samples=anomaly_config.get('max_samples', 'auto'),
            contamination=contamination,
            max_features=anomaly_config.get('max_features', 1.0),
            random_state=42,
            n_jobs=-1,
        )

        # Fit on normal traffic
        self.anomaly_model.fit(X_normal)
        self.anomaly_scaler = StandardScaler()
        self.anomaly_scaler.fit(X_normal)

        logger.info("Isolation Forest training complete")
        return self.anomaly_model

    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores for samples.

        Returns scores in [0, 1] range where higher = more anomalous.
        IsolationForest returns negative scores (more negative = more anomalous),
        so we invert and normalize.
        """
        if not hasattr(self, 'anomaly_model') or self.anomaly_model is None:
            raise ValueError("No anomaly detector trained. Call train_anomaly_detector first.")

        raw_scores = self.anomaly_model.decision_function(X)
        # decision_function: lower (more negative) = more anomalous
        # Convert to 0-1 where 1 = most anomalous
        normalized = 1 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-10)
        return normalized

    def evaluate_anomaly(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
    ) -> Dict[str, Any]:
        """
        Evaluate anomaly detector against labeled test data.

        Args:
            X_test: Test features
            y_test: Binary labels (0=normal, 1=attack)

        Returns:
            Dict with anomaly detection metrics
        """
        logger.info("Evaluating anomaly detector...")

        scores = self.anomaly_scores(X_test)
        predictions = self.anomaly_model.predict(X_test)
        # IsolationForest: 1=normal, -1=anomaly. Convert to our convention: 1=attack
        y_pred = (predictions == -1).astype(int)

        pr_auc = float(average_precision_score(y_test, scores))
        roc_auc = float(roc_auc_score(y_test, scores))

        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)

        metrics = {
            'pr_auc': pr_auc,
            'roc_auc': roc_auc,
            'accuracy': float((y_pred == y_test).mean()),
            'classification_report': report,
            'confusion_matrix': cm.tolist(),
        }

        logger.info(f"Anomaly PR-AUC: {pr_auc:.4f}")
        logger.info(f"Anomaly ROC-AUC: {roc_auc:.4f}")
        logger.info("\nClassification Report (anomaly):")
        print(classification_report(y_test, y_pred, zero_division=0))
        logger.info("\nConfusion Matrix (anomaly):")
        print(cm)

        return metrics

    # =========================================================================
    # Semi-Supervised Learning (Leverage Unlabeled Data)
    # =========================================================================

    def train_semi_supervised(
        self,
        X_labeled: np.ndarray,
        y_labeled: np.ndarray,
        X_unlabeled: np.ndarray,
        base_model: str = 'xgboost',
    ):
        """
        Semi-supervised training using self-training.

        Uses a small set of labeled data + a large pool of unlabeled data.
        The model iteratively labels high-confidence unlabeled samples and
        retrains, expanding its knowledge beyond the labeled set.

        Args:
            X_labeled: Labeled feature matrix
            y_labeled: Labels for labeled data
            X_unlabeled: Unlabeled feature matrix (y = -1)
            base_model: Base classifier ('xgboost' or 'random_forest')
        """
        logger.info("Training semi-supervised model (self-training)...")
        logger.info(f"  Labeled samples: {len(X_labeled):,}")
        logger.info(f"  Unlabeled samples: {len(X_unlabeled):,}")

        # Combine labeled and unlabeled
        X_combined = np.vstack([X_labeled, X_unlabeled])
        # sklearn SelfTraining uses -1 for unlabeled
        y_combined = np.concatenate([
            y_labeled,
            np.full(len(X_unlabeled), -1)
        ])

        # Base classifier must support predict_proba
        if base_model == 'xgboost':
            xgb_config = self.config.get('xgboost', {}).get('binary', {})
            base = xgb.XGBClassifier(
                n_estimators=xgb_config.get('n_estimators', 500),
                max_depth=xgb_config.get('max_depth', 8),
                learning_rate=xgb_config.get('learning_rate', 0.05),
                tree_method='hist',
                random_state=42,
                n_jobs=-1,
                verbosity=0,
                scale_pos_weight=self._compute_class_weights(y_labeled),
            )
        else:
            rf_config = self.config.get('random_forest', {})
            base = RandomForestClassifier(
                n_estimators=rf_config.get('n_estimators', 300),
                max_depth=rf_config.get('max_depth', 15),
                class_weight='balanced',
                n_jobs=-1,
                random_state=42,
            )

        self_trainer = SelfTrainingClassifier(
            estimator=base,
            threshold=0.85,  # Only label samples with >= 85% confidence
            max_iter=10,
            verbose=True,
        )

        self_trainer.fit(X_combined, y_combined)

        n_labeled_after = np.sum(self_trainer.labeled_iter_ >= 0)
        logger.info(f"Self-training complete. Labeled {n_labeled_after - len(y_labeled):,} additional samples")

        self.model = self_trainer
        self.model_type = 'semi_supervised'

        return self_trainer

    # =========================================================================
    # Hybrid Scoring (Supervised + Unsupervised)
    # =========================================================================

    def train_hybrid(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        X_unlabeled: Optional[np.ndarray] = None,
        supervised_model: str = 'xgboost',
        anomaly_weight: float = 0.3,
    ) -> Dict[str, Any]:
        """
        Train a hybrid detection system:
        1. Supervised classifier (XGBoost/LightGBM) for known attack patterns
        2. Isolation Forest on normal traffic for zero-day anomaly detection
        3. Optionally: semi-supervised expansion using unlabeled data
        4. Combined scoring: weighted blend of both

        The idea: supervised model catches known attacks with high precision,
        anomaly detector catches novel/zero-day attacks that don't match
        any trained pattern.

        Args:
            X_train: Labeled training features
            y_train: Training labels (0=normal, 1=attack)
            X_val: Validation features
            y_val: Validation labels
            X_unlabeled: Unlabeled traffic (optional, for semi-supervised)
            supervised_model: 'xgboost' or 'lightgbm'
            anomaly_weight: Weight for anomaly score in hybrid (0-1).
                            0.3 = 70% supervised + 30% anomaly detection.

        Returns:
            Dict with training results for both components
        """
        logger.info("=" * 60)
        logger.info("Hybrid Model Training")
        logger.info(f"  Supervised: {supervised_model}")
        logger.info(f"  Anomaly weight: {anomaly_weight}")
        logger.info(f"  Unlabeled data: {'yes' if X_unlabeled is not None else 'no'}")
        logger.info("=" * 60)

        results = {}

        # --- Step 1: Train supervised classifier ---
        logger.info("\n--- Step 1: Supervised Classifier ---")
        if supervised_model == 'lightgbm':
            self.train_lightgbm(X_train, y_train, X_val, y_val)
        else:
            self.train_xgboost(X_train, y_train, X_val, y_val)

        # Store the supervised model separately
        self._supervised_model = self.model
        self._supervised_model_type = self.model_type
        results['supervised_model'] = self.model_type

        # --- Step 2: Train anomaly detector on normal traffic ---
        logger.info("\n--- Step 2: Anomaly Detector ---")
        normal_mask = y_train == 0
        X_normal = X_train[normal_mask]

        # Estimate contamination from labeled data
        attack_ratio = float(y_train.mean())
        contamination = min(max(attack_ratio, 0.01), 0.1)
        self.train_anomaly_detector(X_normal, contamination=contamination)
        results['anomaly_contamination'] = contamination
        results['normal_samples'] = int(normal_mask.sum())

        # --- Step 3: Semi-supervised expansion (optional) ---
        if X_unlabeled is not None and len(X_unlabeled) > 0:
            logger.info("\n--- Step 3: Semi-Supervised Expansion ---")
            self._semi_model = self.train_semi_supervised(
                X_train, y_train, X_unlabeled, base_model=supervised_model
            )
            # Restore supervised as primary (semi-supervised is auxiliary)
            self.model = self._supervised_model
            self.model_type = self._supervised_model_type
            results['semi_supervised'] = True
            results['unlabeled_samples'] = len(X_unlabeled)
        else:
            self._semi_model = None
            results['semi_supervised'] = False

        # Store hybrid config
        self._anomaly_weight = anomaly_weight
        self._hybrid_mode = True

        self.training_history['hybrid'] = results

        logger.info("\n--- Hybrid Training Complete ---")
        return results

    def hybrid_score(
        self,
        X: np.ndarray,
    ) -> np.ndarray:
        """
        Combined threat score from supervised + anomaly models.

        Score = (1 - w) * supervised_prob + w * anomaly_score

        Where w = anomaly_weight. Higher score = more likely attack/anomaly.

        For SOC deployment:
          >= 0.95 -> auto-block (high confidence from either model)
          >= 0.80 -> alert (probable attack or unusual traffic)
          >= 0.50 -> review (flagged by one model)
        """
        if not hasattr(self, '_hybrid_mode') or not self._hybrid_mode:
            # Fall back to supervised only
            return self.model.predict_proba(X)[:, 1]

        w = self._anomaly_weight

        # Supervised probability
        sup_prob = self._supervised_model.predict_proba(X)[:, 1]

        # Anomaly score
        anom_score = self.anomaly_scores(X)

        # Semi-supervised boost (optional)
        if self._semi_model is not None:
            semi_prob = self._semi_model.predict_proba(X)[:, 1]
            # Average supervised and semi-supervised
            sup_prob = (sup_prob + semi_prob) / 2

        # Weighted combination
        hybrid = (1 - w) * sup_prob + w * anom_score

        return hybrid

    def evaluate_hybrid(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
    ) -> Dict[str, Any]:
        """
        Evaluate hybrid model with component breakdown.

        Shows metrics for:
        1. Supervised model alone
        2. Anomaly detector alone
        3. Hybrid combined score
        """
        logger.info("=" * 60)
        logger.info("Hybrid Model Evaluation")
        logger.info("=" * 60)

        results = {}

        # Supervised alone
        logger.info("\n--- Supervised Only ---")
        sup_prob = self._supervised_model.predict_proba(X_test)[:, 1]
        sup_pred = (sup_prob >= self.threshold).astype(int)
        results['supervised'] = {
            'pr_auc': float(average_precision_score(y_test, sup_prob)),
            'roc_auc': float(roc_auc_score(y_test, sup_prob)),
            'f1': float(f1_score(y_test, sup_pred, zero_division=0)),
        }
        logger.info(f"  PR-AUC: {results['supervised']['pr_auc']:.4f}")
        logger.info(f"  ROC-AUC: {results['supervised']['roc_auc']:.4f}")

        # Anomaly alone
        logger.info("\n--- Anomaly Detector Only ---")
        anom_scores = self.anomaly_scores(X_test)
        anom_pred = (self.anomaly_model.predict(X_test) == -1).astype(int)
        results['anomaly'] = {
            'pr_auc': float(average_precision_score(y_test, anom_scores)),
            'roc_auc': float(roc_auc_score(y_test, anom_scores)),
            'f1': float(f1_score(y_test, anom_pred, zero_division=0)),
        }
        logger.info(f"  PR-AUC: {results['anomaly']['pr_auc']:.4f}")
        logger.info(f"  ROC-AUC: {results['anomaly']['roc_auc']:.4f}")

        # Semi-supervised (if available)
        if self._semi_model is not None:
            logger.info("\n--- Semi-Supervised ---")
            semi_prob = self._semi_model.predict_proba(X_test)[:, 1]
            semi_pred = (semi_prob >= self.threshold).astype(int)
            results['semi_supervised'] = {
                'pr_auc': float(average_precision_score(y_test, semi_prob)),
                'roc_auc': float(roc_auc_score(y_test, semi_prob)),
                'f1': float(f1_score(y_test, semi_pred, zero_division=0)),
            }
            logger.info(f"  PR-AUC: {results['semi_supervised']['pr_auc']:.4f}")

        # Hybrid combined
        logger.info("\n--- Hybrid Combined ---")
        hybrid_scores = self.hybrid_score(X_test)
        hybrid_pred = (hybrid_scores >= self.threshold).astype(int)
        results['hybrid'] = {
            'pr_auc': float(average_precision_score(y_test, hybrid_scores)),
            'roc_auc': float(roc_auc_score(y_test, hybrid_scores)),
            'f1': float(f1_score(y_test, hybrid_pred, zero_division=0)),
            'anomaly_weight': self._anomaly_weight,
        }
        logger.info(f"  PR-AUC: {results['hybrid']['pr_auc']:.4f}")
        logger.info(f"  ROC-AUC: {results['hybrid']['roc_auc']:.4f}")

        # Summary table
        logger.info("\n" + "=" * 60)
        logger.info("Component Comparison")
        logger.info("=" * 60)
        summary = pd.DataFrame([
            {'component': 'Supervised', **results['supervised']},
            {'component': 'Anomaly', **results['anomaly']},
            {'component': 'Hybrid', 'pr_auc': results['hybrid']['pr_auc'],
             'roc_auc': results['hybrid']['roc_auc'], 'f1': results['hybrid']['f1']},
        ])
        if 'semi_supervised' in results:
            summary = pd.concat([summary, pd.DataFrame([
                {'component': 'Semi-Supervised', **results['semi_supervised']}
            ])], ignore_index=True)
        summary = summary.sort_values('pr_auc', ascending=False)
        print(summary.to_string(index=False))

        self.training_history['hybrid_evaluation'] = results
        return results

    def cross_validate(
        self,
        X: np.ndarray,
        y: np.ndarray,
        cv_folds: int = 5,
        scoring: str = 'average_precision'
    ) -> Dict[str, Any]:
        """
        Perform cross-validation.
        
        Args:
            X: Features
            y: Labels
            cv_folds: Number of folds
            scoring: Scoring metric
            
        Returns:
            Dict with CV results
        """
        logger.info(f"Running {cv_folds}-fold cross-validation...")
        
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        
        scores = cross_val_score(
            self.model, X, y,
            cv=cv,
            scoring=scoring,
            n_jobs=-1
        )
        
        results = {
            'metric': scoring,
            'scores': scores.tolist(),
            'mean': float(scores.mean()),
            'std': float(scores.std()),
            'cv_folds': cv_folds
        }
        
        logger.info(f"CV {scoring}: {results['mean']:.4f} (+/- {results['std']:.4f})")
        
        return results
    
    def optimize_threshold(
        self,
        X_val: np.ndarray,
        y_val: np.ndarray,
        metric: str = 'f1'
    ) -> float:
        """
        Find optimal probability threshold.
        
        Args:
            X_val: Validation features
            y_val: Validation labels
            metric: Metric to optimize ('f1', 'precision', 'recall')
            
        Returns:
            Optimal threshold
        """
        logger.info(f"Optimizing threshold for {metric}...")
        
        # Get probabilities
        y_prob = self.model.predict_proba(X_val)[:, 1]
        
        # Search thresholds
        thresholds = np.arange(0.1, 0.95, 0.01)
        best_score = 0
        best_threshold = 0.5
        
        for thresh in thresholds:
            y_pred = (y_prob >= thresh).astype(int)
            
            if metric == 'f1':
                score = f1_score(y_val, y_pred, zero_division=0)
            elif metric == 'precision':
                score = precision_score(y_val, y_pred, zero_division=0)
            elif metric == 'recall':
                score = recall_score(y_val, y_pred, zero_division=0)
            else:
                raise ValueError(f"Unknown metric: {metric}")
            
            if score > best_score:
                best_score = score
                best_threshold = thresh
        
        self.threshold = best_threshold
        logger.info(f"Optimal threshold: {best_threshold:.2f} ({metric}: {best_score:.4f})")
        
        return best_threshold
    
    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        label_encoder=None,
        threshold: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Evaluate model on test set.
        
        Args:
            X_test: Test features
            y_test: Test labels
            label_encoder: Label encoder for class names
            threshold: Classification threshold
            
        Returns:
            Dict with evaluation metrics
        """
        logger.info("Evaluating model...")
        
        if threshold is None:
            threshold = self.threshold
        
        # Get predictions
        y_prob = self.model.predict_proba(X_test)
        
        # Binary case
        if y_prob.shape[1] == 2:
            y_prob_pos = y_prob[:, 1]
            y_pred = (y_prob_pos >= threshold).astype(int)
        else:
            y_pred = np.argmax(y_prob, axis=1)
            y_prob_pos = None
        
        # Basic metrics
        metrics = {
            'accuracy': float((y_pred == y_test).mean()),
            'threshold': threshold
        }
        
        # Binary-specific metrics
        if y_prob_pos is not None:
            metrics['pr_auc'] = float(average_precision_score(y_test, y_prob_pos))
            metrics['roc_auc'] = float(roc_auc_score(y_test, y_prob_pos))
        
        # Per-class metrics
        if label_encoder is not None:
            target_names = label_encoder.classes_
        else:
            target_names = None
        
        report = classification_report(
            y_test, y_pred,
            target_names=target_names,
            output_dict=True,
            zero_division=0
        )
        metrics['classification_report'] = report
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        metrics['confusion_matrix'] = cm.tolist()
        
        # Log summary
        logger.info(f"Accuracy: {metrics['accuracy']:.4f}")
        if 'pr_auc' in metrics:
            logger.info(f"PR-AUC: {metrics['pr_auc']:.4f}")
            logger.info(f"ROC-AUC: {metrics['roc_auc']:.4f}")
        
        logger.info("\nClassification Report:")
        print(classification_report(
            y_test, y_pred,
            target_names=target_names,
            zero_division=0
        ))
        
        logger.info("\nConfusion Matrix:")
        print(cm)
        
        return metrics
    
    def get_feature_importance(
        self,
        feature_names: List[str],
        top_n: int = 20
    ) -> pd.DataFrame:
        """
        Get feature importance from the model.
        
        Args:
            feature_names: List of feature names
            top_n: Number of top features to return
            
        Returns:
            DataFrame with feature importances
        """
        if self.model is None:
            raise ValueError("No model trained")
        
        if hasattr(self.model, 'feature_importances_'):
            importance = self.model.feature_importances_
        else:
            raise ValueError("Model doesn't support feature importance")
        
        # Create DataFrame
        df = pd.DataFrame({
            'feature': feature_names,
            'importance': importance
        })
        
        df = df.sort_values('importance', ascending=False).head(top_n)
        
        logger.info(f"\nTop {top_n} Features:")
        for _, row in df.iterrows():
            logger.info(f"  {row['feature']}: {row['importance']:.4f}")
        
        return df
    
    def save_model(
        self,
        path: str,
        feature_names: List[str],
        label_encoder=None,
        metrics: Optional[Dict] = None
    ):
        """
        Save model and metadata.
        
        Args:
            path: Directory to save to
            feature_names: List of feature names
            label_encoder: Label encoder
            metrics: Evaluation metrics
        """
        os.makedirs(path, exist_ok=True)
        
        # Save model
        if self.model_type == 'xgboost':
            model_path = os.path.join(path, 'model.json')
            self.model.save_model(model_path)
        elif self.model_type == 'lightgbm':
            model_path = os.path.join(path, 'model.lgb')
            self.model.booster_.save_model(model_path)
            # Also save sklearn wrapper for easy loading
            import pickle
            pkl_path = os.path.join(path, 'model.pkl')
            with open(pkl_path, 'wb') as f:
                pickle.dump(self.model, f)
        else:
            import pickle
            model_path = os.path.join(path, 'model.pkl')
            with open(model_path, 'wb') as f:
                pickle.dump(self.model, f)
        
        # Save anomaly model if hybrid
        if hasattr(self, '_hybrid_mode') and self._hybrid_mode:
            import pickle
            anomaly_path = os.path.join(path, 'anomaly_model.pkl')
            with open(anomaly_path, 'wb') as f:
                pickle.dump({
                    'anomaly_model': self.anomaly_model,
                    'anomaly_scaler': self.anomaly_scaler,
                    'anomaly_weight': self._anomaly_weight,
                    'semi_model': self._semi_model,
                }, f)
            logger.info(f"  - Anomaly model: {anomaly_path}")

        # Save metadata
        metadata = {
            'model_type': self.model_type,
            'hybrid_mode': getattr(self, '_hybrid_mode', False),
            'threshold': self.threshold,
            'feature_names': feature_names,
            'n_features': len(feature_names),
            'training_date': datetime.now().isoformat(),
            'config': self.config
        }
        
        if label_encoder is not None:
            metadata['classes'] = label_encoder.classes_.tolist()
        
        if metrics is not None:
            # Convert any numpy types to native Python types
            def convert_numpy(obj):
                if isinstance(obj, np.ndarray):
                    return obj.tolist()
                elif isinstance(obj, (np.int64, np.int32)):
                    return int(obj)
                elif isinstance(obj, (np.float64, np.float32)):
                    return float(obj)
                elif isinstance(obj, dict):
                    return {k: convert_numpy(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_numpy(i) for i in obj]
                return obj
            
            metadata['metrics'] = convert_numpy(metrics)
        
        metadata_path = os.path.join(path, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Model saved to {path}")
        logger.info(f"  - Model: {model_path}")
        logger.info(f"  - Metadata: {metadata_path}")
    
    @classmethod
    def load_model(cls, path: str) -> 'ModelTrainer':
        """
        Load a saved model.
        
        Args:
            path: Directory containing saved model
            
        Returns:
            ModelTrainer instance with loaded model
        """
        # Load metadata
        metadata_path = os.path.join(path, 'metadata.json')
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Create trainer instance
        trainer = cls()
        trainer.model_type = metadata['model_type']
        trainer.threshold = metadata['threshold']
        
        # Load model
        if trainer.model_type == 'xgboost':
            model_path = os.path.join(path, 'model.json')
            trainer.model = xgb.XGBClassifier()
            trainer.model.load_model(model_path)
        elif trainer.model_type == 'lightgbm':
            import pickle
            model_path = os.path.join(path, 'model.pkl')
            with open(model_path, 'rb') as f:
                trainer.model = pickle.load(f)
        else:
            import pickle
            model_path = os.path.join(path, 'model.pkl')
            with open(model_path, 'rb') as f:
                trainer.model = pickle.load(f)
        
        # Load anomaly model if hybrid
        anomaly_path = os.path.join(path, 'anomaly_model.pkl')
        if os.path.exists(anomaly_path):
            import pickle
            with open(anomaly_path, 'rb') as f:
                anomaly_data = pickle.load(f)
            trainer.anomaly_model = anomaly_data['anomaly_model']
            trainer.anomaly_scaler = anomaly_data['anomaly_scaler']
            trainer._anomaly_weight = anomaly_data['anomaly_weight']
            trainer._semi_model = anomaly_data['semi_model']
            trainer._supervised_model = trainer.model
            trainer._supervised_model_type = trainer.model_type
            trainer._hybrid_mode = True
            logger.info("  Hybrid mode restored (anomaly + supervised)")

        logger.info(f"Model loaded from {path}")
        return trainer


def get_trainer(config_path: Optional[str] = None) -> ModelTrainer:
    """Factory function to get model trainer."""
    return ModelTrainer(config_path)


# =============================================================================
# CLI
# =============================================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SOC-ML Model Training")
    parser.add_argument('--task', default='binary', choices=['binary', 'multiclass'])
    parser.add_argument('--compare', action='store_true', help='Compare all models')
    parser.add_argument('--tune', action='store_true', help='Run Optuna tuning')
    parser.add_argument('--tune-trials', type=int, default=50, help='Number of Optuna trials')
    parser.add_argument('--hybrid', action='store_true',
                        help='Train hybrid model (supervised + anomaly detection)')
    parser.add_argument('--anomaly', action='store_true',
                        help='Train anomaly detector only (unsupervised)')
    parser.add_argument('--anomaly-weight', type=float, default=0.3,
                        help='Anomaly weight in hybrid score (0-1, default 0.3)')
    parser.add_argument('--test', action='store_true', help='Quick test with synthetic data')
    args = parser.parse_args()

    if args.test:
        from sklearn.datasets import make_classification
        from sklearn.model_selection import train_test_split

        print("\n" + "=" * 60)
        print("Model Training Test (synthetic data)")
        print("=" * 60)

        X, y = make_classification(
            n_samples=2000,
            n_features=20,
            n_informative=10,
            n_classes=2,
            weights=[0.9, 0.1],
            random_state=42
        )

        X_train, X_tmp, y_train, y_tmp = train_test_split(
            X, y, test_size=0.3, stratify=y, random_state=42
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_tmp, y_tmp, test_size=0.5, stratify=y_tmp, random_state=42
        )

        # Simulate unlabeled data for semi-supervised testing
        X_unlabeled, _ = make_classification(
            n_samples=500,
            n_features=20,
            n_informative=10,
            n_classes=2,
            weights=[0.9, 0.1],
            random_state=99
        )

        trainer = get_trainer()
        feature_names = [f'feature_{i}' for i in range(20)]

        if args.hybrid:
            result = trainer.train_hybrid(
                X_train, y_train, X_val, y_val,
                X_unlabeled=X_unlabeled,
                anomaly_weight=args.anomaly_weight,
            )
            trainer.evaluate_hybrid(X_test, y_test)
        elif args.anomaly:
            normal_mask = y_train == 0
            trainer.train_anomaly_detector(X_train[normal_mask])
            trainer.evaluate_anomaly(X_test, y_test)
        elif args.compare:
            comparison = trainer.compare_models(
                X_train, y_train, X_test, y_test, X_val, y_val
            )
        elif args.tune:
            print("\nTuning XGBoost...")
            xgb_result = trainer.tune_xgboost(
                X_train, y_train, X_val, y_val, n_trials=args.tune_trials
            )
            print(f"\nBest XGBoost PR-AUC: {xgb_result.get('best_pr_auc', 'N/A')}")

            print("\nTuning LightGBM...")
            lgb_result = trainer.tune_lightgbm(
                X_train, y_train, X_val, y_val, n_trials=args.tune_trials
            )
            print(f"\nBest LightGBM PR-AUC: {lgb_result.get('best_pr_auc', 'N/A')}")
        else:
            trainer.train_xgboost(X_train, y_train, X_val, y_val)
            metrics = trainer.evaluate(X_test, y_test)
            trainer.get_feature_importance(feature_names)
