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
