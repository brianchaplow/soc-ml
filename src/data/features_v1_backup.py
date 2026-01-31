"""
SOC-ML Feature Engineering Module
=================================
Transforms raw data into ML-ready features.

Author: Brian Chaplow (Chappy McNasty)
"""

import os
import logging
from typing import Optional, List, Dict, Any, Tuple

import pandas as pd
import numpy as np
import yaml
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class FeatureEngineer:
    """
    Transforms raw SOC data into ML-ready features.
    
    Handles:
    - Numeric feature extraction
    - Categorical encoding
    - Derived feature computation
    - Missing value handling
    - Feature scaling
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the feature engineer.
        
        Args:
            config_path: Path to features.yaml
        """
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__), '..', '..', 'config', 'features.yaml'
            )
        
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Encoders and scalers (fitted during training)
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: List[str] = []
        self._fitted = False
    
    def _extract_numeric_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract and clean numeric features."""
        features = pd.DataFrame(index=df.index)
        
        # Network features
        features['src_port'] = pd.to_numeric(df.get('src_port', 0), errors='coerce').fillna(0)
        features['dest_port'] = pd.to_numeric(df.get('dest_port', 0), errors='coerce').fillna(0)
        
        # Alert metadata
        features['severity'] = pd.to_numeric(df.get('alert.severity', 3), errors='coerce').fillna(3)
        features['signature_id'] = pd.to_numeric(df.get('alert.signature_id', 0), errors='coerce').fillna(0)
        
        # Flow statistics
        for col in ['flow.bytes_toserver', 'flow.bytes_toclient', 
                    'flow.pkts_toserver', 'flow.pkts_toclient']:
            clean_name = col.replace('flow.', '')
            features[clean_name] = pd.to_numeric(df.get(col, 0), errors='coerce').fillna(0)
        
        return features
    
    def _compute_derived_features(self, features: pd.DataFrame) -> pd.DataFrame:
        """Compute derived features from base features."""
        # Total bytes and packets
        features['bytes_total'] = features['bytes_toserver'] + features['bytes_toclient']
        features['pkts_total'] = features['pkts_toserver'] + features['pkts_toclient']
        
        # Ratios (with smoothing to avoid division by zero)
        features['bytes_ratio'] = features['bytes_toserver'] / (features['bytes_toclient'] + 1)
        features['pkts_ratio'] = features['pkts_toserver'] / (features['pkts_toclient'] + 1)
        
        # Average packet sizes
        features['avg_pkt_size_toserver'] = features['bytes_toserver'] / (features['pkts_toserver'] + 1)
        features['avg_pkt_size_toclient'] = features['bytes_toclient'] / (features['pkts_toclient'] + 1)
        
        # Port-based features
        features['is_privileged_src_port'] = (features['src_port'] < 1024).astype(int)
        features['is_privileged_dest_port'] = (features['dest_port'] < 1024).astype(int)
        features['is_ephemeral_src_port'] = (features['src_port'] >= 49152).astype(int)
        
        # Well-known port indicators
        port_categories = self.config.get('features', {}).get('port_categories', {})
        for category, ports in port_categories.items():
            features[f'dest_is_{category}'] = features['dest_port'].isin(ports).astype(int)
        
        # Log transforms for skewed features
        for col in ['bytes_total', 'bytes_toserver', 'bytes_toclient']:
            features[f'{col}_log'] = np.log1p(features[col])
        
        return features
    
    def _encode_categorical_features(
        self, 
        df: pd.DataFrame, 
        fit: bool = True
    ) -> pd.DataFrame:
        """Encode categorical features."""
        features = pd.DataFrame(index=df.index)
        
        # Protocol
        proto_col = df.get('proto', pd.Series(['TCP'] * len(df), index=df.index))
        if fit:
            self.label_encoders['proto'] = LabelEncoder()
            self.label_encoders['proto'].fit(['TCP', 'UDP', 'ICMP', 'OTHER'])
        
        # Handle unknown protocols
        proto_values = proto_col.fillna('OTHER').astype(str)
        proto_values = proto_values.apply(
            lambda x: x if x in self.label_encoders['proto'].classes_ else 'OTHER'
        )
        features['proto_encoded'] = self.label_encoders['proto'].transform(proto_values)
        
        # Direction
        direction_col = df.get('direction', pd.Series(['unknown'] * len(df), index=df.index))
        if fit:
            self.label_encoders['direction'] = LabelEncoder()
            self.label_encoders['direction'].fit(['to_server', 'to_client', 'unknown'])
        
        direction_values = direction_col.fillna('unknown').astype(str)
        direction_values = direction_values.apply(
            lambda x: x if x in self.label_encoders['direction'].classes_ else 'unknown'
        )
        features['direction_encoded'] = self.label_encoders['direction'].transform(direction_values)
        
        # VLAN
        # VLAN can be a list, extract first value
        vlan_col = df.get('vlan', pd.Series([[0]] * len(df), index=df.index))
        
        def extract_vlan(v):
            if pd.isna(v):
                return 0
            if isinstance(v, list) and len(v) > 0:
                return int(v[0]) if not pd.isna(v[0]) else 0
            elif isinstance(v, (int, float)):
                if pd.isna(v):
                    return 0
                return int(v)
            return 0
        
        features['vlan'] = vlan_col.apply(extract_vlan)
        
        # One-hot encode VLANs (your specific VLANs)
        for vlan_id in [10, 20, 30, 40, 50]:
            features[f'vlan_{vlan_id}'] = (features['vlan'] == vlan_id).astype(int)
        
        return features
    
    def _extract_ip_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features from IP addresses."""
        features = pd.DataFrame(index=df.index)
        
        # Check if internal IPs
        src_ip = df.get('src_ip', pd.Series(['0.0.0.0'] * len(df), index=df.index)).fillna('0.0.0.0')
        dest_ip = df.get('dest_ip', pd.Series(['0.0.0.0'] * len(df), index=df.index)).fillna('0.0.0.0')
        
        features['is_internal_src'] = src_ip.str.startswith('10.10.').astype(int)
        features['is_internal_dest'] = dest_ip.str.startswith('10.10.').astype(int)
        
        # Traffic direction (internal-to-internal, internal-to-external, etc.)
        features['is_internal_traffic'] = (
            features['is_internal_src'] & features['is_internal_dest']
        ).astype(int)
        features['is_inbound'] = (
            ~features['is_internal_src'].astype(bool) & features['is_internal_dest'].astype(bool)
        ).astype(int)
        features['is_outbound'] = (
            features['is_internal_src'].astype(bool) & ~features['is_internal_dest'].astype(bool)
        ).astype(int)
        
        return features
    
    def fit_transform(
        self, 
        df: pd.DataFrame,
        scale: bool = False
    ) -> Tuple[np.ndarray, List[str]]:
        """
        Fit on training data and transform.
        
        Args:
            df: Training DataFrame
            scale: Whether to apply standard scaling
            
        Returns:
            Tuple of (feature array, feature names)
        """
        logger.info("Extracting features (fit mode)...")
        
        # Extract all feature groups
        numeric_features = self._extract_numeric_features(df)
        derived_features = self._compute_derived_features(numeric_features)
        categorical_features = self._encode_categorical_features(df, fit=True)
        ip_features = self._extract_ip_features(df)
        
        # Combine
        all_features = pd.concat([
            derived_features,
            categorical_features,
            ip_features
        ], axis=1)
        
        # Store feature names
        self.feature_names = all_features.columns.tolist()
        
        # Handle any remaining NaN/inf
        all_features = all_features.replace([np.inf, -np.inf], np.nan)
        all_features = all_features.fillna(0)
        
        # Convert to numpy
        X = all_features.values.astype(np.float32)
        
        # Optional scaling
        if scale:
            self.scaler = StandardScaler()
            X = self.scaler.fit_transform(X)
        
        self._fitted = True
        
        logger.info(f"Extracted {len(self.feature_names)} features")
        logger.info(f"Feature matrix shape: {X.shape}")
        
        return X, self.feature_names
    
    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transform new data using fitted encoders.
        
        Args:
            df: DataFrame to transform
            
        Returns:
            Feature array
        """
        if not self._fitted:
            raise ValueError("FeatureEngineer not fitted. Call fit_transform first.")
        
        logger.info("Extracting features (transform mode)...")
        
        # Extract all feature groups
        numeric_features = self._extract_numeric_features(df)
        derived_features = self._compute_derived_features(numeric_features)
        categorical_features = self._encode_categorical_features(df, fit=False)
        ip_features = self._extract_ip_features(df)
        
        # Combine
        all_features = pd.concat([
            derived_features,
            categorical_features,
            ip_features
        ], axis=1)
        
        # Ensure same columns in same order
        for col in self.feature_names:
            if col not in all_features.columns:
                all_features[col] = 0
        
        all_features = all_features[self.feature_names]
        
        # Handle any remaining NaN/inf
        all_features = all_features.replace([np.inf, -np.inf], np.nan)
        all_features = all_features.fillna(0)
        
        # Convert to numpy
        X = all_features.values.astype(np.float32)
        
        # Apply scaling if fitted
        if self.scaler is not None:
            X = self.scaler.transform(X)
        
        return X
    
    def get_labels(
        self, 
        df: pd.DataFrame, 
        label_type: str = 'binary'
    ) -> Tuple[np.ndarray, LabelEncoder]:
        """
        Extract and encode labels.
        
        Args:
            df: DataFrame with label columns
            label_type: 'binary' or 'attack_type'
            
        Returns:
            Tuple of (encoded labels, label encoder)
        """
        if label_type == 'binary':
            label_col = 'label_binary'
        else:
            label_col = 'label_attack_type'
        
        if label_col not in df.columns:
            raise ValueError(f"Label column {label_col} not found")
        
        labels = df[label_col].fillna('unknown').astype(str)
        
        encoder = LabelEncoder()
        y = encoder.fit_transform(labels)
        
        logger.info(f"Labels ({label_type}):")
        for cls, count in zip(*np.unique(y, return_counts=True)):
            logger.info(f"  {encoder.classes_[cls]}: {count:,}")
        
        return y, encoder
    
    def save(self, path: str):
        """Save fitted state to disk."""
        import pickle
        
        state = {
            'label_encoders': self.label_encoders,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'config': self.config,
            '_fitted': self._fitted
        }
        
        with open(path, 'wb') as f:
            pickle.dump(state, f)
        
        logger.info(f"Saved FeatureEngineer to {path}")
    
    @classmethod
    def load(cls, path: str) -> 'FeatureEngineer':
        """Load fitted state from disk."""
        import pickle
        
        with open(path, 'rb') as f:
            state = pickle.load(f)
        
        engineer = cls.__new__(cls)
        engineer.label_encoders = state['label_encoders']
        engineer.scaler = state['scaler']
        engineer.feature_names = state['feature_names']
        engineer.config = state['config']
        engineer._fitted = state['_fitted']
        
        logger.info(f"Loaded FeatureEngineer from {path}")
        return engineer


def get_feature_engineer(config_path: Optional[str] = None) -> FeatureEngineer:
    """Factory function to get feature engineer."""
    return FeatureEngineer(config_path)


# =============================================================================
# CLI for testing
# =============================================================================
if __name__ == "__main__":
    # Test with sample data
    sample_data = pd.DataFrame({
        'src_ip': ['10.10.20.10', '8.8.8.8', '10.10.30.40'],
        'dest_ip': ['8.8.8.8', '10.10.20.10', '10.10.30.41'],
        'src_port': [45678, 53, 49152],
        'dest_port': [443, 45678, 445],
        'proto': ['TCP', 'UDP', 'TCP'],
        'direction': ['to_server', 'to_client', 'to_server'],
        'vlan': [[20], [20], [30]],
        'alert.severity': [2, 3, 1],
        'alert.signature_id': [2000001, 0, 9000001],
        'flow.bytes_toserver': [1500, 100, 50000],
        'flow.bytes_toclient': [5000, 200, 1000],
        'flow.pkts_toserver': [10, 2, 100],
        'flow.pkts_toclient': [20, 3, 5],
        'label_binary': ['info', 'benign', 'attack']
    })
    
    engineer = get_feature_engineer()
    X, feature_names = engineer.fit_transform(sample_data)
    
    print(f"\nFeature names ({len(feature_names)}):")
    for name in feature_names:
        print(f"  - {name}")
    
    print(f"\nFeature matrix:\n{X}")
