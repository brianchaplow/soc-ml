"""
SOC-ML Data Extraction Module
=============================
Extracts and samples data from OpenSearch for ML training.

Author: Brian Chaplow (Chappy McNasty)
"""

import os
import logging
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
import hashlib

import pandas as pd
import numpy as np
import yaml
from tqdm import tqdm

from ..utils.opensearch import get_client, SOCOpenSearchClient
from ..utils.zeek import ZeekEnricher

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DataExtractor:
    """
    Extracts and prepares data from OpenSearch for ML training.
    
    Handles:
    - Pulling alerts and flows from OpenSearch
    - Stratified sampling for class balance
    - Temporal train/test splitting
    - Caching extracted data to disk
    """
    
    def __init__(
        self,
        features_config_path: Optional[str] = None,
        opensearch_config_path: Optional[str] = None
    ):
        """
        Initialize the extractor.
        
        Args:
            features_config_path: Path to features.yaml
            opensearch_config_path: Path to opensearch.yaml
        """
        # Load configs
        config_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'config')
        
        if features_config_path is None:
            features_config_path = os.path.join(config_dir, 'features.yaml')
        
        with open(features_config_path, 'r') as f:
            self.features_config = yaml.safe_load(f)
        
        # Initialize OpenSearch client
        self.os_client = get_client(opensearch_config_path)
        
        # Data directory
        self.data_dir = os.path.join(
            os.path.dirname(__file__), '..', '..', 'data'
        )
        os.makedirs(os.path.join(self.data_dir, 'raw'), exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, 'processed'), exist_ok=True)
        os.makedirs(os.path.join(self.data_dir, 'splits'), exist_ok=True)
    
    def _classify_alert(self, row: pd.Series) -> str:
        """
        Classify an alert into noise/info/attack based on config.
        
        Args:
            row: Alert row from DataFrame
            
        Returns:
            Classification string
        """
        signature = row.get('alert.signature', '')
        category = row.get('alert.category', '')
        
        labels_config = self.features_config.get('labels', {}).get('binary', {})
        
        # Check for attack signatures first (most important)
        attack_config = labels_config.get('attack', {})
        
        # Check signature patterns
        for pattern in attack_config.get('signature_patterns', []):
            if pattern in signature:
                return 'attack'
        
        # Check categories
        if category in attack_config.get('categories', []):
            return 'attack'
        
        # Check for noise
        noise_config = labels_config.get('noise', {})
        
        if signature in noise_config.get('signatures', []):
            return 'noise'
        
        if category in noise_config.get('categories', []):
            return 'noise'
        
        # Check for info
        info_config = labels_config.get('info', {})
        
        for pattern in info_config.get('signature_patterns', []):
            if pattern in signature:
                return 'info'
        
        if category in info_config.get('categories', []):
            return 'info'
        
        # Default to noise (conservative)
        return 'noise'
    
    def _classify_attack_type(self, row: pd.Series) -> str:
        """
        Classify attack type for multiclass model.
        
        Args:
            row: Alert row from DataFrame
            
        Returns:
            Attack type string or 'unknown'
        """
        signature = row.get('alert.signature', '')
        category = row.get('alert.category', '')
        
        attack_types = self.features_config.get('labels', {}).get('attack_types', {})
        
        for attack_type, config in attack_types.items():
            # Check signatures
            if signature in config.get('signatures', []):
                return attack_type
            
            # Check signature patterns
            for pattern in config.get('signature_patterns', []):
                if pattern in signature:
                    return attack_type
            
            # Check categories
            if category in config.get('categories', []):
                return attack_type
        
        return 'unknown'
    
    def _zeek_enrich_df(
        self,
        df: pd.DataFrame,
        start_date: Optional[str],
        end_date: Optional[str],
        max_records: Optional[int]
    ) -> pd.DataFrame:
        """
        Enrich a Suricata DataFrame with Zeek conn.log data.

        Args:
            df: Suricata alerts or flows DataFrame
            start_date: Date range start for Zeek query
            end_date: Date range end for Zeek query
            max_records: Suricata record count (Zeek pulls multiplier of this)

        Returns:
            Enriched DataFrame
        """
        zeek_config = self.os_client.config.get('zeek', {})
        correlation = zeek_config.get('correlation', {})
        multiplier = correlation.get('max_records_multiplier', 3)
        time_tolerance = correlation.get('time_tolerance', 2.0)

        zeek_max = (max_records or len(df)) * multiplier

        logger.info(f"Pulling Zeek conn records (max {zeek_max:,})...")
        zeek_df = self.os_client.get_zeek_conn(
            start_date=start_date,
            end_date=end_date,
            max_records=zeek_max
        )

        if zeek_df.empty:
            logger.warning("No Zeek conn records found, skipping enrichment")
            return df

        enricher = ZeekEnricher()
        zeek_df = enricher.normalize_fields(zeek_df)
        df = enricher.enrich(df, zeek_df, time_tolerance=time_tolerance)

        return df

    def extract_alerts(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        max_records: Optional[int] = None,
        cache: bool = True,
        zeek_enrich: bool = True
    ) -> pd.DataFrame:
        """
        Extract alerts from OpenSearch with labels.

        Args:
            start_date: Start date (ISO format)
            end_date: End date (ISO format)
            max_records: Max records to pull
            cache: Whether to cache results
            zeek_enrich: Whether to enrich with Zeek conn.log data

        Returns:
            DataFrame with alerts and labels
        """
        # Generate cache key (include zeek suffix when enriching)
        cache_suffix = "_zeek" if zeek_enrich else ""
        cache_key = hashlib.md5(
            f"{start_date}_{end_date}_{max_records}{cache_suffix}".encode()
        ).hexdigest()[:8]
        cache_path = os.path.join(self.data_dir, 'raw', f'alerts_{cache_key}.parquet')

        # Check cache
        if cache and os.path.exists(cache_path):
            logger.info(f"Loading cached alerts from {cache_path}")
            return pd.read_parquet(cache_path)

        logger.info("Extracting alerts from OpenSearch...")

        # Pull data
        df = self.os_client.get_alerts(
            start_date=start_date,
            end_date=end_date,
            max_records=max_records
        )

        if df.empty:
            return df

        # Zeek enrichment
        zeek_enabled = self.os_client.config.get('zeek', {}).get('enabled', True)
        if zeek_enrich and zeek_enabled:
            df = self._zeek_enrich_df(df, start_date, end_date, max_records)

        # Add labels
        logger.info("Classifying alerts...")
        df['label_binary'] = df.apply(self._classify_alert, axis=1)

        # Add attack type for attacks
        attack_mask = df['label_binary'] == 'attack'
        df.loc[attack_mask, 'label_attack_type'] = df[attack_mask].apply(
            self._classify_attack_type, axis=1
        )
        df['label_attack_type'] = df['label_attack_type'].fillna('none')

        # Cache
        if cache:
            df.to_parquet(cache_path)
            logger.info(f"Cached alerts to {cache_path}")

        return df
    
    def extract_flows(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        max_records: Optional[int] = None,
        cache: bool = True,
        zeek_enrich: bool = True
    ) -> pd.DataFrame:
        """
        Extract flow records (benign baseline) from OpenSearch.

        Args:
            start_date: Start date
            end_date: End date
            max_records: Max records
            cache: Whether to cache
            zeek_enrich: Whether to enrich with Zeek conn.log data

        Returns:
            DataFrame with flows
        """
        cache_suffix = "_zeek" if zeek_enrich else ""
        cache_key = hashlib.md5(
            f"flows_{start_date}_{end_date}_{max_records}{cache_suffix}".encode()
        ).hexdigest()[:8]
        cache_path = os.path.join(self.data_dir, 'raw', f'flows_{cache_key}.parquet')

        if cache and os.path.exists(cache_path):
            logger.info(f"Loading cached flows from {cache_path}")
            return pd.read_parquet(cache_path)

        logger.info("Extracting flows from OpenSearch...")

        df = self.os_client.get_flows(
            start_date=start_date,
            end_date=end_date,
            max_records=max_records
        )

        if df.empty:
            return df

        # Zeek enrichment
        zeek_enabled = self.os_client.config.get('zeek', {}).get('enabled', True)
        if zeek_enrich and zeek_enabled:
            df = self._zeek_enrich_df(df, start_date, end_date, max_records)

        # Label as benign
        df['label_binary'] = 'benign'
        df['label_attack_type'] = 'none'

        if cache:
            df.to_parquet(cache_path)
            logger.info(f"Cached flows to {cache_path}")

        return df
    
    def create_balanced_dataset(
        self,
        alerts_df: pd.DataFrame,
        flows_df: pd.DataFrame,
        random_state: int = 42
    ) -> pd.DataFrame:
        """
        Create a balanced dataset using stratified sampling.
        
        Args:
            alerts_df: Alerts DataFrame
            flows_df: Flows DataFrame
            random_state: Random seed
            
        Returns:
            Balanced DataFrame
        """
        sampling_config = self.features_config.get('sampling', {})
        target_samples = sampling_config.get('target_samples', {})
        min_samples = sampling_config.get('min_samples', 10)
        
        np.random.seed(random_state)
        
        dfs_to_concat = []
        
        # Process alerts by label
        for label in alerts_df['label_binary'].unique():
            label_df = alerts_df[alerts_df['label_binary'] == label]
            target = target_samples.get(label)
            
            if target is None:
                # Use all samples
                dfs_to_concat.append(label_df)
                logger.info(f"  {label}: using all {len(label_df):,} samples")
            elif len(label_df) <= target:
                # Not enough samples, use all
                dfs_to_concat.append(label_df)
                logger.info(f"  {label}: using all {len(label_df):,} samples (target: {target:,})")
            else:
                # Undersample
                sampled = label_df.sample(n=target, random_state=random_state)
                dfs_to_concat.append(sampled)
                logger.info(f"  {label}: sampled {target:,} from {len(label_df):,}")
        
        # Process flows (benign)
        benign_target = target_samples.get('benign', 100000)
        if len(flows_df) <= benign_target:
            dfs_to_concat.append(flows_df)
            logger.info(f"  benign: using all {len(flows_df):,} flows")
        else:
            sampled_flows = flows_df.sample(n=benign_target, random_state=random_state)
            dfs_to_concat.append(sampled_flows)
            logger.info(f"  benign: sampled {benign_target:,} from {len(flows_df):,} flows")
        
        # Combine
        combined = pd.concat(dfs_to_concat, ignore_index=True)
        
        # Shuffle
        combined = combined.sample(frac=1, random_state=random_state).reset_index(drop=True)
        
        logger.info(f"Created balanced dataset with {len(combined):,} total samples")
        logger.info(f"Class distribution:\n{combined['label_binary'].value_counts()}")
        
        return combined
    
    def temporal_split(
        self,
        df: pd.DataFrame,
        split_date: str,
        timestamp_col: str = '@timestamp'
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Split data temporally (train before date, test after).
        
        Args:
            df: Full DataFrame
            split_date: Date to split on
            timestamp_col: Timestamp column name
            
        Returns:
            Tuple of (train_df, test_df)
        """
        # Convert timestamp
        df[timestamp_col] = pd.to_datetime(df[timestamp_col])
        split_dt = pd.to_datetime(split_date)
        
        train_df = df[df[timestamp_col] < split_dt].copy()
        test_df = df[df[timestamp_col] >= split_dt].copy()
        
        logger.info(f"Temporal split at {split_date}:")
        logger.info(f"  Train: {len(train_df):,} samples")
        logger.info(f"  Test:  {len(test_df):,} samples")
        logger.info(f"  Train class distribution:\n{train_df['label_binary'].value_counts()}")
        logger.info(f"  Test class distribution:\n{test_df['label_binary'].value_counts()}")
        
        return train_df, test_df
    
    def extract_and_prepare(
        self,
        train_start: str = "2025-12-03",
        train_end: str = "2026-01-15",
        test_start: str = "2026-01-16",
        test_end: str = "2026-01-27",
        max_alerts: int = 500000,
        max_flows: int = 200000,
        save: bool = True,
        zeek_enrich: bool = True
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Full extraction and preparation pipeline.

        Args:
            train_start/end: Training date range
            test_start/end: Testing date range
            max_alerts: Max alerts to pull
            max_flows: Max flows to pull
            save: Whether to save splits
            zeek_enrich: Whether to enrich with Zeek conn.log data

        Returns:
            Tuple of (train_df, test_df)
        """
        logger.info("=" * 60)
        logger.info("SOC-ML Data Extraction Pipeline")
        logger.info(f"Zeek enrichment: {'enabled' if zeek_enrich else 'disabled'}")
        logger.info("=" * 60)

        # Extract training data
        logger.info(f"\n[1/4] Extracting training alerts ({train_start} to {train_end})...")
        train_alerts = self.extract_alerts(
            start_date=train_start,
            end_date=train_end,
            max_records=max_alerts,
            zeek_enrich=zeek_enrich
        )

        logger.info(f"\n[2/4] Extracting training flows...")
        train_flows = self.extract_flows(
            start_date=train_start,
            end_date=train_end,
            max_records=max_flows,
            zeek_enrich=zeek_enrich
        )

        # Extract test data
        logger.info(f"\n[3/4] Extracting test alerts ({test_start} to {test_end})...")
        test_alerts = self.extract_alerts(
            start_date=test_start,
            end_date=test_end,
            max_records=max_alerts // 4,  # Smaller test set
            zeek_enrich=zeek_enrich
        )

        logger.info(f"\n[4/4] Extracting test flows...")
        test_flows = self.extract_flows(
            start_date=test_start,
            end_date=test_end,
            max_records=max_flows // 4,
            zeek_enrich=zeek_enrich
        )
        
        # Create balanced datasets
        logger.info("\nBalancing training set...")
        train_df = self.create_balanced_dataset(train_alerts, train_flows)
        
        logger.info("\nBalancing test set...")
        test_df = self.create_balanced_dataset(test_alerts, test_flows)
        
        # Save
        if save:
            train_path = os.path.join(self.data_dir, 'splits', 'train.parquet')
            test_path = os.path.join(self.data_dir, 'splits', 'test.parquet')
            
            train_df.to_parquet(train_path)
            test_df.to_parquet(test_path)
            
            logger.info(f"\nSaved train to: {train_path}")
            logger.info(f"Saved test to: {test_path}")
        
        logger.info("\n" + "=" * 60)
        logger.info("Extraction Complete!")
        logger.info("=" * 60)
        
        return train_df, test_df


def get_extractor() -> DataExtractor:
    """Factory function to get data extractor."""
    return DataExtractor()


# =============================================================================
# CLI
# =============================================================================
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="SOC-ML Data Extraction")
    parser.add_argument('--train-start', default='2025-12-03')
    parser.add_argument('--train-end', default='2026-01-15')
    parser.add_argument('--test-start', default='2026-01-16')
    parser.add_argument('--test-end', default='2026-01-27')
    parser.add_argument('--max-alerts', type=int, default=500000)
    parser.add_argument('--max-flows', type=int, default=200000)
    parser.add_argument('--no-zeek', action='store_true',
                        help='Disable Zeek conn.log enrichment')

    args = parser.parse_args()

    extractor = get_extractor()
    train_df, test_df = extractor.extract_and_prepare(
        train_start=args.train_start,
        train_end=args.train_end,
        test_start=args.test_start,
        test_end=args.test_end,
        max_alerts=args.max_alerts,
        max_flows=args.max_flows,
        zeek_enrich=not args.no_zeek
    )
