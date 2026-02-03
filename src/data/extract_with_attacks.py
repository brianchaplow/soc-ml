"""
SOC-ML Data Extraction with Attack Correlation
===============================================
Extracts Suricata alerts and correlates with logged attacks
for ground-truth ML labeling.

Author: Brian Chaplow (Chappy McNasty)
"""

import os
import logging
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta
import pandas as pd
import numpy as np

from .extract import DataExtractor, get_extractor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AttackCorrelator:
    """
    Correlates attack logs with Suricata alerts for ground-truth labeling.
    
    Uses timestamp ranges from attack_log.csv to definitively label
    traffic as attack vs benign.
    """
    
    def __init__(self, attack_log_path: Optional[str] = None):
        """
        Initialize the correlator.
        
        Args:
            attack_log_path: Path to attack_log.csv
        """
        if attack_log_path is None:
            attack_log_path = os.path.join(
                os.path.dirname(__file__), '..', '..', 'attacks', 'attack_log.csv'
            )
        
        self.attack_log_path = attack_log_path
        self.attacks_df = None
        
        if os.path.exists(attack_log_path):
            self._load_attack_log()
        else:
            logger.warning(f"Attack log not found at {attack_log_path}")
    
    def _load_attack_log(self):
        """Load and parse the attack log."""
        try:
            self.attacks_df = pd.read_csv(self.attack_log_path)
            
            # Parse timestamps
            self.attacks_df['timestamp_start'] = pd.to_datetime(
                self.attacks_df['timestamp_start'], utc=True
            )
            self.attacks_df['timestamp_end'] = pd.to_datetime(
                self.attacks_df['timestamp_end'], utc=True
            )
            
            # Add buffer time (Suricata might log slightly before/after)
            self.attacks_df['window_start'] = self.attacks_df['timestamp_start'] - timedelta(seconds=5)
            self.attacks_df['window_end'] = self.attacks_df['timestamp_end'] + timedelta(seconds=30)
            
            logger.info(f"Loaded {len(self.attacks_df)} attacks from log")
            
            # Show summary
            if len(self.attacks_df) > 0:
                logger.info("Attack categories:")
                for cat, count in self.attacks_df['category'].value_counts().items():
                    logger.info(f"  {cat}: {count}")
        
        except Exception as e:
            logger.error(f"Failed to load attack log: {e}")
            self.attacks_df = None
    
    def is_attack_traffic(
        self,
        timestamp: pd.Timestamp,
        src_ip: str,
        dest_ip: str
    ) -> Tuple[bool, Optional[Dict]]:
        """
        Check if traffic matches a logged attack (single-row fallback).

        Args:
            timestamp: Traffic timestamp
            src_ip: Source IP
            dest_ip: Destination IP

        Returns:
            Tuple of (is_attack, attack_info)
        """
        if self.attacks_df is None or len(self.attacks_df) == 0:
            return False, None

        # Ensure timestamp is timezone-aware
        if timestamp.tzinfo is None:
            timestamp = timestamp.tz_localize('UTC')

        # Check each attack window
        for _, attack in self.attacks_df.iterrows():
            # Check time window
            if not (attack['window_start'] <= timestamp <= attack['window_end']):
                continue

            # Check source IP (should be sear: 10.10.20.20)
            if src_ip != attack['source_ip'] and src_ip != '10.10.20.20':
                continue

            # Check destination IP
            target_ip = str(attack['target_ip'])
            if '/' in target_ip:
                # Subnet - check prefix
                prefix = target_ip.split('/')[0].rsplit('.', 1)[0]
                if not dest_ip.startswith(prefix):
                    continue
            else:
                if dest_ip != target_ip:
                    continue

            # Match found!
            return True, {
                'attack_id': attack['attack_id'],
                'category': attack['category'],
                'subcategory': attack['subcategory'],
                'technique_id': attack['technique_id'],
                'tool': attack['tool']
            }

        return False, None

    def _parse_campaign_from_notes(self, notes: str) -> Optional[str]:
        """Extract campaign ID from notes field."""
        if pd.isna(notes) or not isinstance(notes, str):
            return None
        # Look for "Campaign: CAMP-YYYYMMDD-HHMMSS"
        import re
        match = re.search(r'Campaign:\s*(CAMP-\S+)', notes)
        return match.group(1) if match else None

    def label_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add ground-truth attack labels to a dataframe using vectorized operations.

        Replaces O(n*m) row-by-row loop with sorted interval matching via
        boolean masks per attack window for significantly better performance.

        Args:
            df: DataFrame with @timestamp, src_ip, dest_ip columns

        Returns:
            DataFrame with additional label columns
        """
        logger.info("Correlating traffic with attack log (vectorized)...")

        if self.attacks_df is None or len(self.attacks_df) == 0:
            logger.warning("No attacks loaded - returning original labels")
            return df

        # Ensure timestamp is datetime
        df['@timestamp'] = pd.to_datetime(df['@timestamp'], utc=True)

        # Initialize new columns
        df['attack_confirmed'] = False
        df['attack_id'] = None
        df['attack_category'] = None
        df['attack_subcategory'] = None
        df['attack_technique'] = None
        df['attack_tool'] = None
        df['attack_campaign'] = None

        # Vectorized correlation: iterate over attacks (small) not traffic (large)
        # Sort attacks by window_start for efficient processing
        attacks_sorted = self.attacks_df.sort_values('window_start').copy()

        # Parse campaign info from notes
        if 'notes' in attacks_sorted.columns:
            attacks_sorted['campaign'] = attacks_sorted['notes'].apply(
                self._parse_campaign_from_notes
            )
        else:
            attacks_sorted['campaign'] = None

        # Pre-compute traffic arrays for fast masking
        traffic_ts = df['@timestamp'].values
        traffic_src = df['src_ip'].astype(str).values
        traffic_dest = df['dest_ip'].astype(str).values

        # Track which rows have been matched (for overlap handling)
        # When multiple attacks overlap, prefer exact port match
        match_priority = np.full(len(df), -1, dtype=np.int64)  # -1 = no match
        match_is_exact = np.zeros(len(df), dtype=bool)

        confirmed_count = 0

        for atk_idx, attack in attacks_sorted.iterrows():
            # Time window mask (vectorized)
            time_mask = (
                (traffic_ts >= attack['window_start'].to_datetime64()) &
                (traffic_ts <= attack['window_end'].to_datetime64())
            )

            if not time_mask.any():
                continue

            # Source IP mask
            source_ip = str(attack['source_ip'])
            src_mask = (traffic_src == source_ip) | (traffic_src == '10.10.20.20')

            # Destination IP mask
            target_ip = str(attack['target_ip'])
            if '/' in target_ip:
                # Subnet match
                prefix = target_ip.split('/')[0].rsplit('.', 1)[0]
                dest_mask = np.array([d.startswith(prefix) for d in traffic_dest])
                is_exact_target = False
            else:
                dest_mask = (traffic_dest == target_ip)
                is_exact_target = True

            # Combined mask for this attack
            combined_mask = time_mask & src_mask & dest_mask

            if not combined_mask.any():
                continue

            # Handle overlapping windows: prefer exact match over subnet match
            mask_indices = np.where(combined_mask)[0]
            for idx in mask_indices:
                if match_priority[idx] < 0:
                    # No previous match — assign
                    match_priority[idx] = atk_idx
                    match_is_exact[idx] = is_exact_target
                elif is_exact_target and not match_is_exact[idx]:
                    # Current is exact, previous was subnet — override
                    match_priority[idx] = atk_idx
                    match_is_exact[idx] = True
                # Else: keep existing match

            new_matches = combined_mask & (match_priority == atk_idx)
            new_count = new_matches.sum()

            if new_count > 0:
                df.loc[new_matches, 'attack_confirmed'] = True
                df.loc[new_matches, 'attack_id'] = attack['attack_id']
                df.loc[new_matches, 'attack_category'] = attack['category']
                df.loc[new_matches, 'attack_subcategory'] = attack['subcategory']
                df.loc[new_matches, 'attack_technique'] = attack['technique_id']
                df.loc[new_matches, 'attack_tool'] = attack['tool']
                df.loc[new_matches, 'attack_campaign'] = attack.get('campaign', None)
                confirmed_count += new_count

        logger.info(f"Confirmed {confirmed_count:,} records as attack traffic")

        return df
    
    def get_attack_summary(self) -> pd.DataFrame:
        """Get summary of logged attacks."""
        if self.attacks_df is None:
            return pd.DataFrame()
        
        return self.attacks_df[[
            'attack_id', 'timestamp_start', 'category', 
            'subcategory', 'technique_id', 'tool', 
            'target_ip', 'success'
        ]]


class GroundTruthExtractor(DataExtractor):
    """
    Extended data extractor that uses attack logs for ground-truth labeling.
    """
    
    def __init__(self, attack_log_path: Optional[str] = None, **kwargs):
        """Initialize with attack correlator."""
        super().__init__(**kwargs)
        self.correlator = AttackCorrelator(attack_log_path)
    
    def extract_with_ground_truth(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        max_alerts: int = 100000,
        max_flows: int = 50000,
        zeek_enrich: bool = True
    ) -> pd.DataFrame:
        """
        Extract data and apply ground-truth labels from attack log.

        Args:
            start_date: Start date for extraction
            end_date: End date for extraction
            max_alerts: Maximum alerts to pull
            max_flows: Maximum flows to pull
            zeek_enrich: Whether to enrich with Zeek conn.log data

        Returns:
            DataFrame with ground-truth labels
        """
        logger.info("=" * 60)
        logger.info("Ground Truth Extraction Pipeline")
        logger.info(f"Zeek enrichment: {'enabled' if zeek_enrich else 'disabled'}")
        logger.info("=" * 60)

        # Extract alerts
        logger.info("\n[1/3] Extracting alerts...")
        alerts_df = self.extract_alerts(
            start_date=start_date,
            end_date=end_date,
            max_records=max_alerts,
            zeek_enrich=zeek_enrich
        )

        if not alerts_df.empty:
            # Apply ground-truth labels
            alerts_df = self.correlator.label_dataframe(alerts_df)

            # Update label_binary based on ground truth
            # If attack_confirmed, definitely an attack
            # Otherwise, use the existing classification
            alerts_df.loc[alerts_df['attack_confirmed'], 'label_binary'] = 'attack'

        # Extract flows (benign baseline)
        logger.info("\n[2/3] Extracting flows...")
        flows_df = self.extract_flows(
            start_date=start_date,
            end_date=end_date,
            max_records=max_flows,
            zeek_enrich=zeek_enrich
        )
        
        if not flows_df.empty:
            # Also check flows for attack correlation
            flows_df = self.correlator.label_dataframe(flows_df)
            flows_df.loc[flows_df['attack_confirmed'], 'label_binary'] = 'attack'
        
        # Combine
        logger.info("\n[3/3] Combining datasets...")
        combined = pd.concat([alerts_df, flows_df], ignore_index=True)
        
        # Summary
        logger.info("\n" + "=" * 60)
        logger.info("Extraction Summary")
        logger.info("=" * 60)
        logger.info(f"Total records: {len(combined):,}")
        logger.info(f"Attack confirmed (ground truth): {combined['attack_confirmed'].sum():,}")
        logger.info(f"\nLabel distribution:")
        for label, count in combined['label_binary'].value_counts().items():
            logger.info(f"  {label}: {count:,}")
        
        if combined['attack_confirmed'].sum() > 0:
            logger.info(f"\nAttack categories (confirmed):")
            for cat, count in combined[combined['attack_confirmed']]['attack_category'].value_counts().items():
                logger.info(f"  {cat}: {count:,}")
        
        return combined


def get_ground_truth_extractor(attack_log_path: Optional[str] = None) -> GroundTruthExtractor:
    """Factory function for ground truth extractor."""
    return GroundTruthExtractor(attack_log_path)


# =============================================================================
# CLI
# =============================================================================
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Ground Truth Data Extraction")
    parser.add_argument('--start', default='2026-01-20')
    parser.add_argument('--end', default='2026-01-28')
    parser.add_argument('--max-alerts', type=int, default=100000)
    parser.add_argument('--max-flows', type=int, default=50000)
    parser.add_argument('--attack-log', default=None)
    parser.add_argument('--output', default=None)
    parser.add_argument('--no-zeek', action='store_true',
                        help='Disable Zeek conn.log enrichment')

    args = parser.parse_args()

    extractor = get_ground_truth_extractor(args.attack_log)
    
    # Show attack summary
    print("\nLogged Attacks:")
    print(extractor.correlator.get_attack_summary().to_string())
    print()
    
    # Extract data
    df = extractor.extract_with_ground_truth(
        start_date=args.start,
        end_date=args.end,
        max_alerts=args.max_alerts,
        max_flows=args.max_flows,
        zeek_enrich=not args.no_zeek
    )
    
    # Save if output specified
    if args.output:
        df.to_parquet(args.output)
        print(f"\nSaved to {args.output}")
