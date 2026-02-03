"""
SOC-ML Zeek Enrichment Utility
===============================
Correlates Zeek conn.log records with Suricata alerts/flows
via 5-tuple + timestamp matching.

Author: Brian Chaplow (Chappy McNasty)
"""

import logging
from typing import Optional

import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)


class ZeekEnricher:
    """
    Enriches Suricata DataFrames with Zeek conn.log metadata.

    Performs a left-join on composite 5-tuple key + nearest timestamp,
    adding Zeek's richer connection metadata to each Suricata record.
    """

    # Zeek field -> prefixed column name mapping
    FIELD_MAP = {
        'id.orig_h': 'zeek_src_ip',
        'id.orig_p': 'zeek_src_port',
        'id.resp_h': 'zeek_dest_ip',
        'id.resp_p': 'zeek_dest_port',
        'proto': 'zeek_proto',
        'duration': 'zeek_duration',
        'conn_state': 'zeek_conn_state',
        'history': 'zeek_history',
        'service': 'zeek_service',
        'local_orig': 'zeek_local_orig',
        'local_resp': 'zeek_local_resp',
        'orig_bytes': 'zeek_orig_bytes',
        'resp_bytes': 'zeek_resp_bytes',
        'orig_pkts': 'zeek_orig_pkts',
        'resp_pkts': 'zeek_resp_pkts',
        'orig_ip_bytes': 'zeek_orig_ip_bytes',
        'resp_ip_bytes': 'zeek_resp_ip_bytes',
        'missed_bytes': 'zeek_missed_bytes',
        'uid': 'zeek_uid',
    }

    def normalize_fields(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Rename Zeek fields to zeek_ prefixed names to avoid collisions.

        Args:
            df: Raw Zeek conn DataFrame from OpenSearch

        Returns:
            DataFrame with renamed columns
        """
        df = df.copy()

        rename_map = {}
        for old_name, new_name in self.FIELD_MAP.items():
            if old_name in df.columns:
                rename_map[old_name] = new_name

        df = df.rename(columns=rename_map)
        return df

    def _build_merge_key(
        self,
        df: pd.DataFrame,
        src_ip_col: str,
        src_port_col: str,
        dest_ip_col: str,
        dest_port_col: str,
        proto_col: str
    ) -> pd.Series:
        """Build composite merge key: src_ip:src_port->dest_ip:dest_port/proto."""
        src_ip = df[src_ip_col].fillna('').astype(str)
        src_port = df[src_port_col].fillna(0).astype(int).astype(str)
        dest_ip = df[dest_ip_col].fillna('').astype(str)
        dest_port = df[dest_port_col].fillna(0).astype(int).astype(str)
        proto = df[proto_col].fillna('').astype(str).str.lower()

        return src_ip + ':' + src_port + '->' + dest_ip + ':' + dest_port + '/' + proto

    def enrich(
        self,
        suricata_df: pd.DataFrame,
        zeek_df: pd.DataFrame,
        time_tolerance: float = 2.0
    ) -> pd.DataFrame:
        """
        Left-join Zeek conn.log records onto Suricata alerts/flows.

        Matches on composite 5-tuple key + nearest timestamp within tolerance.
        Records without a Zeek match get NaN in zeek_* columns.

        Args:
            suricata_df: Suricata alerts or flows DataFrame
            zeek_df: Zeek conn records (already normalized via normalize_fields)
            time_tolerance: Max seconds between timestamps for a match

        Returns:
            Enriched DataFrame with zeek_* columns appended
        """
        if zeek_df.empty:
            logger.warning("Empty Zeek DataFrame, skipping enrichment")
            return suricata_df

        suricata_df = suricata_df.copy()
        zeek_df = zeek_df.copy()

        # Ensure timestamps are datetime
        suricata_df['@timestamp'] = pd.to_datetime(
            suricata_df['@timestamp'], utc=True
        )
        zeek_df['@timestamp'] = pd.to_datetime(
            zeek_df['@timestamp'], utc=True
        )

        # Build merge keys for Suricata
        suricata_df['_merge_key'] = self._build_merge_key(
            suricata_df,
            src_ip_col='src_ip',
            src_port_col='src_port',
            dest_ip_col='dest_ip',
            dest_port_col='dest_port',
            proto_col='proto'
        )

        # Build merge keys for Zeek
        zeek_df['_merge_key'] = self._build_merge_key(
            zeek_df,
            src_ip_col='zeek_src_ip',
            src_port_col='zeek_src_port',
            dest_ip_col='zeek_dest_ip',
            dest_port_col='zeek_dest_port',
            proto_col='zeek_proto'
        )

        # Sort both by timestamp (required for merge_asof)
        suricata_df = suricata_df.sort_values('@timestamp').reset_index(drop=True)
        zeek_df = zeek_df.sort_values('@timestamp').reset_index(drop=True)

        # Select Zeek columns to merge (exclude key-building cols to avoid dupes)
        zeek_merge_cols = ['@timestamp', '_merge_key'] + [
            c for c in zeek_df.columns
            if c.startswith('zeek_') and c not in (
                'zeek_src_ip', 'zeek_src_port',
                'zeek_dest_ip', 'zeek_dest_port',
                'zeek_proto'
            )
        ]
        zeek_for_merge = zeek_df[zeek_merge_cols].copy()

        # Perform asof merge
        tolerance = pd.Timedelta(seconds=time_tolerance)
        enriched = pd.merge_asof(
            suricata_df,
            zeek_for_merge,
            on='@timestamp',
            by='_merge_key',
            tolerance=tolerance,
            direction='nearest',
            suffixes=('', '_zeek_dup')
        )

        # Drop helper columns
        enriched = enriched.drop(columns=['_merge_key'], errors='ignore')

        # Drop any _zeek_dup columns from suffix collisions
        dup_cols = [c for c in enriched.columns if c.endswith('_zeek_dup')]
        if dup_cols:
            enriched = enriched.drop(columns=dup_cols)

        # Log correlation stats
        total = len(enriched)
        matched = enriched['zeek_uid'].notna().sum() if 'zeek_uid' in enriched.columns else 0
        hit_rate = matched / total * 100 if total > 0 else 0
        logger.info(
            f"Zeek enrichment: {matched:,}/{total:,} records matched "
            f"({hit_rate:.1f}% hit rate)"
        )

        return enriched
