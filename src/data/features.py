"""
SOC-ML Feature Engineering Module v2
====================================
Transforms raw data into ML-ready features.
**FIXED: Removed data leakage from severity and signature_id**

Author: Brian Chaplow (Chappy McNasty)
Version: 2.0 - Leakage-free
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


# =============================================================================
# FEATURES TO EXCLUDE (Data Leakage)
# =============================================================================
# These features directly encode whether something is an attack:
#   - severity: Suricata sets severity=1 for attacks, 2-3 for info/noise
#   - signature_id: HOMELAB rules (9000xxx) are all attacks
#   - alert.signature: Contains attack type in the text
#   - alert.category: Directly indicates attack vs info
# =============================================================================


class FeatureEngineer:
    """
    Transforms raw SOC data into ML-ready features.
    
    v2 Changes:
    - REMOVED: severity, signature_id (data leakage)
    - ADDED: More behavioral features from flow data
    - ADDED: Time-based features
    
    The model should learn attack patterns from BEHAVIOR, not metadata.
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
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        else:
            logger.warning(f"Config not found at {config_path}, using defaults")
            self.config = self._default_config()
        
        # Encoders and scalers (fitted during training)
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: List[str] = []
        self._fitted = False
    
    def _default_config(self) -> Dict:
        """Default configuration if features.yaml not found."""
        return {
            'features': {
                'port_categories': {
                    'web': [80, 443, 8080, 8443],
                    'dns': [53],
                    'ssh': [22],
                    'smb': [445, 139],
                    'rdp': [3389],
                    'database': [3306, 5432, 1433, 27017],
                    'mail': [25, 587, 993, 995]
                }
            }
        }
    
    def _extract_network_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract network-level features (ports, protocol stats).
        
        These are BEHAVIORAL features - how traffic looks, not what Suricata thinks.
        """
        features = pd.DataFrame(index=df.index)
        
        # Port features
        features['src_port'] = pd.to_numeric(df.get('src_port', 0), errors='coerce').fillna(0)
        features['dest_port'] = pd.to_numeric(df.get('dest_port', 0), errors='coerce').fillna(0)
        
        # NOTE: We intentionally DO NOT include:
        # - severity (leakage: directly encodes attack priority)
        # - signature_id (leakage: HOMELAB sigs are all attacks)
        
        return features
    
    def _extract_flow_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract flow statistics - the core behavioral signal.
        
        Attacks often have distinctive traffic patterns:
        - Scans: Many small packets, low bytes
        - Exploits: Specific payload sizes
        - C2: Regular intervals, similar sizes
        - Exfil: High bytes_toclient
        """
        features = pd.DataFrame(index=df.index)
        
        # Raw flow stats
        features['bytes_toserver'] = pd.to_numeric(
            df.get('flow.bytes_toserver', 0), errors='coerce'
        ).fillna(0)
        features['bytes_toclient'] = pd.to_numeric(
            df.get('flow.bytes_toclient', 0), errors='coerce'
        ).fillna(0)
        features['pkts_toserver'] = pd.to_numeric(
            df.get('flow.pkts_toserver', 0), errors='coerce'
        ).fillna(0)
        features['pkts_toclient'] = pd.to_numeric(
            df.get('flow.pkts_toclient', 0), errors='coerce'
        ).fillna(0)
        
        return features
    
    def _compute_derived_features(self, features: pd.DataFrame) -> pd.DataFrame:
        """
        Compute derived features from base network/flow features.
        
        These ratios and aggregates help the model identify patterns.
        """
        # Totals
        features['bytes_total'] = features['bytes_toserver'] + features['bytes_toclient']
        features['pkts_total'] = features['pkts_toserver'] + features['pkts_toclient']
        
        # Ratios (with smoothing to avoid div/0)
        features['bytes_ratio'] = features['bytes_toserver'] / (features['bytes_toclient'] + 1)
        features['pkts_ratio'] = features['pkts_toserver'] / (features['pkts_toclient'] + 1)
        
        # Bidirectional ratio (closer to 1 = more balanced conversation)
        features['bytes_bidirectional'] = (
            np.minimum(features['bytes_toserver'], features['bytes_toclient']) /
            (np.maximum(features['bytes_toserver'], features['bytes_toclient']) + 1)
        )
        
        # Average packet sizes (attack signatures often have specific sizes)
        features['avg_pkt_size_toserver'] = features['bytes_toserver'] / (features['pkts_toserver'] + 1)
        features['avg_pkt_size_toclient'] = features['bytes_toclient'] / (features['pkts_toclient'] + 1)
        features['avg_pkt_size_total'] = features['bytes_total'] / (features['pkts_total'] + 1)
        
        # Port-based features
        features['is_privileged_src_port'] = (features['src_port'] < 1024).astype(int)
        features['is_privileged_dest_port'] = (features['dest_port'] < 1024).astype(int)
        features['is_ephemeral_src_port'] = (features['src_port'] >= 49152).astype(int)
        features['is_high_port_dest'] = (features['dest_port'] >= 10000).astype(int)
        
        # Well-known port indicators
        port_categories = self.config.get('features', {}).get('port_categories', {})
        for category, ports in port_categories.items():
            features[f'dest_is_{category}'] = features['dest_port'].isin(ports).astype(int)
        
        # Port entropy proxy (unusual ports score higher)
        common_ports = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080}
        features['is_uncommon_dest_port'] = (~features['dest_port'].isin(common_ports)).astype(int)
        
        # Log transforms for skewed features (helps with outliers)
        for col in ['bytes_total', 'bytes_toserver', 'bytes_toclient', 'pkts_total']:
            features[f'{col}_log'] = np.log1p(features[col])
        
        # Size categories (binned features can help tree models)
        features['is_small_flow'] = (features['bytes_total'] < 500).astype(int)
        features['is_large_flow'] = (features['bytes_total'] > 10000).astype(int)
        
        return features
    
    def _encode_categorical_features(
        self, 
        df: pd.DataFrame, 
        fit: bool = True
    ) -> pd.DataFrame:
        """Encode categorical features (protocol, direction, VLAN)."""
        features = pd.DataFrame(index=df.index)
        
        # Protocol
        proto_col = df.get('proto', pd.Series(['TCP'] * len(df), index=df.index))
        if fit:
            self.label_encoders['proto'] = LabelEncoder()
            self.label_encoders['proto'].fit(['TCP', 'UDP', 'ICMP', 'OTHER'])
        
        proto_values = proto_col.fillna('OTHER').astype(str).str.upper()
        proto_values = proto_values.apply(
            lambda x: x if x in self.label_encoders['proto'].classes_ else 'OTHER'
        )
        features['proto_encoded'] = self.label_encoders['proto'].transform(proto_values)
        
        # One-hot protocol (often more useful for tree models)
        for proto in ['TCP', 'UDP', 'ICMP']:
            features[f'proto_is_{proto.lower()}'] = (proto_values == proto).astype(int)
        
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
        
        # VLAN extraction (fixed NaN handling)
        vlan_col = df.get('vlan', pd.Series([[0]] * len(df), index=df.index))
        
        def extract_vlan(v):
            if v is None or (isinstance(v, float) and pd.isna(v)):
                return 0
            if isinstance(v, list) and len(v) > 0:
                first = v[0]
                if first is None or (isinstance(first, float) and pd.isna(first)):
                    return 0
                return int(first)
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
        """
        Extract features from IP addresses.
        
        Traffic direction (internal/external) is a valid behavioral signal.
        """
        features = pd.DataFrame(index=df.index)
        
        src_ip = df.get('src_ip', pd.Series(['0.0.0.0'] * len(df), index=df.index)).fillna('0.0.0.0')
        dest_ip = df.get('dest_ip', pd.Series(['0.0.0.0'] * len(df), index=df.index)).fillna('0.0.0.0')
        
        # Internal network detection (10.10.x.x = your VLANs)
        features['is_internal_src'] = src_ip.str.startswith('10.10.').astype(int)
        features['is_internal_dest'] = dest_ip.str.startswith('10.10.').astype(int)
        
        # RFC1918 detection (broader private ranges)
        def is_rfc1918(ip_series):
            return (
                ip_series.str.startswith('10.') |
                ip_series.str.startswith('172.16.') |
                ip_series.str.startswith('172.17.') |
                ip_series.str.startswith('172.18.') |
                ip_series.str.startswith('172.19.') |
                ip_series.str.startswith('172.20.') |
                ip_series.str.startswith('172.21.') |
                ip_series.str.startswith('172.22.') |
                ip_series.str.startswith('172.23.') |
                ip_series.str.startswith('172.24.') |
                ip_series.str.startswith('172.25.') |
                ip_series.str.startswith('172.26.') |
                ip_series.str.startswith('172.27.') |
                ip_series.str.startswith('172.28.') |
                ip_series.str.startswith('172.29.') |
                ip_series.str.startswith('172.30.') |
                ip_series.str.startswith('172.31.') |
                ip_series.str.startswith('192.168.')
            ).astype(int)
        
        features['is_private_src'] = is_rfc1918(src_ip)
        features['is_private_dest'] = is_rfc1918(dest_ip)
        
        # Traffic direction patterns
        features['is_internal_traffic'] = (
            features['is_internal_src'] & features['is_internal_dest']
        ).astype(int)
        features['is_inbound'] = (
            ~features['is_internal_src'].astype(bool) & features['is_internal_dest'].astype(bool)
        ).astype(int)
        features['is_outbound'] = (
            features['is_internal_src'].astype(bool) & ~features['is_internal_dest'].astype(bool)
        ).astype(int)
        
        # Localhost/multicast detection
        features['is_localhost'] = (
            src_ip.str.startswith('127.') | dest_ip.str.startswith('127.')
        ).astype(int)
        features['is_multicast'] = (
            dest_ip.str.startswith('224.') | dest_ip.str.startswith('239.')
        ).astype(int)
        
        return features
    
    def _extract_connection_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract connection rate features using rolling window approximation.

        These features detect:
        - Brute force: many connections to same dest in short time
        - Port scanning: many unique dest ports in short time
        - Host scanning / lateral movement: many unique dest IPs in short time
        """
        features = pd.DataFrame(index=df.index)

        timestamp_col = df.get('@timestamp', df.get('timestamp', None))
        dest_ip = df.get('dest_ip', pd.Series(['0.0.0.0'] * len(df), index=df.index)).fillna('0.0.0.0')
        dest_port = pd.to_numeric(df.get('dest_port', 0), errors='coerce').fillna(0).astype(int)
        src_ip = df.get('src_ip', pd.Series(['0.0.0.0'] * len(df), index=df.index)).fillna('0.0.0.0')

        if timestamp_col is not None and len(df) > 0:
            try:
                ts = pd.to_datetime(timestamp_col, errors='coerce', utc=True)

                # Create a temporary DataFrame for groupby operations
                tmp = pd.DataFrame({
                    'ts': ts,
                    'src_ip': src_ip.values,
                    'dest_ip': dest_ip.values,
                    'dest_port': dest_port.values
                }, index=df.index)

                # Sort by timestamp for rolling operations
                tmp = tmp.sort_values('ts')

                # Bin into 5-minute windows (approximation of rolling window)
                tmp['window'] = tmp['ts'].dt.floor('5min')

                # Connections to same dest in 5min (grouped by src, dest, window)
                conn_counts = tmp.groupby(['src_ip', 'dest_ip', 'window']).transform('size')
                features['connections_to_same_dest_5min'] = conn_counts.reindex(df.index).fillna(1).astype(int)

                # Unique dest ports in 5min (grouped by src, window)
                port_counts = tmp.groupby(['src_ip', 'window'])['dest_port'].transform('nunique')
                features['unique_dest_ports_5min'] = port_counts.reindex(df.index).fillna(1).astype(int)

                # Unique dest IPs in 5min (grouped by src, window)
                ip_counts = tmp.groupby(['src_ip', 'window'])['dest_ip'].transform('nunique')
                features['unique_dest_ips_5min'] = ip_counts.reindex(df.index).fillna(1).astype(int)

            except Exception as e:
                logger.warning(f"Could not extract connection features: {e}")
                features['connections_to_same_dest_5min'] = 1
                features['unique_dest_ports_5min'] = 1
                features['unique_dest_ips_5min'] = 1
        else:
            features['connections_to_same_dest_5min'] = 1
            features['unique_dest_ports_5min'] = 1
            features['unique_dest_ips_5min'] = 1

        return features

    def _extract_zeek_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from Zeek conn.log enrichment columns.

        ~31 features across 6 groups:
        - Duration (3): raw, log, has_match
        - Connection state (11): one-hot + aggregated indicators
        - History flags (5): length, data/reset/fin/partial indicators
        - Service (8): DPI-based classification + port mismatch
        - Byte overhead (4): IP overhead ratios, missed bytes

        All features handle missing Zeek data gracefully (NaN -> defaults).
        None of these features leak labels.
        """
        features = pd.DataFrame(index=df.index)

        has_zeek = 'zeek_uid' in df.columns
        has_match = df['zeek_uid'].notna() if has_zeek else pd.Series(False, index=df.index)

        # --- Duration (3 features) ---
        if has_zeek and 'zeek_duration' in df.columns:
            duration = pd.to_numeric(df['zeek_duration'], errors='coerce')
        else:
            duration = pd.Series(np.nan, index=df.index)

        features['zeek_duration'] = duration.fillna(-1)
        features['zeek_duration_log'] = np.log1p(duration.clip(lower=0)).fillna(0)
        features['zeek_has_match'] = has_match.astype(int)

        # --- Connection state one-hot (11 features) ---
        if has_zeek and 'zeek_conn_state' in df.columns:
            conn_state = df['zeek_conn_state'].fillna('')
        else:
            conn_state = pd.Series('', index=df.index)

        for state in ['S0', 'S1', 'SF', 'REJ', 'RSTO', 'RSTR', 'SH', 'OTH']:
            features[f'zeek_state_{state}'] = (conn_state == state).astype(int)

        features['zeek_state_is_normal'] = conn_state.isin(['SF', 'S1']).astype(int)
        features['zeek_state_is_scan'] = conn_state.isin(['S0', 'SH', 'SHR']).astype(int)
        features['zeek_state_is_rejected'] = conn_state.isin(['REJ', 'RSTO', 'RSTR']).astype(int)

        # --- History flags (5 features) ---
        if has_zeek and 'zeek_history' in df.columns:
            history = df['zeek_history'].fillna('')
        else:
            history = pd.Series('', index=df.index)

        features['zeek_history_len'] = history.str.len()
        features['zeek_history_has_data'] = history.str.contains('[Dd]', regex=True, na=False).astype(int)
        features['zeek_history_has_reset'] = history.str.contains('[Rr]', regex=True, na=False).astype(int)
        features['zeek_history_has_fin'] = history.str.contains('[Ff]', regex=True, na=False).astype(int)
        features['zeek_history_is_partial'] = (~history.str.contains('[Ss]', regex=True, na=False) & (history.str.len() > 0)).astype(int)

        # --- Service (8 features) ---
        if has_zeek and 'zeek_service' in df.columns:
            service = df['zeek_service'].fillna('').astype(str).str.lower()
        else:
            service = pd.Series('', index=df.index)

        for svc in ['http', 'ssl', 'ssh', 'dns', 'ftp', 'smtp']:
            features[f'zeek_service_is_{svc}'] = service.str.contains(svc, na=False).astype(int)

        features['zeek_service_known'] = ((service != '') & (service != '-') & (service != 'nan')).astype(int)

        # Port-service mismatch detection
        dest_port = pd.to_numeric(df.get('dest_port', 0), errors='coerce').fillna(0).astype(int)
        port_to_service = {
            80: 'http', 8080: 'http', 8000: 'http', 3000: 'http',
            443: 'ssl', 8443: 'ssl',
            22: 'ssh', 53: 'dns', 20: 'ftp', 21: 'ftp', 25: 'smtp'
        }
        expected_service = dest_port.map(port_to_service).fillna('')

        # Mismatch: port implies a service, Zeek identified a service, but they differ
        service_matches_expected = pd.Series(
            [exp == '' or exp in svc for svc, exp in zip(service, expected_service)],
            index=df.index
        )
        features['zeek_port_service_mismatch'] = (
            features['zeek_service_known'].astype(bool) &
            (expected_service != '') &
            ~service_matches_expected
        ).astype(int)

        # --- Byte overhead (4 features) ---
        if has_zeek:
            orig_bytes = pd.to_numeric(df.get('zeek_orig_bytes', 0), errors='coerce').fillna(0)
            resp_bytes = pd.to_numeric(df.get('zeek_resp_bytes', 0), errors='coerce').fillna(0)
            orig_ip_bytes = pd.to_numeric(df.get('zeek_orig_ip_bytes', 0), errors='coerce').fillna(0)
            resp_ip_bytes = pd.to_numeric(df.get('zeek_resp_ip_bytes', 0), errors='coerce').fillna(0)
            missed = pd.to_numeric(df.get('zeek_missed_bytes', 0), errors='coerce').fillna(0)
        else:
            orig_bytes = pd.Series(0, index=df.index)
            resp_bytes = pd.Series(0, index=df.index)
            orig_ip_bytes = pd.Series(0, index=df.index)
            resp_ip_bytes = pd.Series(0, index=df.index)
            missed = pd.Series(0, index=df.index)

        features['zeek_overhead_ratio_orig'] = (orig_ip_bytes - orig_bytes) / (orig_bytes + 1)
        features['zeek_overhead_ratio_resp'] = (resp_ip_bytes - resp_bytes) / (resp_bytes + 1)
        features['zeek_missed_bytes'] = missed
        features['zeek_has_missed_bytes'] = (missed > 0).astype(int)

        return features

    def _extract_protocol_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract protocol-specific traffic indicator features.
        """
        features = pd.DataFrame(index=df.index)

        dest_port = pd.to_numeric(df.get('dest_port', 0), errors='coerce').fillna(0).astype(int)

        features['is_smb_traffic'] = dest_port.isin([445, 139]).astype(int)
        features['is_dns_traffic'] = (dest_port == 53).astype(int)
        features['is_rdp_traffic'] = (dest_port == 3389).astype(int)
        features['is_snmp_traffic'] = dest_port.isin([161, 162]).astype(int)
        features['is_ftp_traffic'] = dest_port.isin([20, 21]).astype(int)

        return features

    def _extract_time_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract time-based features.
        
        Attack patterns often vary by time of day/week.
        """
        features = pd.DataFrame(index=df.index)
        
        timestamp_col = df.get('@timestamp', df.get('timestamp', None))
        
        if timestamp_col is not None:
            try:
                ts = pd.to_datetime(timestamp_col, errors='coerce')
                
                # Hour of day (attacks often happen at specific times)
                features['hour_of_day'] = ts.dt.hour.fillna(12).astype(int)
                
                # Day of week (0=Monday, 6=Sunday)
                features['day_of_week'] = ts.dt.dayofweek.fillna(0).astype(int)
                
                # Weekend flag
                features['is_weekend'] = (features['day_of_week'] >= 5).astype(int)
                
                # Business hours (9-17 local)
                features['is_business_hours'] = (
                    (features['hour_of_day'] >= 9) & (features['hour_of_day'] <= 17)
                ).astype(int)
                
                # Night time (22-06)
                features['is_night'] = (
                    (features['hour_of_day'] >= 22) | (features['hour_of_day'] <= 6)
                ).astype(int)
                
            except Exception as e:
                logger.warning(f"Could not extract time features: {e}")
                features['hour_of_day'] = 12
                features['day_of_week'] = 0
                features['is_weekend'] = 0
                features['is_business_hours'] = 1
                features['is_night'] = 0
        else:
            # No timestamp available
            features['hour_of_day'] = 12
            features['day_of_week'] = 0
            features['is_weekend'] = 0
            features['is_business_hours'] = 1
            features['is_night'] = 0
        
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
        logger.info("=" * 60)
        logger.info("Feature Engineering v2 (Leakage-Free)")
        logger.info("=" * 60)
        logger.info("EXCLUDED features: severity, signature_id (data leakage)")
        logger.info("INCLUDED features: network behavior, flow stats, timing, zeek conn")

        # Extract all feature groups
        network_features = self._extract_network_features(df)
        flow_features = self._extract_flow_features(df)
        derived_features = self._compute_derived_features(
            pd.concat([network_features, flow_features], axis=1)
        )
        categorical_features = self._encode_categorical_features(df, fit=True)
        ip_features = self._extract_ip_features(df)
        time_features = self._extract_time_features(df)
        connection_features = self._extract_connection_features(df)
        protocol_features = self._extract_protocol_features(df)
        zeek_features = self._extract_zeek_features(df)

        # Combine all features
        all_features = pd.concat([
            derived_features,
            categorical_features,
            ip_features,
            time_features,
            connection_features,
            protocol_features,
            zeek_features
        ], axis=1)
        
        # Remove any duplicate columns
        all_features = all_features.loc[:, ~all_features.columns.duplicated()]
        
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
        
        logger.info(f"\nExtracted {len(self.feature_names)} features")
        logger.info(f"Feature matrix shape: {X.shape}")
        logger.info("\nFeature categories:")
        logger.info(f"  - Network/Flow: bytes, packets, ports, ratios")
        logger.info(f"  - Categorical: protocol, direction, VLAN")
        logger.info(f"  - IP-based: internal/external, traffic direction")
        logger.info(f"  - Time-based: hour, day, business hours")
        logger.info(f"  - Connection rate: connections/5min, unique ports/IPs")
        logger.info(f"  - Protocol-specific: SMB, DNS, RDP, SNMP, FTP indicators")
        logger.info(f"  - Zeek conn: duration, conn_state, history, service, overhead")
        
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
        network_features = self._extract_network_features(df)
        flow_features = self._extract_flow_features(df)
        derived_features = self._compute_derived_features(
            pd.concat([network_features, flow_features], axis=1)
        )
        categorical_features = self._encode_categorical_features(df, fit=False)
        ip_features = self._extract_ip_features(df)
        time_features = self._extract_time_features(df)
        connection_features = self._extract_connection_features(df)
        protocol_features = self._extract_protocol_features(df)
        zeek_features = self._extract_zeek_features(df)

        # Combine
        all_features = pd.concat([
            derived_features,
            categorical_features,
            ip_features,
            time_features,
            connection_features,
            protocol_features,
            zeek_features
        ], axis=1)
        
        # Remove duplicates
        all_features = all_features.loc[:, ~all_features.columns.duplicated()]
        
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
        
        logger.info(f"\nLabels ({label_type}):")
        for cls, count in zip(*np.unique(y, return_counts=True)):
            logger.info(f"  {encoder.classes_[cls]}: {count:,}")
        
        return y, encoder
    
    def get_feature_groups(self) -> Dict[str, List[str]]:
        """Return features grouped by category for analysis."""
        groups = {
            'flow_stats': [f for f in self.feature_names if any(x in f for x in ['bytes', 'pkts', 'flow']) and not f.startswith('zeek_')],
            'port_based': [f for f in self.feature_names if ('port' in f or 'dest_is_' in f) and not f.startswith('zeek_')],
            'protocol': [f for f in self.feature_names if 'proto' in f and not f.startswith('zeek_')],
            'direction': [f for f in self.feature_names if 'direction' in f or 'bound' in f],
            'vlan': [f for f in self.feature_names if 'vlan' in f],
            'ip_based': [f for f in self.feature_names if ('internal' in f or 'private' in f or 'traffic' in f) and not f.startswith('zeek_')],
            'time_based': [f for f in self.feature_names if any(x in f for x in ['hour', 'day', 'weekend', 'business', 'night'])],
            'connection_rate': [f for f in self.feature_names if any(x in f for x in ['connections_to', 'unique_dest'])],
            'protocol_specific': [f for f in self.feature_names if any(x in f for x in ['is_smb', 'is_dns', 'is_rdp', 'is_snmp', 'is_ftp']) and not f.startswith('zeek_')],
            'zeek_conn': [f for f in self.feature_names if f.startswith('zeek_')]
        }
        return groups
    
    def save(self, path: str):
        """Save fitted state to disk."""
        import pickle
        
        state = {
            'label_encoders': self.label_encoders,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'config': self.config,
            '_fitted': self._fitted,
            'version': '2.0-leakage-free'
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
        logger.info(f"Version: {state.get('version', '1.0')}")
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
        # NOTE: These are NOT used as features anymore (leakage)
        'alert.severity': [2, 3, 1],
        'alert.signature_id': [2000001, 0, 9000001],
        # Flow data IS used
        'flow.bytes_toserver': [1500, 100, 50000],
        'flow.bytes_toclient': [5000, 200, 1000],
        'flow.pkts_toserver': [10, 2, 100],
        'flow.pkts_toclient': [20, 3, 5],
        '@timestamp': ['2026-01-27T10:30:00', '2026-01-27T14:00:00', '2026-01-27T23:00:00'],
        'label_binary': ['info', 'benign', 'attack']
    })
    
    print("\n" + "=" * 60)
    print("Testing FeatureEngineer v2 (Leakage-Free)")
    print("=" * 60)
    
    engineer = FeatureEngineer()
    X, feature_names = engineer.fit_transform(sample_data)
    
    print(f"\nFeature names ({len(feature_names)}):")
    for name in feature_names:
        print(f"  - {name}")
    
    # Verify leaky features are NOT present
    leaky = ['severity', 'signature_id']
    for leak in leaky:
        if leak in feature_names:
            print(f"\n⚠️  WARNING: Leaky feature '{leak}' still present!")
        else:
            print(f"\n✅ Confirmed: '{leak}' NOT in features (good!)")
    
    print(f"\nFeature matrix shape: {X.shape}")
    print(f"\nSample feature values:\n{X}")
