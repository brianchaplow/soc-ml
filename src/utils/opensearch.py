"""
SOC-ML OpenSearch Client Utility
================================
Handles all interactions with OpenSearch for data extraction.

Author: Brian Chaplow (Chappy McNasty)
"""

import os
import logging
from typing import Optional, List, Dict, Any, Generator
from datetime import datetime

import pandas as pd
import yaml
from opensearchpy import OpenSearch, helpers
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SOCOpenSearchClient:
    """
    OpenSearch client for SOC ML data extraction.
    
    Handles connection management, scrolling through large datasets,
    and converting results to pandas DataFrames.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the client.
        
        Args:
            config_path: Path to opensearch.yaml config file
        """
        # Load config
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__), 
                '..', '..', 'config', 'opensearch.yaml'
            )
        
        self.config = self._load_config(config_path)
        
        # Initialize connection
        self.client = self._create_client()
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Substitute environment variables
            conn = config.get('connection', {})
            conn['host'] = os.getenv('OPENSEARCH_HOST', conn.get('host', 'localhost'))
            conn['port'] = int(os.getenv('OPENSEARCH_PORT', conn.get('port', 9200)))
            conn['user'] = os.getenv('OPENSEARCH_USER', conn.get('user', 'admin'))
            conn['password'] = os.getenv('OPENSEARCH_PASS', conn.get('password', ''))
            
            return config
            
        except Exception as e:
            logger.warning(f"Could not load config from {config_path}: {e}")
            # Return defaults
            return {
                'connection': {
                    'host': os.getenv('OPENSEARCH_HOST', 'localhost'),
                    'port': int(os.getenv('OPENSEARCH_PORT', 9200)),
                    'user': os.getenv('OPENSEARCH_USER', 'admin'),
                    'password': os.getenv('OPENSEARCH_PASS', ''),
                },
                'query': {
                    'scroll_size': 10000,
                    'scroll_timeout': '5m',
                    'max_records': 1000000,
                }
            }
    
    def _create_client(self) -> OpenSearch:
        """Create OpenSearch client connection."""
        conn = self.config.get('connection', {})
        
        client = OpenSearch(
            hosts=[{
                'host': conn.get('host', 'localhost'),
                'port': conn.get('port', 9200)
            }],
            http_auth=(conn.get('user', 'admin'), conn.get('password', '')),
            use_ssl=conn.get('use_ssl', True),
            verify_certs=conn.get('verify_certs', False),
            ssl_show_warn=conn.get('ssl_show_warn', False),
            timeout=conn.get('timeout', 60)
        )
        
        logger.info(f"OpenSearch client created: {conn.get('host')}:{conn.get('port')}")
        return client
    
    def test_connection(self) -> bool:
        """Test the OpenSearch connection."""
        try:
            info = self.client.info()
            logger.info(f"Connected to OpenSearch {info['version']['number']}")
            return True
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    def get_index_count(self, index: str, query: Optional[Dict] = None) -> int:
        """Get document count for an index."""
        try:
            body = {"query": query} if query else None
            result = self.client.count(index=index, body=body)
            return result['count']
        except Exception as e:
            logger.error(f"Error getting count for {index}: {e}")
            return 0
    
    def scroll_search(
        self,
        index: str,
        query: Dict[str, Any],
        source_fields: Optional[List[str]] = None,
        max_records: Optional[int] = None
    ) -> Generator[Dict, None, None]:
        """
        Scroll through search results yielding documents.
        
        Args:
            index: Index name
            query: OpenSearch query DSL
            source_fields: Fields to return (None = all)
            max_records: Maximum records to return
            
        Yields:
            Document _source dicts
        """
        query_config = self.config.get('query', {})
        scroll_size = query_config.get('scroll_size', 10000)
        scroll_timeout = query_config.get('scroll_timeout', '5m')
        
        if max_records is None:
            max_records = query_config.get('max_records', 1000000)
        
        body = {
            "query": query,
            "size": scroll_size
        }
        
        if source_fields:
            body["_source"] = source_fields
        
        try:
            # Initial search
            response = self.client.search(
                index=index,
                body=body,
                scroll=scroll_timeout
            )
            
            scroll_id = response['_scroll_id']
            hits = response['hits']['hits']
            total_yielded = 0
            
            while hits and total_yielded < max_records:
                for hit in hits:
                    if total_yielded >= max_records:
                        break
                    yield hit['_source']
                    total_yielded += 1
                
                if total_yielded >= max_records:
                    break
                    
                # Get next batch
                response = self.client.scroll(
                    scroll_id=scroll_id,
                    scroll=scroll_timeout
                )
                scroll_id = response['_scroll_id']
                hits = response['hits']['hits']
            
            # Clear scroll context
            self.client.clear_scroll(scroll_id=scroll_id)
            
            logger.info(f"Scroll complete: {total_yielded} documents retrieved")
            
        except Exception as e:
            logger.error(f"Scroll search error: {e}")
            raise
    
    def get_alerts(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        categories: Optional[List[str]] = None,
        signatures: Optional[List[str]] = None,
        max_records: Optional[int] = None,
        source_fields: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """
        Get Suricata alerts as a DataFrame.
        
        Args:
            start_date: Start date (ISO format)
            end_date: End date (ISO format)
            categories: Filter by alert categories
            signatures: Filter by specific signatures
            max_records: Maximum records to return
            source_fields: Fields to include
            
        Returns:
            DataFrame with alerts
        """
        # Build query
        must_clauses = [
            {"term": {"event_type": "alert"}}
        ]
        
        # Date range
        if start_date or end_date:
            date_range = {}
            if start_date:
                date_range["gte"] = start_date
            if end_date:
                date_range["lte"] = end_date
            must_clauses.append({"range": {"@timestamp": date_range}})
        
        # Category filter
        if categories:
            must_clauses.append({
                "terms": {"alert.category.keyword": categories}
            })
        
        # Signature filter
        if signatures:
            must_clauses.append({
                "terms": {"alert.signature.keyword": signatures}
            })
        
        query = {"bool": {"must": must_clauses}}
        
        # Default fields for alerts
        if source_fields is None:
            source_fields = [
                "@timestamp",
                "src_ip", "src_port",
                "dest_ip", "dest_port",
                "proto", "vlan", "direction",
                "alert.signature", "alert.signature_id",
                "alert.category", "alert.severity",
                "alert.action",
                "flow.bytes_toserver", "flow.bytes_toclient",
                "flow.pkts_toserver", "flow.pkts_toclient"
            ]
        
        # Collect records
        index = self.config.get('indices', {}).get('alerts', 'fluentbit-default')
        records = list(self.scroll_search(
            index=index,
            query=query,
            source_fields=source_fields,
            max_records=max_records
        ))
        
        if not records:
            logger.warning("No alerts found matching criteria")
            return pd.DataFrame()
        
        # Convert to DataFrame
        df = pd.json_normalize(records)
        logger.info(f"Retrieved {len(df)} alerts")
        
        return df
    
    def get_flows(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        max_records: Optional[int] = None,
        source_fields: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """
        Get Suricata flow records (non-alert traffic) as a DataFrame.
        
        Args:
            start_date: Start date (ISO format)
            end_date: End date (ISO format)
            max_records: Maximum records to return
            source_fields: Fields to include
            
        Returns:
            DataFrame with flows
        """
        # Build query
        must_clauses = [
            {"term": {"event_type": "flow"}}
        ]
        
        # Date range
        if start_date or end_date:
            date_range = {}
            if start_date:
                date_range["gte"] = start_date
            if end_date:
                date_range["lte"] = end_date
            must_clauses.append({"range": {"@timestamp": date_range}})
        
        query = {"bool": {"must": must_clauses}}
        
        # Default fields for flows
        if source_fields is None:
            source_fields = [
                "@timestamp",
                "src_ip", "src_port",
                "dest_ip", "dest_port",
                "proto", "vlan",
                "flow.bytes_toserver", "flow.bytes_toclient",
                "flow.pkts_toserver", "flow.pkts_toclient",
                "flow.state"
            ]
        
        # Collect records
        index = self.config.get('indices', {}).get('alerts', 'fluentbit-default')
        records = list(self.scroll_search(
            index=index,
            query=query,
            source_fields=source_fields,
            max_records=max_records
        ))
        
        if not records:
            logger.warning("No flows found matching criteria")
            return pd.DataFrame()
        
        # Convert to DataFrame
        df = pd.json_normalize(records)
        logger.info(f"Retrieved {len(df)} flows")
        
        return df
    
    def get_zeek_conn(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        max_records: Optional[int] = None,
        source_fields: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """
        Get Zeek conn.log records as a DataFrame.

        Queries for records where source=zeek and uid exists (conn.log indicator)
        but event_type does not exist (excludes Suricata records).

        Args:
            start_date: Start date (ISO format)
            end_date: End date (ISO format)
            max_records: Maximum records to return
            source_fields: Fields to include (defaults from config)

        Returns:
            DataFrame with Zeek conn records
        """
        must_clauses = [
            {"term": {"source": "zeek"}},
            {"exists": {"field": "uid"}}
        ]
        must_not_clauses = [
            {"exists": {"field": "event_type"}}
        ]

        if start_date or end_date:
            date_range = {}
            if start_date:
                date_range["gte"] = start_date
            if end_date:
                date_range["lte"] = end_date
            must_clauses.append({"range": {"@timestamp": date_range}})

        query = {
            "bool": {
                "must": must_clauses,
                "must_not": must_not_clauses
            }
        }

        if source_fields is None:
            zeek_config = self.config.get('zeek', {})
            source_fields = zeek_config.get('conn_fields', [
                "@timestamp", "uid",
                "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                "proto", "duration", "conn_state", "history", "service",
                "local_orig", "local_resp",
                "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
                "orig_ip_bytes", "resp_ip_bytes", "missed_bytes"
            ])

        index = self.config.get('indices', {}).get('alerts', 'fluentbit-default')
        records = list(self.scroll_search(
            index=index,
            query=query,
            source_fields=source_fields,
            max_records=max_records
        ))

        if not records:
            logger.warning("No Zeek conn records found matching criteria")
            return pd.DataFrame()

        df = pd.json_normalize(records)
        logger.info(f"Retrieved {len(df)} Zeek conn records")

        return df

    def get_aggregation(
        self,
        index: str,
        agg_field: str,
        query: Optional[Dict] = None,
        size: int = 100
    ) -> Dict[str, int]:
        """
        Get aggregation counts for a field.
        
        Args:
            index: Index name
            agg_field: Field to aggregate on (use .keyword for text)
            query: Optional filter query
            size: Number of buckets to return
            
        Returns:
            Dict mapping field values to counts
        """
        body = {
            "size": 0,
            "aggs": {
                "field_counts": {
                    "terms": {
                        "field": agg_field,
                        "size": size
                    }
                }
            }
        }
        
        if query:
            body["query"] = query
        
        try:
            response = self.client.search(index=index, body=body)
            buckets = response['aggregations']['field_counts']['buckets']
            return {b['key']: b['doc_count'] for b in buckets}
        except Exception as e:
            logger.error(f"Aggregation error: {e}")
            return {}


def get_client(config_path: Optional[str] = None) -> SOCOpenSearchClient:
    """Factory function to get OpenSearch client."""
    return SOCOpenSearchClient(config_path)


# =============================================================================
# CLI for testing
# =============================================================================
if __name__ == "__main__":
    client = get_client()
    
    if client.test_connection():
        print("✅ Connection successful!")
        
        # Show index counts
        print("\nIndex counts:")
        for event_type in ['alert', 'flow', 'http', 'dns']:
            count = client.get_index_count(
                'fluentbit-default',
                {"term": {"event_type": event_type}}
            )
            print(f"  {event_type}: {count:,}")

        # Zeek conn count
        zeek_count = client.get_index_count(
            'fluentbit-default',
            {"bool": {
                "must": [
                    {"term": {"source": "zeek"}},
                    {"exists": {"field": "uid"}}
                ],
                "must_not": [
                    {"exists": {"field": "event_type"}}
                ]
            }}
        )
        print(f"  zeek_conn: {zeek_count:,}")
    else:
        print("❌ Connection failed!")
