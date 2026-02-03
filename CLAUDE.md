# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SOC-ML is a supervised machine learning pipeline for threat detection in a HomeLab SOC v2 environment. It ingests Suricata alerts and network flow records from OpenSearch, enriches them with Zeek conn.log metadata via 5-tuple + timestamp correlation, engineers behavioral features, and trains an XGBoost binary classifier to distinguish attacks from noise/informational/benign traffic. A Purple Team attack framework generates ground-truth labeled training data.

**Environment:** sear (Kali Linux) on VLAN 20, Python 3.11, Conda

## Commands

### Environment Setup
```bash
./setup_sear.sh                    # First-time setup (creates conda env)
conda activate soc-ml              # Activate environment
pip install -r requirements.txt    # Install/update dependencies
cp .env.example .env               # Configure OpenSearch credentials
```

### Data Extraction
```bash
python -m src.data.extract \
  --train-start 2025-12-03 --train-end 2026-01-15 \
  --test-start 2026-01-16 --test-end 2026-01-27 \
  --max-alerts 500000 --max-flows 200000

# Without Zeek enrichment
python -m src.data.extract --no-zeek \
  --train-start 2025-12-03 --train-end 2026-01-15 \
  --test-start 2026-01-16 --test-end 2026-01-27
```

### Ground-Truth Extraction (with attack correlation)
```bash
python -m src.data.extract_with_attacks

# Without Zeek enrichment
python -m src.data.extract_with_attacks --no-zeek
```

### Model Training
```bash
python -m src.models.train --task binary
```

### Connectivity Test
```bash
python -m src.utils.opensearch
```

### Jupyter Notebooks
```bash
jupyter lab --ip=0.0.0.0 --port=8888
```
- `notebooks/01_model_training.ipynb` — primary training pipeline
- `notebooks/02_ground_truth_v2_training.ipynb` — ground-truth labeled training (current version)

### Attack Simulation (Purple Team)
```bash
cd attacks/
./run_attack.sh <attack_id> "description"   # Always use the wrapper for logging
sleep 300                                    # Wait for Suricata ingestion
python -m src.data.extract_with_attacks      # Extract with ground-truth labels
```

## Architecture

### Data Flow

```
OpenSearch (smokehouse @ 10.10.20.10:9200)
    |
SOCOpenSearchClient (src/utils/opensearch.py)
    |  scrolls & caches queries (Suricata alerts/flows + Zeek conn.log)
    |
ZeekEnricher (src/utils/zeek.py)
    |  left-joins Zeek conn.log onto Suricata via 5-tuple + timestamp (merge_asof, 2s tolerance)
    |
DataExtractor (src/data/extract.py)
    |  extracts alerts + flows, Zeek enrichment, labels binary, stratified sampling, temporal split
    |
AttackCorrelator (src/data/extract_with_attacks.py)  [optional]
    |  correlates traffic with attacks/attack_log.csv timestamps for ground-truth labels
    |
FeatureEngineer (src/data/features.py)
    |  70+ behavioral features: network, flow stats, derived ratios, categorical, IP, Zeek conn
    |
ModelTrainer (src/models/train.py)
    |  XGBoost with auto class weights, early stopping, threshold optimization, SHAP
    |
Trained Model → soc-automation integration (score >= 0.95 → block, >= 0.8 → alert)
```

### Key Design Decisions

- **Temporal train/test split** (not random) to prevent data leakage — train on data before 2026-01-16, test after
- **Behavioral features only** — severity and signature_id are excluded because Suricata sets severity=1 for attacks (leaks the label). Only network/flow/derived/Zeek features are used.
- **Zeek conn.log enrichment** — Suricata records are enriched with Zeek's conn_state, history, service DPI, duration, and byte overhead via 5-tuple + timestamp correlation. Adds ~31 features. Disabled with `--no-zeek`.
- **PR-AUC as primary metric** (not ROC-AUC) because the dataset is heavily imbalanced
- **Stratified sampling** balances classes: noise 50K, info 20K, benign 100K, attack all available
- **Configuration-driven** — all parameters in YAML configs under `config/`, environment variables override via `.env`

### Module Responsibilities

| Module | Class | Role |
|--------|-------|------|
| `src/utils/opensearch.py` | `SOCOpenSearchClient` | OpenSearch connection, scroll search, Zeek conn queries, aggregations |
| `src/utils/zeek.py` | `ZeekEnricher` | 5-tuple + timestamp correlation of Zeek conn.log onto Suricata records |
| `src/data/extract.py` | `DataExtractor` | Alert/flow extraction, Zeek enrichment, binary labeling, balanced datasets |
| `src/data/extract_with_attacks.py` | `AttackCorrelator` | Correlates traffic with `attack_log.csv` for ground-truth labels |
| `src/data/features.py` | `FeatureEngineer` | Feature engineering with fit/transform pattern (70+ features incl. Zeek) |
| `src/models/train.py` | `ModelTrainer` | XGBoost/RF/LR training, cross-validation, threshold optimization, SHAP |

Factory functions (`get_client()`, `get_extractor()`, `get_feature_engineer()`, `get_trainer()`) provide dependency injection.

### Configuration Files

- `config/opensearch.yaml` — connection, indices (`fluentbit-default`), query settings, date ranges, Zeek correlation settings
- `config/features.yaml` — label definitions (noise/info/attack signature patterns), feature specs (incl. Zeek conn), sampling strategy
- `config/model.yaml` — XGBoost/RF/LightGBM hyperparameters, evaluation metrics, SHAP settings, deployment thresholds

### Data Storage

- `data/raw/` — raw parquet extracts
- `data/processed/` — engineered feature datasets
- `data/splits/` — train/test parquet files
- `models/` — trained model artifacts (XGBoost JSON, sklearn pickle, metadata JSON)
- `results/` — metrics, plots, reports

### Attack Framework

Located in `attacks/`. All attacks MUST target VLAN 40 only (10.10.40.0/24). Always use `./run_attack.sh` wrapper to ensure logging to `attack_log.csv`. The log provides ground-truth labels with precise timestamps for correlation with Suricata alerts.

## Conventions

- No formal test suite or linter configured — validation is done via inline checks in notebooks and logging
- Modules are run as `python -m src.<module>` from the project root
- Model artifacts are saved with timestamp-based directory names (e.g., `xgboost_binary_20260127_120522/`)
- OpenSearch credentials must never be committed — use `.env` file (listed in `.gitignore`)
