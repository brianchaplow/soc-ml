# SOC-ML: Machine Learning for HomeLab SOC

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.0+-green.svg)](https://xgboost.readthedocs.io/)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-2.x-orange.svg)](https://opensearch.org/)

Machine learning threat detection for the HomeLab SOC v2 infrastructure.

**Author:** Brian Chaplow (Chappy McNasty)  
**Environment:** sear (Kali Linux) on VLAN 20

---

## Overview

This project implements supervised machine learning for threat detection using data from the HomeLab SOC:

- **13M+ Suricata alerts** with custom HOMELAB rules
- **12.6M+ flow records** as benign baseline
- **XGBoost classifier** optimized for imbalanced data
- **SHAP interpretability** for understanding predictions

### Key Features

- ✅ Proper temporal train/test split (no data leakage)
- ✅ Class balancing via stratified sampling
- ✅ PR-AUC metric (appropriate for imbalanced data)
- ✅ Threshold optimization for deployment
- ✅ SHAP analysis for interpretability
- ✅ Integration-ready for SOC automation

---

## Quick Start

### 1. Setup Environment (on sear)

```bash
# Clone/copy project to sear
scp -r soc-ml/ butcher@10.10.20.20:~/

# SSH to sear
ssh butcher@10.10.20.20

# Run setup script
cd ~/soc-ml
chmod +x setup_sear.sh
./setup_sear.sh

# Configure credentials
cp .env.example .env
nano .env  # Add your OpenSearch password
```

### 2. Activate Environment

```bash
conda activate soc-ml
```

### 3. Run Training Notebook

```bash
cd ~/soc-ml
jupyter lab --ip=0.0.0.0 --port=8888
```

Open `notebooks/01_model_training.ipynb` in your browser.

---

## Project Structure

```
soc-ml/
├── config/
│   ├── opensearch.yaml     # OpenSearch connection
│   ├── features.yaml       # Feature definitions & labels
│   └── model.yaml          # Model hyperparameters
├── src/
│   ├── data/
│   │   ├── extract.py      # OpenSearch data extraction
│   │   └── features.py     # Feature engineering
│   ├── models/
│   │   └── train.py        # Model training & evaluation
│   └── utils/
│       └── opensearch.py   # OpenSearch client
├── notebooks/
│   └── 01_model_training.ipynb
├── models/                  # Saved models
├── data/                    # Cached datasets
├── results/                 # Metrics, plots
├── setup_sear.sh           # Environment setup
└── requirements.txt
```

---

## Data Pipeline

### Labels

Data is classified into three categories:

| Label | Description | Examples |
|-------|-------------|----------|
| **noise** | Protocol anomalies (not threats) | STREAM errors, Ethertype unknown |
| **info** | Informational (benign) | ET INFO, DNS lookups |
| **attack** | Security threats | HOMELAB rules, ET EXPLOIT |

### Features

| Category | Features |
|----------|----------|
| Network | src_port, dest_port, proto, direction |
| Flow Stats | bytes_toserver/toclient, pkts_toserver/toclient |
| Derived | bytes_ratio, is_privileged_port, is_internal |
| VLAN | vlan_10, vlan_20, vlan_30, vlan_40, vlan_50 |

---

## Model Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SOC-ML Pipeline                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   OpenSearch ──→ Extraction ──→ Features ──→ XGBoost       │
│       │              │             │            │           │
│       ▼              ▼             ▼            ▼           │
│   13M alerts    Temporal      35+ features   Binary         │
│   12M flows     Split         Engineered     Classifier     │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                    Output                           │   │
│   ├─────────────────────────────────────────────────────┤   │
│   │  • Threat probability score (0-1)                   │   │
│   │  • Optimized threshold for deployment               │   │
│   │  • SHAP explanations per prediction                 │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration

### OpenSearch Connection

Edit `config/opensearch.yaml` or set environment variables:

```bash
export OPENSEARCH_HOST=10.10.20.10
export OPENSEARCH_PORT=9200
export OPENSEARCH_USER=admin
export OPENSEARCH_PASS=your_password
```

### Model Hyperparameters

Edit `config/model.yaml`:

```yaml
xgboost:
  binary:
    n_estimators: 500
    max_depth: 8
    learning_rate: 0.05
    scale_pos_weight: auto  # Handles imbalance
```

---

## Usage

### Command Line

```bash
# Extract data
python -m src.data.extract --train-start 2025-12-03 --train-end 2026-01-15

# Train model (after extraction)
python -m src.models.train --task binary
```

### Python API

```python
from src.data.extract import get_extractor
from src.data.features import get_feature_engineer
from src.models.train import get_trainer

# Extract
extractor = get_extractor()
train_df, test_df = extractor.extract_and_prepare()

# Feature engineering
engineer = get_feature_engineer()
X_train, feature_names = engineer.fit_transform(train_df)
X_test = engineer.transform(test_df)

# Train
trainer = get_trainer()
model = trainer.train_xgboost(X_train, y_train)
metrics = trainer.evaluate(X_test, y_test)
```

---

## Integration with SOC Automation

The trained model can be integrated with the existing `soc-automation` container:

```python
# In autoblock.py or enrichment.py
from soc_ml import load_model, predict

# Load model
model = load_model('/path/to/model')

# Score new traffic
score = model.predict_proba(features)[0, 1]

if score >= 0.95:
    # High confidence attack - auto-block
    block_ip(ip)
elif score >= 0.8:
    # Suspicious - alert
    send_discord_alert(ip, score)
```

---

## Results

### Metrics (Example)

| Metric | Value |
|--------|-------|
| PR-AUC | TBD |
| ROC-AUC | TBD |
| Precision | TBD |
| Recall | TBD |

### Top Features

1. TBD (after training)
2. TBD
3. TBD

---

## Troubleshooting

### OpenSearch Connection Failed

```bash
# Test connectivity from sear
curl -sk -u admin 'https://10.10.20.10:9200/_cluster/health?pretty'
```

### Out of Memory

Reduce data volume in extraction:

```python
extractor.extract_and_prepare(max_alerts=100000, max_flows=50000)
```

### GPU Not Detected

```python
# Check GPU availability
import xgboost as xgb
print(xgb.build_info())  # Look for GPU support
```

---

## References

- [XGBoost Documentation](https://xgboost.readthedocs.io/)
- [SHAP Documentation](https://shap.readthedocs.io/)
- [HomeLab SOC v2](https://github.com/brianchaplow/HomeLab-SOC-v2)

---

## License

MIT License - See LICENSE file
