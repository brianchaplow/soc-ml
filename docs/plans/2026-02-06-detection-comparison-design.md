# Detection Comparison & Multi-Model Analysis System

**Author:** Brian Chaplow
**Date:** 2026-02-06
**Status:** Design Complete — Awaiting Implementation

---

## Problem Statement

After attack campaigns complete, we need to answer three questions:

1. **How does Suricata signature-based detection compare to ML model detection?**
2. **Which ML model type performs best on our IDS data?**
3. **How does detection improve as training data grows across campaigns?**

The existing `detection_comparison.py` compares a single XGBoost model against Suricata. This design expands it into a full multi-model research comparison framework with portfolio-quality reporting.

---

## Training Data Strategy

Three datasets form a progressive growth narrative:

| Dataset | Source | Expected Size | Attack Coverage |
|---------|--------|---------------|-----------------|
| Original | Early training runs | Small (~10K records) | Basic attack types |
| 96h Campaign | `full_campaign_96h.yaml` (CAMP-20260202-072638, 1,310 attacks) | Large (~500K records) | 11 phases, broad attack mix, AD attacks |
| 48h Aggressive | `maximum_noise_48h.yaml` (83+ attack functions) | Large | C2 simulation, cryptomining, protocol abuse, gap attacks |

**Approach:**

- Train individual models on each dataset for growth comparison
- Train final production model on combined (all three) dataset
- Temporal train/test split preserved throughout (no data leakage)
- PR-AUC remains the primary evaluation metric (imbalanced data)

The automation pipeline handles this automatically:

```
96h completes → extract → train all models (model set A) → compare(A)
48h completes → extract → train all models (model set B) → compare(B)
combine all data → train all models (model set C) → compare(A, B, C) → deploy best from C
```

---

## Architecture

### System Layers

```
train.py (--compare-all)          detection_comparison.py           report_generator.py
    |                                      |                              |
    +-- XGBoost                            |                              +-- Terminal tables
    +-- LightGBM                           |                              +-- JSON
    +-- RandomForest         <-- feeds --> | <-- compares all -->          +-- Discord digest
    +-- LogReg                             |     models + Suricata        +-- HTML report
    +-- KNN (new)                          |         |                       (Plotly + SHAP)
    +-- MLP (new)                          |         |
    +-- IsolationForest                    |         v
                                      Combined results JSON
```

**Separation of concerns:**

- `train.py` trains models and saves artifacts
- `detection_comparison.py` analyzes detection accuracy across all models + Suricata
- `report_generator.py` produces all output formats from the combined JSON

### File Layout

```
soc-ml/
+-- src/
|   +-- models/
|   |   +-- train.py                  # Extended: +KNN, +MLP
|   |   +-- mlp.py                    # New: PyTorch MLP model class
|   +-- analysis/
|       +-- detection_comparison.py   # Refactored: multi-model support
|       +-- report_generator.py       # New: all output formatters
+-- results/
|   +-- comparison/
|       +-- detection_comparison_{timestamp}.json
|       +-- report_{timestamp}.html
+-- models/
    +-- xgboost_binary_{timestamp}/
    +-- lightgbm_binary_{timestamp}/
    +-- random_forest_binary_{timestamp}/
    +-- logistic_regression_binary_{timestamp}/
    +-- knn_binary_{timestamp}/
    +-- mlp_binary_{timestamp}/
    +-- isolation_forest_binary_{timestamp}/
```

---

## Component Details

### 1. Model Training Extensions (train.py)

#### KNN (new)

- Scikit-learn `KNeighborsClassifier`
- StandardScaler pipeline required (features have different ranges: byte counts vs ratios)
- `algorithm='ball_tree'` for 500K+ row scalability
- `n_neighbors` tuned via existing Optuna `--tune` path
- Saves `scaler.pkl` + `model.pkl` to timestamped directory

#### MLP (new — mlp.py)

- PyTorch feedforward network
- Architecture: `Input(70+) -> 256 -> 128 -> 64 -> 1`
- ReLU activations, BatchNorm between layers, Dropout(0.3)
- Binary cross-entropy loss with class weights (handles imbalance)
- Trains on GPU (`cuda:0` — GTX 1650 Ti on sear), falls back to CPU
- Early stopping on validation PR-AUC (consistent with primary metric)
- Saves `model.pt` + `scaler.pkl` + `architecture.json`

#### Existing Models (unchanged)

- XGBoost, LightGBM, RandomForest, LogisticRegression, IsolationForest
- All continue to use the same feature engineering pipeline (70+ features)
- All continue to use temporal train/test split
- Model artifact directory pattern: `{model_type}_binary_{timestamp}/`

#### --compare-all Flag

Trains all 7 models sequentially. MLP uses GPU while CPU models could theoretically run in parallel, but sequential is simpler and total training time is ~45 min.

---

### 2. Detection Comparison Refactor (detection_comparison.py)

#### Current Classes (preserved)

- `SuricataAnalyzer` — signature detection accuracy against ground truth
- `MLModelAnalyzer` — single model prediction accuracy
- `DetectionComparator` — single model vs Suricata

#### New Class: MultiModelComparator

Orchestrates the full comparison:

```
MultiModelComparator
  +-- SuricataAnalyzer (unchanged, runs once)
  +-- MLModelAnalyzer x N (one per model type)
  +-- DetectionComparator x N (each model vs Suricata)
  +-- CrossModelAnalyzer (new)
```

#### New Class: CrossModelAnalyzer

Answers cross-model questions:

| Analysis | Description |
|----------|-------------|
| Consensus matrix | Per-attack: how many of N models detected it (0 through N) |
| Unique catches | Attacks only one specific model detects |
| Blind spots | Attacks evading ALL models + Suricata |
| Agreement heatmap | Pairwise agreement rates between all models (N x N matrix) |
| Category x Model matrix | Detection rate for each attack category across each model |
| Rankings | Models ranked by PR-AUC, recall, precision, F1 with winner per metric |

#### CLI Changes

```bash
# Single model (backwards compatible)
python -m src.analysis.detection_comparison \
  --data ground_truth.parquet \
  --model models/xgboost_binary_*/

# Multi-model comparison
python -m src.analysis.detection_comparison \
  --data ground_truth.parquet \
  --model-dir models/ \
  --all-models

# Progressive comparison across datasets
python -m src.analysis.detection_comparison \
  --data ground_truth_96h.parquet ground_truth_48h.parquet ground_truth_combined.parquet \
  --model-dir models/ \
  --all-models \
  --progressive
```

The `--progressive` flag compares the same model type across different dataset sizes for the growth narrative.

#### Output JSON Structure

```json
{
  "metadata": {
    "data_path": "...",
    "model_dir": "...",
    "threshold": 0.5,
    "total_records": 487231,
    "attack_records": 12847,
    "models_compared": ["xgboost", "lightgbm", "random_forest", "logistic_regression", "knn", "mlp", "isolation_forest"]
  },
  "suricata": {
    "detection_rates": {},
    "signature_performance": [],
    "category_performance": {},
    "false_positives": {},
    "missed_attacks": {}
  },
  "models": {
    "xgboost": {
      "detection_rates": {},
      "category_performance": {},
      "confidence_distribution": {},
      "threshold_analysis": [],
      "missed_attacks": {},
      "false_positives": {},
      "shap_top_features": []
    },
    "lightgbm": { "..." : "..." },
    "random_forest": { "..." : "..." },
    "logistic_regression": { "..." : "..." },
    "knn": { "..." : "..." },
    "mlp": { "..." : "..." },
    "isolation_forest": { "..." : "..." }
  },
  "cross_model": {
    "consensus_matrix": {},
    "agreement_heatmap": {},
    "category_model_matrix": {},
    "unique_catches": {},
    "blind_spots": {},
    "rankings": {}
  },
  "progressive": {
    "original": { "best_model": "xgboost", "pr_auc": 0.72, "models": {} },
    "96h": { "best_model": "xgboost", "pr_auc": 0.86, "models": {} },
    "48h": { "best_model": "mlp", "pr_auc": 0.89, "models": {} },
    "combined": { "best_model": "xgboost", "pr_auc": 0.93, "models": {} }
  },
  "recommendations": []
}
```

---

### 3. Report Generator (report_generator.py)

#### Terminal Tables

Enhanced `_print_summary()` using `tabulate` for multi-model output:

```
Model Rankings (by PR-AUC)
------------------------------------------------------
  #   Model              PR-AUC   Recall   Precision   F1
  1   XGBoost             0.912    0.887     0.834    0.860
  2   LightGBM            0.905    0.879     0.841    0.860
  3   MLP                 0.891    0.902     0.798    0.847
  ...
  *   Suricata (rules)      --     0.743     0.921    0.822

Category x Model Detection Rates (%)
------------------------------------------------------
  Category        Suricata  XGB   LGBM   RF   MLP   KNN
  sql_injection      94.2  91.3  90.1  88.7  89.4  82.1
  c2_simulation       0.0  67.3  64.1  41.2  78.9  55.3
  brute_force        88.1  95.7  94.2  93.8  91.0  90.4
```

#### JSON

The full output structure from Section 2 above. Saved to `results/comparison/detection_comparison_{timestamp}.json`.

#### Discord Digest

Single embed posted to the existing webhook:

- Winner model + key metrics (PR-AUC, recall, precision)
- Biggest category gaps between Suricata and best ML model
- Blind spot count (attacks evading everything)
- One-liner per model: `XGBoost: 88.7% recall | MLP: 90.2% recall | Suricata: 74.3% recall`

Designed to be scannable on mobile.

#### HTML Report (portfolio-quality)

Self-contained single HTML file. Plotly.js embedded (no CDN dependency). Dark cybersecurity theme. Nav sidebar for section jumping. All charts interactive (hover/zoom).

**9 visualizations:**

| # | Chart | Type | Purpose |
|---|-------|------|---------|
| 1 | Model Radar | Radar chart | All models + Suricata on axes: Recall, Precision, F1, PR-AUC, FP Rate |
| 2 | Category Heatmap | Heatmap | Detection rate per category per model, color-coded green to red |
| 3 | Agreement Heatmap | Heatmap | Pairwise model agreement (N x N grid + Suricata) |
| 4 | Consensus Bars | Stacked bar | Per-attack: how many detectors caught it (all, most, few, none) |
| 5 | PR Curves | Line overlay | Precision-recall curves for each ML model |
| 6 | Progressive Growth | Line chart | PR-AUC across dataset sizes (original, 96h, 48h, combined) |
| 7 | Confusion Matrices | Small multiples | One confusion matrix per model, side by side |
| 8 | SHAP Beeswarm | Beeswarm per model | Top 20 features driving predictions, one plot per model |
| 9 | SHAP Comparison | Grouped bar | Top 10 features ranked by mean |SHAP| across all models — shows if models use the same signals |

**SHAP implementation notes:**

- Tree-based models (XGBoost, LightGBM, RF): `shap.TreeExplainer` (fast)
- MLP, LogReg: `shap.DeepExplainer` or `shap.LinearExplainer`
- KNN: `shap.KernelExplainer` on a sampled subset (~1000 rows) due to computational cost
- IsolationForest: `shap.TreeExplainer` (supported)
- Beeswarm plots rendered via matplotlib, embedded as base64 images in the HTML

---

### 4. Post-Campaign Automation Integration (post_campaign_automation.sh)

#### Current Flow

```
Step 1: Wait for campaign completion
Step 2: Extract ground-truth data
Step 3: Train XGBoost model
Step 4: Launch next campaign
```

#### New Flow

```
Step 1: Wait for campaign completion
Step 2: Extract ground-truth data
Step 3: Train ALL models (--compare-all)
Step 4: Run detection comparison (--all-models)
Step 5: Generate reports (terminal + JSON + Discord + HTML)
Step 6: Launch next campaign
```

#### Integration Details

- Steps 4-5 are **non-blocking**: if they fail, Step 6 still runs
- Discord notification at each step (success or failure)
- HTML report saves to `results/comparison/report_{timestamp}.html`
- `--progressive` runs automatically when multiple ground-truth parquets exist in `data/processed/`

#### Timing Estimate

| Step | Duration |
|------|----------|
| Extract | ~10 min |
| Train 7 models | ~45 min (MLP on GPU, rest on CPU) |
| SHAP values (all models) | ~15 min |
| Detection comparison + report | ~5 min |
| **Total pipeline** | **~75 min** |

75-minute gap between campaign end and next campaign launch is acceptable.

---

## Suricata Custom Rules Verification

Verified all 10 custom HOMELAB rules (SID 9000001-9000021). All use `any any -> any any` addressing:

```
alert http any any -> any any (msg:"HOMELAB ..."; ...)
```

This is **correct** for the purple team lab. If rules used `$EXTERNAL_NET -> $HOME_NET`, internal attacks from sear (10.10.20.20, VLAN 20) to targets (10.10.40.x, VLAN 40) would be invisible because both networks fall within HOME_NET (10.0.0.0/8).

The `any any` pattern ensures all HTTP traffic on the SPAN port is inspected regardless of source/destination, which is the desired behavior for internal attack detection.

No changes needed.

---

## Dependencies

### Existing

- pandas, numpy, scikit-learn, xgboost, lightgbm, shap
- OpenSearch Python client, fluent-bit

### New

| Package | Purpose | Install |
|---------|---------|---------|
| torch | MLP neural network | `conda install pytorch torchvision -c pytorch` (GPU build) |
| plotly | Interactive HTML charts | `pip install plotly` |
| tabulate | Terminal table formatting | `pip install tabulate` |
| kaleido | Plotly static image export (optional) | `pip install kaleido` |

All other dependencies (matplotlib for SHAP beeswarms, etc.) are already installed.

---

## Implementation Order

1. **mlp.py** — PyTorch MLP model class (standalone, no dependencies on other changes)
2. **train.py** — Add KNN and MLP to `--compare` flow
3. **detection_comparison.py** — Refactor: `MultiModelComparator`, `CrossModelAnalyzer`
4. **report_generator.py** — Terminal tables, JSON, Discord digest, HTML+Plotly+SHAP
5. **post_campaign_automation.sh** — Insert comparison and reporting steps
6. **End-to-end test** — Run against 96h campaign data once extracted

---

## Success Criteria

- All 7 models train without error on ground-truth data
- MLP trains on GPU (cuda:0) with fallback to CPU
- detection_comparison.py produces valid JSON with all cross-model metrics
- HTML report renders all 9 visualizations with interactive Plotly charts
- SHAP beeswarm plots generate for all model types
- Discord digest posts a readable summary
- Post-campaign automation runs the full pipeline unattended
- Progressive comparison shows growth across dataset sizes
- Total pipeline completes in under 90 minutes
