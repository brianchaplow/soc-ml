#!/bin/bash
# =============================================================================
# SOC-ML Project Setup Script for sear (Kali Linux)
# Author: Brian Chaplow (Chappy McNasty)
# Purpose: Initialize ML environment for HomeLab SOC threat detection
# =============================================================================

set -e

echo "=============================================="
echo "  SOC-ML Environment Setup"
echo "  Target: sear (Kali Linux)"
echo "=============================================="

# Project directory
PROJECT_DIR="${HOME}/soc-ml"
mkdir -p "${PROJECT_DIR}"
cd "${PROJECT_DIR}"

# Create directory structure
echo "[1/6] Creating directory structure..."
mkdir -p {config,src/{data,models,utils},notebooks,models,data/{raw,processed,splits},results/{metrics,plots,reports},logs}

# Create __init__.py files
touch src/__init__.py
touch src/data/__init__.py
touch src/models/__init__.py
touch src/utils/__init__.py

# Check for conda/mamba
echo "[2/6] Setting up Python environment..."
if command -v mamba &> /dev/null; then
    CONDA_CMD="mamba"
elif command -v conda &> /dev/null; then
    CONDA_CMD="conda"
else
    echo "Neither conda nor mamba found. Installing miniconda..."
    wget -q https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O /tmp/miniconda.sh
    bash /tmp/miniconda.sh -b -p "${HOME}/miniconda3"
    eval "$(${HOME}/miniconda3/bin/conda shell.bash hook)"
    CONDA_CMD="conda"
fi

# Create conda environment
echo "[3/6] Creating soc-ml conda environment..."
$CONDA_CMD create -n soc-ml python=3.11 -y || true
eval "$($CONDA_CMD shell.bash hook)"
conda activate soc-ml

# Install core packages
echo "[4/6] Installing Python packages..."
pip install --upgrade pip

# Core ML stack
pip install \
    numpy>=1.24.0 \
    pandas>=2.0.0 \
    scikit-learn>=1.3.0 \
    xgboost>=2.0.0 \
    lightgbm>=4.0.0 \
    shap>=0.43.0

# Data handling
pip install \
    opensearch-py>=2.4.0 \
    pyarrow>=14.0.0 \
    pyyaml>=6.0

# Visualization
pip install \
    matplotlib>=3.7.0 \
    seaborn>=0.12.0 \
    plotly>=5.17.0

# Jupyter
pip install \
    jupyterlab>=4.0.0 \
    ipywidgets>=8.0.0

# Utilities
pip install \
    tqdm>=4.66.0 \
    python-dotenv>=1.0.0 \
    rich>=13.0.0

# Optional: GPU support for XGBoost (if CUDA available)
if command -v nvidia-smi &> /dev/null; then
    echo "[4b/6] NVIDIA GPU detected, XGBoost will use GPU acceleration"
    # XGBoost pip package includes GPU support
fi

# Create requirements.txt for reproducibility
echo "[5/6] Creating requirements.txt..."
cat > "${PROJECT_DIR}/requirements.txt" << 'EOF'
# SOC-ML Requirements
# Generated: $(date)
# Environment: sear (Kali Linux)

# Core ML
numpy>=1.24.0
pandas>=2.0.0
scikit-learn>=1.3.0
xgboost>=2.0.0
lightgbm>=4.0.0
shap>=0.43.0

# Data Sources
opensearch-py>=2.4.0
pyarrow>=14.0.0
pyyaml>=6.0

# Visualization
matplotlib>=3.7.0
seaborn>=0.12.0
plotly>=5.17.0

# Jupyter
jupyterlab>=4.0.0
ipywidgets>=8.0.0

# Utilities
tqdm>=4.66.0
python-dotenv>=1.0.0
rich>=13.0.0
EOF

# Create .env template
echo "[6/6] Creating configuration templates..."
cat > "${PROJECT_DIR}/.env.example" << 'EOF'
# SOC-ML Environment Variables
# Copy to .env and fill in values

# OpenSearch Connection (smokehouse)
OPENSEARCH_HOST=10.10.20.10
OPENSEARCH_PORT=9200
OPENSEARCH_USER=admin
OPENSEARCH_PASS=your_password_here

# Paths
DATA_DIR=/home/butcher/soc-ml/data
MODELS_DIR=/home/butcher/soc-ml/models
RESULTS_DIR=/home/butcher/soc-ml/results
EOF

echo ""
echo "=============================================="
echo "  Setup Complete!"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. Copy .env.example to .env and add your OpenSearch password"
echo "  2. Activate environment: conda activate soc-ml"
echo "  3. Start Jupyter: jupyter lab --ip=0.0.0.0 --port=8888"
echo ""
echo "Project structure created at: ${PROJECT_DIR}"
echo ""
