#!/bin/bash
###############################################################################
# POST-CAMPAIGN AUTOMATION
# Waits for 96h campaign to finish, then:
#   1. Extracts ground-truth labeled data
#   2. Retrains the ML model
#   3. Launches the 48h maximum noise campaign
#
# Run in tmux/screen: ./post_campaign_automation.sh
###############################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_FILE="$PROJECT_DIR/attacks/campaigns/automation_$(date +%Y%m%d_%H%M%S).log"

# Discord webhook
DISCORD_WEBHOOK="https://discord.com/api/webhooks/1450877041598795989/8rqAWCAOv718eA4kbRuHkBsUVmcjxXQCugeOAo7go53YC9Shl489HTQuGv7cwPN-IGxc"

# Campaign timing
CAMPAIGN_START="2026-02-02T12:26:39Z"
CAMPAIGN_DURATION_HOURS=96

# Conda environment
CONDA_ENV="soc-ml"

#=============================================================================
# LOGGING & NOTIFICATIONS
#=============================================================================

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" | tee -a "$LOG_FILE"
}

discord_notify() {
    local title="$1"
    local message="$2"
    local color="${3:-3447003}"  # Default blue, use 3066993 for green, 15158332 for red

    curl -s -H "Content-Type: application/json" \
        -X POST "$DISCORD_WEBHOOK" \
        -d "{
            \"embeds\": [{
                \"title\": \"$title\",
                \"description\": \"$message\",
                \"color\": $color,
                \"footer\": {\"text\": \"SOC-ML Automation | $(hostname)\"},
                \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
            }]
        }" > /dev/null 2>&1

    log "Discord notification sent: $title"
}

discord_error() {
    discord_notify "❌ Automation Error" "$1" 15158332
}

discord_success() {
    discord_notify "✅ $1" "$2" 3066993
}

discord_info() {
    discord_notify "ℹ️ $1" "$2" 3447003
}

#=============================================================================
# CAMPAIGN MONITORING
#=============================================================================

get_remaining_seconds() {
    local start_epoch=$(date -d "$CAMPAIGN_START" +%s)
    local end_epoch=$((start_epoch + CAMPAIGN_DURATION_HOURS * 3600))
    local now_epoch=$(date +%s)
    echo $((end_epoch - now_epoch))
}

format_duration() {
    local seconds=$1
    local hours=$((seconds / 3600))
    local mins=$(((seconds % 3600) / 60))
    echo "${hours}h ${mins}m"
}

wait_for_campaign() {
    log "=== Waiting for 96h campaign to complete ==="

    local remaining=$(get_remaining_seconds)

    if [[ $remaining -le 0 ]]; then
        log "Campaign already finished!"
        return 0
    fi

    log "Campaign ends in: $(format_duration $remaining)"
    discord_info "Campaign Monitor Started" "Waiting for **full_spectrum_96h** to complete.\n\nRemaining: **$(format_duration $remaining)**\n\nI'll notify you when extraction and retraining begin."

    # Check every 5 minutes
    while true; do
        remaining=$(get_remaining_seconds)

        if [[ $remaining -le 0 ]]; then
            log "Campaign completed!"
            break
        fi

        # Log progress every hour
        if [[ $((remaining % 3600)) -lt 300 ]]; then
            log "Campaign ends in: $(format_duration $remaining)"
        fi

        sleep 300  # Check every 5 minutes
    done

    # Wait an extra 5 minutes for any final attacks to complete
    log "Waiting 5 minutes for final attacks to finish..."
    sleep 300

    discord_success "Campaign Complete" "**full_spectrum_96h** has finished!\n\nStarting data extraction and model retraining pipeline..."
}

#=============================================================================
# DATA EXTRACTION
#=============================================================================

extract_data() {
    log "=== Extracting Ground-Truth Labeled Data ==="

    cd "$PROJECT_DIR"

    # Activate conda
    eval "$(conda shell.bash hook)"
    conda activate "$CONDA_ENV"

    discord_info "Data Extraction" "Extracting Suricata alerts with ground-truth labels from attack_log.csv...\n\nThis may take 10-15 minutes."

    # Run extraction with attack correlation
    local output_file="$PROJECT_DIR/data/processed/ground_truth_$(date +%Y%m%d).parquet"

    python -m src.data.extract_with_attacks \
        --start 2026-01-20 \
        --end 2026-02-07 \
        --max-alerts 500000 \
        --max-flows 100000 \
        --output "$output_file" \
        2>&1 | tee -a "$LOG_FILE"

    if [[ $? -ne 0 ]]; then
        discord_error "Data extraction failed! Check logs at $LOG_FILE"
        exit 1
    fi

    # Get stats
    local total_records=$(python -c "import pandas as pd; df=pd.read_parquet('$output_file'); print(len(df))" 2>/dev/null)
    local attack_records=$(python -c "import pandas as pd; df=pd.read_parquet('$output_file'); print(df['attack_confirmed'].sum())" 2>/dev/null)

    discord_success "Data Extraction Complete" "**Total records:** ${total_records}\n**Attack (ground-truth):** ${attack_records}\n\nOutput: \`$output_file\`"

    log "Extraction complete: $total_records records, $attack_records attacks"

    # Export the output file path for the training step
    echo "$output_file"
}

#=============================================================================
# MODEL TRAINING
#=============================================================================

train_model() {
    local data_file="$1"

    log "=== Training ML Model ==="

    cd "$PROJECT_DIR"

    # Activate conda
    eval "$(conda shell.bash hook)"
    conda activate "$CONDA_ENV"

    discord_info "Model Training" "Training XGBoost model on ground-truth labeled data...\n\nThis may take 15-30 minutes depending on dataset size."

    # Run training
    python -m src.models.train \
        --task binary \
        --input "$data_file" \
        2>&1 | tee -a "$LOG_FILE"

    if [[ $? -ne 0 ]]; then
        discord_error "Model training failed! Check logs at $LOG_FILE"
        exit 1
    fi

    # Find the latest model directory
    local model_dir=$(ls -td "$PROJECT_DIR/models/xgboost_binary_"* 2>/dev/null | head -1)

    if [[ -z "$model_dir" ]]; then
        discord_error "Could not find trained model directory"
        exit 1
    fi

    # Extract metrics from metadata
    local metrics=""
    if [[ -f "$model_dir/metadata.json" ]]; then
        metrics=$(python -c "
import json
with open('$model_dir/metadata.json') as f:
    m = json.load(f)
    test = m.get('test_metrics', {})
    print(f\"**PR-AUC:** {test.get('pr_auc', 'N/A'):.4f}\")
    print(f\"**ROC-AUC:** {test.get('roc_auc', 'N/A'):.4f}\")
    print(f\"**Precision:** {test.get('precision', 'N/A'):.4f}\")
    print(f\"**Recall:** {test.get('recall', 'N/A'):.4f}\")
    print(f\"**F1:** {test.get('f1', 'N/A'):.4f}\")
" 2>/dev/null)
    fi

    discord_success "Model Training Complete" "$metrics\n\nModel saved to:\n\`$model_dir\`"

    log "Training complete: $model_dir"

    echo "$model_dir"
}

#=============================================================================
# LAUNCH NEW CAMPAIGN
#=============================================================================

launch_noise_campaign() {
    log "=== Launching Maximum Noise 48h Campaign ==="

    cd "$PROJECT_DIR/attacks/campaigns"

    discord_info "Launching Campaign" "Starting **maximum_noise_48h** campaign...\n\nThis 48-hour campaign will generate high-signal training data with:\n- C2 simulation (Cobalt Strike, Meterpreter, etc.)\n- Cryptomining patterns\n- Protocol abuse\n- 83 attack functions"

    # Launch campaign in background
    nohup ./runner.sh --config configs/maximum_noise_48h.yaml \
        >> "$PROJECT_DIR/attacks/campaigns/noise_campaign_$(date +%Y%m%d).log" 2>&1 &

    local campaign_pid=$!

    sleep 10  # Wait for campaign to start

    # Verify it's running
    if ps -p $campaign_pid > /dev/null 2>&1; then
        discord_success "Campaign Launched" "**maximum_noise_48h** is now running!\n\n**PID:** $campaign_pid\n**Duration:** 48 hours\n**Ends:** $(date -d '+48 hours' '+%Y-%m-%d %H:%M %Z')\n\nMonitor with:\n\`tail -f $PROJECT_DIR/attacks/campaigns/noise_campaign_$(date +%Y%m%d).log\`"
        log "Campaign launched with PID $campaign_pid"
    else
        discord_error "Campaign failed to start! Check logs."
        exit 1
    fi
}

#=============================================================================
# MAIN
#=============================================================================

main() {
    log "=============================================="
    log "POST-CAMPAIGN AUTOMATION STARTED"
    log "=============================================="
    log "Log file: $LOG_FILE"

    # Step 1: Wait for campaign to finish
    wait_for_campaign

    # Step 2: Extract data
    local data_file=$(extract_data)

    # Step 3: Train model
    local model_dir=$(train_model "$data_file")

    # Step 4: Launch new campaign
    launch_noise_campaign

    log "=============================================="
    log "AUTOMATION COMPLETE"
    log "=============================================="

    discord_success "Automation Pipeline Complete" "All steps completed successfully!\n\n✅ Data extracted\n✅ Model retrained\n✅ 48h noise campaign launched\n\nNext steps:\n- Monitor campaign progress\n- Review model metrics\n- Plan next training iteration"
}

# Run main
main "$@"
