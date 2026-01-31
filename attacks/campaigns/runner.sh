#!/bin/bash
###############################################################################
# Campaign Runner — Master Orchestrator
#
# Usage:
#   ./runner.sh --config configs/full_campaign_72h.yaml
#   ./runner.sh --config configs/quick_campaign_4h.yaml --dry-run
#   ./runner.sh --resume state/CAMP-20260131-120000.state
#   ./runner.sh --stop state/CAMP-20260131-120000.state
###############################################################################

set -euo pipefail

CAMPAIGNS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKS_DIR="$(dirname "$CAMPAIGNS_DIR")"
RUN_ATTACK="${ATTACKS_DIR}/run_attack.sh"

# Source helpers
source "${CAMPAIGNS_DIR}/state.sh"
source "${CAMPAIGNS_DIR}/scheduler.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

###############################################################################
# Argument Parsing
###############################################################################

CONFIG_FILE=""
RESUME_FILE=""
DRY_RUN=false
STOP_FILE=""
DURATION_OVERRIDE=""

print_usage() {
    echo "Usage: $(basename "$0") [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --config <file>            Campaign YAML config file"
    echo "  --resume <state_file>      Resume from saved state"
    echo "  --stop <state_file>        Request graceful stop of running campaign"
    echo "  --dry-run                  Show what would execute without running"
    echo "  --duration-override <hrs>  Override campaign duration (hours)"
    echo "  -h, --help                 Show this help"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --resume)
            RESUME_FILE="$2"
            shift 2
            ;;
        --stop)
            STOP_FILE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --duration-override)
            DURATION_OVERRIDE="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

###############################################################################
# Stop command
###############################################################################

if [[ -n "$STOP_FILE" ]]; then
    if [[ ! -f "$STOP_FILE" ]]; then
        echo -e "${RED}State file not found: $STOP_FILE${NC}"
        exit 1
    fi
    echo -e "${YELLOW}Requesting graceful stop...${NC}"
    state_request_pause "$STOP_FILE"
    state_summary "$STOP_FILE"
    exit 0
fi

###############################################################################
# Validate inputs
###############################################################################

if [[ -n "$RESUME_FILE" ]]; then
    if [[ ! -f "$RESUME_FILE" ]]; then
        echo -e "${RED}State file not found: $RESUME_FILE${NC}"
        exit 1
    fi
    CONFIG_FILE=$(state_read "$RESUME_FILE" "config_file")
    echo -e "${CYAN}Resuming campaign from: $RESUME_FILE${NC}"
    state_summary "$RESUME_FILE"
fi

if [[ -z "$CONFIG_FILE" ]]; then
    echo -e "${RED}No config file specified. Use --config or --resume${NC}"
    print_usage
    exit 1
fi

# Resolve config path — try multiple locations
if [[ ! "$CONFIG_FILE" = /* ]]; then
    if [[ -f "${CAMPAIGNS_DIR}/${CONFIG_FILE}" ]]; then
        CONFIG_FILE="${CAMPAIGNS_DIR}/${CONFIG_FILE}"
    elif [[ -f "${ATTACKS_DIR}/${CONFIG_FILE}" ]]; then
        CONFIG_FILE="${ATTACKS_DIR}/${CONFIG_FILE}"
    else
        CONFIG_FILE="${CAMPAIGNS_DIR}/${CONFIG_FILE}"
    fi
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${RED}Config file not found: $CONFIG_FILE${NC}"
    exit 1
fi

###############################################################################
# Campaign Initialization
###############################################################################

CAMPAIGN_NAME=$(get_campaign_name "$CONFIG_FILE")
DURATION_HOURS=$(get_campaign_duration "$CONFIG_FILE")
if [[ -n "$DURATION_OVERRIDE" ]]; then
    DURATION_HOURS="$DURATION_OVERRIDE"
fi

TOTAL_PHASES=$(python3 -c "
import yaml
with open('$CONFIG_FILE') as f:
    config = yaml.safe_load(f)
print(len(config.get('phases', [1])))
")

# Create or resume state
if [[ -n "$RESUME_FILE" ]]; then
    STATE_FILE="$RESUME_FILE"
    state_update "$STATE_FILE" "status" "running"
    state_update "$STATE_FILE" "pause_requested" "false"
    CAMPAIGN_ID=$(state_read "$STATE_FILE" "campaign_id")
else
    CAMPAIGN_ID="CAMP-$(date +%Y%m%d-%H%M%S)"
    STATE_FILE=$(state_create "$CAMPAIGN_ID" "$CONFIG_FILE" "$TOTAL_PHASES")
fi

START_EPOCH=$(date +%s)
END_EPOCH=$(( START_EPOCH + DURATION_HOURS * 3600 ))

###############################################################################
# Banner
###############################################################################

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║            AUTOMATED CAMPAIGN FRAMEWORK                       ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo -e "║  Campaign:  ${GREEN}${CAMPAIGN_NAME}${CYAN}"
echo -e "║  ID:        ${GREEN}${CAMPAIGN_ID}${CYAN}"
echo -e "║  Config:    ${CONFIG_FILE}"
echo -e "║  Duration:  ${DURATION_HOURS} hours"
echo -e "║  State:     ${STATE_FILE}"
echo -e "║  Dry Run:   ${DRY_RUN}"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${YELLOW}DRY RUN MODE — No attacks will be executed${NC}"
    echo ""

    # Show what would happen
    for hour in $(seq 0 "$DURATION_HOURS"); do
        level=$(get_intensity_for_hour "$CONFIG_FILE" "$hour")
        phase=$(get_phase_for_hour "$CONFIG_FILE" "$hour")
        aph=$(get_attacks_per_hour "$level")
        echo -e "  Hour ${hour}: ${BLUE}${phase}${NC} @ ${YELLOW}${level}${NC} (${aph} attacks/hr)"
    done

    echo ""
    echo "Phases and attack lists:"
    while IFS= read -r phase_name; do
        echo -e "\n  ${GREEN}${phase_name}:${NC}"
        while IFS= read -r atk; do
            echo "    - ${atk}"
        done < <(get_phase_attacks "$CONFIG_FILE" "$phase_name")
    done < <(get_all_phases "$CONFIG_FILE")

    exit 0
fi

###############################################################################
# Signal Handling — Graceful Shutdown
###############################################################################

cleanup() {
    echo ""
    echo -e "${YELLOW}Interrupt received — saving state and shutting down...${NC}"
    state_update "$STATE_FILE" "status" "interrupted"
    state_summary "$STATE_FILE"
    echo -e "${GREEN}State saved to: ${STATE_FILE}${NC}"
    echo -e "${GREEN}Resume with: ./runner.sh --resume ${STATE_FILE}${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

###############################################################################
# Main Campaign Loop
###############################################################################

echo -e "${GREEN}Campaign started at $(date -u +%Y-%m-%dT%H:%M:%SZ)${NC}"
echo -e "${GREEN}Will run until $(date -u -d @${END_EPOCH} +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r ${END_EPOCH} +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "epoch $END_EPOCH")${NC}"
echo ""

while true; do
    NOW_EPOCH=$(date +%s)

    # Check if campaign duration exceeded
    if [[ "$NOW_EPOCH" -ge "$END_EPOCH" ]]; then
        echo -e "${GREEN}Campaign duration reached. Finishing...${NC}"
        state_update "$STATE_FILE" "status" "completed"
        break
    fi

    # Check if pause requested
    if state_is_paused "$STATE_FILE"; then
        echo -e "${YELLOW}Pause requested. Saving state...${NC}"
        state_summary "$STATE_FILE"
        echo -e "${GREEN}Resume with: ./runner.sh --resume ${STATE_FILE}${NC}"
        exit 0
    fi

    # Calculate current hour into campaign
    ELAPSED_SECONDS=$(( NOW_EPOCH - START_EPOCH ))
    CURRENT_HOUR=$(( ELAPSED_SECONDS / 3600 ))

    # Get intensity and phase
    INTENSITY=$(get_intensity_for_hour "$CONFIG_FILE" "$CURRENT_HOUR")
    APH=$(get_attacks_per_hour "$INTENSITY")
    PHASE_NAME=$(get_phase_for_hour "$CONFIG_FILE" "$CURRENT_HOUR")

    state_update "$STATE_FILE" "current_phase_name" "$PHASE_NAME"

    # Quiet period — sleep
    if [[ "$APH" -eq 0 ]]; then
        echo -e "${BLUE}[Hour ${CURRENT_HOUR}] Quiet period — sleeping 5 minutes...${NC}"
        sleep 300
        continue
    fi

    # Get attack list for current phase
    mapfile -t PHASE_ATTACKS < <(get_phase_attacks "$CONFIG_FILE" "$PHASE_NAME")

    if [[ ${#PHASE_ATTACKS[@]} -eq 0 ]]; then
        echo -e "${YELLOW}[Hour ${CURRENT_HOUR}] No attacks defined for phase '${PHASE_NAME}' — sleeping 60s${NC}"
        sleep 60
        continue
    fi

    # Pick random attack avoiding recent repeats
    ATTACK_TYPE=$(pick_attack "$STATE_FILE" "${PHASE_ATTACKS[@]}")

    if [[ -z "$ATTACK_TYPE" ]]; then
        echo -e "${YELLOW}Could not select attack — sleeping 60s${NC}"
        sleep 60
        continue
    fi

    # Execute attack
    COMPLETED=$(state_read "$STATE_FILE" "attacks_completed")
    FAILED=$(state_read "$STATE_FILE" "attacks_failed")
    TOTAL=$(( COMPLETED + FAILED ))

    echo -e "${CYAN}[Hour ${CURRENT_HOUR}] Phase: ${PHASE_NAME} | Intensity: ${INTENSITY} (${APH}/hr) | Attack #$((TOTAL + 1))${NC}"
    echo -e "${GREEN}Executing: ${ATTACK_TYPE}${NC}"

    if bash "$RUN_ATTACK" --auto-confirm --campaign-id "$CAMPAIGN_ID" "$ATTACK_TYPE" "Campaign: ${CAMPAIGN_NAME} | Phase: ${PHASE_NAME}"; then
        state_increment "$STATE_FILE" "attacks_completed"
        state_log_attack "$STATE_FILE" "$ATTACK_TYPE" "" "true" "$PHASE_NAME"
        echo -e "${GREEN}Attack completed successfully${NC}"
    else
        state_increment "$STATE_FILE" "attacks_failed"
        state_log_attack "$STATE_FILE" "$ATTACK_TYPE" "" "false" "$PHASE_NAME"
        echo -e "${RED}Attack failed (continuing)${NC}"
    fi

    # Calculate delay
    DELAY=$(calculate_delay "$APH" 30)
    echo -e "${BLUE}Next attack in ${DELAY}s${NC}"
    echo ""

    # Sleep with periodic pause checks
    SLEEP_REMAINING=$DELAY
    while [[ "$SLEEP_REMAINING" -gt 0 ]]; do
        if state_is_paused "$STATE_FILE"; then
            echo -e "${YELLOW}Pause detected during delay. Saving state...${NC}"
            state_summary "$STATE_FILE"
            echo -e "${GREEN}Resume with: ./runner.sh --resume ${STATE_FILE}${NC}"
            exit 0
        fi
        CHUNK=30
        if [[ "$SLEEP_REMAINING" -lt "$CHUNK" ]]; then
            CHUNK=$SLEEP_REMAINING
        fi
        sleep "$CHUNK"
        SLEEP_REMAINING=$(( SLEEP_REMAINING - CHUNK ))
    done
done

###############################################################################
# Campaign Complete
###############################################################################

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                  CAMPAIGN COMPLETE                             ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

state_summary "$STATE_FILE"

# Generate report
if [[ -f "${CAMPAIGNS_DIR}/reporter.sh" ]]; then
    echo ""
    echo -e "${CYAN}Generating campaign report...${NC}"
    bash "${CAMPAIGNS_DIR}/reporter.sh" "$STATE_FILE"
fi

echo ""
echo -e "${GREEN}Campaign state saved to: ${STATE_FILE}${NC}"
echo -e "${YELLOW}Next: Wait 5 minutes for Suricata ingestion, then run:${NC}"
echo -e "  python -m src.data.extract_with_attacks"
