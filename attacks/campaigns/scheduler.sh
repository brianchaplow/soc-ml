#!/bin/bash
###############################################################################
# Campaign Scheduler
# Handles intensity levels, timing, phase transitions, and jitter
###############################################################################

# Intensity levels: attacks per hour
declare -A INTENSITY_APH
INTENSITY_APH[quiet]=0
INTENSITY_APH[low]=6
INTENSITY_APH[medium]=15
INTENSITY_APH[high]=30
INTENSITY_APH[burst]=60

# Get intensity level for a given hour
get_intensity_for_hour() {
    local config_file="$1"
    local current_hour="$2"

    python3 -c "
import yaml, sys
with open('$config_file') as f:
    config = yaml.safe_load(f)
schedule = config.get('intensity', {}).get('schedule', [{'hour': 0, 'level': 'medium'}])
# Find the active level: use the last schedule entry whose hour <= current_hour
level = 'medium'
for entry in sorted(schedule, key=lambda x: x['hour']):
    if entry['hour'] <= $current_hour:
        level = entry['level']
print(level)
"
}

# Get attacks per hour for an intensity level
get_attacks_per_hour() {
    local level="$1"
    echo "${INTENSITY_APH[$level]:-5}"
}

# Calculate delay between attacks (seconds) with jitter
calculate_delay() {
    local attacks_per_hour="$1"
    local jitter_pct="${2:-30}"

    if [[ "$attacks_per_hour" -eq 0 ]]; then
        echo "3600"  # sleep for an hour during quiet periods
        return
    fi

    # Base delay in seconds
    local base_delay=$(( 3600 / attacks_per_hour ))

    # Apply jitter (±jitter_pct%)
    local jitter_range=$(( base_delay * jitter_pct / 100 ))
    local jitter=$(( RANDOM % (jitter_range * 2 + 1) - jitter_range ))
    local delay=$(( base_delay + jitter ))

    # Minimum 10 seconds between attacks
    if [[ "$delay" -lt 10 ]]; then
        delay=10
    fi

    echo "$delay"
}

# Get active phase for a given hour
get_phase_for_hour() {
    local config_file="$1"
    local current_hour="$2"

    python3 -c "
import yaml
with open('$config_file') as f:
    config = yaml.safe_load(f)
phases = config.get('phases', [])
active_phase = None
for phase in phases:
    start = phase.get('start_hour', 0)
    end = phase.get('end_hour', 9999)
    if start <= $current_hour < end:
        active_phase = phase
        break
if active_phase:
    print(active_phase.get('name', 'default'))
else:
    print('default')
"
}

# Get attack list for a phase
get_phase_attacks() {
    local config_file="$1"
    local phase_name="$2"

    python3 -c "
import yaml
with open('$config_file') as f:
    config = yaml.safe_load(f)
phases = config.get('phases', [])
for phase in phases:
    if phase.get('name') == '$phase_name':
        attacks = phase.get('attacks', [])
        for a in attacks:
            print(a)
        break
"
}

# Pick a random attack from a list, avoiding recent repeats
pick_attack() {
    local state_file="$1"
    shift
    local attacks=("$@")

    if [[ ${#attacks[@]} -eq 0 ]]; then
        echo ""
        return
    fi

    # Get recent attacks to avoid
    local recent
    recent=$(python3 -c "
import json
with open('$state_file') as f:
    state = json.load(f)
history = state.get('attack_history', [])
recent = [h['attack_type'] for h in history[-5:]]
print('\n'.join(recent))
" 2>/dev/null)

    # Try to pick one not in recent list
    local available=()
    for atk in "${attacks[@]}"; do
        if ! echo "$recent" | grep -q "^${atk}$"; then
            available+=("$atk")
        fi
    done

    # If all were recent, use full list
    if [[ ${#available[@]} -eq 0 ]]; then
        available=("${attacks[@]}")
    fi

    # Random selection
    local idx=$(( RANDOM % ${#available[@]} ))
    echo "${available[$idx]}"
}

# Get campaign duration from config
get_campaign_duration() {
    local config_file="$1"
    python3 -c "
import yaml
with open('$config_file') as f:
    config = yaml.safe_load(f)
print(config.get('campaign', {}).get('duration_hours', 4))
"
}

# Get campaign name from config
get_campaign_name() {
    local config_file="$1"
    python3 -c "
import yaml
with open('$config_file') as f:
    config = yaml.safe_load(f)
print(config.get('campaign', {}).get('name', 'unnamed'))
"
}

# Get all phase names
get_all_phases() {
    local config_file="$1"
    python3 -c "
import yaml
with open('$config_file') as f:
    config = yaml.safe_load(f)
phases = config.get('phases', [])
for p in phases:
    print(p.get('name', 'unknown'))
"
}

# Get target scope for a phase (returns IPs)
get_phase_targets() {
    local config_file="$1"
    local phase_name="$2"

    python3 -c "
import yaml
with open('$config_file') as f:
    config = yaml.safe_load(f)
phases = config.get('phases', [])
for phase in phases:
    if phase.get('name') == '$phase_name':
        targets = phase.get('targets', [])
        for t in targets:
            print(t)
        break
"
}
