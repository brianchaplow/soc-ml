#!/bin/bash
###############################################################################
# Campaign State Management
# Provides JSON state read/write helpers for pause/resume functionality
###############################################################################

CAMPAIGNS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${CAMPAIGNS_DIR}/state"

# Create state directory if needed
mkdir -p "$STATE_DIR"

# Create a new campaign state file
state_create() {
    local campaign_id="$1"
    local config_file="$2"
    local total_phases="$3"
    local state_file="${STATE_DIR}/${campaign_id}.state"

    python3 -c "
import json, datetime
state = {
    'campaign_id': '$campaign_id',
    'config_file': '$config_file',
    'status': 'running',
    'created_at': datetime.datetime.utcnow().isoformat() + 'Z',
    'updated_at': datetime.datetime.utcnow().isoformat() + 'Z',
    'current_phase': 0,
    'current_phase_name': '',
    'total_phases': $total_phases,
    'attacks_completed': 0,
    'attacks_failed': 0,
    'attacks_skipped': 0,
    'last_attack_id': None,
    'last_attack_type': None,
    'attack_history': [],
    'pause_requested': False,
    'error': None
}
with open('$state_file', 'w') as f:
    json.dump(state, f, indent=2)
print('$state_file')
"
}

# Read a field from state
state_read() {
    local state_file="$1"
    local field="$2"

    python3 -c "
import json
with open('$state_file') as f:
    state = json.load(f)
val = state.get('$field', '')
if isinstance(val, bool):
    print('true' if val else 'false')
else:
    print(val if val is not None else '')
"
}

# Update a field in state
state_update() {
    local state_file="$1"
    local field="$2"
    local value="$3"

    python3 -c "
import json, datetime
with open('$state_file') as f:
    state = json.load(f)
# Handle type conversion
val = '''$value'''
if val == 'true':
    val = True
elif val == 'false':
    val = False
elif val.isdigit():
    val = int(val)
state['$field'] = val
state['updated_at'] = datetime.datetime.utcnow().isoformat() + 'Z'
with open('$state_file', 'w') as f:
    json.dump(state, f, indent=2)
"
}

# Increment a numeric counter
state_increment() {
    local state_file="$1"
    local field="$2"

    python3 -c "
import json, datetime
with open('$state_file') as f:
    state = json.load(f)
state['$field'] = state.get('$field', 0) + 1
state['updated_at'] = datetime.datetime.utcnow().isoformat() + 'Z'
with open('$state_file', 'w') as f:
    json.dump(state, f, indent=2)
"
}

# Append to attack history
state_log_attack() {
    local state_file="$1"
    local attack_type="$2"
    local attack_id="$3"
    local success="$4"
    local phase="$5"

    python3 -c "
import json, datetime
with open('$state_file') as f:
    state = json.load(f)
entry = {
    'attack_type': '$attack_type',
    'attack_id': '$attack_id',
    'success': '$success' == 'true',
    'phase': '$phase',
    'timestamp': datetime.datetime.utcnow().isoformat() + 'Z'
}
state['attack_history'].append(entry)
state['last_attack_id'] = '$attack_id'
state['last_attack_type'] = '$attack_type'
state['updated_at'] = datetime.datetime.utcnow().isoformat() + 'Z'
with open('$state_file', 'w') as f:
    json.dump(state, f, indent=2)
"
}

# Check if pause was requested
state_is_paused() {
    local state_file="$1"
    local paused
    paused=$(state_read "$state_file" "pause_requested")
    [[ "$paused" == "true" ]]
}

# Request graceful pause
state_request_pause() {
    local state_file="$1"
    state_update "$state_file" "pause_requested" "true"
    state_update "$state_file" "status" "paused"
}

# Get recent attack types (for avoiding repeats)
state_recent_attacks() {
    local state_file="$1"
    local count="${2:-10}"

    python3 -c "
import json
with open('$state_file') as f:
    state = json.load(f)
history = state.get('attack_history', [])
recent = [h['attack_type'] for h in history[-$count:]]
print('\n'.join(recent))
"
}

# Print state summary
state_summary() {
    local state_file="$1"

    python3 -c "
import json
with open('$state_file') as f:
    state = json.load(f)
print(f\"Campaign: {state['campaign_id']}\")
print(f\"Status:   {state['status']}\")
print(f\"Phase:    {state['current_phase']}/{state['total_phases']} ({state.get('current_phase_name', '')})\")
print(f\"Attacks:  {state['attacks_completed']} completed, {state['attacks_failed']} failed, {state['attacks_skipped']} skipped\")
print(f\"Last:     {state.get('last_attack_type', 'none')} ({state.get('last_attack_id', 'none')})\")
print(f\"Updated:  {state['updated_at']}\")
if state.get('error'):
    print(f\"Error:    {state['error']}\")
"
}
