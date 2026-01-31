#!/bin/bash
###############################################################################
# Campaign Reporter
# Generates post-campaign summary reports from state files and attack logs
###############################################################################

CAMPAIGNS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKS_DIR="$(dirname "$CAMPAIGNS_DIR")"
ATTACK_LOG="${ATTACKS_DIR}/attack_log.csv"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ $# -lt 1 ]]; then
    echo "Usage: $(basename "$0") <state_file> [output_file]"
    exit 1
fi

STATE_FILE="$1"
OUTPUT_FILE="${2:-}"

if [[ ! -f "$STATE_FILE" ]]; then
    echo "State file not found: $STATE_FILE"
    exit 1
fi

generate_report() {
    python3 - "$STATE_FILE" "$ATTACK_LOG" "$OUTPUT_FILE" << 'PYTHON_REPORT'
import json
import sys
import csv
from datetime import datetime
from collections import Counter

state_file = sys.argv[1]
attack_log_file = sys.argv[2]
output_file = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None

# Load state
with open(state_file) as f:
    state = json.load(f)

campaign_id = state['campaign_id']

# Load attack log and filter by campaign
campaign_attacks = []
try:
    with open(attack_log_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            notes = row.get('notes', '')
            if campaign_id in notes:
                campaign_attacks.append(row)
except FileNotFoundError:
    pass

# Compute stats from state history
history = state.get('attack_history', [])
attack_types = Counter(h['attack_type'] for h in history)
phase_counts = Counter(h['phase'] for h in history)
success_count = sum(1 for h in history if h.get('success', False))
fail_count = sum(1 for h in history if not h.get('success', True))

# Time range from attack log
if campaign_attacks:
    start_times = [a['timestamp_start'] for a in campaign_attacks if a.get('timestamp_start')]
    end_times = [a['timestamp_end'] for a in campaign_attacks if a.get('timestamp_end')]
    first_attack = min(start_times) if start_times else 'N/A'
    last_attack = max(end_times) if end_times else 'N/A'
else:
    first_attack = state.get('created_at', 'N/A')
    last_attack = state.get('updated_at', 'N/A')

# Category breakdown from attack log
categories = Counter(a.get('category', 'unknown') for a in campaign_attacks)
tools = Counter(a.get('tool', 'unknown') for a in campaign_attacks)
targets = Counter(a.get('target_ip', 'unknown') for a in campaign_attacks)

# Generate report
lines = []
lines.append("=" * 70)
lines.append(f"  CAMPAIGN REPORT: {campaign_id}")
lines.append("=" * 70)
lines.append("")
lines.append(f"  Campaign:    {state.get('config_file', 'N/A')}")
lines.append(f"  Status:      {state['status']}")
lines.append(f"  Started:     {state.get('created_at', 'N/A')}")
lines.append(f"  Ended:       {state.get('updated_at', 'N/A')}")
lines.append(f"  First ATK:   {first_attack}")
lines.append(f"  Last ATK:    {last_attack}")
lines.append("")
lines.append("-" * 70)
lines.append("  SUMMARY")
lines.append("-" * 70)
lines.append(f"  Total attacks executed:  {state['attacks_completed'] + state['attacks_failed']}")
lines.append(f"  Successful:              {state['attacks_completed']}")
lines.append(f"  Failed:                  {state['attacks_failed']}")
lines.append(f"  Skipped:                 {state.get('attacks_skipped', 0)}")
lines.append(f"  Logged in attack_log:    {len(campaign_attacks)}")
lines.append("")

if attack_types:
    lines.append("-" * 70)
    lines.append("  ATTACK TYPE DISTRIBUTION")
    lines.append("-" * 70)
    for atk, count in attack_types.most_common():
        bar = "#" * min(count, 40)
        lines.append(f"  {atk:<30} {count:>4}  {bar}")
    lines.append("")

if phase_counts:
    lines.append("-" * 70)
    lines.append("  PHASE DISTRIBUTION")
    lines.append("-" * 70)
    for phase, count in phase_counts.most_common():
        lines.append(f"  {phase:<30} {count:>4}")
    lines.append("")

if categories:
    lines.append("-" * 70)
    lines.append("  ATTACK CATEGORIES (from attack_log)")
    lines.append("-" * 70)
    for cat, count in categories.most_common():
        lines.append(f"  {cat:<30} {count:>4}")
    lines.append("")

if tools:
    lines.append("-" * 70)
    lines.append("  TOOLS USED")
    lines.append("-" * 70)
    for tool, count in tools.most_common():
        lines.append(f"  {tool:<30} {count:>4}")
    lines.append("")

if targets:
    lines.append("-" * 70)
    lines.append("  TARGET DISTRIBUTION")
    lines.append("-" * 70)
    for target, count in targets.most_common():
        lines.append(f"  {target:<30} {count:>4}")
    lines.append("")

lines.append("=" * 70)

report = "\n".join(lines)
print(report)

if output_file:
    with open(output_file, 'w') as f:
        f.write(report)
    print(f"\nReport saved to: {output_file}")

PYTHON_REPORT
}

generate_report
