# Purple Team Attack Framework

## Overview

Structured attack generation for SOC-ML training data. All attacks are logged with precise timestamps enabling ground-truth labeling for ML training.

**Author:** Brian Chaplow (Chappy McNasty)  
**Environment:** sear (Kali) → Target VLAN 40

---

## Quick Start

```bash
# 1. Setup (first time only)
cd ~/soc-ml/attacks
chmod +x scripts/*.sh

# 2. Run an attack (always use the wrapper!)
./run_attack.sh web_sqli_union "SQLmap UNION attack against DVWA"

# 3. View attack log
cat attack_log.csv | column -t -s,
```

---

## Directory Structure

```
attacks/
├── README.md               # This file
├── attack_log.csv          # Master log (ground truth for ML)
├── run_attack.sh           # Wrapper script - ALWAYS use this
├── scripts/
│   ├── web_sqli.sh         # SQL injection variants
│   ├── web_xss.sh          # Cross-site scripting
│   ├── web_dirbusting.sh   # Directory enumeration
│   ├── recon_portscan.sh   # Nmap scanning variants
│   ├── recon_vuln.sh       # Vulnerability scanning
│   ├── brute_ssh.sh        # SSH brute force
│   ├── brute_web.sh        # Web login brute force
│   ├── exploit_msf.sh      # Metasploit modules
│   └── c2_beacon.sh        # C2 beaconing simulation
├── configs/
│   ├── targets.conf        # Target definitions
│   └── wordlists.conf      # Wordlist paths
└── results/                # Attack output files
```

---

## Attack Categories

### 1. Web Application Attacks
| ID | Attack | Tool | MITRE ATT&CK |
|----|--------|------|--------------|
| web_sqli_union | UNION-based SQLi | sqlmap | T1190 |
| web_sqli_blind | Blind SQLi | sqlmap | T1190 |
| web_sqli_time | Time-based SQLi | sqlmap | T1190 |
| web_xss_reflected | Reflected XSS | manual/xsser | T1189 |
| web_xss_stored | Stored XSS | manual | T1189 |
| web_lfi | Local File Inclusion | manual | T1083 |
| web_rfi | Remote File Inclusion | manual | T1105 |
| web_dirbusting | Directory enumeration | gobuster/dirb | T1083 |

### 2. Reconnaissance
| ID | Attack | Tool | MITRE ATT&CK |
|----|--------|------|--------------|
| recon_syn | SYN scan | nmap | T1046 |
| recon_full | Full TCP connect | nmap | T1046 |
| recon_udp | UDP scan | nmap | T1046 |
| recon_version | Version detection | nmap | T1046 |
| recon_vuln | Vulnerability scan | nmap/nikto | T1595 |
| recon_os | OS fingerprinting | nmap | T1082 |

### 3. Brute Force
| ID | Attack | Tool | MITRE ATT&CK |
|----|--------|------|--------------|
| brute_ssh | SSH password attack | hydra | T1110.001 |
| brute_ftp | FTP password attack | hydra | T1110.001 |
| brute_web_basic | HTTP Basic Auth | hydra | T1110.001 |
| brute_web_form | Web form login | hydra | T1110.001 |

### 4. Exploitation
| ID | Attack | Tool | MITRE ATT&CK |
|----|--------|------|--------------|
| exploit_eternalblue | MS17-010 | metasploit | T1210 |
| exploit_shellshock | Shellshock | metasploit | T1190 |
| exploit_tomcat | Tomcat manager | metasploit | T1190 |

### 5. C2 Simulation
| ID | Attack | Tool | MITRE ATT&CK |
|----|--------|------|--------------|
| c2_beacon_http | HTTP beaconing | custom | T1071.001 |
| c2_beacon_dns | DNS beaconing | custom | T1071.004 |
| c2_exfil_http | HTTP exfiltration | custom | T1048 |

---

## Usage Rules

### ⚠️ ALWAYS Use the Wrapper

```bash
# CORRECT - logged with timestamps
./run_attack.sh web_sqli_union "Testing DVWA SQL injection"

# WRONG - no logging, can't correlate with Suricata
sqlmap -u "http://10.10.40.10/..." --batch
```

### Target VLAN Only

All attacks MUST target VLAN 40 (10.10.40.0/24):
- DVWA: 10.10.40.10
- Juice Shop: 10.10.40.10:3000
- Metasploitable: 10.10.40.20

**NEVER** attack:
- VLAN 10 (Management)
- VLAN 20 (SOC) - except sear itself for testing
- VLAN 30 (Lab/AD) - unless specifically planned
- VLAN 50 (IoT)
- Any external targets

---

## Correlating with Suricata

After running attacks, the `attack_log.csv` provides ground truth:

```python
import pandas as pd

# Load attack log
attacks = pd.read_csv('attack_log.csv')

# Load Suricata alerts from OpenSearch
# Filter alerts where:
#   - timestamp between attack_start and attack_end
#   - src_ip matches attack source
#   - dest_ip matches attack target

# These are CONFIRMED attacks for training
```

---

## Data Generation Workflow

### Step 1: Plan Attack Session
```bash
# Review what attacks you'll run
cat scripts/web_sqli.sh
```

### Step 2: Execute Attacks
```bash
# Run each attack type
./run_attack.sh web_sqli_union "DVWA union SQLi"
./run_attack.sh recon_syn "Subnet SYN scan"
./run_attack.sh brute_ssh "Metasploitable SSH brute"
```

### Step 3: Wait for Log Ingestion
```bash
# Give Suricata/Fluent Bit time to process (~2-5 min)
sleep 300
```

### Step 4: Extract Labeled Data
```bash
# Use the ML pipeline with attack correlation
cd ~/soc-ml
python -m src.data.extract_with_attacks
```

---

## Attack Log Schema

| Field | Type | Description |
|-------|------|-------------|
| attack_id | string | Unique ID (ATK-YYYYMMDD-HHMMSS) |
| timestamp_start | ISO8601 | Attack start time |
| timestamp_end | ISO8601 | Attack end time |
| category | string | Attack category |
| subcategory | string | Specific attack type |
| technique_id | string | MITRE ATT&CK ID |
| tool | string | Tool used |
| source_ip | IP | Attack source (sear) |
| target_ip | IP | Target IP |
| target_port | int | Target port(s) |
| target_service | string | Target service name |
| success | bool | Did attack succeed? |
| notes | string | Additional context |

---

## Safety Checklist

Before each attack session:

- [ ] Confirm target is in VLAN 40
- [ ] Verify attack won't escape network
- [ ] Check Suricata is capturing (`docker exec suricata-live suricatasc -c "iface-stat eth4"`)
- [ ] Ensure enough disk space for logs
- [ ] Document any deviations from planned attacks

---

## Metrics Goals

Target dataset composition after attack generation:

| Class | Current | Target | Notes |
|-------|---------|--------|-------|
| benign | 100K | 100K | Flow data |
| noise | 50K | 50K | Protocol anomalies |
| info | 3K | 10K | Informational alerts |
| attack | <1K | **10K+** | Diverse attack types |

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
