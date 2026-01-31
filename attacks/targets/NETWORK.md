# HomeLab SOC v2 — Network Reference

**Author:** Brian Chaplow (Chappy McNasty)
**Updated:** 2026-01-31

---

## Physical Topology

```
                    Internet (Verizon)
                         |
                    ┌────┴────┐
                    │ Protectli│  OPNsense Firewall
                    │  (igc1) │  igc0=Trunk, igc1=WAN, igc3=AsusRouter
                    └────┬────┘
                    igc0 │ 802.1Q trunk (VLANs 10,20,30,40,50)
                         │
                 ┌───────┴────────┐
                 │   MokerLink    │  10G08410GSM
                 │ 8x10GE+4xSFP  │  Managed Switch
                 └─┬──┬──┬──┬──┬─┘
                   │  │  │  │  │
          ┌────────┘  │  │  │  └─── ... (other devices)
          │           │  │  │
     ┌────┴────┐ ┌───┴──┴──┴───┐
     │  sear   │ │   smoker    │
     │ (Kali)  │ │ (Proxmox)   │
     │ VLAN 20 │ │ VLAN 30+40  │
     └─────────┘ └──────┬──────┘
                        │
              ┌─────────┼──────────┐
              │         │          │
          Proxmox VMs  Docker   Docker
          (VLAN 40)   (VLAN 40) (VLAN 40)
```

---

## VLANs

| VLAN | Name | Subnet | Gateway (OPNsense) | Purpose |
|------|------|--------|---------------------|---------|
| 10 | LAN / Management | 10.10.10.0/24 | 10.10.10.1 | Management access, Proxmox web UI |
| 20 | SOC | 10.10.20.0/24 | 10.10.20.1 | SOC infrastructure (sear, smokehouse, Suricata) |
| 30 | Lab | 10.10.30.0/24 | 10.10.30.1 | Hypervisors, AD lab |
| **40** | **Targets** | **10.10.40.0/24** | **10.10.40.1** | **Attack targets — safe to attack** |
| 50 | IoT | 10.10.50.0/24 | 10.10.50.1 | IoT devices |

---

## OPNsense (Protectli)

### Physical Interfaces

| NIC | Device | Role | IP | Link Speed |
|-----|--------|------|----|------------|
| igc0 | Trunk parent | VLAN trunk to MokerLink | none (parent only) | 2.5 GbE |
| igc1 | WAN | Internet (Verizon DHCP) | 108.56.24.254/24 | 2.5 GbE |
| igc2 | Unused | no carrier | none | down |
| igc3 | AsusRouter (opt5) | Secondary router link | 192.168.100.1/24 | 2.5 GbE |

### VLAN Subinterfaces (on igc0)

| OPNsense Interface | Device | VLAN Tag | OPNsense Name | IP |
|---------------------|--------|----------|---------------|----|
| igc0_vlan10 | vlan0 | 10 | LAN | 10.10.10.1/24 |
| vlan01 | vlan1 | 20 | SOC (opt1) | 10.10.20.1/24 |
| vlan02 | vlan2 | 30 | Lab (opt2) | 10.10.30.1/24 |
| vlan03 | vlan3 | 40 | Targets (opt3) | 10.10.40.1/24 |
| vlan04 | vlan4 | 50 | IoT (opt4) | 10.10.50.1/24 |

All VLANs ride on igc0 as 802.1Q tagged subinterfaces. The Protectli's igc0 port connects to the MokerLink switch as a **trunk** carrying all 5 VLANs.

### Required Firewall Rules (OPNsense)

For the Purple Team attack framework, the following inter-VLAN traffic must be permitted:

| Source | Destination | Ports | Purpose |
|--------|-------------|-------|---------|
| VLAN 20 (SOC) 10.10.20.0/24 | VLAN 40 (Targets) 10.10.40.0/24 | ANY | sear → attack targets |
| VLAN 40 (Targets) 10.10.40.0/24 | VLAN 20 (SOC) 10.10.20.0/24 | Established/Related | Return traffic from targets |
| VLAN 30 (Lab) 10.10.30.0/24 | VLAN 40 (Targets) 10.10.40.0/24 | ANY | smoker host management → Docker containers |

**Isolation rules (DENY):**
- VLAN 40 should NOT initiate connections to VLAN 10, 20, 30, or 50 (targets are isolated)
- VLAN 40 should NOT have internet access (prevent accidental external attacks)

---

## MokerLink Switch (10G08410GSM)

### Required Port Configuration

The switch must pass VLAN 40 tagged traffic between the Protectli and smoker. At minimum:

| Port | Connected Device | Mode | VLANs | Notes |
|------|-----------------|------|-------|-------|
| Port X | Protectli igc0 | **Trunk** | 10,20,30,40,50 (tagged) | All VLANs |
| Port Y | smoker eno1 | **Trunk** | 30 (PVID/untagged), 40 (tagged) | VLAN 30 for management, VLAN 40 for targets |
| Port Z | sear NIC | **Access** or **Trunk** | 20 | SOC VLAN |

### Key Switch Settings for VLAN 40

1. **VLAN 40 must exist** in the switch's VLAN database
2. **Protectli port** must be a trunk member of VLAN 40 (tagged)
3. **smoker port** must be a trunk member of VLAN 40 (tagged)
   - smoker receives VLAN 40 frames tagged → eno1.40 strips the tag → vmbr0v40 bridge → VMs and Docker containers
4. Any port connecting to a VLAN 40 device directly should be access mode with PVID 40

### Verifying on the Switch

In the MokerLink web UI:
- Navigate to **VLAN > 802.1Q VLAN**
- Confirm VLAN 40 exists with ports for Protectli and smoker as **Tagged** members
- Navigate to **VLAN > Port VLAN** to verify PVID settings

---

## smoker (Proxmox — 10.10.30.21)

### Network Interfaces

```
eno1 (physical, 2.5GbE)
 ├── vmbr0 (Proxmox bridge, VLAN 30)
 │    └── 10.10.30.21/24  ← smoker management IP
 │
 └── eno1.40 (802.1Q VLAN 40 subinterface)
      └── vmbr0v40 (Proxmox bridge, VLAN 40)
           ├── tap200i0  ← VM 200 (DVWA/Juice Shop)
           ├── tap202i0  ← VM 202 (Metasploitable 3)
           └── Docker ipvlan (L2)
                ├── 10.10.40.30 (WordPress)
                ├── 10.10.40.31 (crAPI)
                ├── 10.10.40.32 (FTP)
                ├── 10.10.40.42 (SMTP)
                └── 10.10.40.43 (SNMP)
```

### How VLAN 40 Traffic Flows

```
sear (10.10.20.20, VLAN 20)
    → OPNsense gateway (10.10.20.1 → routes to 10.10.40.1)
    → MokerLink switch (VLAN 40 tagged frame)
    → smoker eno1 (receives tagged frame)
    → eno1.40 (strips VLAN tag)
    → vmbr0v40 (bridge)
    → VM tap interface or Docker ipvlan container
```

### Docker Network on smoker

```bash
# Created once (already exists):
docker network create \
  --driver ipvlan \
  --subnet 10.10.40.0/24 \
  --gateway 10.10.40.1 \
  -o parent=vmbr0v40 \
  -o ipvlan_mode=l2 \
  vlan40
```

- **Driver:** ipvlan (not macvlan — macvlan fails because eno1.40 is bridge-enslaved)
- **Mode:** L2 (containers appear as distinct IPs on the VLAN 40 segment)
- **Parent:** vmbr0v40 (the Proxmox bridge, not eno1.40 directly)
- **Note:** `privileged: true` required on many containers due to Proxmox PVE kernel seccomp restrictions

### Proxmox VM Configuration (for reference)

VMs on VLAN 40 need their network device set to:
- **Bridge:** vmbr0v40
- **VLAN Tag:** (none — the bridge is already VLAN 40)
- **Model:** virtio (recommended)

---

## IP Address Map — VLAN 40 (Targets)

| IP | Host | Type | Service | Ports | Location |
|----|------|------|---------|-------|----------|
| 10.10.40.1 | OPNsense | Gateway | Router/Firewall | - | Protectli |
| 10.10.40.10 | DVWA + Juice Shop | Proxmox VM | Web app targets | 80, 3000 | smoker VM 200 |
| 10.10.40.20 | Metasploitable 3 | Proxmox VM | Multi-service target | 21,22,23,25,80,445,3306,5432,8180 | smoker VM 202 |
| 10.10.40.21 | *(planned)* Windows | Proxmox VM | SMB/RDP/IIS | 80,445,3389,5985,8080 | smoker *(future)* |
| 10.10.40.30 | WordPress | Docker | WPScan, XML-RPC | 80 | smoker |
| 10.10.40.31 | crAPI (OWASP) | Docker | REST API attacks | 80, 443 | smoker |
| 10.10.40.32 | vsftpd | Docker | FTP brute force | 21 | smoker |
| 10.10.40.33 | *(planned)* Honeypot | Docker | WAF evasion | 80, 8080 | smoker *(future)* |
| 10.10.40.42 | SMTP relay | Docker | SMTP attacks | 25 | smoker |
| 10.10.40.43 | SNMPd | Docker | SNMP enumeration | 161/udp | smoker |

### Key SOC Hosts (other VLANs, for reference)

| IP | VLAN | Host | Role |
|----|------|------|------|
| 10.10.20.10 | 20 | smokehouse | OpenSearch, Suricata, Fluent Bit |
| 10.10.20.20 | 20 | sear | Kali Linux, attack source, ML training |
| 10.10.30.21 | 30 | smoker | Proxmox hypervisor hosting all VLAN 40 targets |

---

## Docker Compose Stacks on smoker

All compose files are at `/opt/targets/` on smoker, with source copies at `~/soc-ml/attacks/targets/` on sear.

| Stack | Path | Containers | IPs |
|-------|------|------------|-----|
| WordPress | `/opt/targets/wordpress/` | target-wp-db, target-wordpress | .30 |
| crAPI | `/opt/targets/crapi/` | crapi-postgres, crapi-mongo, crapi-mailhog, crapi-identity, crapi-community, crapi-workshop, crapi-web | .31 |
| Services | `/opt/targets/services/` | target-ftp, target-smtp, target-snmp | .32, .42, .43 |

### Managing Docker Stacks

```bash
# From sear:
ssh smoker "cd /opt/targets/wordpress && docker compose up -d"
ssh smoker "cd /opt/targets/crapi && docker compose up -d"
ssh smoker "cd /opt/targets/services && docker compose up -d"

# Check all containers:
ssh smoker "docker ps --format 'table {{.Names}}\t{{.Status}}'"

# Restart a stack:
ssh smoker "cd /opt/targets/crapi && docker compose down && docker compose up -d"
```

---

## Troubleshooting Checklist

### New target not reachable from sear?

1. **Is the container/VM running?**
   ```bash
   ssh smoker "docker ps" # or check Proxmox web UI
   ```

2. **Does the container have the right IP on vlan40?**
   ```bash
   ssh smoker "docker inspect <container> | grep IPAddress"
   ```

3. **Is VLAN 40 passing through the switch?**
   - Check MokerLink: VLAN 40 must be tagged on both the Protectli port and the smoker port
   - Test from smoker itself: `ping 10.10.40.1` (should reach the OPNsense gateway)

4. **Is OPNsense routing between VLANs?**
   - Check OPNsense: Firewall > Rules > Targets (VLAN 40) — ensure rules allow traffic
   - Check OPNsense: Firewall > Rules > SOC (VLAN 20) — ensure outbound to VLAN 40 allowed
   - Test: `traceroute 10.10.40.30` from sear — should go through 10.10.20.1 → 10.10.40.30

5. **Is it a Docker networking issue?**
   - The `vlan40` Docker network must exist on smoker: `docker network ls | grep vlan40`
   - It must be ipvlan on vmbr0v40: `docker network inspect vlan40`
   - Containers must be on this network in their compose file

6. **ARP/connectivity between Docker ipvlan and Proxmox VMs?**
   - ipvlan containers and VMs on vmbr0v40 share the same L2 segment
   - If a container can't reach the gateway, check that OPNsense has an ARP entry for it:
     OPNsense > Interfaces > Diagnostics > ARP Table — look for the target IP

### Adding a new VLAN 40 target

1. Assign a free IP in 10.10.40.0/24 (see IP map above, avoid .1 and used IPs)
2. Add to Docker compose with `ipv4_address` on the `vlan40` network
3. Use `privileged: true` if the container needs raw socket or file operations (common on Proxmox)
4. Update `attacks/configs/targets.conf` with the new IP
5. Update relevant campaign YAML configs under `attacks/campaigns/configs/`
6. Test: `curl http://10.10.40.<new>/ ` or `nmap -sT 10.10.40.<new>`

---

## Quick Verification Commands

```bash
# From sear — verify all targets reachable
for ip in 10.10.40.10 10.10.40.20 10.10.40.30 10.10.40.31 10.10.40.32 10.10.40.42 10.10.40.43; do
    echo -n "$ip: "
    timeout 3 bash -c "echo | nc -w 2 $ip 80 2>/dev/null" && echo "open" || echo "closed/filtered"
done

# From smoker — verify Docker network
docker network inspect vlan40 --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{"\n"}}{{end}}'

# From smoker — verify VLAN 40 gateway reachable
ping -c 1 -W 2 10.10.40.1

# From sear — verify inter-VLAN routing
traceroute -n -m 3 10.10.40.30
```
