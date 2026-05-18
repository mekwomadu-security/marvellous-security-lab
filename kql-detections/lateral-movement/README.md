# Lateral Movement Detection

## What this detects
This rule detects when an account accesses multiple machines 
across the network within a short time window. Lateral movement 
is what attackers do after they get into one machine — they use 
that foothold to spread across the network, access sensitive 
systems, and work towards their final objective.

This detection catches that spreading behaviour by monitoring 
remote logon events across machines and flagging accounts that 
access an unusual number of systems in a short period.

## Why this is different
Most basic rules look at logon failures. This detection looks at 
successful logons across multiple machines — which is far more 
dangerous because it means the attacker already has valid 
credentials and is actively moving through the network.

### Three critical event IDs
```kql
| where EventID in (4624, 4648, 4672)
```
Each event ID tells a different part of the story:

| Event ID | Name | What it means |
|----------|------|---------------|
| 4624 | Successful logon | Account accessed a machine |
| 4648 | Explicit credential logon | Used specific credentials — common in Pass the Hash and PsExec attacks |
| 4672 | Special privileges assigned | Logged in with admin rights |

Together these three events paint a complete picture of an 
attacker moving through the network with elevated privileges 
using explicit credentials.

### Logon type filtering
```kql
| where LogonType in (3, 10)
```
Not all logons indicate lateral movement. This filter keeps only:

| Logon Type | Name | Why it matters |
|------------|------|----------------|
| Type 3 | Network logon | Classic SMB lateral movement |
| Type 10 | Remote interactive | RDP session — attacker on the machine |

Filtering by logon type removes noise from local logons and 
service account activity that would otherwise flood the results.

### Machine count threshold
```kql
| where MachinesAccessed >= minMachinesAccessed
```
A normal user logs into one or two machines. An attacker moves 
across many. The threshold of 3 machines in 1 hour is low enough 
to catch early stage movement while filtering out legitimate 
admin activity.

### Movement pattern classification
Every alert is automatically labelled with what stage of lateral 
movement this represents:

| Machines Accessed | Pattern | What it means |
|------------------|---------|---------------|
| 3-9 | Early lateral movement | Attacker exploring the network |
| 10-19 | Aggressive lateral movement | Attacker pivoting rapidly |
| 20+ | Worm-like propagation | Automated tool spreading across network |

This tells the SOC analyst immediately whether they are dealing 
with a human attacker or an automated tool — which completely 
changes the response.

### Blast radius field
```kql
BlastRadius = strcat(
    tostring(MachinesAccessed),
    " machines accessed in ",
    tostring(timeWindow),
    " — immediate containment required if confirmed"
)
```
Every alert generates a plain English summary of how many 
machines have been touched. This tells the analyst exactly 
how wide the containment effort needs to be before they open 
a single log.

### MachineList field
```kql
MachineList = make_set(Computer, 20)
```
Captures up to 20 of the affected machines in one field. The 
analyst immediately knows which machines to isolate without 
running a separate investigation query.

### Risk scoring
| Machines Accessed | Risk Score |
|------------------|------------|
| 3+ | Medium |
| 10+ | High |
| 20+ | Critical |

## How lateral movement connects to your other detections
Lateral movement sits in the middle of the attack chain:

1. Attacker runs **password spray** → finds valid credentials
2. Attacker logs in → triggers **impossible travel** detection
3. Attacker escalates privileges → triggers **privilege escalation**
4. Attacker moves across network → triggers this detection
5. Attacker reaches target systems → data exfiltration begins

Each detection you have built covers one stage of this chain. 
Together they give complete visibility across the full attack.

## MITRE ATT&CK
| Field | Value |
|-------|-------|
| Tactic | Lateral Movement |
| Technique | T1021 — Remote Services |
| Sub-techniques | T1021.001 RDP, T1021.002 SMB |

## Data source
- SecurityEvent (Windows Security Log)
- DeviceLogonEvents (Microsoft Defender for Endpoint)

## Deployment
1. Open Microsoft Sentinel
2. Go to **Logs**
3. Paste the query from `lateral_movement.kql`
4. Set schedule to run every **30 minutes**
5. Set alert threshold to **greater than 0 results**

## Tuning
| Parameter | Default | Description |
|-----------|---------|-------------|
| timeWindow | 1h | Time window to group logons |
| minMachinesAccessed | 3 | Minimum machines to trigger alert |
| lookback | 24h | How far back to look |

Lower `minMachinesAccessed` to catch very early movement. 
Raise it in environments where admins legitimately access 
many machines — such as patch management windows.

## False positives
- IT administrators performing maintenance across machines
- Patch management tools accessing multiple endpoints
- Legitimate RDP sessions by support teams
- Backup agents running across the network

## Response actions
When this alert fires:
1. Identify the source account and immediately review 
   recent activity
2. Check for password spray or brute force alerts on 
   the same account
3. Isolate the machines in MachineList if movement 
   is confirmed malicious
4. Reset credentials for the affected account
5. Review all machines accessed for signs of persistence

## Author
Marvellous Ekwomadu
Built independently as part of the Marvellous Security Lab