# Data Exfiltration Detection

## What this detects
This rule detects abnormal outbound data transfers that indicate 
an attacker is stealing data from the organisation. Data 
exfiltration is typically the final stage of an attack — the 
attacker has already gained access, moved laterally, and is now 
taking what they came for.

This detection monitors network traffic for unusual volumes of 
data leaving the environment and flags transfers that exceed 
normal thresholds to unknown destinations.

## Why this is different
Most basic rules simply alert on large transfers. This detection 
adds intelligence on top — telling the SOC analyst where the data 
went, how it was sent, whether it went to one place or many, and 
exactly how much was taken.

### Known safe destination exclusion
```kql
let knownSafeDestinations = dynamic([
    "backup.internal.com",
    "sharepoint.com",
    "onedrive.com"
]);
```
Legitimate large transfers happen every day — backups, cloud 
syncs, file sharing. This exclusion list removes known safe 
destinations from alerts so analysts only see genuinely 
suspicious transfers. This is what keeps the false positive 
rate low without missing real exfiltration.

### Data volume threshold
```kql
let dataThresholdMB = 500;
```
500MB is the floor for alerting. Below this could be normal 
business activity. Above this warrants investigation. This 
threshold should be tuned based on the organisation's normal 
baseline — a media company transfers more data than a law firm.

### Exfiltration pattern classification
```kql
ExfiltrationPattern = case(
    UniqueDestinations >= 10,
    "Scattered exfiltration — data sent to multiple destinations",
    UniqueDestinations >= 5,
    "Multi destination exfiltration — possible staging servers",
    UniqueDestinations == 1,
    "Single destination exfiltration — likely C2 server",
    "Monitor"
)
```
The number of destinations tells you everything about the 
attack style:

| Destinations | Pattern | What it means |
|-------------|---------|---------------|
| 1 | Single destination | Data going directly to attacker C2 server |
| 5-9 | Multi destination | Data being staged across servers |
| 10+ | Scattered | Automated tool distributing stolen data |

A single destination is the clearest indicator of a C2 
server receiving stolen data. Multiple destinations suggest 
a more sophisticated operation with staging infrastructure.

### Data summary field
```kql
DataSummary = strcat(
    tostring(round(TotalDataSentMB, 0)),
    "MB sent to ",
    tostring(UniqueDestinations),
    " destination(s) over ",
    tostring(SessionCount),
    " sessions"
)
```
Every alert generates a plain English summary like:

> 2400MB sent to 3 destination(s) over 47 sessions

A SOC analyst immediately understands the scale of the 
incident without opening a single log.

### Ports used field
```kql
PortsUsed = make_set(DestinationPort, 10)
```
Captures which ports were used for the transfer. Attackers 
often use common ports like 443 to blend in with legitimate 
HTTPS traffic. Seeing unusual ports like 4444 or 8080 
alongside large transfers is a strong indicator of malicious 
activity.

### Risk scoring by volume
| Data Sent | Risk Score |
|-----------|------------|
| 500MB+ | Medium |
| 2000MB+ | High |
| 5000MB+ | Critical |

## How data exfiltration connects to your other detections
Data exfiltration is the final stage of the attack chain:

1. Attacker runs **password spray** → finds valid credentials
2. Attacker logs in → triggers **impossible travel** detection
3. Attacker escalates privileges → triggers **privilege escalation**
4. Attacker moves across network → triggers **lateral movement**
5. Attacker steals data → triggers this detection

If you see a data exfiltration alert alongside lateral movement 
and privilege escalation alerts for the same account — that is 
a full breach in progress requiring immediate response.

## MITRE ATT&CK
| Field | Value |
|-------|-------|
| Tactic | Exfiltration |
| Technique | T1041 — Exfiltration Over C2 Channel |

## Data source
- CommonSecurityLog (Firewall / Network logs)
- AzureNetworkAnalytics (Azure Network Watcher)

## Deployment
1. Open Microsoft Sentinel
2. Go to **Logs**
3. Paste the query from `data_exfiltration.kql`
4. Set schedule to run every **30 minutes**
5. Set alert threshold to **greater than 0 results**

## Tuning
| Parameter | Default | Description |
|-----------|---------|-------------|
| dataThresholdMB | 500 | Minimum MB to trigger alert |
| timeWindow | 1h | Time window to group transfers |
| lookback | 24h | How far back to look |
| knownSafeDestinations | 3 entries | Destinations to exclude |

Add your organisation's known backup and cloud sync 
destinations to `knownSafeDestinations` to reduce false 
positives significantly.

## False positives
- Legitimate cloud backups to known destinations
- Large file transfers to approved cloud storage
- Software update downloads
- Video conferencing data uploads

## Response actions
When this alert fires:
1. Identify the source IP and user account immediately
2. Check DestinationList — are these known malicious IPs
3. Cross reference with lateral movement and privilege 
   escalation alerts for the same account
4. Block the destination IPs at the firewall immediately
5. Preserve network logs as evidence before isolating

## Author
Marvellous Ekwomadu
Built independently as part of the Marvellous Security Lab