# Brute Force Login Detection

## What this detects
This rule detects brute force login attacks against user accounts by 
monitoring failed authentication attempts in Azure AD sign-in logs. 
It catches both fast automated attacks and patient manual attackers 
who deliberately slow down to avoid detection.

## Why this is different
Most out-of-the-box brute force rules fire a single alert when a 
failure count hits a static threshold. This detection goes further:

### Two attack windows
- **Fast window (10 minutes)** — catches automated tools hitting 
hard and fast
- **Slow window (30 minutes)** — catches patient manual attackers 
spreading attempts to stay under the radar

A sophisticated attacker who knows standard thresholds will 
deliberately slow down and never trigger a basic rule. This 
detection catches them anyway.

### Attack classification
Every alert is automatically labelled:
- `Fast — automated attack` — likely a bot or scripted tool
- `Low and slow — manual attacker` — someone is personally 
targeting this account

This changes the entire response. A bot gets blocked at the 
firewall. A human attacker means the organisation is being 
targeted specifically — a completely different investigation.

### Risk scoring
Alerts are automatically prioritised:
| Failed Attempts | Risk Score |
|----------------|------------|
| 5+ | Medium |
| 10+ | High |
| 20+ | Critical |

A SOC analyst seeing 50 alerts knows exactly where to start.

### Success after failure flag
The most critical field in this detection. Flags whether the 
attacker may have eventually succeeded:
- `Investigate — possible successful breach` 
- `Monitor`

This is the difference between catching an attempt and catching 
an actual compromise.

### IP intelligence
- `DistinctIPs` — how many unique IPs were used
- `IPList` — full list of attacker IPs

One IP = single attacker. Twenty IPs = botnet. Completely 
different response required.

## MITRE ATT&CK
| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Technique | T1110 — Brute Force |
| Sub-technique | T1110.001 — Password Guessing |

## Data source
- SigninLogs (Azure AD / Microsoft Entra ID)

## Deployment
1. Open Microsoft Sentinel
2. Go to **Logs**
3. Paste the query from `brute_force_login.kql`
4. Set schedule to run every **10 minutes**
5. Set alert threshold to **greater than 0 results**

## Tuning
| Parameter | Default | Description |
|-----------|---------|-------------|
| fastThreshold | 5 | Failures to trigger fast alert |
| fastWindow | 10m | Time window for fast detection |
| slowThreshold | 5 | Failures to trigger slow alert |
| slowWindow | 30m | Time window for slow detection |

Adjust thresholds based on your organisation's baseline. 
Higher thresholds reduce false positives but risk missing 
low and slow attacks.

## False positives
- Scripted service accounts with bad credentials
- Bulk migration tools
- Users who frequently mistype passwords

## Author
Marvellous Ekwomadu
Built independently as part of the Marvellous Security Lab