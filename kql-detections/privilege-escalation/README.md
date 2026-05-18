# Privilege Escalation Detection

## What this detects
This rule detects when user accounts are assigned sensitive or 
administrative roles in Azure AD. Privilege escalation is one of 
the most critical events in any environment — an attacker who 
gains Global Administrator access owns the entire tenant.

This detection monitors every role assignment in real time and 
immediately flags when a sensitive role is granted, who granted 
it, and whether the user assigned it to themselves.

## Why this is different
Most basic rules simply log role changes. This detection adds 
intelligence on top of every assignment — telling the SOC analyst 
exactly what the role can do, how dangerous it is, and whether 
the escalation pattern looks suspicious.

### Sensitive role list
```kql
let sensitiveRoles = dynamic([
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "Conditional Access Administrator"
]);
```
Not all roles are equal. This detection maintains a curated list 
of the most dangerous roles in Azure AD — the ones an attacker 
would target to maximise their access. Only assignments to these 
roles trigger an alert, keeping noise low and signal high.

### Self escalation detection
```kql
EscalationType = case(
    InitiatedBy == TargetUser,
    "Self escalation — user assigned own privileges",
    "Third party escalation — admin assigned by another user"
)
```
This is the most powerful field in the detection. It compares 
who initiated the role assignment against who received it. If 
they are the same person — that is self escalation, one of the 
strongest indicators of a compromised admin account or a 
malicious insider.

A legitimate role assignment is always done by one admin for 
another user. A self assignment has almost no legitimate 
justification.

### Risk context field
```kql
RiskContext = case(
    TargetRole == "Global Administrator",
    "Full tenant control — highest possible privilege",
    TargetRole == "Conditional Access Administrator",
    "Can disable MFA and bypass access controls"
)
```
Every alert comes with a plain English explanation of what the 
assigned role can actually do. A SOC analyst who has never seen 
a particular role before immediately understands the blast radius 
without having to look it up.

### Risk scoring by role
| Role | Risk Score | Why |
|------|------------|-----|
| Global Administrator | Critical | Full tenant control |
| Privileged Role Administrator | Critical | Can assign any role |
| Security Administrator | High | Can modify security policies |
| Conditional Access Administrator | High | Can disable MFA |
| All others | Medium | Elevated but limited scope |

### CorrelationId field
```kql
CorrelationId
```
Links this alert back to the original audit event in Azure AD. 
If the analyst needs to investigate further they can use this ID 
to pull the full context of exactly what happened and when.

## How privilege escalation connects to your other detections
Privilege escalation rarely happens in isolation:

1. Attacker runs **password spray** → finds valid credentials
2. Attacker logs in → triggers **impossible travel** detection
3. Attacker assigns themselves Global Admin → triggers this detection
4. Attacker now owns the tenant

These four detections together map the complete kill chain from 
initial credential theft to full tenant compromise.

## MITRE ATT&CK
| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation |
| Technique | T1078 — Valid Accounts |
| Sub-technique | T1078.002 — Domain Accounts |

## Data source
- AuditLogs (Azure AD / Microsoft Entra ID)

## Deployment
1. Open Microsoft Sentinel
2. Go to **Logs**
3. Paste the query from `privilege_escalation.kql`
4. Set schedule to run every **5 minutes**
5. Set alert threshold to **greater than 0 results**

Note: This detection should run more frequently than others 
because a Global Administrator assignment is an emergency 
that requires immediate response.

## Tuning
| Parameter | Default | Description |
|-----------|---------|-------------|
| sensitiveRoles | 10 roles | List of roles that trigger alerts |
| lookback | 1d | How far back to look |

Add or remove roles from `sensitiveRoles` based on your 
organisation's role structure. Every role in the list should 
be one that would cause serious damage if assigned to a 
compromised account.

## False positives
- Planned admin provisioning by IT teams
- Helpdesk activity assigning standard roles
- Onboarding of new administrators
- PIM — Privileged Identity Management activations

## Response actions
When this alert fires:
1. Immediately verify with the initiating admin if the 
   assignment was planned
2. If self escalation — treat as critical, suspend account
3. Review all actions taken by the account after escalation
4. Check for impossible travel or brute force alerts on 
   the same account

## Author
Marvellous Ekwomadu
Built independently as part of the Marvellous Security Lab