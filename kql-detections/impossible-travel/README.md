# Impossible Travel Detection

## What this detects
This rule detects when a user account logs in from two geographic 
locations within a timeframe that is physically impossible to travel 
between. For example a user logging in from Lagos and then London 
within 30 minutes — no commercial flight covers that distance in 
that time.

This is a strong indicator of account compromise where an attacker 
in one country is using stolen credentials while the legitimate user 
is in another country.

## Why this is different
Most basic impossible travel rules simply compare two countries and 
fire an alert if they are different. This detection goes much further.

### Haversine formula — real geographic distance
```kql
DistanceKm = 6371 * 2 * asin(sqrt(
    sin((radians(Lat) - radians(PrevLat)) / 2) *
    sin((radians(Lat) - radians(PrevLat)) / 2) +
    cos(radians(PrevLat)) * cos(radians(Lat)) *
    sin((radians(Lon) - radians(PrevLon)) / 2) *
    sin((radians(Lon) - radians(PrevLon)) / 2)
))
```
This is the actual mathematical formula used in aviation and 
navigation to calculate the shortest distance between two points 
on a sphere. Most out-of-the-box rules just compare country codes. 
This rule calculates the real kilometre distance between the two 
login coordinates — far more precise and far harder to evade.

### Speed calculation
```kql
SpeedKmph = DistanceKm / TimeDiffHours
```
The rule calculates exactly how fast the user would have had to 
travel between the two logins. The threshold is set at 900km/h — 
the cruising speed of a commercial aircraft. Anything above that 
is physically impossible.

### Risk scoring based on speed
| Speed | Risk Score | What it means |
|-------|------------|---------------|
| 900+ km/h | Medium | Faster than possible by air |
| 2000+ km/h | High | Faster than a fighter jet |
| 5000+ km/h | Critical | Physically impossible by any means |

The faster the impossible travel, the more certain it is a 
compromise rather than a VPN or proxy.

### Travel summary field
```kql
TravelSummary = strcat(
    "Login from ", PrevCity, " (", PrevCountry, ") then ",
    City, " (", Country, ") in ",
    round(TimeDiffHours, 2), " hours — ",
    round(DistanceKm, 0), "km at ",
    round(SpeedKmph, 0), "km/h"
)
```
Every alert generates a human readable summary like:

> Login from Lagos (Nigeria) then London (United Kingdom) 
> in 0.5 hours — 4800km at 9600km/h

A SOC analyst can understand exactly what happened without 
opening a single log.

### Minimum distance filter
```kql
| where DistanceKm > minDistanceKm
```
Filters out logins within 100km of each other. This removes 
GPS imprecision noise where two logins in the same city 
appear as different coordinates.

### Only successful logins
```kql
| where ResultType == "0"
```
Only fires on successful authentications. A failed login from 
another country is suspicious but not a confirmed compromise. 
A successful one means the attacker has valid credentials and 
is actively using them.

## MITRE ATT&CK
| Field | Value |
|-------|-------|
| Tactic | Initial Access / Defense Evasion |
| Technique | T1078 — Valid Accounts |

## Data source
- SigninLogs (Azure AD / Microsoft Entra ID)

## Deployment
1. Open Microsoft Sentinel
2. Go to **Logs**
3. Paste the query from `impossible_travel.kql`
4. Set schedule to run every **1 hour**
5. Set alert threshold to **greater than 0 results**

## Tuning
| Parameter | Default | Description |
|-----------|---------|-------------|
| maxSpeedKmph | 900 | Speed threshold in km/h |
| minDistanceKm | 100 | Minimum distance to filter GPS noise |
| lookback | 1d | How far back to look |

Lower the speed threshold to catch VPN users switching 
servers. Raise the minimum distance to reduce noise in 
dense urban environments.

## False positives
- VPN users switching between servers in different countries
- Tor exit nodes appearing in unexpected locations
- Split tunnelling configurations
- Proxy services routing traffic internationally

## Author
Marvellous Ekwomadu
Built independently as part of the Marvellous Security Lab