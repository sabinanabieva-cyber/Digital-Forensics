# Memory Forensics Investigation: Deepship Insider Threat

**Date:** April 2026  
**Course:** CYBV 400  
**Tools:** Volatility, Security Onion  
**Difficulty:** Intermediate  

---

## Scenario

As a SOC analyst at a university, I was tasked with investigating 
a suspected malicious insider at Deepship. Using Volatility memory 
forensics against a captured memory image, I identified multiple 
indicators of compromise including rootkit activity, unauthorized 
remote access, API hooking, and process injection.

---

## Objectives

- Identify malicious and suspicious processes in memory
- Detect rootkit activity using cross-referenced process lists
- Identify unauthorized RDP access
- Detect API hooks and injected code
- Map findings to the MITRE ATT&CK framework

---

## Tools & Plugins Used

| Tool | Purpose |
|------|---------|
| Volatility | Memory forensics framework |
| pslist | List active processes via kernel linked list |
| psscan | Scan raw memory for EPROCESS structures |
| psxview | Cross-reference multiple process listing methods |
| pstree | Display parent-child process relationships |
| malfind | Detect injected code and PE files in memory |
| apihooks | Identify hooked API functions |
| ldrmodules | Detect hidden/unlinked DLLs |
| dlllist | List loaded DLLs per process |

---

## Findings Summary

| # | Finding | Severity |
|---|---------|----------|
| 1 | Unauthorized RDP access via rdpclip.exe | High |
| 2 | Hidden process via DKOM rootkit (wsmprovhost.ex PID 464) | High |
| 3 | Malicious API hook with unknown hooking module | High |
| 4 | Injected code detected by malfind | High |
| 5 | Remote access software installation (winvnc + websockify) | High |
| 6 | Suspicious process chain via nssm.exe | Medium |

---

## Detailed Findings

- [Finding 1 - Unauthorized RDP Access](findings/rdp-investigation.md)
- [Finding 2 - Rootkit Detection](findings/rootkit-indicators.md)
- [Finding 3 - API Hook Analysis](findings/api-hooks.md)
- [Finding 4 - Injected Code](findings/injected-code.md)
- [Finding 5 - Remote Access Software](findings/remote-a
