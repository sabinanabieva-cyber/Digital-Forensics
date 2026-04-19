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
- [Finding 5 - Remote Access Software](findings/remote-access.md)

---

## Executive Summary
Memory forensic analysis of the Deepship endpoint revealed 
strong evidence of malicious insider activity. A hidden process 
(wsmprovhost.ex, PID 464) was found exhibiting rootkit behavior 
through Direct Kernel Object Manipulation (DKOM), making it 
invisible to standard process listing while remaining detectable 
via raw memory scanning. Malicious API hooks with an unknown 
hooking module were identified targeting pspluginwkr-v3.dll, 
intercepting the InitPlugin function and redirecting execution 
to injected code at address 0x7ffb8a61623a. Evidence of 
unauthorized RDP access was confirmed via rdpclip.exe (PID 1072) 
and a second winlogon session. Additionally, remote access 
software (winvnc + websockify via node.exe) was found installed 
as a service through nssm.exe, indicating deliberate persistence 
mechanisms were established by the insider threat.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Finding |
|-------------|------|---------|
| T1014 | Rootkit | DKOM process hiding |
| T1055 | Process Injection | Injected code in memory |
| T1179 | Hooking | API hooks in wsmprovhost.ex |
| T1021.001 | Remote Desktop Protocol | Unauthorized RDP via rdpclip.exe |
| T1219 | Remote Access Software | winvnc + websockify installation |
| T1547 | Boot or Logon Autostart | nssm.exe service persistence |
