# Finding 2 — Rootkit Detection via DKOM

## Overview
A hidden process was identified by cross-referencing pslist 
and psscan output using the psxview plugin. The process was 
invisible to standard process enumeration but detectable via 
raw memory scanning — a classic indicator of Direct Kernel 
Object Manipulation (DKOM).

---

## Background

### What is DKOM?
Direct Kernel Object Manipulation (DKOM) is a rootkit technique 
where malware modifies the Windows kernel's doubly-linked process 
list (PsActiveProcessHead) by unlinking a malicious process from 
the list. This makes the process invisible to tools like pslist 
that walk the linked list, while the process continues running 
in memory.

### How psxview Detects It
psxview cross-references seven different process detection methods 
simultaneously. A legitimate running process should appear True 
in all columns. A process that is True in psscan but False in 
pslist (with no exit timestamp) is actively hiding.

---

## Methodology
1. Ran psxview plugin against the Deepship memory image
2. Identified discrepancies between pslist and psscan columns
3. Located wsmprovhost.ex (PID 464) with two entries
4. Confirmed absence of exit timestamp on suspicious entry
5. Corroborated with apihooks output showing unknown hooking module

---

## Evidence

### psxview Output — wsmprovhost.ex (PID 464)

| Memory Address | pslist | psscan | csrss | Other Columns |
|----------------|--------|--------|-------|---------------|
| 0x0000000016c7c900 | True | True | True | All True |
| 0x00000000835a8900 | **False** | **True** | **False** | **All False** |

![psxview output showing PID 464](../screenshots/psxview-rootkit-pid464.png)<img width="647" height="555" alt="image" src="https://github.com/user-attachments/assets/958537b5-1243-4421-9e7d-c7ad759e094b" />


### Key Indicators
- Second instance shows **False in pslist** but **True in psscan**
- **No exit timestamp** present despite being absent from pslist
- A legitimately terminated process would show an exit time
- Absence of exit time while hidden from pslist = active concealment
- All other columns False — process hiding from every detection method except raw memory scan

### DKOM Visualization

Normal linked list:
[svchost] <-> [wsmprovhost.ex] ↔ [explorer]
After DKOM manipulation:
[svchost] <-> [explorer]
 |
wsmprovhost.ex unlinked
but still running in memory
— found by psscan via raw scan

---

## Corroborating Evidence
This finding is supported by the API hooks analysis which found 
wsmprovhost.ex (PID 464) with a Hooking module: \<unknown\> — 
further confirming malicious activity within this process.

See: [API Hook Analysis](api-hooks.md)

---

## Assessment
wsmprovhost.ex (PID 464) at memory address 0x00000000835a8900 
is actively running but deliberately hidden from the kernel 
linked list using DKOM. The absence of an exit timestamp 
confirms the process did not terminate normally — it is 
concealed. This is a strong indicator of rootkit activity 
consistent with a malicious insider maintaining a hidden 
presence on the system.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Relevance |
|-------------|------|-----------|
| T1014 | Rootkit | DKOM used to hide process from pslist |
| T1055 | Process Injection | Malicious code injected into wsmprovhost.ex |
| T1036 | Masquerading | Process hiding behind legitimate Windows process name |

---

## Recommendations
- Investigate all activity associated with wsmprovhost.ex (PID 464)
- Cross-reference network connections from this PID
- Analyze injected code found at associated memory addresses
- Check for persistence mechanisms tied to this process

