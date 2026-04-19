# Finding 1: Unauthorized RDP Access

## Overview
Evidence of an active Remote Desktop Protocol (RDP) session 
was identified in the memory image via the pstree Volatility 
plugin. The presence of rdpclip.exe alongside a second 
winlogon.exe instance is consistent with unauthorized remote 
access by the suspected malicious insider at Deepship.

---

## Background

### What is rdpclip.exe?
rdpclip.exe is the Remote Desktop Clipboard Monitor — a 
Windows process responsible for managing clipboard sharing 
between a local and remote machine during an RDP session. 
It only runs when an active RDP session is established, 
making its presence a reliable indicator of RDP activity.

### What is rdpinput.exe?
rdpinput.exe handles touch and pen input redirection during 
an RDP session. Its presence as a child of rdpclip.exe 
further confirms an active RDP connection was established.

### Why is a Second winlogon.exe Significant?
winlogon.exe is a per-session singleton, one instance runs 
per active session. A second winlogon.exe appearing shortly 
before rdpclip.exe indicates a new user session was created, 
consistent with an RDP logon event.

---

## Methodology
1. Ran pstree plugin against the Deepship memory image
2. Searched for rdpclip.exe in the process tree output
3. Identified parent-child relationship and timestamps
4. Corroborated with second winlogon.exe instance
5. Compared timestamps to establish session timeline

---

## Evidence

### pstree Output: rdpclip.exe
svchost.exe (PID 2484, PPID 676)
     rdpclip.exe (PID 1072, PPID 2484)
     rdpinput.exe (PID 88, PPID 1072)

### Process Details

| Property | Value |
|----------|-------|
| Process | rdpclip.exe |
| PID | 1072 |
| PPID | 2484 (svchost.exe) |
| Start Time | 2017-12-28 03:06:41 UTC |
| Child Process | rdpinput.exe (PID 88) |

![pstree output showing rdpclip.exe](../screenshots/pstree-rdpclip.png)

### Supporting Evidence: Second winlogon.exe

| Property | First Instance | Second Instance |
|----------|---------------|-----------------|
| PID | 636 | 1368 |
| Start Time | 02:59:56 UTC | **03:06:38 UTC** |
| Assessment | Normal boot session | New RDP session |

### Session Timeline
02:59:56 UTC — System boots, first winlogon.exe (PID 636) starts
↓
03:06:38 UTC — Second winlogon.exe (PID 1368) appears
← new session established (RDP logon)
↓
03:06:41 UTC — rdpclip.exe (PID 1072) starts
← confirms RDP session active
↓
03:06:41 UTC — rdpinput.exe (PID 88) starts
← RDP input handling active

### Key Indicators

- **rdpclip.exe running** — only present during active RDP session
- **rdpinput.exe as child** — confirms RDP input handling active
- **Second winlogon.exe** — confirms new session created
- **Timestamp correlation** — winlogon and rdpclip start within 3 seconds
- **Start time of 03:06:41** — notably later than all system processes
- **No legitimate business justification** identified for remote access

---

## Corroborating Evidence
The remote access software finding further supports this 
investigation. winvnc.exe was also found running alongside 
a websockify tunnel, indicating multiple remote access 
methods were established by the insider.

See: [Remote Access Software](remote-access.md)<img width="646" height="358" alt="image" src="https://github.com/user-attachments/assets/c815f698-a72e-42da-b70f-1aaa678988f4" />


---

## Assessment
The presence of rdpclip.exe (PID 1072) and rdpinput.exe 
(PID 88) alongside a second winlogon.exe session starting 
at 03:06:38 UTC strongly confirms an unauthorized RDP session 
was actively established during the timeframe of the 
investigation. The timing correlation between the second 
winlogon and rdpclip startup is consistent with a deliberate 
remote logon event by the suspected malicious insider. 
Combined with the discovery of winvnc and websockify, 
this system had multiple simultaneous remote access channels 
active — a hallmark of insider threat activity.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Relevance |
|-------------|------|-----------|
| T1021.001 | Remote Services: Remote Desktop Protocol | Unauthorized RDP session confirmed via rdpclip.exe |
| T1078 | Valid Accounts | Insider used legitimate credentials to establish RDP |
| T1563.002 | Remote Service Session Hijacking: RDP Hijacking | Potential session hijacking by insider |

---

## Recommendations
- Review Windows Security Event logs for Event ID 4624 
  (successful logon) around 03:06:38 UTC
- Identify the account used to establish the RDP session
- Review Event ID 4778 (session reconnected) and 
  4779 (session disconnected) for full RDP activity
- Determine the source IP address of the RDP connection
- Revoke credentials of suspected insider immediately
- Enable Network Level Authentication (NLA) if not already active
- Restrict RDP access via Windows Firewall to authorized IPs only

