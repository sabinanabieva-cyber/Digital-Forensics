# Finding 5: Remote Access Software Installation

## Overview
Evidence of deliberate remote access software installation 
was identified through a suspicious process chain discovered 
in the psscan output. The insider established a persistent 
remote access capability using winvnc.exe (VNC server) tunneled 
through websockify via node.exe, installed as a persistent 
Windows service using nssm.exe, indicating deliberate and 
sophisticated persistence by the malicious insider.

---

## Background

### What is winvnc.exe?
winvnc.exe is the server component of VNC (Virtual Network 
Computing), a remote desktop sharing system that allows 
full graphical control of a remote machine. While legitimate 
in some contexts, its unauthorized installation is a strong 
indicator of malicious remote access activity.

### What is websockify?
Websockify is an open source tool that creates a WebSocket 
to TCP proxy bridge. Adversaries use it to tunnel VNC 
traffic over WebSocket connections, making the remote 
access traffic:
- Harder to detect by network monitoring tools
- Able to blend in with normal web traffic
- Capable of bypassing firewall rules that allow HTTP/HTTPS

### What is nssm.exe?
nssm.exe (Non-Sucking Service Manager) is a tool that 
allows any application to be installed and run as a 
Windows service. Adversaries abuse it to:
- Make malicious software survive reboots
- Run processes in the background without user visibility
- Establish persistent footholds on compromised systems

### What is node.exe?
node.exe is the Node.js JavaScript runtime. In this context 
it was used to execute the websockify script, providing the 
WebSocket tunneling capability for the VNC connection.

---

## Methodology
1. Ran psscan plugin against the Deepship memory image
2. Identified suspicious process chain via PID/PPID relationships
3. Located nssm.exe spawning cmd.exe spawning node.exe
4. Identified winvnc.exe running as a service
5. Cross-referenced with dlllist to confirm websockify usage
6. Established full parent-child process relationship

---

## Evidence

### Suspicious Process Chain

services.exe (PID 676)
└── nssm.exe (PID 1572)          <- Service Manager abuse
├── conhost.exe (PID 1672) <- Console host
└── cmd.exe (PID 1776)     <- Command prompt
└── node.exe (PID 1792)  <- Runs websockify
└── websockify.cmd <- WebSocket-TCP proxy

### Process Details

| Process | PID | PPID | Role |
|---------|-----|------|------|
| nssm.exe | 1572 | 676 | Installs malicious setup as Windows service |
| cmd.exe | 1776 | 1572 | Launched by nssm to execute commands |
| node.exe | 1792 | 1776 | Executes websockify tunnel |
| winvnc.exe | 1060 | 952 | VNC server (remote desktop access) |

![psscan output showing suspicious process chain](../screenshots/psscan-process-chain.png)<img width="638" height="630" alt="image" src="https://github.com/user-attachments/assets/624f24b4-b41b-478a-821e-2a1d7b9d1460" />


### winvnc.exe Details

| Property | Value |
|----------|-------|
| Process | winvnc.exe |
| PID | 1060 |
| PPID | 952 (svchost.exe) |
| Start Time | 2017-12-28 03:06:41 UTC |
| Assessment | Unauthorized VNC server |

### Attack Architecture
Insider (remote location)
|
WebSocket connection (blends with web traffic)
|
websockify (node.exe, PID 1792)
| converts WebSocket to TCP
winvnc.exe (PID 1060)
|
Full graphical control of Deepship endpoint

### Key Indicators

- **nssm.exe spawning cmd.exe** — service manager abused 
  for persistence
- **node.exe as child of cmd.exe** — unusual for enterprise 
  environment
- **winvnc.exe running** — unauthorized VNC server active
- **websockify tunneling** — traffic obfuscation technique
- **Start time 03:06:41 UTC** — same timeframe as RDP access
- **No legitimate business justification** for VNC or 
  websockify in this environment

### Timeline Correlation

03:06:38 UTC — Second winlogon.exe appears (RDP session)
03:06:41 UTC — rdpclip.exe starts    (RDP confirmed)
03:06:41 UTC — winvnc.exe starts     (VNC server starts)
03:06:41 UTC — taskhostex.exe starts
<- all start simultaneously
<- suggests coordinated insider action

---

## Corroborating Evidence
This finding directly supports the RDP investigation finding. 
Both rdpclip.exe and winvnc.exe started at the exact same 
timestamp — 03:06:41 UTC — suggesting the insider established 
multiple simultaneous remote access channels in a coordinated 
manner.

See: [Unauthorized RDP Access](rdp-investigation.md)

---

## Assessment
The malicious insider at Deepship deliberately installed a 
multi-layered remote access infrastructure on the compromised 
endpoint. Using nssm.exe to register the setup as a persistent 
Windows service ensured the remote access capability would 
survive system reboots. The use of websockify to tunnel VNC 
traffic over WebSocket demonstrates technical sophistication 
and intent to evade network-based detection. The simultaneous 
startup of winvnc.exe alongside rdpclip.exe at 03:06:41 UTC 
indicates a coordinated effort to establish multiple remote 
access channels — a hallmark of deliberate insider threat 
activity rather than accidental compromise.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Relevance |
|-------------|------|-----------|
| T1219 | Remote Access Software | winvnc.exe unauthorized VNC server |
| T1021.005 | Remote Services: VNC | VNC used for remote graphical access |
| T1547.001 | Registry Run Keys / Startup Folder | nssm.exe establishes persistence |
| T1090 | Proxy | websockify used to tunnel and obfuscate VNC traffic |
| T1059.003 | Windows Command Shell | cmd.exe used in malicious service chain |
| T1569.002 | System Services: Service Execution | nssm.exe installs malicious service |

---

## Recommendations
- Immediately terminate winvnc.exe and node.exe processes
- Remove nssm.exe service registration from the system
- Block VNC ports (5900-5910) at the firewall
- Block WebSocket traffic from unauthorized endpoints
- Search all endpoints for nssm.exe, winvnc.exe, 
  and node.exe outside of approved software inventory
- Review all Windows services for unauthorized entries
- Conduct full network traffic analysis for WebSocket 
  tunneling activity
- Identify all systems the insider may have accessed 
  remotely via this infrastructure

  

