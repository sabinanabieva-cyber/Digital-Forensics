# Finding 4: Injected Code Detection via Malfind

## Overview
The malfind Volatility plugin identified memory regions 
containing indicators of injected malicious code. Suspicious 
memory regions were flagged based on three key markers, 
executable permissions, private memory, and VadS tags,
consistent with process injection techniques used by malware.

---

## Background

### What is Process Injection?
Process injection is a technique where malware writes and 
executes malicious code within the address space of a 
legitimate process. This allows malware to:
- Hide inside trusted processes
- Evade process-based security controls
- Inherit the privileges of the host process
- Bypass application whitelisting

### How Malfind Works
Malfind identifies suspicious memory regions by looking 
for three markers that together indicate injected code:

| Marker | Description |
|--------|-------------|
| **PAGE_EXECUTE_READWRITE** | Memory is both writable and executable — legitimate code regions are normally execute-only |
| **PrivateMemory: 1** | Memory is not backed by any file on disk — legitimate DLLs and executables map to files |
| **VadS Tag** | Virtual Address Descriptor tag indicating private unmapped memory with no file association |

When all three markers are present together, malfind flags 
the region as potentially containing injected code.

### MZ Header Significance
An MZ header (bytes 4D 5A) at the start of a flagged region 
indicates a full PE (Portable Executable) file was injected 
into memory — suggesting process hollowing or reflective 
DLL injection rather than simple shellcode.

---

## Methodology
1. Ran malfind plugin against the Deepship memory image
2. Reviewed flagged memory regions for all three markers
3. Examined hex dumps for MZ headers indicating PE injection
4. Cross-referenced suspicious PIDs with other plugin findings
5. Assessed each finding in context of overall investigation

---

## Evidence


### Malfind Markers Explained
Vad Tag: VadS                    <- private unmapped memory
Protection: PAGE_EXECUTE_READWRITE  <- writable AND executable
Flags: PrivateMemory: 1          <- not backed by any file on disk

![malfind output showing injected code markers](../screenshots/malfind-injected-code.png)<img width="623" height="117" alt="image" src="https://github.com/user-attachments/assets/77155909-8e9c-4c17-b71c-6434d2e1ae73" />


### Key Indicators Per Flag

#### PAGE_EXECUTE_READWRITE
Normal legitimate memory:    PAGE_EXECUTE_READ
Suspicious injected memory:  PAGE_EXECUTE_READWRITE
↑
Writable at runtime =
code written into memory

#### PrivateMemory: 1
Legitimate DLL:   Backed by file on disk (PrivateMemory: 0)
Injected code:    No file on disk       (PrivateMemory: 1)

#### VadS Tag
VadF / Vad = file-backed memory   Normal
VadS        = private memory      Suspicious when executable

### Connection to API Hook Finding
The injected code detected by malfind is directly related 
to the API hook finding. The hook in wsmprovhost.ex (PID 464) 
pointed to address 0x7ffb8a61623a,  private injected memory 
with no file backing. This is the same type of memory region 
malfind is designed to detect.

API Hook JMP destination: 0x7ffb8a61623a
|
Private executable memory
|
Detected by malfind as
PAGE_EXECUTE_READWRITE
PrivateMemory: 1
VadS tag

---

## False Positive Consideration
Not every malfind result is malicious. Legitimate software 
that uses Just-In-Time (JIT) compilation such as .NET and 
Java also creates executable private memory regions. Always 
cross-reference malfind results with:

| Check | Purpose |
|-------|---------|
| Process context | Is it a known JIT process? |
| MZ header present | Indicates full PE injection |
| Other plugin findings | Corroborated by apihooks or ldrmodules? |
| Hooking module unknown | Confirms malicious origin |

In this investigation malfind findings are corroborated by:
- API hooks with unknown hooking module in same process
- DKOM rootkit hiding the same process from pslist
- No JIT-based software identified to explain the regions

---

## Corroborating Evidence
This finding directly supports and is supported by both 
the rootkit detection and API hook findings. All three 
point to the same compromised process — wsmprovhost.ex 
(PID 464).

- [Rootkit Detection](rootkit-indicators.md)
- [API Hook Analysis](api-hooks.md)

---

## Assessment
Malfind identified memory regions consistent with injected 
malicious code in the Deepship memory image. The presence 
of PAGE_EXECUTE_READWRITE permissions combined with 
PrivateMemory: 1 and VadS tags — with no legitimate JIT 
compiler to explain them — confirms malicious code was 
injected into process memory. This injected code is the 
same code performing the API hooks identified in Finding 3, 
establishing a clear chain of evidence linking process 
injection to API hooking within the compromised 
wsmprovhost.ex process.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Relevance |
|-------------|------|-----------|
| T1055 | Process Injection | Malicious code injected into process memory |
| T1055.001 | Dynamic-link Library Injection | PE file injected — MZ header present |
| T1055.012 | Process Hollowing | Legitimate process memory replaced with malicious code |
| T1620 | Reflective Code Loading | Code loaded without Windows loader involvement |

---

## Recommendations
- Dump all flagged memory regions for offline analysis
- Submit dumped regions to malware analysis sandbox
- Scan dumped PE files against threat intelligence feeds
- Check hash values against known malware databases
- Correlate injected code with known malware families
- Investigate all processes flagged by malfind not 
  explained by legitimate JIT compilation
