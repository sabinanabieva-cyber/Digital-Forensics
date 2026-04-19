# Finding 3: Malicious API Hook Analysis

## Overview
The apihooks Volatility plugin identified a malicious inline 
API hook in wsmprovhost.ex (PID 464) with an unknown hooking 
module. This is a strong indicator of injected malicious code 
intercepting and redirecting API calls to execute malicious 
functionality.

---

## Background

### What is API Hooking?
API hooking is a technique used to intercept function calls 
made by a process. When a program calls a Windows API function, 
the hook redirects execution to malicious code before (or 
instead of) the legitimate function. Malware uses this to:
- Monitor and steal data passing through API calls
- Modify return values to hide malicious activity
- Redirect execution to injected shellcode

### What is an Inline/Trampoline Hook?
An inline hook overwrites the first few bytes of a legitimate 
function with a JMP (jump) instruction that redirects execution 
to malicious code. The original bytes may be saved elsewhere 
to maintain normal appearance.

Normal function entry:
0x7ffb8a616230  MOV EDI, EDI
0x7ffb8a616232  PUSH EBP
0x7ffb8a616234  MOV EBP, ESP
Hooked function entry:
0x7ffb8a616230  JMP 0x7ffb8a61623a   ← overwrites legitimate instructions
0x7ffb8a616232  UD2
0x7ffb8a616234  JMP QWORD [RIP+0xefe]

### What Does <unknown> Hooking Module Mean?
A legitimate hook always belongs to an identifiable, 
file-backed module (e.g. an antivirus DLL). When Volatility 
cannot attribute a hook to any known loaded module, it labels 
it as <unknown>. This means the hook resides in private, 
injected memory with no corresponding file on disk — a 
definitive indicator of malicious activity.

---

## Methodology
1. Ran apihooks plugin against the Deepship memory image
2. Filtered results for Process 464 (wsmprovhost.ex)
3. Identified hooks with Hooking module: <unknown>
4. Located the InitPlugin hook in pspluginwkr-v3.dll
5. Analyzed the disassembly to find the JMP destination
6. Confirmed JMP points to injected private memory

---

## Evidence

### Hook Details

| Property | Value |
|----------|-------|
| Process | wsmprovhost.ex (PID 464) |
| Hook Mode | Usermode |
| Hook Type | Inline/Trampoline |
| Victim DLL | pspluginwkr-v3.dll |
| Hooked Function | InitPlugin |
| Function Address | 0x7ffb8a616230 |
| Hook Address | 0x7ffb34490d88 |
| Hooking Module | **\<unknown\>** |
| JMP Destination | **0x7ffb8a61623a** |

### Disassembly Output

```asm
0x7ffb8a616230  eb08             JMP 0x7ffb8a61623a  ← redirects to injected code
0x7ffb8a616232  0f0b             UD2
0x7ffb8a616234  ff25fe0e0000     JMP QWORD [RIP+0xefe]
0x7ffb8a61623a  ff25000f0000     JMP QWORD [RIP+0xf00]
0x7ffb8a616240  cc               INT 3
```

![apihooks output showing unknown hooking module](../screenshots/apihooks-unknown-module.png)

### Key Indicators
- **Hooking module is \<unknown\>** — no legitimate DLL owns this hook
- **First instruction is a JMP** — classic inline hook signature
- **JMP destination 0x7ffb8a61623a** — points to injected private memory
- **Inline/Trampoline type** — first bytes of function overwritten
- **Victim is pspluginwkr-v3.dll** — Windows PowerShell plugin worker DLL
- **InitPlugin targeted** — intercepts plugin initialization

### Execution Flow After Hook
wsmprovhost.ex calls InitPlugin
↓
Reaches 0x7ffb8a616230 (function entry)
↓
JMP 0x7ffb8a61623a  ← hook redirects execution
↓
Injected malicious code executes
↓
(may or may not return to legitimate function)

---

## Kernelmode Hooks Assessment

All Kernelmode hooks found in the apihooks output were 
attributed to known, legitimate Windows drivers:

| Hooking Module | Type | Assessment |
|----------------|------|------------|
| NETIO.SYS | Kernelmode | Legitimate - Windows Network I/O |
| dump_xencrsh.sys | Kernelmode | Legitimate - Xen hypervisor driver |
| tm.sys | Kernelmode | Legitimate - Transaction Manager |
| wfplwfs.sys | Kernelmode | Legitimate - Windows Filtering Platform |

**No Kernelmode hooks with \<unknown\> were found** — the 
malicious hooking activity was confined to Usermode.

---

## Corroborating Evidence
This finding directly supports the rootkit detection finding. 
The same process (wsmprovhost.ex, PID 464) was found hidden 
from pslist via DKOM while simultaneously containing malicious 
API hooks — confirming this process is fully compromised.

See: [Rootkit Detection](rootkit-indicators.md)<img width="637" height="145" alt="image" src="https://github.com/user-attachments/assets/f3a84e99-ff5c-4f78-86b1-51b3179afd2a" />


---

## Assessment
Malware injected code into wsmprovhost.ex (PID 464) and 
placed an inline hook on the InitPlugin function in 
pspluginwkr-v3.dll. The unknown hooking module confirms 
the hook does not belong to any legitimate loaded module, 
it resides in private injected memory. This technique allows 
the malware to intercept PowerShell plugin initialization, 
potentially monitoring, modifying, or hijacking PowerShell 
execution on the compromised system.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Relevance |
|-------------|------|-----------|
| T1179 | Hooking | Inline API hook on InitPlugin |
| T1055 | Process Injection | Injected code performing the hook |
| T1059.001 | PowerShell | pspluginwkr-v3.dll is a PowerShell component |
| T1014 | Rootkit | Combined with DKOM hiding of same process |

---

## Recommendations
- Dump and analyze the injected code at 0x7ffb8a61623a
- Investigate all PowerShell activity on the compromised host
- Check for lateral movement originating from wsmprovhost.ex
- Review Windows Remote Management (WinRM) logs as 
  wsmprovhost.ex is the WinRM provider host process
- Isolate the endpoint immediately to prevent further compromise

