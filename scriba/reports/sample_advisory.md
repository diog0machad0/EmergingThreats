---
tlp: WHITE
date: 2026-03-18
author: Security Joes
classification: Proprietary and Confidential
template: advisory
---

# Critical Telnetd Remote Code Execution Vulnerability (CVE-2026-32746)

## Security Advisory

# Executive Summary

A critical vulnerability (CVE-2026-32746) has been identified in multiple Telnet daemon
(telnetd) implementations, enabling unauthenticated remote code execution (RCE). The flaw
stems from improper handling of Telnet protocol negotiation sequences, allowing attackers
to send specially crafted packets to trigger memory corruption. Successful exploitation
could allow attackers to gain full system control without authentication, posing a
significant risk to legacy systems and embedded devices still relying on Telnet services.

# Details

CVE-2026-32746 is a memory corruption vulnerability affecting Telnet daemon services due
to improper parsing of Telnet option negotiation commands. The flaw occurs when the
telnetd service processes malformed IAC (Interpret As Command) sequences, leading to
buffer overflow or heap corruption.

Attackers can exploit this vulnerability by sending specially crafted Telnet packets to a
listening telnetd service *(typically TCP port 23)*. No authentication is required, making
it highly exploitable over exposed networks.

The vulnerability is particularly dangerous in environments where Telnet is still enabled
for remote administration, including legacy Unix/Linux systems, network appliances, and
embedded/IoT devices.

| CVE | Description | CVSSv3 score |
| --- | --- | --- |
| **CVE-2026-32746** | Telnetd memory corruption leading to unauthenticated RCE | **9.8 (Critical)** |

# Impact

Organizations with exposed Telnet services are at immediate risk, especially where Telnet
is used instead of secure protocols like SSH.

- Unauthenticated remote code execution
- Full system compromise (root-level access)
- Lateral movement within internal networks
- Potential deployment of ransomware or botnets
- Exploitation of legacy infrastructure and embedded systems

# Affected Product

The vulnerability impacts multiple telnetd implementations across Unix-like systems and
embedded environments.

| Product | Affected Version | Fixed Version |
| --- | --- | --- |
| GNU Inetutils telnetd | ≤ 2.5 | 2.6 and later |
| BusyBox telnetd | ≤ 1.36.0 | 1.36.1 and later |
| FreeBSD telnetd | 13.x / 14.x prior to patch | Patched releases (March 2026) |
| OpenBSD telnetd | Default builds prior to advisory | Patched builds (March 2026) |
| Embedded Linux (various vendors) | Varies (unpatched firmware) | Vendor-specific updates |

# Recommendations

- Immediately disable Telnet services on all systems where not strictly required.
- Apply vendor patches and firmware updates addressing CVE-2026-32746.
- Replace Telnet with secure alternatives such as SSH.
- Restrict network access to port 23 via firewalls and ACLs.
- Monitor network traffic for suspicious Telnet activity.
- Audit legacy and embedded devices for exposed Telnet services.
- Implement network segmentation to limit exposure.

# References

- <https://thehackernews.com/2026/03/critical-telnetd-flaw-cve-2026-32746.html>
- <https://nvd.nist.gov/vuln/detail/CVE-2026-32746>
- <https://www.suse.com/security/cve/CVE-2026-32746.html>
