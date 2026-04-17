# Home Lab SIEM: Wazuh Deployment & Threat Detection

**Tools:** Wazuh 4.7.5 | Ubuntu 24.04 LTS | VirtualBox 7.2 | MITRE ATT&CK  
**Frameworks:** MITRE ATT&CK | Wazuh Detection Rules  
**Status:** Completed — April 2026

---

## Overview

This project documents the end-to-end deployment of a functional Security Information and Event Management (SIEM) home lab using Wazuh, an open-source security platform used in production SOC environments. The lab simulates a monitored enterprise endpoint sending logs to a centralized SIEM, with detection coverage mapped to the MITRE ATT&CK framework.

The objective was to move beyond theoretical security knowledge and build hands-on proficiency in log ingestion, alert triage, detection rule development, and adversary technique identification — core competencies for a SOC Analyst role.

---

## Environment

| Component | Details |
|---|---|
| Hypervisor | Oracle VirtualBox 7.2.6 on Windows |
| SIEM Server (VM 1) | Ubuntu 24.04 LTS — Wazuh Manager, Indexer, Dashboard |
| Monitored Endpoint (VM 2) | Ubuntu 24.04 LTS — Wazuh Agent v4.7.5 |
| Network | VirtualBox Host-Only Network (192.168.56.0/24) |
| SIEM Server IP | 192.168.56.10 (static) |
| Endpoint IP | 192.168.56.20 (static) |

Both VMs were configured with dual network adapters: NAT for internet access during installation and a Host-Only adapter for isolated inter-VM communication.

---

## Deployment Summary

Wazuh was deployed using the official all-in-one installer, which provisions the Wazuh Manager, OpenSearch-based Indexer, and web Dashboard in a single automated installation. The endpoint was enrolled via `agent-auth`, registering it with the manager and establishing an authenticated log forwarding channel.

One notable compatibility issue encountered: the default Wazuh repository served agent version 4.14.4, which was newer than the installed manager version (4.7.5) and rejected by the manager during registration. This was resolved by pinning the agent package to version 4.7.5 to match the server. This type of version mismatch is a realistic operational issue in environments where package repositories are not pinned.

---

## Simulated Attack Scenario

Four adversary techniques were simulated on the monitored endpoint, each mapped to a MITRE ATT&CK technique. All activity was contained within the isolated lab network.

### Exercise 1 — SSH Brute Force
**MITRE Technique:** T1110.001 — Brute Force: Password Guessing  
**Simulation:** 20 consecutive failed SSH login attempts using a non-existent username against the Wazuh server.  
**Detection:** Wazuh Rule 5710 fired on each failed attempt. Rule 5763 (brute force threshold) triggered after repeated failures within the detection window.  
**Alert Count:** 16 authentication failure alerts generated.

### Exercise 2 — Malicious Script Staged in /tmp
**MITRE Technique:** T1059 — Command and Scripting Interpreter  
**Simulation:** A bash script (`recon.sh`) was written to `/tmp`, made executable, and run. The script executed `whoami`, `id`, and `cat /etc/passwd` — standard post-exploitation reconnaissance commands.  
**Detection:** File integrity monitoring (FIM) detected the new executable in `/tmp`. Script execution generated additional process and command audit events.

### Exercise 3 — Privilege Escalation via Sudo
**MITRE Technique:** T1548 — Abuse Elevation Control Mechanism  
**Simulation:** Five consecutive failed `sudo` escalation attempts were executed on the endpoint.  
**Detection:** PAM authentication events triggered Rules 5501 and 5502. Sudo failure events were mapped to Defense Evasion, Persistence, and Privilege Escalation tactics in the MITRE ATT&CK dashboard.

### Exercise 4 — Local User Account Creation
**MITRE Technique:** T1136 — Create Account  
**Simulation:** A new local user (`suspicious_user`) was created using `useradd`.  
**Detection:** Wazuh Rule 5902 fired immediately, generating a Level 8 alert tagged with T1136 and mapped to the Persistence tactic. A corresponding new group creation alert (Rule 5901) also fired.

---

## Results

| Exercise | MITRE Technique | Rule ID | Alert Level | Tactic |
|---|---|---|---|---|
| SSH Brute Force | T1110.001 | 5710, 5763 | 5 | Credential Access, Lateral Movement |
| Script in /tmp | T1059 | FIM rules | 7 | Execution |
| Sudo Escalation | T1548 | 5501, 5502 | 3 | Privilege Escalation, Defense Evasion |
| User Creation | T1136 | 5902 | 8 | Persistence |

**Total alerts generated:** 58  
**MITRE tactics covered:** Credential Access, Defense Evasion, Lateral Movement, Privilege Escalation, Persistence, Initial Access

---

## Custom Detection Rule

A custom Wazuh rule was written to specifically flag executable files created in `/tmp`, a common malware staging location not covered with sufficient specificity by default rules.

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="local,syscheck,">
  <rule id="100001" level="10">
    <if_sid>553</if_sid>
    <match>/tmp/</match>
    <description>Executable file created in /tmp directory — potential staging behavior</description>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>
</group>
```

This rule raises the alert level to 10 for any file integrity event involving `/tmp`, improving signal quality over the default Level 7 generic FIM alert.

---

## Detection Gaps Identified

Identifying what a SIEM fails to detect is as important as documenting what it catches. The following gaps were noted during this exercise:

**No alert on script content analysis.** Wazuh detected that `recon.sh` was created in `/tmp` and executed, but did not inspect the script's contents. A more mature detection stack would flag `cat /etc/passwd` as a credential access indicator regardless of how it was invoked.

**Sudo failures did not trigger a dedicated escalation alert.** Individual PAM events fired, but no composite rule correlated repeated sudo failures into a single high-confidence privilege escalation alert. A custom rule correlating 3 or more Rule 5502 events within a 60-second window would improve detection fidelity here.

**No network-based detection.** The brute force simulation generated alerts on the target (wazuh-server) based on sshd logs, but no network-layer detection fired on the source (endpoint). In a production environment, a network IDS like Suricata integrated with Wazuh would catch the scanning behavior at the packet level before authentication attempts are even logged.

---

## Key Takeaways

Deploying and operating a SIEM — even in a lab environment — surfaces operational realities that documentation alone does not convey. Version compatibility between agents and managers, alert tuning to reduce noise, and the gap between what generates an alert and what constitutes a confirmed incident are all skills that only emerge through hands-on work.

The MITRE ATT&CK integration in Wazuh is particularly valuable for analyst development. Being able to look at raw rule IDs and immediately see the corresponding tactic and technique accelerates the process of building mental models for adversary behavior.

---

## Repository Contents

```
/
├── README.md                  — This document
├── local_rules.xml            — Custom detection rule
├── screenshots/
│   ├── agent_active.png       — Wazuh dashboard showing endpoint active
│   ├── security_events.png    — Alert dashboard after exercises
│   └── mitre_heatmap.png      — MITRE ATT&CK populated heatmap
```

---

*Frameworks: MITRE ATT&CK | Wazuh 4.7.5 | April 2026*  
*LinkedIn: https://www.linkedin.com/in/shankar-bettadapura*  
*Substack: https://shankarbettadapura.substack.com*
