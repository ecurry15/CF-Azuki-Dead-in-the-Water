# 🕵️‍♂️ Threat Hunt Report: Azuki Breach CF
<img width="340" height="610" alt="Azuki" src="https://github.com/user-attachments/assets/990cbaa6-3b4d-45b8-ab67-49646b289572" />


**Analyst:** Edward Campbell  
**Investigation Date:** 7-January-2026  
**Incident Date:** 27-November-2025  

## 🎯 EXECUTIVE SUMMARY

**What Happened:**  

On November 19, 2025, at 18:36UTC, Azuki Import/Export Trading Co. was compromised when an attacker accessed an IT admin VM by using stolen RDP credentials. A week later, ransom notes were found across every system.

---
## 🖥️ INCIDENT DETAILS
### **Timeline Overview**

- **First Malicious Activity:** 19 November 2025 18:36:18.503997Z
- **Last Observed Activity:** 22 November 2025 00:38:47.8327343Z
- **Total Duration:** 54 hours 2 minutes

### **Attack Overview**

- **Affected Systems:** azuki-sl, azuki-adminPC, azuki-FS01, azuki-BackupSrv
- **Attacker IP Address:** 88.97.178.12
- **Investigation Tool:** Microsoft Defender for Endpoint (MDE)
  
## 🧬 MITRE ATT&CK Mapping (Attack Chain)

| Tactic | Technique ID | Description |
|-------|--------------|-------------|
| **Execution (TA0002)** | T1059.001 | PowerShell was used to run the malicious script `wupdate.ps1`. |
| **Persistence (TA0003)** | T1053.005 | A Scheduled Task was created to run the malicious payload. |
| **Defense Evasion (TA0005)** | T1564.001 / T1036.008 / T1105 | Attacker used hidden directories, file-type masquerading, and abused `certutil.exe` to download tools. |
| **Discovery (TA0007)** | T1016 | `arp -a` and `ipconfig /all` used to enumerate local network configuration. |
| **Credential Access (TA0006)** | T1003.001 | Mimikatz was used for credential dumping. |
| **Lateral Movement (TA0008)** | T1021.001 | `mstsc.exe /V:<IP>` used to attempt RDP lateral movement. |
| **Command & Control (TA0011)** | T1071.001 | HTTPS (port 443) used for C2 to external IP. |
| **Impact (TA0040)** | T1136.001 | Backdoor account `support` created for persistent access. |



---




## :triangular_flag_on_post: Flag 1 - 3 – How was the Backup Server Accessed? 

**Finding**: 

**Thoughts**: 

**KQL Query**:
```

```
<img  />


---
## :triangular_flag_on_post: Flag 4 & 5 – How did the attacker find Backup directory contents & backup archives?

**Finding**: 

**Notes**:  

**KQL Query**:
```

```
<img  />
---

## :triangular_flag_on_post: Flag 6 – What command enumerated local accounts?

**Finding**: 

**Thoughts**: 

**KQL Query**:
```

```
<img />


---
## :triangular_flag_on_post: Flag 7 – What command revealed scheduled jobs on the system?

**Finding**: 

**Thoughts**:

**KQL Query**:
```
```
<img/>

---

## :triangular_flag_on_post: Flag 8 – What command downloaded external tools?

**Finding**:

**KQL Query**:
```

```
<img />

---

## :triangular_flag_on_post: Flag 9 – What command accessed stored credentials?

**Finding**:   

**REG Path**: 

**KQL Query**:
```

```
<img />
---
## :triangular_flag_on_post: Flag 10 - 12 – How did the attacker disable backup services and destroy backup files?

**Finding**: 

**Command Used**:


**KQL Query**:
```

```
<img />
---

## :triangular_flag_on_post: Flag 13 & 14 – What tool did the attacker use to execute commands on remote systems?

**Finding**:

**Command Used**: 


**KQL Query**:
```

```
<img />

---
## :triangular_flag_on_post: Flag 15 – What payload was deployed?

**Finding**:  

**Commands Used**:

**KQL Queries**:
```
```
<img />

---
## :triangular_flag_on_post: Flag 16 & 17 – How did the attacker stop the shadow copy service and the backup engine?

**Finding**:  

**Thoughts**:


**KQL Query**:
```

```
<img  />


## :triangular_flag_on_post: Flag 18 – What command terminated processes to unlock files?

**Finding**: 

**KQL Query**:
```
```
<img  />
---

## :triangular_flag_on_post: Flag 19 - 22 – How did the attacker inhibit system recovery?

**Finding**: 

**Commands Used**:

**Thoughts**:

**KQL Query**:
```
```
<img  />
---
## :triangular_flag_on_post: Flag 23 & 24 – How did the attacker establish persistence? 

**Finding**: 

**Command Used**: 

**KQL Query**:
```
```
<img  />
---
## :triangular_flag_on_post: Flag 25 – What command deleted forensic evidence?

**Finding**:
**KQL Query**:
```

```
<img/>

---

## :triangular_flag_on_post: Flag 26 – What is the ransom note filename?

**Finding**: 

**Command Used**: 


**KQL Query**:
```
```
<img/>
---

## **APPENDIX**

### **Key Indicators of Compromise (IOCs)**

---

### 🔹 **IP Addresses**
| Type | Address |
|------|---------|
| Attacker IP | **88.97.178.12** |
| C2 Server | **78.141.196.6** |
| Download Server | **78.141.196.6** |
| Lateral Movement Target | **10.1.0.188** |

### 🔹 **File Hashes**
| File | SHA256 |
|------|--------|
| **svchost.exe** | `729214e56d3c54956ce9c2d93b238563bcedc8b80a5ca0b8e7636602d9c712d5` |
| **mm.exe** | `61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1` |
| **export-data.zip** | `7fea3a7e71c3a493effd91ff9084d602857954c96fdc04e022415069d39bef2e` |

### 🔹 **Accounts**
| Type | Username |
|------|----------|
| Compromised | **kenji.sato** |
| Attacker-Created | **support** |

### 🔹 **Domains**
- **discord.com**

---

**Report Completed By:** Edward Campbell

**Date:** 25 November 2025
