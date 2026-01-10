# 🕵️‍♂️ Threat Hunt Report: Azuki Breach CF
<img width="340" height="510" alt="Azuki" src="https://github.com/user-attachments/assets/990cbaa6-3b4d-45b8-ab67-49646b289572" />


**Analyst:** Edward Campbell  
**Investigation Date:** 7-January-2026  
**Incident Date:** 27-November-2025  

## 🎯 EXECUTIVE SUMMARY

**What Happened:**  

On November 19, 2025, at 18:36UTC, Azuki Import/Export Trading Co. was compromised when an attacker accessed an IT admin VM by using stolen RDP credentials. A week later, the attacker moved laterally to a Linux backup server. They stole credentials, deleted backups, and disabled backup services to eliminate recovery options. They then deployed ransomware across Windows systems, blocked all recovery mechanisms, encrypted files, and left a ransom note on all systems.

---
## 🖥️ INCIDENT DETAILS
### **Timeline Overview**

- Attacker laterally moved from `10.1.0.108` to the Linux backup server (`10.1.0.189`) via SSH using the `backup-admin` account.  - `2025-11-25T05:39:10.889728Z`
- Performed system discovery, enumerated users and scheduled jobs, and accessed stored credentials. - `2025-11-25T05:47:51.749736Z
`  
- Downloaded external tooling, deleted backup archives, and stopped/disabled cron to prevent recovery. - `2025-11-25T05:45:34.259149Z`
- Used `PsExec64.exe` to deploy and execute `silentlynx.exe` on Windows systems. - `2025-11-25T05:58:35.0610353Z`
- Stopped backup and shadow copy services, terminated file-locking processes, deleted shadow copies, limited shadow storage, disabled Windows recovery, and removed the backup catalog. - `2025-11-25T05:47:02.660493Z`
- Established persistence via a registry autorun key and a scheduled task. - `2025-11-25T06:07:09.8191737Z`
- Deleted the NTFS USN journal to hinder forensic investigation. - `2025-11-25T06:10:04.9141148Z`
- dropped A ransom note `SILENTLYNX_README.txt`. - `2025-11-25T06:05:01.1043756Z`


### **Attack Overview**

- **Affected Systems:** azuki-sl, azuki-adminPC, azuki-FS01, azuki-BackupSrv
- **Comprimised Account:** backup-admin
- **Investigation Tool:** Azure Log Analytics Workspace
  
## 🧬 MITRE ATT&CK Mapping (Attack Chain)

| Tactic | Technique ID | Description |
|-------|--------------|-------------|
| **Execution (TA0002)** | T1204.002 | Ransomware payload `silentlynx.exe` was executed on Windows systems. |
| **Persistence (TA0003)** | T1547.001 / T1053.005 | Attacker established persistence using a registry autorun key and a scheduled task. |
| **Defense Evasion (TA0005)** | T1562.001 / T1070.004 | Security processes were terminated and the NTFS USN journal was deleted to hinder investigation. |
| **Discovery (TA0007)** | T1083 / T1087.001 | Backup directories, files, scheduled jobs, and local user accounts were enumerated. |
| **Credential Access (TA0006)** | T1552.001 | Credentials were accessed from unsecured files on the backup server. |
| **Lateral Movement (TA0008)** | T1021.004 / T1021.002 | SSH was used to access the Linux backup server and PsExec was used to move laterally to Windows systems. |
| **Command & Control (TA0011)** | T1105 | External tooling was downloaded to the backup server using `curl`. |
| **Impact (TA0040)** | T1485 / T1489 / T1490 / T1486 | Backups were destroyed, services and recovery features were disabled, systems were encrypted, and a ransom note was dropped. |




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
