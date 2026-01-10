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

#### November 25, 2025
- **05:39:10 UTC** — Attacker laterally moved from `10.1.0.108` to the Linux backup server (`10.1.0.189`) via SSH using the `backup-admin` account.

- **05:45:34 UTC** — External tooling was downloaded, backup archives were deleted, and `cron` was stopped and disabled to prevent future backups.

- **05:47:02 UTC** — Backup and shadow copy services were stopped, file-locking processes were terminated, all shadow copies were deleted, shadow storage was limited, Windows recovery was disabled, and the backup catalog was removed.

- **05:47:51 UTC** — System discovery was performed, local users and scheduled jobs were enumerated, and stored credentials were accessed.

- **05:58:35 UTC** — `PsExec64.exe` was used to deploy and execute the ransomware payload `silentlynx.exe` on Windows systems.

- **06:05:01 UTC** — Ransom note `SILENTLYNX_README.txt` was dropped, confirming successful encryption.

- **06:07:09 UTC** — Persistence was established via a registry autorun key and a scheduled task.

- **06:10:04 UTC** — The NTFS USN journal was deleted to hinder forensic investigation.




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

### 🔹 **File Hashes**
| File | SHA256 |
|------|--------|
| **SILENTLYNX_README.txt** | `ba9ee9747a60b34e6099ceb2f51a95b748a4f34d2114b5171756e8ae55f688ec` |
| **silentlynx.exe** | `edfae1a69522f87b12c6dac3225d930e4848832e3c551ee1e7d31736bf4525ef` |
| **PsExec64.exe** | `0ff6f2c94bc7e2833a5f7e16de1622e5dba70396f31c7d5f56381870317e8c46` |
| **destroy.7z** | `aca992dba6da014cd5baaa739624e68362c8930337f3a547114afdbd708d06a4` |

### 🔹 **Accounts**
| Type | Username |
|------|----------|
| Compromised | **kenji.sato** |
| Attacker-Created | **support** |

### 🔹 **Ip addresses**
| System | IP |
|------|----------|
| 1st connection to Backup sever  | **10.1.0.108** |
| Backup sever  | **10.1.0.189** |
| Windows Target  | **10.1.0.102** |

### 🔹 **Ransom Note**

<img width="505" height="593" alt="note" src="https://github.com/user-attachments/assets/23de8a0b-b05b-42a4-96c8-2afd29426910" />

---

**Report Completed By:** Edward Campbell

**Date:** 7 January 2025
