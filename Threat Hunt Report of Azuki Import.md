**<u>Threat Hunt Report of Compromised IT Admin Workstation (Azuki Import/Export)</u>**

**Incident Date:** 19 November, 2025  
**Analyst:** Shegufa Haque  
**Compromised Host:** azuki-sl  
**Compromised Account:** kenji.sato

---

**📌 Executive Summary**

Between **19–20 November 2025 (UTC)**, Azuki Import/Export Co. experienced a targeted compromise resulting in the theft of sensitive supplier pricing data and shipping contract information. The investigation—supported entirely by **Microsoft Defender for Endpoint telemetry**—revealed a structured, multi-stage intrusion that progressed through every phase of the **full intrusion lifecycle**: *Initial Access → Execution → Persistence → Privilege Escalation → Credential Access → Discovery → Lateral Movement → Collection → Command & Control → Exfiltration → Anti-Forensics → Impact.*

Analysis confirmed that the attacker gained initial access by executing a malicious PowerShell downloader script. Once inside the environment, they deployed an obfuscated credential dumping tool, harvested administrative credentials, and used them to elevate privileges and move laterally toward more sensitive systems.

The attacker staged internal contracts and pricing data, compressed them into a ZIP archive, and exfiltrated the data using the **Discord web service**, blending malicious activity with legitimate HTTPS traffic over port **443**. The adversary then attempted to destroy forensic evidence by clearing key event logs and created a hidden **backdoor account (support)** to maintain persistent access. Lateral movement operations targeted an internal system at **10.1.0.188**, using built-in RDP tooling (mstsc.exe) to avoid detection.

The investigation confirms that this was a **highly coordinated, credential-based intrusion** involving data theft and anti-forensic actions. While exfiltrated data likely included sensitive pricing and supplier contract files, containment actions and further forensic follow-up can limit persistent exposure.

---

## Timeline of Events
| **Time (UTC)** | **Stage** | **Event / Artifact** |
|----|----|----|
| 2025-11-19T18:30:00Z | INITIAL ACCESS – Remote Access Source (Flag 1) | Repeated RDP connection attempts originating from external IP **88.97.178.12** (source of initial access). |
| 2025-11-19T18:36:18.503997Z | INITIAL ACCESS – Compromised User Account (Flag 2) | Successful RDP logon by **kenji.sato** from IP **88.97.178.12** (compromised account). |
| 2025-11-19T19:04:01.773778Z | DISCOVERY – Network Reconnaissance (Flag 3) | Execution of **"ARP.EXE" -a** to enumerate local network neighbors and MAC addresses. |
| 2025-11-19T19:05:33.7665036Z | DEFENCE EVASION – Malware Staging Directory (Flag 4) | Creation/usage of hidden staging directory **C:\ProgramData\WindowsCache** (malware staging). |
| 2025-11-19T18:49:27.7301011Z | DEFENCE EVASION – File Extension Exclusions (Flag 5) | Registry changes adding **3** file-extension exclusions to Windows Defender. |
| 2025-11-19T18:49:27.6830204Z | DEFENCE EVASION – Temporary Folder Exclusion (Flag 6) | Registry change adding **C:\Users\KENJI~1.SAT\AppData\Local\Temp** to Defender exclusion paths. |
| 2025-11-19T19:06:58.5778439Z | DEFENCE EVASION – Download Utility Abuse (Flag 7) | **certutil.exe** executed to download remote payload(s) (LOLBIN download activity). |
| 2025-11-19T19:07:46.9796512Z | PERSISTENCE – Scheduled Task Name (Flag 8) | Creation of scheduled task named **Windows Update Check** (schtasks /create observed). |
| 2025-11-19T19:07:46.9796512Z | PERSISTENCE – Scheduled Task Target (Flag 9) | Scheduled task configured to run **C:\ProgramData\WindowsCache\svchost.exe** (malware persistence). |
| 2025-11-19T19:06:58.7993762Z | COMMAND & CONTROL – C2 Server Address (Flag 10) | Outbound connection to C2 **78.141.196.6** initiated by malicious process (certutil download activity). |
| 2025-11-19T19:11:04.1766386Z | COMMAND & CONTROL – C2 Communication Port (Flag 11) | C2 communications observed over destination port **443** to **78.141.196.6** (HTTPS disguised C2). |
| 2025-11-19T19:07:21.0804181Z | CREDENTIAL ACCESS – Credential Theft Tool (Flag 12) | Download / execution of credential-dumping tool **mm.exe** (short filename in staging). |
| 2025-11-19T19:08:26.2804285Z | CREDENTIAL ACCESS – Memory Extraction Module (Flag 13) | **sekurlsa::logonpasswords** invoked (mm.exe / mimikatz module) to extract logon credentials. |
| 2025-11-19T19:09:21.3267384Z | COLLECTION – Data Staging Archive (Flag 14) | Creation of compressed archive **export-data.zip** inside staging for exfiltration. |
| 2025-11-19T19:09:21.3879432Z | EXFILTRATION – Exfiltration Channel (Flag 15) | Outbound upload activity to **discord** (cloud service used as exfil channel). |
| 2025-11-19T19:11:39.0934399Z | ANTI-FORENSICS – Log Tampering (Flag 16) | First cleared Windows event log: **Security** (wevtutil.exe cl Security observed). |
| 2025-11-19T19:09:53.0528848Z | IMPACT – Persistence Account (Flag 17) | Creation of backdoor local admin account **support** (net user / add + add to Administrators). |
| 2025-11-19T18:49:48.7079818Z | EXECUTION – Malicious Script (Flag 18) | PowerShell script **wupdate.ps1** created and executed from Temp/staging (automation script). |
| 2025-11-19T19:10:37.2625077Z | LATERAL MOVEMENT – Secondary Target (Flag 19) | Lateral movement attempts targeting internal IP **10.1.0.188** (cmdkey / mstsc usage). |
| 2025-11-19T19:10:41.372526Z | LATERAL MOVEMENT – Remote Access Tool (Flag 20) | Use of **mstsc.exe** (Windows RDP client) to attempt remote desktop access to target system. |

---

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|------|-----------|----|
| Initial Access | External Remote Services (RDP), Valid Accounts | T1133, T1078 |
| Discovery | Network Discovery | T1046 |
| Defense Evasion | Hidden Files & Directories, Modify Registry, Signed Binary Proxy Execution, Clear Windows Event Logs  | T1564.001, T1112, T1218.010, T1070.001 |
| Persistence | Scheduled Task, Create Account | T1053.005, T1136 |
| Command & Control | Web Protocols (HTTPS) | T1071.001 |
| Credential Access | OS Credential Dumping (LSASS), OS Credential Dumping (Mimikatz - sekurlsa) | T1003.001 |
| Collection | Archive Collected Data | T1560.001 |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 |
| Execution | PowerShell | T1059.001 |
| Lateral Movement | Use of Alternate Authentication Material, RDP | T1550, T1021.001 |

---

**🎯 Flag-by-Flag Findings**

### 🚩Flag 1: INITIAL ACCESS – Remote Access Source

**Objective:**  
Identify the external source IP used to establish the initial Remote Desktop Protocol (RDP) connection into the compromised system.

**Finding:**  
Multiple failed and successful RDP login attempts originated from an external IP address targeting the host *azuki-sl*.

**Evidence:**  
DeviceLogonEvents revealed repeated remote logon attempts from IP **88.97.178.12**, which ultimately resulted in a successful logon by the compromised user.

** KQL Query Used:**
```kql
DeviceLogonEvents 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where DeviceName contains "azuki-sl" 
| where ActionType == "LogonAttempted" 
| where RemoteIP != "-" 
| summarize FailedAttempts = count() by RemoteIP,AccountName,DeviceName, bin(Timestamp, 15m) 
| order by FailedAttempts desc 
```

**Why this matters:**  
Identifying the attacker’s entry point helps with attribution, blocking, and understanding the origin of the intrusion. This is critical for preventing reinfection.

**Time**: 2025-11-19T18:30:00Z

**Flag Answer:** **88.97.178.12**

<img width="1191" height="251" alt="image" src="https://github.com/user-attachments/assets/2d29963a-bc7f-43f4-926b-4da51bacfdf8" />


### 🚩Flag 2: INITIAL ACCESS – Compromised User Account

**Objective:**  
Determine which user account was successfully used by the attacker to authenticate during the RDP intrusion.

**Finding:**  
The compromised credentials belonged to **kenji.sato**, whose account successfully authenticated from the attacker’s IP.

**Evidence:**  
DeviceLogonEvents showed a successful remote logon by **kenji.sato** from the malicious IP during the incident timeframe.

**KQL Query Used:**

```kql
DeviceLogonEvents 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where DeviceName contains "azuki-sl" 
| where AccountName == "kenji.sato" 
| where RemoteIP == "88.97.178.12" 
| where ActionType == "LogonSuccess" 
| project Timestamp, AccountName, RemoteIP, DeviceName, LogonType, ActionType 
| order by Timestamp asc 
```

**Why this matters:**  
Identifying compromised credentials enables immediate remediation actions such as password resets, account audits, and privilege reviews.

Time: 2025-11-19T18:36:18.503997Z

**Flag Answer:** **kenji.sato**

<img width="1204" height="218" alt="image" src="https://github.com/user-attachments/assets/24cae701-b58f-4bed-821f-a30074900b42" />


### 🚩Flag 3: DISCOVERY – Network Reconnaissance

**Objective:**  
Identify the command used by the attacker to enumerate network neighbors and discover additional systems.

**Finding:**  
The attacker executed **ARP.EXE -a** to enumerate network devices and associated MAC addresses.

**Evidence:**  
DeviceProcessEvents logs show execution of the ARP utility with the “-a” argument shortly after initial access.

**KQL Query Used:**

```kql
DeviceProcessEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine has_all ("arp", "a") 
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine 
| order by Timestamp asc 
```

**Why this matters:**  
Network reconnaissance helps attackers map internal systems and plan lateral movement. Detecting this behavior is critical for early containment.

Time: 2025-11-19T19:04:01.773778Z

**Flag Answer:** **"ARP.EXE" -a**

<img width="1173" height="377" alt="image" src="https://github.com/user-attachments/assets/5c3b59fe-2324-4114-a1cb-4f328f2e3935" />


### 🚩Flag 4: DEFENCE EVASION – Malware Staging Directory

**Objective:**  
Identify the primary directory where the attacker stored malicious payloads.

**Finding:**  
Malware was staged in **C:\ProgramData\WindowsCache**, a hidden directory created by the attacker.

**Evidence:**  
Execution of directory creation commands followed by attribute modifications (e.g., “attrib +h”) indicates intentional hiding of this folder.

**KQL Query Used:**

```kql
DeviceProcessEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine matches regex @"(mkdir|md|New-Item).*" 
or ProcessCommandLine contains "attrib" 
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine 
| order by Timestamp asc
```

**Why this matters:**  
Attackers typically use hidden staging directories to store payloads, tools, and exfiltrated data, making detection more difficult.

Time: 2025-11-19T19:05:33.7665036Z

**Flag Answer:** **C:\ProgramData\WindowsCache**

<img width="1120" height="408" alt="image" src="https://github.com/user-attachments/assets/5b77f01b-8ec8-4245-8e26-09814eb21615" />


### 🚩Flag 5: DEFENCE EVASION – File Extension Exclusions

**Objective:**  
Determine how many file extensions the attacker excluded from Windows Defender scanning.

**Finding:**  
Three malicious file extensions were added to Windows Defender’s exclusion list.

**Evidence:**  
Registry modifications under *Windows Defender\Exclusions\Extensions* indicate multiple extension entries added during the attack.

**KQL Query Used:**

```kql
DeviceRegistryEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where RegistryKey contains "Windows Defender" and RegistryKey contains "Exclusions" 
| where ActionType == "RegistryValueSet" 
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName 
```

**Why this matters:**  
Extension exclusions allow malware with specific file types to evade detection, giving attackers uninterrupted execution capability.

Time: 2025-11-19T18:49:27.7301011Z

**Flag Answer:** **3**

<img width="1177" height="363" alt="image" src="https://github.com/user-attachments/assets/95d2ca15-5b7e-42b9-8324-d6f7332ad985" />


### 🚩Flag 6: DEFENCE EVASION – Temporary Folder Exclusion

**Objective:**  
Identify which temporary directory the attacker excluded from Windows Defender.

**Finding:**  
The temporary directory **C:\Users\KENJI~1.SAT\AppData\Local\Temp** was excluded from Defender scans.

**Evidence:**  
Registry entries under *Windows Defender\Exclusions\Paths* show this folder added during the attack timeline.

**KQL Query Used:**

```kql
DeviceRegistryEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where RegistryKey contains "Windows Defender" and RegistryKey contains "Exclusions" 
| where ActionType == "RegistryValueSet" 
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName
```

**Why this matters:**  
Excluding temporary folders allows attackers to freely download, extract, and execute tooling without triggering antivirus detection.

Time: 2025-11-19T18:49:27.6830204Z

**Flag Answer:** **C:\Users\KENJI~1.SAT\AppData\Local\Temp**

<img width="1159" height="328" alt="image" src="https://github.com/user-attachments/assets/7f9e2a73-e516-4bd0-85a3-b6bddc23c0f2" />


### 🚩Flag 7: DEFENCE EVASION – Download Utility Abuse

**Objective:**  
Identify the Windows-native binary abused by the attacker to download malicious files.

**Finding:**  
The attacker used **certutil.exe**, a legitimate Windows utility, to download external payloads.

**Evidence:**  
DeviceProcessEvents showed execution of certutil with command-line parameters containing URLs and output file paths.

**KQL Query Used:**

```kql
DeviceProcessEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine contains "url" 
| where FileName endswith ".exe" 
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, ActionType, ProcessCommandLine
```

**Why this matters:**  
Certutil is commonly used for living-off-the-land (LOLBIN) activity, allowing attackers to bypass security controls and blend in with legitimate processes.

Time: 2025-11-19T19:06:58.5778439Z

**Flag Answer:** **certutil.exe**

<img width="1299" height="343" alt="image" src="https://github.com/user-attachments/assets/a8ef58ef-5e30-4bfc-948b-282dff2d7c39" />


### 🚩Flag 8: PERSISTENCE – Scheduled Task Name

**Objective:**  
Determine the name of the malicious scheduled task created for persistence.

**Finding:**  
The attacker created a scheduled task named **"Windows Update Check"** to execute malware repeatedly.

**Evidence:**  
A schtasks.exe command with the /create flag was detected, referencing the task name.

**KQL Query Used:**

```kql
DeviceProcessEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine contains "" 
| where FileName endswith "schtasks.exe" 
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, ActionType, ProcessCommandLine
```

**Why this matters:**  
Scheduled tasks provide reliable persistence across reboots and are a common method used by attackers to maintain long-term access.

Time: 2025-11-19T19:07:46.9796512Z

**Flag Answer:** **Windows Update Check**

<img width="1128" height="389" alt="image" src="https://github.com/user-attachments/assets/ed5b98d1-4b7a-4ca9-b30b-854208fe5a36" />


### 🚩Flag 9: PERSISTENCE – Scheduled Task Target

**Objective:**  
Identify which executable was configured to run via the malicious scheduled task.

**Finding:**  
The scheduled task launched the malware located at **C:\ProgramData\WindowsCache\svchost.exe**.

**Evidence:**  
The /tr argument in the schtasks command specified this executable as the task’s action.

**KQL Query Used:**

```kql
DeviceProcessEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine contains "" 
| where FileName endswith "schtasks.exe" 
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, ActionType, ProcessCommandLine
```

**Why this matters:**  
Identifying the payload executed by the scheduled task confirms the malware path and assists in full remediation.

Time: 2025-11-19T19:07:46.9796512Z

**Flag Answer:** **C:\ProgramData\WindowsCache\svchost.exe**

<img width="1137" height="371" alt="image" src="https://github.com/user-attachments/assets/ae0336f5-53b9-40ac-be25-dcbaffccf6c7" />


### 🚩Flag 10: COMMAND & CONTROL – C2 Server Address

**Objective:**  
Identify the attacker’s command-and-control (C2) IP address used to communicate with the compromised host.

**Finding:**  
The C2 server contacted by the malicious process was **78.141.196.6**.

**Evidence:**  
Outbound network connections initiated by certutil.exe pointed to this external IP.

**KQL Query Used:**

```kql
DeviceNetworkEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where InitiatingProcessFileName contains "certutil.exe" 
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort
```

**Why this matters:**  
Identifying the C2 server allows for blocking, threat intelligence correlation, and detection of further activity tied to the attacker infrastructure.

Time: 2025-11-19T19:06:58.7993762Z

**Flag Answer:** **78.141.196.6**

<img width="1172" height="376" alt="image" src="https://github.com/user-attachments/assets/f843820e-d215-4a5e-a015-e40bc471e677" />


### 🚩Flag 11: COMMAND & CONTROL – C2 Communication Port

**Objective:**

Determine the destination port used by the malicious executable to communicate with the command-and-control server.

**Finding:**

The attacker’s malware connected to the C2 server over port **443**, disguising malicious traffic as standard HTTPS.

**Evidence:**

Outbound connections from the compromised host (azuki-sl) to the C2 IP 78.141.196.6 showed RemotePort 443.

**KQL Query Used:**

```kql
DeviceNetworkEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where RemoteIP == "78.141.196.6" 
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort
```

**Why this matters:**

Using port 443 enables attackers to blend malicious C2 traffic into normal encrypted web activity, making it extremely challenging to detect using traditional firewall or IDS rules.

Time: 2025-11-19T19:11:04.1766386Z

**Flag Answer: 443**

<img width="1162" height="226" alt="image" src="https://github.com/user-attachments/assets/f12397c7-24fb-466e-a3c5-7d9730617162" />


### 🚩Flag 12: CREDENTIAL ACCESS – Credential Theft Tool

**Objective:**

Identify the filename of the credential dumping tool used by the attacker.

**Finding:**

The attacker downloaded a renamed credential-dumping tool named **mm.exe** into the staging directory.

**Evidence:**

Process creation logs show certutil.exe downloading mm.exe, a short and suspiciously named executable.

**KQL Query Used:**

```kql
DeviceProcessEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine contains "certutil.exe" 
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine 
| order by Timestamp asc
```

**Why this matters:**

Short, obscure filenames are a common tactic for disguising well-known tools like Mimikatz, making manual detection harder and evading basic signatures.

Time: 2025-11-19T19:07:21.0804181Z

**Flag Answer: mm.exe**

<img width="1107" height="355" alt="image" src="https://github.com/user-attachments/assets/7e6cf284-0cb7-464b-867a-592cb5cb3232" />


### 🚩Flag 13: CREDENTIAL ACCESS – Memory Extraction Module

**Objective:**

Determine the module and command used to extract credentials from LSASS memory.

**Finding:**

The module sekurlsa::logonpasswords was invoked using the attacker’s credential-dumping utility.

**Evidence:**

Command line arguments of mm.exe show invocation of the Mimikatz command sekurlsa::logonpasswords.

**KQL Query Used:**

```kql
DeviceProcessEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine contains "mm.exe" 
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine 
| order by Timestamp asc
```

**Why this matters:**

This confirms the theft of plaintext credentials or NTLM hashes, allowing broad lateral movement and domain compromise.

Time: 2025-11-19T19:08:26.2804285Z

**Flag Answer: sekurlsa::logonpasswords**

<img width="1096" height="363" alt="image" src="https://github.com/user-attachments/assets/689daf3e-76a6-489b-a9c5-f15da88d6da4" />


### 🚩Flag 14: COLLECTION – Data Staging Archive

**Objective:**

Identify the stolen data archive prepared for exfiltration.

**Finding:**

The attacker created a ZIP archive named **export-data.zip** within the staging directory.

**Evidence:**

Process logs show .zip file creation via PowerShell’s Compress-Archive.

**KQL Query Used:**

```kql
DeviceProcessEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine contains ".zip" 
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine 
| order by Timestamp asc
```

**Why this matters:**

Compressed archives are a strong indicator of data staging prior to exfiltration and help determine the scope of potential data loss.

Time: 2025-11-19T19:09:21.3267384Z

**Flag Answer: export-data.zip**

<img width="1412" height="332" alt="image" src="https://github.com/user-attachments/assets/70d32dda-d461-4d9a-adc5-0d2a6dcd0302" />


### 🚩Flag 15: EXFILTRATION – Exfiltration Channel

**Objective:**

Identify which cloud service was used to exfiltrate data.

**Finding:**

The attacker used **Discord** as the exfiltration platform.

**Evidence:**

Outbound HTTPS requests and tool command lines indicated uploads to Discord, a common covert C2 and exfiltration method.

**KQL Query Used:**

```kql
DeviceNetworkEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where InitiatingProcessCommandLine has_any ("https", "curl") 
| project Timestamp, DeviceName, InitiatingProcessAccountName, Protocol, 
InitiatingProcessCommandLine, RemoteIP, RemotePort
```

**Why this matters:**

Discord-based exfiltration bypasses many corporate egress controls because it uses legitimate cloud infrastructure.

Time: 2025-11-19T19:09:21.3879432Z

**Flag Answer: discord**

<img width="1410" height="380" alt="image" src="https://github.com/user-attachments/assets/27a26e94-3065-4081-a47c-bb8e7a41a0cf" />


### 🚩Flag 16: ANTI-FORENSICS – Log Tampering

**Objective:**

Identify which Windows event log was cleared first by the attacker.

**Finding:**

The attacker cleared the **Security** event log first using wevtutil.exe.

**Evidence:**

Process logs show execution of wevtutil.exe cl Security, appearing earliest in the log-clearing sequence.

**KQL Query Used:**

```kql
DeviceProcessEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine contains "wevtutil.exe" 
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine 
| order by Timestamp asc
```

**Why this matters:**

Clearing the Security log indicates an intentional attempt to destroy critical evidence related to account misuse, privilege escalation, and lateral movement.

Time: 2025-11-19T19:11:39.0934399Z

**Flag Answer: Security**

<img width="1132" height="389" alt="image" src="https://github.com/user-attachments/assets/54b74280-68a2-40e3-b8ad-a15935f3dbcd" />


### 🚩Flag 17: IMPACT – Persistence Account

**Objective:**

Identify the hidden administrator account created by the attacker for long-term persistence.

**Finding:**

The attacker created a new backdoor account named **support**.

**Evidence:**

net user support /add followed by adding the account to Administrators was logged in DeviceProcessEvents.

**KQL Query Used:**

```kql
DeviceProcessEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine has_any ("net", "Administrators") 
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine 
| order by Timestamp asc
```

**Why this matters:**

Backdoor accounts provide attackers with stealthy, long-term access even after passwords are reset and malware is removed.

Time: 2025-11-19T19:09:53.0528848Z

**Flag Answer: support**

<img width="1099" height="427" alt="image" src="https://github.com/user-attachments/assets/7e3ebbd2-6796-4519-a90a-e1c28fc95ab2" />


### 🚩Flag 18: EXECUTION – Malicious Script

**Objective:**

Identify the malicious PowerShell script used to automate the attack chain.

**Finding:**

The script **wupdate.ps1** was created and executed from a temporary/staging folder.

**Evidence:**

File creation logs show the PowerShell script being written to Temp/AppData/ProgramData directories.

**KQL Query Used:**

```kql
DeviceFileEvents 
| where DeviceName contains "azuki-sl" 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where ActionType == "FileCreated" 
| where FileName endswith ".ps1" 
| where FolderPath has_any ("Temp", "AppData", "ProgramData") 
| project Timestamp, DeviceName, FileName, FolderPath 
| order by Timestamp asc
```

**Why this matters:**

PowerShell scripts provide flexible automation and are commonly used by threat actors to orchestrate multi-stage attacks.

Time: 2025-11-19T18:49:48.7079818Z

**Flag Answer: wupdate.ps1**

<img width="1144" height="372" alt="image" src="https://github.com/user-attachments/assets/38cf48ae-17f3-4a7c-a793-4869d18ff64b" />


### 🚩Flag 19: LATERAL MOVEMENT – Secondary Target

**Objective:**

Identify the target IP address for lateral movement attempts.

**Finding:**

The attacker targeted the internal system **10.1.0.188** using cmdkey and mstsc.

**Evidence:**

Command lines showed credential caching (cmdkey) and remote desktop commands (mstsc) referencing 10.1.0.188.

**KQL Query Used:**

```kql
DeviceProcessEvents 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where DeviceName contains "azuki-sl" 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine has_any ("cmdkey", "mstsc") 
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessRemoteSessionIP 
| order by Timestamp asc
```

**Why this matters:**

Identifying the lateral movement path is critical for containing breaches and assessing which systems may now be compromised.

Time: 2025-11-19T19:10:37.2625077Z

**Flag Answer: 10.1.0.188**

<img width="1137" height="336" alt="image" src="https://github.com/user-attachments/assets/994a1efa-ab95-4196-b6e8-f42f2aeadb1e" />


### 🚩Flag 20: LATERAL MOVEMENT – Remote Access Tool

**Objective:**

Identify the remote access tool used to attempt lateral movement.

**Finding:**

The attacker used **mstsc.exe**, the built-in Windows Remote Desktop Client.

**Evidence:**

Process logs captured mstsc.exe invocations with remote IP arguments.

**KQL Query Used:**

```kql
DeviceProcessEvents 
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20)) 
| where DeviceName contains "azuki-sl" 
| where AccountName == "kenji.sato" 
| where ProcessCommandLine has_any ("cmdkey", "mstsc") 
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessRemoteSessionIP 
| order by Timestamp asc
```

**Why this matters:**

Living-off-the-land remote tools like MSTSC blend seamlessly into normal admin operations, making lateral movement extremely difficult to detect.

Time: 2025-11-19T19:10:41.372526Z

**Flag Answer: mstsc.exe**

<img width="1134" height="381" alt="image" src="https://github.com/user-attachments/assets/db547b55-9cdf-4943-bfdf-9e4e7351f719" />

---

**🚨 After Action Recommendations**

- **Reset all compromised credentials**, including kenji.sato and any cached tokens (cmdkey).

- **Remove the backdoor account (support)** and audit all local accounts for unauthorized additions.

- **Rebuild or fully reimage** the compromised system (azuki-sl) to ensure malware remnants (svchost.exe, wupdate.ps1, mm.exe) are eliminated.

- **Block known malicious infrastructure**, including C2 IP 78.141.196.6 and Discord exfiltration endpoints.

- **Implement strict RDP restrictions**, including MFA, network-level authentication, and IP allowlisting.

- **Enhance Windows Defender configuration** by restoring deleted exclusions and preventing modification by non-admin users.

- **Deploy LSASS protection** (Credential Guard, RunAsPPL) to prevent future password dumping.

- **Implement outbound network monitoring** to detect unusual HTTPS uploads to cloud services like Discord.

- **Enable event log forwarding & tamper alerts** to detect any future log clearing attempts.

- **Perform a full lateral movement scoping** on the targeted host 10.1.0.188 to ensure the attacker did not compromise it.










