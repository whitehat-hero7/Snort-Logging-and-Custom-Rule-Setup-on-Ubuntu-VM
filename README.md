# Snort Logging Setup and Custom Rules on Ubuntu VM

## Objective
**`Snort`** is a powerful open-source **`Intrusion Detection and Prevention System (IDS/IPS)`** designed to analyze network traffic and detect potential threats in real time. This comprehensive guide walks you through the step-by-step process of configuring **`Snort`** logging and custom rule creation within an **`Ubuntu VM`** running on a **`VirtualBox`** home lab. By following this guide, you’ll gain hands-on experience in monitoring network activity, identifying security threats, and fine-tuning **`Snort’s`** detection capabilities to generate custom alerts for suspicious behavior, enhancing both your cybersecurity skills and your ability to respond to real-world attacks.

<img src="https://github.com/whitehat-hero7/Snort-Installation-in-Ubuntu-Virtual-Machine-VM/blob/main/docs/snort_logo.PNG">

## 1. Snort Logging Setup
**`Snort`** offers versatile logging options, including **`Plain Text`**, **`JSON`**, **`PCAP`**, and more, allowing flexible data analysis and integration with other security tools. In this exercise, we'll configure and learn different aspects of Snort’s logging settings, set up proper directory permissions, test the logging output, and address common troubleshooting scenarios you might encounter when using **`Plain Text`** and **`PCAP`** logging.

### 🔸Step 1: Choose a Logging Format

**`Snort`** supports multiple logging formats depending on your needs:


| **Format** | **Use Case** |
|-|-|
|Plain Text (`alert_fast`) | Simple, human-readable alerts|
|PCAP (`log_pcap`) | Captures full packet data for deep analysis|
|JSON (`alert_json`) | Structured logs for SIEMs like Splunk or ELK|
|Unified2 (`log_unified2`) | Optimized binary format for Barnyard2 processing|
|Syslog (`log_syslog`) | Sends alerts to a centralized syslog server|
|Full (`log_full`) | Logs complete packet payloads and metadata|
|CSV ( `log_csv`) | Stores alerts in a structured, comma-separated format|

(**Note:** **`JSON`** format was introduced in **`Snort 3`**, for this exercise we are running on **`Snort version 2.9.20`**, so it is not available for us to configure at this time).

### 🔸Step 2: Configure Snort Logging

**🔵 Edit the Snort configuration file:** *`sudo nano /etc/snort/snort.conf`*

![image](https://github.com/user-attachments/assets/5e76948e-bfc5-424a-a76a-52d4f7727ef6)

Then, locate the **`(Step #6: Configure output plugins)`** section, scroll down and uncomment or add any of the following logging methods (e.g., **`Plain Text`**, **`PCAP`**, etc.) you prefer:

![image](https://github.com/user-attachments/assets/049d7935-1f20-4bbf-b396-00fe84239617)

#### 🟢 Enable Plain Text Logging (Default)
**`Plain Text`** logging is the simplest and most straightforward way to capture and review **`Snort`** alerts. When enabled, **`Snort`** writes alerts directly to a log file in an easy-to-read format. This method is useful for basic monitoring, debugging, and quick analysis without requiring additional tools.

Add the following output directive to the **`Snort`** configuration file (**`snort.conf`**).

**Output Directive:** **`output alert_fast: /var/log/snort/alert.log`**

Before:

![image](https://github.com/user-attachments/assets/9ab63d47-6e9d-4b1c-a350-4d26ab598111)

After:

![image](https://github.com/user-attachments/assets/cb5acb89-4fa9-4d4a-853e-2706011c61e8)

| **Part** | **Explanation** |
|-|-|
| `output` | Specifies that **`Snort`** should generate an output.|
| `alert_fast` | Tells **`Snort`** to use the "**`Fast Alert`**" logging format, which logs alerts in a concise, one-line format.|
| `/var/log/snort/alert.log` | Defines the file path where **`Snort`** will store alert logs.|

This stores alerts in **`/var/log/snort/alert.log`** in a human-readable format.

**🔹Log Entry - Format Example:**
|02/28-14:32:17.001234 [* *] [1:1000001:1] ICMP Ping Detected [**] [Priority: 3] {ICMP} 192.168.1.5 -> 192.168.1.1|
|-|

**🔹Understanding Each Part of the Log Entry:**

| **Part** | **Explanation** |
|-|-|
| `02/28-14:32:17.001234` | **Timestamp** (MM/DD-HH:MM:SS.Milliseconds) when the alert was triggered.|
| `[**] [1:1000001:1]` | **Snort rule metadata: [Generator ID: Rule ID: Revision]**. This helps identify the specific rule that triggered the alert.|
| `ICMP Ping Detected` | **Alert message**, describing the detected activity.|
| `[Priority: 3]` | The **priority level** of the alert (**lower is more critical**).|
| `{ICMP}` | The **protocol** associated with the alert (e.g., **TCP**, **UDP**, **ICMP**). |
| `192.168.1.5 -> 192.168.1.1` | **Source and destination IP addresses** for the detected activity. |

**🔹How to View and Analyze Plain Text Logs:**

Once logging is enabled and **`Snort`** is running, you can check alerts using the following commands:

**📜 View the last 10 alerts:** *`sudo tail -n 10 /var/log/snort/alert.log`*

**📜 Monitor alerts in real time:** *`sudo tail -f /var/log/snort/alert.log`*

**📜 Search for specific alerts (e.g., ICMP traffic):** *`sudo grep "ICMP" /var/log/snort/alert.log`*

**🔹Why Use Plain Text Logging:**

**✅ Easy to read:** The output is simple and human-readable.

**✅ Quick analysis:** No additional tools are required to view logs.

**✅ Lightweight:** Uses minimal system resources compared to database logging.

**✅ Good for troubleshooting:** Helps validate whether **`Snort`** is working correctly.

However, `Plain Text` logging lacks structure for automated log analysis. If you plan to integrate **`Snort`** with log management or **`SIEM`** tools (e.g., **`Splunk`**, **`ELK Stack`**), **`JSON`** or **`Unified2`** formats are better choices, but they are introduced on **`Snort 3`**.

#### 🟢 Enable PCAP Logging (For Packet Capture & Deep Analysis)

**`PCAP (Packet Capture)`** logging in **`Snort`** allows you to record full network packets for later analysis. This is useful for deep forensic investigation, intrusion analysis, and troubleshooting network threats. Security analysts often use **`PCAP`** logs with tools like **`Wireshark`**, **`Zeek`**, or **`tcpdump`** to inspect raw network traffic.

Add the following output directive to the **`Snort`** configuration file (**`snort.conf`**).

**Output Directive:** **`output log_tcpdump: /var/log/snort/log.pcap`**

![image](https://github.com/user-attachments/assets/fa026409-6c6b-4eba-9473-8fb347271c31)

| **Part** | **Explanation** |
|-|-|
| `output` | Specifies that **`Snort`** should generate an output.|
| `log_tcpdump` | Tells **`Snort`** to store network packets in **`PCAP`** format, similar to how **`Wireshark`** captures packets.|
| `/var/log/snort/log.pcap` | Defines the file path where **`Snort`** will capture network traffic.|

This format allows you to analyze **full network packets** in **`Wireshark`**.

**🔹What Does a PCAP Log Contain?**

Unlike **`Plain Text`** or **`JSON`** logs, **`PCAP`** files contain raw packet data, including:

**✅ Packet headers** (source/destination IPs, ports, protocols, timestamps).

**✅ Packet payloads** (actual transmitted data).

**✅ Full conversation reconstruction** between attackers and victims.

**✅ Deep packet inspection** for advanced forensic investigations.

A **`PCAP`** log does **not** contain human-readable text like **`JSON`** or **`Plain Text`** logs. Instead, it **stores raw network packets** that need to be analyzed using tools like **`Wireshark`** or **`tcpdump`**.

**🔹How to View and Analyze PCAP Logs**

Once **`PCAP`** logging is enabled and **`Snort`** is running, you can inspect captured packets using:

**📜 Check if the PCAP log file exists:** *`ls -l /var/log/snort/log.pcap`*

**📜 Analyze the PCAP log using tcpdump:** *`sudo tcpdump -r /var/log/snort/log.pcap`*

**📜 Open the PCAP log in Wireshark (GUI):** *`wireshark /var/log/snort/log.pcap`*

**📜 Filter PCAP logs to show only HTTP traffic:** *`sudo tcpdump -r /var/log/snort/log.pcap -nn -A port 80`*

**📜 Extract and display only source/destination IPs from the PCAP log:** *`sudo tcpdump -r /var/log/snort/log.pcap -nn -q`*

**🔹Why Use PCAP Logging?**

**✅ Capture Full Network Packets:** Unlike text-based alerts, **`PCAP`** logs store complete packet data for forensic analysis.

**✅ Advanced Investigation:** Allows security analysts to **reconstruct network attacks, extract malware payloads, and analyze exploit techniques**.

**✅ Integration with Wireshark & Zeek:** Enables **deep traffic analysis** and **protocol inspection** for detailed insights.

**✅ Ideal for Network Forensics & Incident Response:** Helps **correlate attack patterns** and **understand adversary techniques**.

### 🔸Step 3: Create and Configure the Logging Directory

Before **`Snort`** can store its logs, you must create a dedicated directory and configure the proper permissions. This ensures that **`Snort`** can write logs securely and prevents permission issues during runtime.

**🔹Why Do We Need a Logging Directory?**

**✅ Ensures Snort has a specific location** to store logs such as alerts, packet captures, and event data.

**✅ Prevents permission issues** that could cause **`Snort`** to fail when trying to write logs.

**✅ Improves organization** by keeping all **`Snort`** logs in one central location.

**✅ Enhances security** by restricting access to **`Snort’s`** log files.

**🔵 Create the Logging Directory:** *`sudo mkdir -p /var/log/snort`*

![image](https://github.com/user-attachments/assets/5d230907-19f1-42c0-af10-7d06e5ba8107)

**Command Breakdown:**

| **Command** | **Explanation** |
|-|-|
| *`sudo`* | Runs the command with superuser (**`root`**) privileges to avoid permission issues.|
| *`mkdir`* | Creates a new directory.|
| *`-p`* | Ensures that if the directory already exists, it won’t return an error.|

**🔹Why use /var/log/snort?**

✅ The **`/var/log/`** directory is the standard location for system and application logs.

✅ Keeping **`Snort`** logs here maintains consistency with Linux logging conventions.

**🔵 Set the Correct Permissions:** *`sudo chmod -R 755 /var/log/snort`*

![image](https://github.com/user-attachments/assets/dc445b30-6d9a-4c6c-9012-8d81c24c7450)

**Command Breakdown:**

| **Command** | **Explanation** |
|-|-|
| *`sudo`* | Runs the command with superuser (**`root`**) privileges to avoid permission issues.|
| *`chmod`* | Changes file/directory permissions.|
| *`-R`* | Recursively applies the permission change to all files and subdirectories.|
| *`755`* | Assigns **read, write, and execute (rwx) permissions** to the owner, and **read and execute (r-x) permissions** to others.|

**🔹What does *755* mean?**

**✅ Owner (snort):** Read, write, and execute (**rwx**) = 7

**✅ Group (snort):** Read and execute (**r-x**) = 5

**✅ Others:** Read and execute (**r-x**) = 5

This setup ensures that **`Snort`** can write logs, but other users cannot modify them.

**🔵 Set Ownership to the Snort User:** *`sudo chown -R snort:snort /var/log/snort`*

![image](https://github.com/user-attachments/assets/7635cbc9-5d4c-48a8-9480-4bcafce16909)

**Command Breakdown:**

| **Command** | **Explanation** |
|-|-|
| *`sudo`* | Runs the command with superuser (**`root`**) privileges to avoid permission issues.|
| *`chown`* | Changes ownership of a file or directory.|
| *`-R`* | Recursively applies the ownership change to all files and subdirectories.|
| *`snort:snort`* | Assigns both user (`snort`) and group (`snort`) ownership.|
| *`/var/log/snort`* | Target directory where ownership is changed.|

**🔹Why change Ownership?**

✅ **`Snort`** runs under the `snort` user, not `root`.

✅ Giving ownership to `snort` allows **`Snort`** to write logs without requiring `root` privileges.

### 🔸Step 4: Verifying the Logging Directory Setup

**🔵 Check directory existence:** *`ls -ld /var/log/snort`*

**Expected Output:**

![image](https://github.com/user-attachments/assets/1348913b-4307-451c-a859-4b10ef434cc5)

**Output Explanation:**

|✅ **`drwxr-xr-x → 755 permissions`**|
|-|
**Note:** If you receive **`drwxr-sr-x`** instead of **`drwxr-xr-x`**, this is due to the **`setgid (Set Group ID)`** bit being enabled on the directory. This is safe and even recommended, ensuring that any new files created inside the directory inherit the group ownership (`snort`) rather than the user’s primary group.

|**Output** | **Explanation** |
|-|-|
| `d` | Directory|
| `rwx` **(Owner: snort)** | Full read (`r`), write (`w`), and execute (`x`) permissions.|
| `r-s` **(Group: snort)** | Read (`r`) and execute (`x`) permissions, but with the setgid (`s`) bit enabled. |
| `r-x` **(Others)** | Read (`r`) and execute (`x`) permissions for all users.|
| `snort snort` | Correct Ownership|

**🔵 Check file permissions recursively:** *`ls -l /var/log/snort/`*

**Expected Output:**

![image](https://github.com/user-attachments/assets/54271393-456d-42c8-b636-67d3d03310db)

(**Note:** If your output includes `.gz` files, this means `Snort` is automatically compressing older log files using `gzip`. This happens when `log rotation` is enabled in your system.)

`Snort` generates multiple log files based on the output configurations in the `snort.conf` file. Each log file serves a different purpose. If you only want `alert.log`, you need to modify `Snort's` `log rotation/logging` settings.

**Understanding Common Snort Log Files:**

|**File Name** | **Description** |
|-|-|
| `alert.log` | The current alert log (human-readable format).|
| `snort.alert` | Default `Snort` alert file (similar to `alert.log`).|
| `snort.alert.fast` | Alerts in a simplified, human-readable format.|
| `snort.alert.fast.1.gz` | Rotated and compressed version of `snort.alert.fast`.|
| `snort.log` | Packet logging (binary format).|
| `snort.log.1.gz` | Rotated and compressed version of `snort.log`.|
| `log.pcap.xxxxxxxxxx` | Captured packets (if `log_pcap` is enabled).|

**🔵 Confirm Snort can write to the directory:** *`sudo -u snort touch /var/log/snort/test.log && ls -l /var/log/snort/test.log`*

**Expected Output:**

![image](https://github.com/user-attachments/assets/99bf4602-d53e-48bb-815e-3dde359474ee)

**Output Explanation:**

|**Output** | **Explanation** |
|-|-|
| `-rw-rw-r--` | This shows the file permissions for `test.log`. |
| `-` | Indicates a regular file. |
| `rw-` **(Owner: snort)** | Full read (`r`), and write (`w`) permissions.|
| `rw-` **(Group: snort)** | Full read (`r`), and write (`w`) permissions.|
| `r--` **(Others)** | Read only (`r`). |
| `1` | The number of hard links to the file (in this case, it’s just 1). |
| `snort snort` | This indicates that the `owner` and `group` of the file are both set to `snort`. |

🛑 If there’s an error, check ownership and permissions again.

### 🔸Step 5: Configure for Console Mode and Log Alerts

If you want to see real-time alerts in the terminal (`Console Mode`) and log them (`alert.log`), update your `Snort` configuration file.

**🔵 Edit the Snort configuration file:** *`sudo nano /etc/snort/snort.conf`*

Find the output logging section and enable the following Output Directives:

**Output Directive:** **`output alert_fast: stdout`**

**Output Directive:** **`output alert_fast: /var/log/snort/alert.log`**

![image](https://github.com/user-attachments/assets/98221bfd-7956-4a6f-971b-e23fb65993ea)

Save & exit.

This ensures alerts are printed to the terminal (`stdout`) and saved to `alert.log`.

**🔵 Restart Snort:** *`sudo systemctl restart snort`*

### 🔸Step 6: Test Logging Output

After configuring `Snort’s` logging settings and setting up the `/var/log/snort/` directory, you can verify that `Snort` is generating logs correctly when we test our custom rules later during this exercise. This command ensures that `Snort` is capturing alerts and storing them in the configured log file (`alert.log`).

**🔵 To check if Snort is logging correctly, run:** *`sudo tail -f /var/log/snort/alert.log`*

**Command Breakdown:**

| **Command** | **Explanation** |
|-|-|
| *`sudo`* | Runs the command with superuser (**`root`**) privileges to avoid permission issues.|
| *`tail`* | Displays the last few lines of a file.|
| *`-f`* | Follows the log file in real time, showing new entries as they appear. |
| *`snort:snort`* | Assigns both user (`snort`) and group (`snort`) ownership.|
| *`/var/log/snort/alert.log`* | Target directory where log file is located. |
 
This will show real-time alerts once `Snort` detects suspicious activity.

### 🔸Step 7: Troubleshooting Logging Output

If alerts are printed in the terminal (`Console Mode`), but not being logged in the `alert.log` file, check the current status of the `Snort` service on your system. 

**🔵 Check Snort status:** *`sudo systemctl status snort`*

![image](https://github.com/user-attachments/assets/01122117-8260-4c30-803d-7d33059bfaed)

`Snort` failed to start, as seen above:

**Output Explanation:**

|**Output** | **Explanation** |
|-|-|
| **Active: failed (Result: exit-code)** | `Snort` failed to start. |
| **status=1/FAILURE** | The exit code suggests an issue, often a misconfiguration. |
| **Process: xxxxx ExecStart=... (code=exited, status=1/FAILURE)** | Shows which command failed. |

In this case, “**`Loaded: loaded (/etc/systemd/system/snort.service`**” indicates that the `Snort` service unit file exists and is recognized by `systemd`, but it does not confirm that `Snort` is running correctly, `Snort` tried to start but encountered an error from the `snort.service` file.

To resolve this issue, ensure that the `snort.service` unit file isn’t empty, if so, correctly configure the file with the parameters shown in the screenshot below.

**🔵 Edit the Snort service file:** *`sudo nano /etc/systemd/system/snort.service`*

(**Note:** For `Snort` to open raw sockets (for sniffing network traffic), it typically needs to be run with elevated privileges. Therefore, configure `snort.service` to run `Snort` as `root` by adjusting the `User` and `Group` directives in the service unit file, as shown below.)

![image](https://github.com/user-attachments/assets/f99cf1cc-ae96-4d57-a055-8a8d9698eac6)

Save & exit.

Next, reload `systemd` to apply the changes and then restart `Snort`.

**🔵 Reload systemd:** *`sudo systemctl daemon-reload`*

**🔵 Restart Snort:** *`sudo systemctl restart snort`*

## 2. Creating Custom Snort Rules

`Snort` rules define what network traffic should trigger an alert.

### 🔸Step 1: Understanding Snort Rule Structure

`Snort` rules follow a standard format:

| [action] [protocol] [source IP] [source port] -> [destination IP] [destination port] (rule options) |
|-|

|**Part** | **Explanation** |
|-|-|
| **Action** | What to do when traffic matches (e.g., alert, log, drop). |
| **Protocol** | Which protocol to monitor (e.g., tcp, udp, icmp, ip). |
| **->** | Arrow indicating traffic from Source to Destination. |
| **Source IP & Port** | Where the traffic originates. |
| **Destination IP & Port** | The intended target. |
| **Rule Options** | Additional details like alert messages, thresholds, and payload content. |

### 🔸Step 2: Edit the Local Rules file with Custom Rules

Edit the `local.rules` file to add your custom rules.

**🔵 Edit local rules file:** *`sudo nano /etc/snort/rules/local.rules`*

![image](https://github.com/user-attachments/assets/8c7590cf-c8b7-4c80-891a-ebfd2823e34f)

If the `local.rules` file doesn’t exist, create it.

### 🔸Step 3: Writing Custom Rules

The following are some common custom `Snort` rules that you can add to the `local.rules` file.

(Note: Verify punctuation and spaces are written and followed correctly when adding each of the custom rules. Otherwise, `Snort` will not detect the custom rules.)

**✅ Detect ICMP Ping (Ping Sweep)**

This rule detects network scans using `ICMP` (ping requests).

| alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;) |
|-|

![image](https://github.com/user-attachments/assets/9b120555-4dd0-44fe-b0a7-6afde2f34508)

|**Part** | **Explanation** |
|-|-|
| **alert** | Specifies the action `Snort` should take when the rule is triggered (generate an alert). |
| **icmp** | The protocol being monitored. |
| **any any** | Monitors traffic from any `source IP` and any `source port`. |
| **->** | Arrow indicating traffic from Source to Destination. |
| **any any** | Monitors traffic to any `destination IP` and any `destination port`. |
| **msg:"ICMP Ping Detected"** | The message that appears in logs when this rule is triggered. |
| **sid:1000001** | `Snort Rule ID` (unique identifier for this rule) (must be >= 1000000 for custom rules). |
| **rev:1** | `Rule revision number` (used for version tracking) (increment this number when modifying rules). |

**✅ Detect SSH Brute Force Attempts**

This rule alerts if multiple connection attempts to an `SSH` server (`port 22`) occur within `60 seconds`.

| alert tcp any any -> any 22 (msg:"Possible SSH Brute Force"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000002; rev:1;) |
|-|

![image](https://github.com/user-attachments/assets/e6954b9b-a2a6-4fe5-aadb-3d7c93d76e50)

|**Part** | **Explanation** |
|-|-|
| **alert** | Specifies the action `Snort` should take when the rule is triggered (generate an alert). |
| **tcp** | The protocol being monitored (`SSH` uses `TCP`). |
| **any any** | Monitors traffic from any `source IP` and any `source port`. |
| **->** | Arrow indicating traffic from Source to Destination. |
| **any 22** | The `destination IP` is any, and the `destination port` is `22 (SSH service)`. |
| **msg:"Possible SSH Brute Force"** | The message that appears in logs when this rule is triggered. |
| **flags:S** | This rule looks for packets with the `SYN flag` set, meaning an attempt to establish a new connection. |
| **threshold:type both, track by_src, count 5, seconds 60** | Triggers an alert immediately on the first match and then only if `5 or more connection attempts` occur from the same source within `60 seconds`. |
| **sid:1000002** | `Snort Rule ID` (unique identifier for this rule) (must be >= 1000000 for custom rules). |
| **rev:1** | `Rule revision number` (used for version tracking) (increment this number when modifying rules). |

**✅ Detect HTTP Traffic Containing "cmd=" (Possible Command Injection)**

This rule watches for `HTTP requests` containing (`cmd=`), often used in `web exploits`.

|alert tcp any any -> any 80 (msg:"Suspicious HTTP Request"; content:"cmd="; nocase; sid:1000003; rev:1;) |
|-|

![image](https://github.com/user-attachments/assets/c189340b-bb37-4f82-b4b5-12404b113b46)

|**Part** | **Explanation** |
|-|-|
| **alert** | Specifies the action `Snort` should take when the rule is triggered (generate an alert). |
| **tcp** | The protocol being monitored (`HTTP` uses `TCP`). |
| **any any** | Monitors traffic from any `source IP` and any `source port`. |
| **->** | Arrow indicating traffic from Source to Destination. |
| **any 80** | The `destination IP` is any, and the `destination port` is `80 (HTTP service)`. |
| **msg:"Suspicious HTTP Request"** | The message that appears in logs when this rule is triggered. |
| **content:“cmd=”** | This rule looks for the string `"cmd="` in `HTTP` traffic, which may indicate a command injection attempt. |
| **nocase** | Makes the search case-insensitive, so it detects "CMD=", "Cmd=", etc. |
| **sid:1000003** | `Snort Rule ID` (unique identifier for this rule) (must be >= 1000000 for custom rules). |
| **rev:1** | `Rule revision number` (used for version tracking) (increment this number when modifying rules). |

### 🔸Step 4: Enable Local Rules in Snort

**🔵 Edit the Snort configuration file:** *`sudo nano /etc/snort/snort.conf`*

Then, locate the section `(Step #7: Customize your rule set)`, scroll down and uncomment the line: `include $RULE_PATH/local.rules`, (remove the # if present).

![image](https://github.com/user-attachments/assets/e253324e-defe-4d44-b6e8-93ae3ca91d93)

### 🔸Step 5: Restart Snort to Apply Rules

After adding rules, restart Snort to apply changes.

**🔵 Restart Snort:** *`sudo systemctl restart snort`*

![image](https://github.com/user-attachments/assets/942d987b-f624-4ec8-a46d-432fddb9947c)


## 3. Testing Custom Snort Rules

### 🔸Step 1: Setup Monitoring for Custom Rules 

Run `Snort` in `Console Mode` to monitor rule triggers: 

**🔵 Run Snort in Console Mode:** *`sudo snort -i enp0s3 -c /etc/snort/snort.conf -A console`*

(**Note:** If necessary, replace `enp0s3` with your actual network interface name.)

![image](https://github.com/user-attachments/assets/8afad84f-3c6a-4d60-ad8c-de676ea93fa1)

If ran correctly, you should see `“Commencing packet processing”` as shown below. Leave this command running while testing the custom rules below. If you want to stop the command, type `CTR+Z`. 

![image](https://github.com/user-attachments/assets/6f7a2b0e-4745-47de-9d1e-5912edf34f6f)

In addition to monitoring alerts on `Console Mode`, check if `Snort` is logging real-time alerts on the `alert.log` file.

**🔵 Check Snort Logging:** *`sudo tail -f /var/log/snort/alert.log`*

🛑 If you encounter logging errors/failures, please go back and review the following steps to help resolve these issues:

🔸 Step 5: Configure Console Mode and Log Alerts

🔸 Step 6: Test Logging Output

🔸 Step 7: Troubleshooting Logging Output

### 🔸Step 2: Test Your Custom Rules 

For this exercise, I’ll use a `Kali Linux VM (IP Address: 10.0.2.4)` as the **"attacker machine"** connected to the same `NAT Network` as this `Ubuntu VM (IP Address: 10.0.2.15)` **"victim machine"**, within `VirtualBox`. Keep in mind that these custom rules can be triggered between any other VMs connected in the same `NAT Network` or from external traffic trying to communicate to any other VMs in the `NAT Network`. Of course this depends how the custom rules were written. In this case, the custom rules we establich will monitor traffic from any `source IP` and any `source port` to any `destination IP` and a specifed `destination port`, as long as the target is within our `NAT Network`. 

**✅ Test for ICMP Ping (Ping Sweep)**

**🔵 To trigger the `ICMP` ping rule, ping your `Ubuntu VM` from another machine:** *`ping -c 4 <your_Ubuntu_VM_IP>`*

**Kali Linux VM (Attacker Machine)**

![image](https://github.com/user-attachments/assets/ca14f3cc-9b42-4d14-aa27-5be6da7a232c)

**Ubuntu VM (Console Mode)**

![image](https://github.com/user-attachments/assets/3422a12b-4692-4ce5-a36f-b6ae8cf94f48)

As a result, your `Ubuntu VM` should display `"ICMP Ping Detected"` while on `Console Mode`, triggered by the four pings sent from your **"attacker machine"** to the `Ubuntu VM`, as demonstrated above.

If `Snort` is configured correctly, you should see alerts in `/var/log/snort/alert.log`.

**Ubuntu VM (alert.log)**

![image](https://github.com/user-attachments/assets/3e38f2c5-2314-423a-ae9e-c31ec0328393)

**✅ Test for SSH Brute Force Attempts**

**🔵 To simulate an `SSH brute-force` attack, you can use the `Hydra` tool:** *`hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<your_Ubuntu_VM_IP>`*

![image](https://github.com/user-attachments/assets/f41dd439-d216-4d47-90a4-14f54d06e70a)

If you encounter the error `“File for passwords not found”`, by default, `rockyou.txt` is stored in a compressed format `rockyou.txt.gz`. 

Extract it with the command: *`sudo gunzip /usr/share/wordlists/rockyou.txt.gz`*

You should see the `rockyou.txt` file on the path: **`/usr/share/wordlists/`**

Next, in order for this test to work, make sure the `Uncomplicated Firewall (UFW)`, `SSH Service`, and `port 22 (SSH)` on your `Ubuntu VM` are enabled:

**🔹Step 1: Install `OpenSSH Server`**

**🔵 Check if OpenSSH Server is installed:** *`dpkg -l | grep openssh-server`*

**🔵 If it’s not installed, install it using:** *`sudo apt update && sudo apt install openssh-server -y`*

![image](https://github.com/user-attachments/assets/a9386c7e-822f-45a1-a60b-20d23868d80d)

`OpenSSH Server` is a component of the `Open Secure Shell (SSH)` suite, which enables secure remote access, file transfers, and command execution over an encrypted connection via `SSH` protocol.

**🔹Step 2: Start and enable `SSH Service`**

**🔵 Ensure `SSH service` is running:** *`sudo systemctl start ssh`*

**🔵 Enable `SSH Service`:** *`sudo systemctl enable ssh`*

**🔵 Check status of `SSH Service`:** *`sudo systemctl status ssh`*

![image](https://github.com/user-attachments/assets/75ecfccb-8c4b-42ee-9f60-0c06bcf5d3fa)

If the status returns as active, then `SSH` is running.

**🔹 Step 3: Allow `SSH Port 22` in the Firewall (UFW).**

`UFW (Uncomplicated Firewall)` is a user-friendly command-line interface for managing iptables, the default firewall system in Linux. It simplifies firewall rule management, making it easier to configure network security on Ubuntu and other Debian-based systems.

**🔵 Check status of UFW:** *`sudo ufw status`*

If it’s inactive, activate it and allow `Port 22` for `SSH`.

**🔵 Allow Port 22:** *`sudo ufw allow 22/tcp`*

**🔵 Enable UFW:** *`sudo ufw enable`*

**🔵 Check status of UFW:** *`sudo ufw status`*

![image](https://github.com/user-attachments/assets/bc969f68-7ad5-4e3e-9c6d-9ad5b07e8be6)

Lastly, test for SSH Brute Force attack again. 

**🔵 Simulate SSH Brute Force attack:** *`hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<your_Ubuntu_VM_IP>`*

**Kali Linux VM (Attacker Machine)**

![image](https://github.com/user-attachments/assets/b1861378-29e6-457a-9c81-42f78113b019)

**Ubuntu VM (Console Mode)**

![image](https://github.com/user-attachments/assets/2dca2bb0-113e-4751-b31a-44afb2c512ee)

As a result, `Snort` should display `"Possible SSH Brute Force"` on your `Ubuntu VM` while in `Console Mode`, triggered from your other machine, in this case the `Kali Linux VM` to the `Ubuntu VM`, as shown above.

If `Snort` logging is configured correctly, you should see alerts in `/var/log/snort/alert.log`, as shown below.

**Ubuntu VM (alert.log)**

![image](https://github.com/user-attachments/assets/003ccad9-8abd-46da-99d2-af0a0fc31e85)

**✅ Test for HTTP Traffic Containing "cmd=" (Possible Command Injection)**

**🔹 Step 1: Start and enable `HTTP Server` (`Apache2`)**

An `HTTP Server` must be running on your `Ubuntu VM`, if not, you need to install, start, and enable `Apache2 `to open `port 80`. Run the following commands.

**🔵 Update and Install Apache2:** *`sudo apt update && sudo apt install apache2 -y`*

**🔵 Start Apache2:** *`sudo systemctl start apache2`*

**🔵 Enable Apache2:** *`sudo systemctl enable apache2`*

This installs `Apache2` and ensures it starts automatically on boot.

**🔵 Check the status of Apache2:** *`sudo systemctl status apache2`*

![image](https://github.com/user-attachments/assets/c66e8137-deff-4ad2-a1d5-eb6866d63b18)

If the status returns as active, then `HTTP Server`(`Apache2`) is running.

**🔹 Step 2: Allow `HTTP Port 80` in the Firewall (UFW)**

**🔵 Check status of UFW:** *`sudo ufw status`*

If it’s inactive, activate it and allow `Port 80` for `HTTP`.

**🔵 Allow Port 80:** *`sudo ufw allow 80/tcp`*

**🔵 Enable UFW:** *`sudo ufw enable`*

**🔵 Check status of UFW:** *`sudo ufw status`*

![image](https://github.com/user-attachments/assets/485ed0e4-59b0-440a-8903-3a1215dc0822)

**🔹 Step 3: Simulate HTTP Traffic Containing "cmd="** 

Simulate `HTTP` traffic and the intended attack using `curl`, which is a command used to send `HTTP` requests and retrieve responses from the command line.

**🔵 Simulate HTTP Traffic Containing "cmd=":** *`curl http://<your_Ubuntu_VM_IP>?cmd=id`*

**Kali Linux VM (Attacker Machine)**

![image](https://github.com/user-attachments/assets/233f83b4-e2b2-49bd-86b5-e3c7a2204416)

`Snort` should detect `"cmd="` and trigger the alert `“Suspicious HTTP Request”`, as shown below.

**Ubuntu VM (Console Mode)**

![image](https://github.com/user-attachments/assets/475141da-9044-4fb5-8b39-8c630d25832e)

If `Snort` logging is configured correctly, you should see alerts in `/var/log/snort/alert.log`, as shown below.

**Ubuntu VM (alert.log)**

![image](https://github.com/user-attachments/assets/92b4e87b-4039-48b7-b2ae-832377a4327a)

## 4. Conclusion

🚀 Congratulations! `Snort` is now carefully configured with logging and custom rules!
With these rules in place, `Snort` can actively monitor your `VM NAT network`, detect potential attacks, unauthorized access attempts, and malicious activity, helping you strengthen the security of your home lab. Fine-tune your rules as needed, create more complex rules, and keep exploring new ways to enhance your network defense! 🔥















