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

[Insert Screenshot] snort_conf.png

Then, locate the **`(Step #6: Configure output plugins)`** section, scroll down and uncomment or add any of the following logging methods (e.g., **`Plain Text`**, **`PCAP`**, etc.) you prefer:

[Insert Screenshot] configure_output_plugins.png

#### 🟢 Enable Plain Text Logging (Default)
**`Plain Text`** logging is the simplest and most straightforward way to capture and review **`Snort`** alerts. When enabled, **`Snort`** writes alerts directly to a log file in an easy-to-read format. This method is useful for basic monitoring, debugging, and quick analysis without requiring additional tools.

Add the following output directive to the **`Snort`** configuration file (**`snort.conf`**).

**Output Directive:** **`output alert_fast: /var/log/snort/alert.log`**

Before:
[Insert Screenshot] plaintext_before.png

After:
[Insert Screenshot] plaintext_after.png

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

However, plain text logging **lacks structure** for automated log analysis. If you plan to integrate **`Snort`** with log management or **`SIEM`** tools (e.g., **`Splunk`**, **`ELK Stack`**), **`JSON`** or **`Unified2`** formats are better choices, but they are introduced on **`Snort 3`**.

#### 🟢 Enable PCAP Logging (For Packet Capture & Deep Analysis)

**`PCAP (Packet Capture)`** logging in **`Snort`** allows you to record full network packets for later analysis. This is useful for deep forensic investigation, intrusion analysis, and troubleshooting network threats. Security analysts often use **`PCAP`** logs with tools like **`Wireshark`**, **`Zeek`**, or **`tcpdump`** to inspect raw network traffic.

Add the following output directive to the **`Snort`** configuration file (**`snort.conf`**).

**Output Directive:** **`output log_tcpdump: /var/log/snort/log.pcap`**

[Insert Screenshot] log_pcap.png

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

### 🔸Step 3: Create the Logging Directory

Before **`Snort`** can store its logs, you must create a dedicated directory and configure the proper permissions. This ensures that **`Snort`** can write logs securely and prevents permission issues during runtime.

**🔹Why Do We Need a Logging Directory?**

**✅ Ensures Snort has a specific location** to store logs such as alerts, packet captures, and event data.

**✅ Prevents permission issues** that could cause **`Snort`** to fail when trying to write logs.

**✅ Improves organization** by keeping all **`Snort`** logs in one central location.

**✅ Enhances security** by restricting access to **`Snort’s`** log files.


**🔵 Create the Logging Directory:** *`sudo mkdir -p /var/log/snort`*

[Insert Screenshot] create_log_directory.png

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

[Insert Screenshot] Set_permissions.png

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

[Insert Screenshot] Set_ownership.png

**Command Breakdown:**

| **Command** | **Explanation** |
|-|-|
| *`sudo`* | Runs the command with superuser (**`root`**) privileges to avoid permission issues.|
| *`chown`* | Changes ownership of a file or directory.|
| *`-R`* | Recursively applies the ownership change to all files and subdirectories.|
| *`snort:snort`* | Assigns both user (`snort`) and group (`snort`) ownership.|
| *`/var/log/snort`* | Target directory where ownership is changed.|













