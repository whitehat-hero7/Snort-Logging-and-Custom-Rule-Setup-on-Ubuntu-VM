# Snort Logging Setup and Custom Rules on Ubuntu VM

## Objective
**`Snort`** is a powerful open-source **`Intrusion Detection and Prevention System (IDS/IPS)`** designed to analyze network traffic and detect potential threats in real time. This comprehensive guide walks you through the step-by-step process of configuring **`Snort`** logging and custom rule creation within an **`Ubuntu VM`** running on a **`VirtualBox`** home lab. By following this guide, you’ll gain hands-on experience in monitoring network activity, identifying security threats, and fine-tuning **`Snort’s`** detection capabilities to generate custom alerts for suspicious behavior, enhancing both your cybersecurity skills and your ability to respond to real-world attacks.

<img src="https://github.com/whitehat-hero7/Snort-Installation-in-Ubuntu-Virtual-Machine-VM/blob/main/docs/snort_logo.PNG">

## 1. Snort Logging Setup
**`Snort`** offers versatile logging options, including **`Plain Text`**, **`JSON`**, **`PCAP`**, and more, allowing flexible data analysis and integration with other security tools. In this exercise, we'll configure Snort’s logging settings, set up proper directory permissions, test the logging output, and address common troubleshooting scenarios you might encounter when using **`Plain Text`** logging.

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
Edit the **`Snort`** configuration file: **`sudo nano /etc/snort/snort.conf`**

[Insert Screenshot] snort_conf.png

Then, locate the **`(Step #6: Configure output plugins)`** section, scroll down and uncomment or add any of the following logging methods (e.g., **`Plain Text`**, **`PCAP`**, etc.) you prefer:

[Insert Screenshot] configure_output_plugins.png

#### ✅ Enable Plain Text Logging (Default)
**`Plain Text`** logging is the simplest and most straightforward way to capture and review **`Snort`** alerts. When enabled, **`Snort`** writes alerts directly to a log file in an easy-to-read format. This method is useful for basic monitoring, debugging, and quick analysis without requiring additional tools.

Add the following output directive to the **`Snort`** configuration file (**`snort.conf`**).

**Output Directive**: **`output alert_fast: /var/log/snort/alert.log`**

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

**🔹Format Example:**

02/28-14:32:17.001234 [* *] [1:1000001:1] ICMP Ping Detected [**] [Priority: 3] {ICMP} 192.168.1.5 -> 192.168.1.1
















