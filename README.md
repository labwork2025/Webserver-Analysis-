# SOC Analyst Report: Triage of 3.9GB Web Server PCAP

* **Date:** 11/14/2025
* **Analyst:** Elijah Banks
* **Source File:** `2025-02-07-three-days-of-scans-and-probes...pcap.zip`
* **Tools:** Kali Linux, tshark, VirusTotal

---

## 1. Summary

I analyzed a 3.9GB packet capture containing three days of "real-world" web server traffic. The goal was to triage this "noisy" data, separate routine background noise from active threats, and identify the most significant risks.

The analysis was a 3-step process:
1.  **Triage:** I used `tshark` to find the "Top 10" noisiest IP addresses.
2.  **Enrichment:** I used VirusTotal (OSINT) to check the reputation of those IPs.
3.  **Investigation:** I performed a deep-dive `tshark` analysis on the #1 threat.

My investigation confirmed that at least four of the top 10 scanners were **known-malicious infrastructure**, and the #1 attacker was performing a comprehensive, automated scan for high-value ports, including SMB (Port 445) and SSH (Port 22).

---

## 2. Step 1: Triage (Finding the "Top Talkers")

First, I had to sift through the noise. I ran a `tshark` command to read all 3.9GB of traffic and generate a sorted list of the Top 10 most frequent source IPs.

**Evidence: Top 10 "Noisiest" IPs**
![tshark output showing the Top 10 IPs by hit count](evidence/Screenshot (993).png)

This first step immediately narrowed my focus. The top two IPs (`203.161.44.208` and `203.161.44.39`) were clearly the main subjects, with far more hits than any others.

---

## 3. Step 2: Enrichment (OSINT with VirusTotal)

My next step was to find out if these "noisy" IPs were just harmless scanners or known threats. I used VirusTotal to check the reputation of the top IPs from my list.

This step confirmed that this PCAP was not just "scans and probes" but contained active attacks from known-malicious sources.

* **Suspect 1 (`203.161.44.208`):** **Confirmed Malicious.** Flagged by Fortinet for "Malware."
    ![VirusTotal report for 203.161.44.208](PASTE_LINK_FOR_SCREENSHOT_994_HERE)
* **Suspect 3 (`104.156.155.10`):** **Confirmed Malicious.** 6 vendors flagged this IP for "Malicious" and "Phishing."
    ![VirusTotal report for 104.156.155.10](PASTE_LINK_FOR_SCREENSHOT_996_HERE)
* **Suspect 4 (`79.124.62.126`):** **Confirmed HIGHLY Malicious.** 13 vendors flagged this IP for "Malicious," "Phishing," and "Malware."
    ![VirusTotal report for 79.124.62.126](PASTE_LINK_FOR_SCREENSHOT_999_HERE)

---

## 4. Step 3: Investigation (Deep Dive on the #1 Threat)

Now that I'd confirmed the #1 attacker (`203.161.44.208`) was malicious, I performed a deep dive to see *what* it was scanning for. I ran a new `tshark` command to filter for *only* that IP and find its Top 10 destination ports.

**Evidence: Top 10 Ports Scanned by the Attacker**
![tshark output showing the top 10 ports scanned by the #1 attacker](PASTE_LINK_FOR_SCREENSHOT_1004_HERE)

This output shows a comprehensive, automated scan for the most common, high-value vulnerabilities:
* **Port 80 (HTTP):** Standard web server scan.
* **Port 22 (SSH):** Hunting for open remote access.
* **Port 445 (SMB):** **CRITICAL.** This is the port used for Windows file sharing and is the primary attack vector for ransomware (like WannaCry) and lateral movement.
* **Port 5985 (WinRM):** Hunting for Windows Remote Management.
* **Port 23 (Telnet):** Hunting for unencrypted remote access.

---

## 5. Risk & AI Governance Impact

This analysis uncovered the first stage of a broad, automated attack. An attacker who finds an open **Port 445 (SMB)** or **Port 22 (SSH)** has a foothold to move laterally, escalate privileges, and deploy ransomware.

From an **AI Governance (NIST RMF)** perspective, this is a failure to **"Protect"** the environment. If an attacker compromises *any* server on this network, they could move laterally to:
* Access file shares containing **sensitive training data**.
* Compromise a developer's machine to **steal AI models or API keys**.
* Deploy ransomware and hold the entire AI/ML environment hostage.

---

## 6. Recommended Controls

#### Immediate (Critical):
1.  **Block Malicious IPs:** Add the confirmed-malicious IPs (`203.161.44.208`, `104.156.155.10`, `79.124.62.126`, etc.) to the firewall blocklist immediately.

#### Standard (Hardening):
1.  **Close High-Risk Ports:** **Port 445 (SMB)** and **Port 23 (Telnet)** should *never* be exposed to the public internet. These ports must be firewalled off from all external traffic.
2.  **Harden SSH:** Port 22 (SSH) should be restricted to known IP addresses and use key-based authentication, not passwords.
