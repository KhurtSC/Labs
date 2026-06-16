# Atomic Red Team Home Lab

In this lab I am simulating MITRE ATT&CK techniques, hunting for evidence 
in Splunk, and building detection rules from scratch to improve further the skills.



## Environment

| Component | Details |
|---|---|
| **Analyst machine** | Parrot OS |
| **SIEM** | Splunk Enterprise |
| **Victim machine** | Windows 10 Home |
| **Telemetry** | Sysmon + Splunk Universal Forwarder |
| **Attack framework** | Invoke-AtomicRedTeam |



## Techniques Covered

| ID | Name | Tactic | Result | Writeup |
|---|---|---|---|---|
| T1057 | Process Discovery | Discovery | Detected | [View](./T1057-Process-Discovery/) |
