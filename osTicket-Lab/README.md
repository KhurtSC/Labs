# osTicket Writeup

## Overview

This lab covers setting up osTicket as the ticketing component of my **Mini SOC Lab.** The goal was to have a real, functional ticketing system, not just read about how SOC ticketing works, but actually configure one for blue team use: custom help topics, custom SOC-specific fields, and a proper incident ticket structure that mirrors what a Tier 1 analyst would produce. This new component will be added as a new part of my Atomic Red Team Lab, where I will start to implement ticketing.

---

## What I Learned

- Hands-on experience creating, managing, and replying to tickets, including understanding the full lifecycle from alert to closure or escalation.
- Configured osTicket from a normal helpdesk tool into a SOC-ready system by creating relevant help topics and custom fields / forms that reflect real incident reporting needs.
- The ticket is the output of an investigation, not the starting point. The SIEM is where the work happens, osTicket is where you document the conclusion of that work.
- Gained another knowledge on work process of a SOC, which is the ticketing, this was a little blurry side of understanding for me.

---

## What I Used

- Parrot OS (host machine)
- Docker + Docker Compose
- osTicket via `devinsolutions/osticket` Docker image
- MariaDB 10.11

---

## The Setup

Ran osTicket using Docker Compose with two containers, one for the app, one for the database. Chose MariaDB over MySQL 8 because of authentication plugin compatibility issues with the osTicket image. The official `osticket/osticket` image was also abandoned (5 years old, broken PHP version), so I switched to a community-maintained image that packages the same osTicket software with a working PHP8 environment.

Once both containers were running and the database initialized successfully, osTicket was accessible at `http://localhost:8080`.

**Admin Side:**

![images/admin_view.png](admin_view.png)

**Client Side:**

![images/user_view.png](user_view.png)

---

## SOC Configuration

Out of the box, osTicket is a generic helpdesk tool. The goal here was to make it feel like a SOC incident management system, not a customer support portal.

### Help Topics Created

Replaced the default topics with SOC-relevant categories:

- Malware Detection
- Suspicious Login / Brute Force
- Phishing Email
- Suspicious Network Traffic
- Web Attack

### Custom Ticket Fields

Added custom fields to the Ticket Details form so every ticket captures the information a Tier 1 analyst actually needs:

| Field | Purpose |
| --- | --- |
| Alert | Brief description of the alert that fired |
| MITRE ATT&CK Technique | Maps the activity to the ATT&CK framework |
| Affected Host / IP | The asset involved, where the incident happened |
| IOCs | Indicators of compromise found during investigation, malicious IPs, hashes, domains, URLs |
| Verdict | True Positive / False Positive / Benign True Positive |
| Recommended Action | What should happen next, escalate, close, tune, whitelist |

**Topic Config:**

![images/topic_config.png](topic_config.png)

**Form Config:**

![images/form_config.png](form_config.png)

---

## Pipeline Position

```
Atomic Red Team (threat simulation)
        ↓
Sysmon (endpoint telemetry)
        ↓
Splunk (detection rule fires)
        ↓
osTicket (case / ticket making)
        ↓
Tier 2 (if True Positive)
```