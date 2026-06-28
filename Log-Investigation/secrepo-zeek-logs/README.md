# secrepo - http.logs (Zeek) Analysis

source: https://www.secrepo.com/
## Executive Summary

In this threat hunting project, I explored roughly 2 million log events captured by a Dionaea honeypot. Since honeypots by design only record malicious traffic, this exercise served as a practical lesson in one of the most critical skills in threat hunting which is **separating loud, automated background noise from genuinely targeted attacks.**

Using Splunk and custom-built Regex patterns, I narrowed the massive dataset down to four primary threat actors. By profiling their behavior, user-agents, and payloads, I was able to dismiss three of them as automated vulnerability scanners (DirBuster, Nmap/Nikto, and Nessus) and zero in on a fourth, a stealthy, targeted attacker armed with weaponized exploits for MantisBT RCE, Joomla file upload abuse, and Local File Inclusion. A final forensic review of the logs confirmed the attacks were unsuccessful. The breach failed, and the incident was categorized, documented, and closed.

---

## Phase 1: Scoping the Battlefield

Before diving into payloads, I needed a macro-level view first. Jumping straight into individual events across 2 million logs can be difficult for me so I started on this method first.

I ran a timechart query to visualize attack frequency over time:

```
index=main host=dionaea_honeypot_01
| timechart span=1d count
```

![time-chart.png](time-chart.png)

The chart immediately revealed a massive spike on **March 16**, accounting for nearly the entire 2-million-event dataset in a single day. With the timeframe isolated, I pivoted to identifying the loudest attackers.

Because the raw logs were malformed upon import, fields were misaligned and unstructured. I had to build a custom Regex string to properly extract and parse the relevant fields before I could rank the noisiest IPs:

```
index=main host=dionaea_honeypot_01
| rex field=_raw "^(?<ts>\S+)\s+(?<uid>\S+)\s+(?<src_ip>\S+)"
| top limit=10 src_ip
```

![top-10.png](top-10.png)

The results were clear. Four IP addresses stood out immediately, their request counts dwarfed every other entry on the board, with the top attacker generating millions of hits alone. These became my four primary suspects.

---

## Phase 2: Profiling the Adversaries (Behavioral Triage)

Knowing who was hitting the honeypot wasn't enough. I needed to understand how they were attacking and what tools they were carrying. I ran a deeper query using advanced Regex to break down each suspect's traffic by HTTP Method, User-Agent, and Request Length:

```
index=main host=dionaea_honeypot_01 "192.168.202."
| rex field=_raw "^(?<ts>\S+)\s+(?<uid>\S+)\s+(?<src_ip>\S+)\s+(?<src_port>\d+)\s+(?<dest_ip>\S+)\s+(?<dest_port>\d+)\s+(?<depth>\d+)\s+(?<method>\S+)\s+(?<http_host>\S+)\s+(?<uri>\S+)\s+(?<referrer>\S+)\s+(?<user_agent>.+?)\s+(?<req_len>\d+)\s+(?<status_code>\d+)"
| stats count by method, user_agent, req_len
| sort -count
```

Here is what the triage revealed:

| **Threat Actor IP** | **Identified Behavior** | **Tool / Methodology** |
| --- | --- | --- |
| **192[.]168[.]203[.]63** | Directory Discovery | DirBuster |
| **192[.]168[.]202[.]79** | Broad Vulnerability Scanning | Nmap Scripting Engine + Nikto |
| **192[.]168[.]202[.]102** | Stealth / Targeted Exploitation | Unknown ( deliberately hidden) |
| **192[.]168[.]202[.]110** | Enterprise Vulnerability Scanning | Nessus |

---

### 192.168.203.63 - DirBuster

![first-sus.png](first-sus.png)

This one identified itself immediately. The user-agent field read `DirBuster-0.12 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)` - no ambiguity whatsoever. DirBuster is a directory and file brute-forcing tool developed under the OWASP project, designed to discover hidden paths on a web server by hammering it with thousands of guesses.

What confirmed this further was the HTTP method, nearly every single request was a `HEAD` request, not a `GET`. This is a classic DirBuster pattern: it only needs to know whether a path *exists*, not the actual content, so it sends lightweight HEAD requests to check for a response without downloading anything. The sheer volume of requests reflects this, over a million hits, all probing for directory structure.

We can assume here that this is a Reconnaissance.

---

### 192.168.202.79 - Nmap + Nikto

![second-sus.png](second-sus.png)

Two tools, both self-identifying. The user-agent clearly showed `Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)` alongside `Mozilla/5.00 (Nikto/2.1.5) (Evasions:None)`.

Nmap is well-known as a port scanner, but its Scripting Engine (NSE) extends it into a full vulnerability detection suite, capable of probing services, fingerprinting versions, and running targeted checks. Nikto is a dedicated web vulnerability scanner, built to rapidly identify misconfigurations, outdated software, and exposed sensitive files.

The `(Evasions:None)` tag in the Nikto user-agent is particularly telling. It made zero attempt to hide itself. This was a broad, noisy and uses all tools for the scan. 

---

### 192.168.202.102 - Stealth

![third-sus-1.png](third-sus-1.png)

This is where things got interesting.

Unlike the other three suspects, `.102` had no tool name anywhere in its traffic. The user-agent was just a generic browser string - `Mozilla/4.0 (compatible; MSIE 8.0/9.0; Windows NT 6.0/6.1)` - the kind of thing that would blend in with normal web traffic.

The other three suspects were doing recon. They were loud, they announced their tools, and they were easy to categorize. `.102` was different. It was deliberately masquerading as legitimate traffic to avoid detection. In security, I though that **things you cannot see are the things that should concern you the most.** That made `.102` the priority for deeper investigation.

---

### 192.168.202.110 - Nessus

![fourth-sus-1.png](fourth-sus-1.png)

![fourth-sus-2.png](fourth-sus-2.png)

The first screenshot says there was, a wide variety of attack types including XSS attempts, SQL injection strings, command injection, and header manipulation. But the second screenshot confirmed the tool behind it all.

The user-agent field contained references to `.nasl` files like those `exponent_0964.nasl`, `plogger_checked_sql_injection.nasl`, `calendarix_id_sql_injection.nasl`, and others. NASL stands for **Nessus Attack Scripting Language**, a proprietary scripting format used exclusively by Nessus, the enterprise vulnerability scanner developed by Tenable, Inc. Each `.nasl` file is a plugin targeting a specific known vulnerability, so what looked like a diverse wave of attacks was actually a single tool methodically running through its vulnerability checklist.

Dangerous-looking on the surface, but entirely automated and highly fingerprint-able.

---

## Phase 3: Payload Analysis & Target Acquisition

With behavioral profiles established, I moved into payload-level analysis, inspecting the `uri` field for each suspect to determine exactly which doors they were trying to kick down.

**Suspects .63, .79, and .110** were straightforward. DirBuster's URIs were entirely plain directory guesses (`/v1/`, `/admin/`, `/backup/`, etc.). Nmap and Nikto produced the messy, wide-net output you'd expect from a vulnerability scanner running through a checklist. Nessus was the same, its NASL plugins firing off one after another. Nothing targeted and crafted unlike the .102

**Suspect .102 was a different story entirely.**

While the other three were throwing everything at the system, `.102` showed up with specific, pre-built payloads aimed at known vulnerabilities. This wasn't a tool blindly scanning. This was someone or something that had already done their homework before starting.

Three attack vectors stood out:

---

### Attack Vector 1: Joomla File Upload Exploitation

![third-ip-attacking-1.png](third-ip-attacking-2.png)

```
/joomla12/plugins/editors/tinymce/jscripts/tiny_mce/plugins/tinybrowser/upload.php?type=file&folder=
```

This URI targets the **TinyBrowser file upload component,** a known vulnerable plugin in older Joomla installations. The vulnerability allows unauthenticated users to upload arbitrary files, including PHP web shells, directly to the server.

A successful upload here would not just be a foothold, it would be a full door left open. A PHP shell on the server gives an attacker the ability to execute commands remotely, move laterally, and establish persistence. The end goal of this specific path is Remote Code Execution, just through a different entry point.

---

### Attack Vector 2: Local File Inclusion (LFI)

![third-ip-attacking-2.png](third-ip-attacking-3.png)

```
/twg176/admin/index.php?lang=../../counter/_twg.log\x00
```

Breaking this down:

- `../../` - Directory traversal, attempting to climb out of the web root and access files elsewhere on the system
- `counter/_twg.log` - A specific application log file being targeted, not a generic system file
- `\x00` - A null byte injection, used to trick PHP into ignoring file extension filters

Generic LFI scanners typically go after common targets like `/etc/passwd`. This payload was aimed at a specific log file, which suggests the attacker had prior knowledge of the target environment. Beyond information disclosure, a successful LFI can escalate into Remote Code Execution if an attacker can get their own code written into a readable file first - making it a strong potential foothold.

---

### Attack Vector 3: MantisBT Remote Code Execution

![third-ip-attacking-3.png](third-ip-attacking-1.png)

```
/mantis/manage_proj_page.php?sort=']);error_reporting(0);print(_code_);exec(base64_decode($_SERVER[HTTP_CMD]));die;#
```

Breaking it down piece by piece:

- `']);` - Breaks out of the existing PHP query to inject arbitrary code
- `error_reporting(0)` - Silences all PHP error output, so the system doesn't generate any alerts or logs while the attack runs
- `print(_code_)` - A probe to confirm successful code execution
- `exec(base64_decode($_SERVER[HTTP_CMD]))` - Decodes and executes a command hidden inside an HTTP header in base64 encoding, effectively smuggling the malicious instruction inside the request itself
- `die;#` - Terminates execution and comments out anything after, cleaning up the injection

This is not a scanner output. This is a crafted, weaponized exploit. RCE is effectively the endgame for an attacker - once arbitrary code runs on a victim's system, the door is wide open for persistence, lateral movement, data exfiltration, and more. Also the base64-encoded and delivered via HTTP headers shows deliberate effort to avoid detection.

---

## Phase 4: Verifying if succeeded (Forensic Verification)

Given the severity of the MantisBT RCE attempt, I needed verify that attempt was succesful.

I dropped all formatting queries and ran a raw search specifically looking for a successful `HTTP 200 OK` response tied to the Mantis exploit:

```
index=main host=dionaea_honeypot_01 "192.168.202.102" "mantis" 200
```

**Result: 0 Events.**

To be absolutely certain, I followed up with a manual review of the raw logs.

![102-deep-dive.png](102-deep-dive.png)

The manual check confirmed the query. Every single attempt from `.102` returned either a POST request with no success response or a `404 Not Found`. The targeted paths did not exist on the honeypot, and the exploit had nothing to latch onto.

---

## Final Verdict

The deliberate use of a generic browser user-agent to mask their activity (.102), combined with pre-crafted exploits targeting known CVE classes, points to a more sophisticated and intentional actor than the noisy scanners sharing the logs.

The incident was successfully triaged, categorized, and closed. Things I learned here like getting to know more of regex, more trick on filtering, solidifying methodology, I think what I mostly learned or realized here is that, things that you have no visibility with, tends to have more danger.