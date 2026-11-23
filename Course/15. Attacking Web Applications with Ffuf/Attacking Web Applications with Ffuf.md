# Introduction
The following topics will be discussed:
- Fuzzing for directories
- Fuzzing for files and extensions
- Identifying hidden vhosts
- Fuzzing for PHP parameters
- Fuzzing for parameter values

If we get a response code 200, then we know that this page exists on the webserver, and we can look at it manually.

# Web Fuzzing
## Fuzzing
The term refers to a testing technique that sends various types of user input to a certain interface to study how it would react. 
For SQLi vulnerabilities, we would be sending random special characters and seeing how the server would react.
For a buffer overflow, we would be sending long strips and incrementing their length to see if and when the binary would break.

There are tools that can do the fuzzing process automatically, and such tools send hundreds of requests every second, study the response HTTP code, and determine whether the page exists or not. 
## Wordlists
The specific wordlist we will be utilizing for pages and directory fuzzing is another commonly used wordlist called `directory-list-2.3`, and it is available in various forms and size.

> `locate directory-list-2.3-small.txt` for searching up the file across the machine.

> Tip: Taking a look at this wordlist we will notice that it contains copyright comments at the beginning, which can be considered as part of the wordlist and clutter the results. We can use the following in `ffuf` to get rid of these lines with the `-ic` flag.

# Directory Fuzzing
## Ffuf
```bash
ffuf -h
```

## Directory Fuzzing
The main two options are:
- `-w` for wordlists
- `-u` for the URL

```
ffuf -w <SNIP> -u http://SERVER_IP:PORT/FUZZ

ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
```

We can use the flag `-t 200` to use threads, but we could disrupt the service and cause a `Denial of Service`, or bring down your internet connection in severe cases.
# Page Fuzzing

| Server | Language          |
| ------ | ----------------- |
| Apache | `.php`            |
| IIS    | `.asp` or `.aspx` |
We can utilize the following wordlist in `SecLists` for extensions:
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ <SNIP>
```
We can use two wordlists and have a unique keyword for each, and then do `FUZZ_1.FUZZ_2` to fuzz for both. However, there is one file we can always find in most websites, which is `index.*`, so we will use it as our file and fuzz extensions on it.

> Note: The wordlist we chose already contains a dot (.), so we will not have to add the dot after "index" in our fuzzing.

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
```

## Page Fuzzing
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
```

# Recursive Fuzzing
## Recursive Flags
When we scan recursively, it automatically starts another scan under any newly identified directories that may have on their pages until it has fuzzed the main website and all of its subdirectories.

It's important to specify a depth to our recursive scan, such that it will not scan directories that are deeper than that depth. We can enable recursive scanning with the `-recursion` flag, and we can specify the depth with the `-recursion-depth` flag. When using recursion, we can specify our extension with `-e .php`.

## Recursive Scanning
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```

# DNS Records
We have to change the `/etc/hosts` because if we visit the IP directly, the browser goes to that IP directly and knows how to connect to it. But in this case, we tell it to go to `academy.htb`, so it looks into the local `/etc/hosts` file and doesn't find any mention of it. It asks the public DNS about it and does not find any mention of it, since it is not a public website, and eventually fails to connect. 
```bash
sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'
```

If we can't find anything about `admin` or panels, even when we did a full recursive scan on our target, we start looking for **sub-domains** under `*.academy.htb` and see if we find anything.
# Sub-domain Fuzzing
## Sub-domains
A sub-domain is any website underlying another domain. For example, `https://photos.google.com` is the `photos` sub-domain of `google.com`.

Before running a scan we need two things:
- A `wordlist`
- A `target`

There is a folder for this: `/usr/share/seclists/Discovery/DNS/` and, in our case, we will use `subdomains-top1million-5000.txt`.
```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
```
```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/
```

If we can't see any sub-domain under a domain, that does not mean it doesn't exist. It means that there are no **public** sub-domains under a domain, as it does not have a public DNS record, as previously mentioned. 
# Vhost Fuzzing
When it came to fuzzing sub-domains that do not have a public DNS record or sub-domains under websites that are not public, we could not use the same method. So, we will learn how to do that with Vhost Fuzzing.

## Vhosts vs. Sub-domains
The main difference between a vhost and a sub-domain is that a vhost is basically a "sub-domain" served on the same server and has the same IP, such that a single IP could be serving two or more different websites.

**Vhosts may or may not have public DNS records.**

## Vhosts Fuzzing
To scan for vhosts, without manually adding the entire wordlist to our `/etc/hosts`, we will be fuzzing HTTP headers, specifically the `Host: ` header. To do so, we can use the `-H` flag to specify a header.

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
```

If the vhost does exist and we send a correct one in the header, we should get a different response size, as in that case, we would be getting the page from that vhosts, which is likely to show a different page.
# Filtering Results
## Filtering
We knoe the response size of the incorrect results, which is **900**, and we can filter it out with `-fs 900`.
```bash
ffuf -h

ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs 900
```

> Note 1: Don't forget to add "admin.academy.htb" to "/etc/hosts".
> Note 2: If your exercise has been restarted, ensure you still have the correct port when visiting the website.


## Connect to HTB
```bash
sudo nano /etc/hosts
	154.57.164.78 academy.htb

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:31350/ -H 'Host: FUZZ.academy.htb'

# We get the size response is: 986
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:31350/ -H 'Host: FUZZ.academy.htb' -fs 986
admin
test

# So the response is:
# test.academy.htb
```

# Parameter Fuzzing - GET
Some keys would usually be passed as a `parameter`, using either a `GET` or a `POST` HTTP request. 
> **Tip:** Fuzzing parameters may expose unpublished parameters that are publicly accessible. Such parameters tend to be less tested and less secured, so it is important to test such parameters for the web vulnerabilities we discuss in other modules.

- `http://admin.academy.htb:PORT/admin/admin.php?param1=key`

So, we just need to replace `param1` with `FUZZ` and rerun our scan. We need to use an appropriate wordlist like `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt`. 
```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
```
## Connect to HTB
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:31350/admin/admin.php\?FUZZ\=key

ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:31350/admin/admin.php\?FUZZ\=key -fs 798

user
```

# Parameter Fuzzing - POST
`POST` requests are passed in the `data` field within the HTTP request. 

To fuzz the `data` field, we can use the `-d` flag. We also have to add `-X POST` to send `POST` requests.
> **Tip**: In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'".

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx

id
```

```bash
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

# Value Fuzzing
## Custom Wordlist
```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```
## Value Fuzzing
```bash
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```

## Connect to HTB
```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done

ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:31350/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'

ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:31350/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 768

curl http://admin.academy.htb:31350/admin/admin.php -X POST -d 'id=73' -H 'Content-Type: application/x-www-form-urlencoded'

HTB{p4r4m373r_fuzz1n6_15_k3y!}
```

# Skills Assessment - Web Fuzzing
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:30599/ -H 'Host: FUZZ.academy.htb'

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:30599/ -H 'Host: FUZZ.academy.htb' -fs 985

################# FIRST WITH: test #############
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://test.academy.htb:30599/ -H 'Host: FUZZ.test.academy.htb'

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://test.academy.htb:30599/ -H 'Host: FUZZ.test.academy.htb' -fs 985

################# SECOND WITH: archive #############
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://archive.academy.htb:30599/ -H 'Host: FUZZ.archive.academy.htb'

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://archive.academy.htb:30599/ -H 'Host: FUZZ.archive.academy.htb' -fs 985

################# THIRD WITH: faculty #############
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://faculty.academy.htb:30599/ -H 'Host: FUZZ.faculty.academy.htb'

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://faculty.academy.htb:30599/ -H 'Host: FUZZ.faculty.academy.htb' -fs 985

# Response:
# test archive faculty

ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://faculty.academy.htb:30599/indexFUZZ

# Response:
# .php .phps .php7

ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ -u http://154.57.164.75:30599/FUZZ.php

ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ -u http://154.57.164.75:30599/FUZZ.phps

ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ -u http://154.57.164.75:30599/FUZZ.php7

ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ -u http://154.57.164.75:30599/FUZZ.phps -fc 403

ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:30599/FUZZ -recursion -recursion-depth 1 -e .php,.php7,.phps -ic

ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:30599/FUZZ -recursion -recursion-depth 1 -e .php,.php7,.phps -ic -fs 287

courses

ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:30599/courses/linux-security.php7 -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'

ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:30599/courses/linux-security.php7 -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 774

user
username

ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ  -u http://faculty.academy.htb:30599/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'

ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ  -u http://faculty.academy.htb:30599/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 781

curl http://faculty.academy.htb:30599/courses/linux-security.php7 -X POST -d 'username=harry' -H 'Content-Type: application/x-www-form-urlencoded'
```