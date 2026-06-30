# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

An [Obsidian](https://obsidian.md/) vault containing personal notes and writeups for the [HackTheBox](https://www.hackthebox.com/) Penetration Tester job-role path. There is no code, build system, or test suite — all content is Markdown.

## Structure

```
<number>. <Module Name>/        # HTB Academy module notes (one .md per module)
    <Module Name>.md            # Main notes file
    <Subtopic>.md               # Optional writeups for specific exercises
Machines/
    Easy/                       # HTB machine writeups by difficulty
Glossary.md                     # Running acronym/term reference
```

Modules are numbered to match their order in the HTB learning path. Not all numbers are present (gaps are modules not yet started).

## Note conventions

- Module notes follow the structure of the HTB Academy lesson: headings mirror the lesson sections, command blocks use the relevant shell (bash/PowerShell/msfconsole), and practical takeaways are highlighted in blockquotes or bold.
- Machine writeups document the full exploitation chain: enumeration → foothold → privilege escalation → flag. Commands used are included verbatim in code blocks.
- Images pasted from Obsidian are stored alongside the .md file as `Pasted image <timestamp>.png`.
- The `Glossary.md` file is a flat list of acronyms; add new ones alphabetically.

## Modules covered so far

| # | Module |
|---|--------|
| 1 | Penetration Testing Process |
| 2 | Getting Started |
| 3 | Network Enumeration With Nmap |
| 4 | Footprinting |
| 6 | Vulnerability Assessment |
| 7 | File Transfers |
| 9 | Using The Metasploit Framework |
| 15 | Attacking Web Applications with Ffuf |
