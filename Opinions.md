# Opinions
## Exam Environment
- The Kali machine runs in-browser - be prepared for that
- Copy/paste may not work immediately out of the box - budget time to fix it before starting

## Exam approach
- Think methodology, not flag hunting.
- Started with a ping sweep to map the DMZ network
- Compromised machines progressively, then answered related questions with gathered evidence
- Used Metasploit for pivoting into an internal network via a dual-interface host

## Biggest mistake
- Blindly trying payloads on one machine instead of researching the correct one first - cost them points.

## Key takeaways
- Before the exam, read the Rules of Engagement PDF carefully - it contains useful info and recommended tools
- Review and organize your notes into checklists the day before
- Detailed notes per machine (nmap output, creds, service versions) are essential
- Enumeration is the most critical skill
- Don't overthink readiness - just start
- If you're stuck, you haven't enumerated enough
- After rooting a box, enumerate again with the credentials you obtained
- Keep detailed notes per machine: nmap output, credentials, service versions, exploitation steps
- Organize by activity type
- Don't waste hours on one machine - move on and return later
- Strategy: Enumerate -> Compromise -> Enumerate again
- The Questions could contain hints, read them again if necessary
- Take breaks
- Use just the course tools only, others may not be graded