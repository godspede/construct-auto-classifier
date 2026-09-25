# How it decides, in full

The [README](../README.md#2-multi-tier-evaluation-1ms-fast-path) gives each stage of the gate in a few sentences. This page has the exact shapes behind three of them: what the fast deny refuses, what the fast allow vouches for, and which script runs are trusted without the model.

## Fast deny

The gate refuses a command that would change the gate itself. That is a command that does any of these:

- sets an `AUTO_CLASSIFIER_*` or `TYPESAFE_*` variable;
- names one of the gate's files as the target of a redirect of any form: `>`, `>>`, `>|`, `&>`, `&>>`, `<>` or `>&file`, with or without an `N` or `{name}` prefix, glued to the words around it or not;
- names one of its files as a file argument of `rm`, `mv`, `cp`, `install`, `tee`, `truncate`, `chmod`, `chown`, `chgrp`, `shred`, `ln`, `rsync`, `dd` (its `of=`), `sed -i`, or `find` with an action (`-delete`, `-exec`, …);
- runs one of these `git` subcommands in its code directory: `checkout`, `switch`, `reset`, `restore`, `pull`, `merge`, `rebase`, `cherry-pick`, `revert`, `am`, `apply`, `stash`, `clean`, `rm` or `mv`.

The gate's files are:

- its config directory, `~/.config/auto-classifier/`, which holds its config, overlay and, by default, its log, telemetry and timeout records;
- any config, overlay or `sanctionedRemotesFile` kept elsewhere: the files `AUTO_CLASSIFIER_CONFIG`, `AUTO_CLASSIFIER_LOCAL_CONFIG` and `sanctionedRemotesFile` name, protected even before they exist;
- its OpenCode plugin drop-in, `~/.config/opencode/plugins/auto-classifier.js`;
- its session state;
- its code: the package it runs from (the directory whose `package.json` names `construct-auto-classifier`: `dist/`, `bin/`, `src/`, …), or the single file when it runs as a bundle copied on its own or as a compiled binary.

A relative path is placed against the command's directory and any `cd` on the line. A symlink to one of its files counts as that file, and so does a hard link to a file in its config directory, a configured config file or its plugin drop-in. This check does not read the config, so an agent cannot edit it away, and the config that holds `rules.fastDeny` is one of the files it protects. A change made any other way (an interpreter's inline code, a build script) is not recognized here and goes through the later stages like any other command.

Then the `rules.fastDeny` patterns (`mkfs`, `dd` onto a disk, a fork bomb) are tested against the whole line and against every simple command in it.

Both checks, and the [upload check](../README.md#uploads-go-only-where-you-sanctioned), see through:

- a wrapper that runs a command unchanged: `env` (including its `-i`/`-u`/`-S` forms and assignments), `sudo`, `doas`, `timeout`, `nice`, `ionice`, `stdbuf`, `setsid`, `chrt`, `taskset`, `nohup`, `time`, `command`, `exec`, `xargs`, `watch`, `unbuffer` and `busybox`;
- shell syntax in front of a command: a subshell's parentheses, `{`, `!`, `if`, `then`, `else`, `elif`, `while`, `until`, `do` and `coproc`;
- however the verb is written: `/usr/bin/curl`, `\curl`, `curl.exe`.

Fast allow does not see through any of these: a rule vouches only for the text it names.

A command refused here escalates on a retry like any other denial, so that you can overrule the rule at your harness's permission prompt; where nobody can be asked, it stays refused ([Self-Defense Protocol](../README.md#3-actionable-self-defense-protocol-denymode-both)).

## Fast allow

These run with no model call:

- read-only verbs (`git status`, `ls`, `systemctl status`, `gh pr view`, `rg`, …);
- local git writes (`git add`, `git commit`);
- a plain `git push <remote> <branch>` to any branch but a protected one (`policy.protectedBranches`, default `main` and `master`; the upload check has already vetted the remote);
- a few test runners (`pytest`, `npm test`, `cargo check`). Test runners execute the project's own code, which the agent may just have edited; drop those rules if that is not a trade you want.

That holds only when **every** simple command on the line matches a rule, and the line carries none of the tells that make a read-only verb write, execute or escape. The tells (any one sends the line to the model):

- a redirect that writes anywhere but `/dev/null`, a file descriptor (`2>&1`, `>&2`) or a scratch path;
- `tee`, `sed`/`awk`/`perl`, `find -delete`/`-exec`, or `xargs`;
- `$( )` or backticks;
- an interpreter given inline code;
- a `PATH=` or `LD_PRELOAD=` prefix;
- a here-document or here-string;
- a PowerShell script block;
- an argument or redirect naming a credential-looking path (`~/.ssh/…`, `.env`, `*.pem`, a token file, …).

Every redirect counts, glued to the command or spaced from it (`journalctl>x` is a write exactly as `journalctl > x` is), and redirect syntax the gate cannot parse (a missing target, a process substitution) counts as a write. A scratch path is a literal path (no `$`, glob, braces or `~` for the shell to expand) inside `rules.scratchWriteRoots` (default `/tmp/`), not itself a symlink, still inside a root once the directories on its way are resolved, and not a sensitive startup location such as anything under `/etc`.

As a backstop, a line holding syntax the gate does not fully model is never allowed without the model, whether by this stage, by [landed-script trust](#script-provenance) or by the cache. The deterministic denials in [Fast deny](#fast-deny) still apply to it. The syntax the gate does not model:

- a `#` anywhere outside quotes (a comment), or PowerShell's `<# #>`;
- a subshell, a brace group or a `name()` definition;
- `$( )`, `$(( ))`, backticks or process substitution;
- a compound command: `if`, `for`, `while`, `case`, `select`, `[[ ]]`, `!` or `time -p`;
- `function`, `coproc`, `alias`, `set`, `shopt`, `hash`, `enable` or `trap`;
- quoting it cannot follow: `$"…"`, quotes nested in `${…}`, an unterminated quote, or an escape bash honors and PowerShell or cmd do not, such as `\"` inside double quotes, `\;` or a line continuation;
- a control character other than tab, newline and a CR ending a line;
- an invisible or curly-quote character anywhere, or any other non-ASCII character outside quotes;
- a here-document;
- a line over 8 KB.

## Script provenance

A line that runs one script (`./deploy.sh`, `python3 tools/x.py`, `pwsh -File x.ps1`, optionally behind `cd DIR &&` or ahead of `| tail -N`) is checked against git. A script byte-identical to its copy on the repository's remote default branch (the branch the remote's `HEAD` names, or else the first of `policy.protectedBranches` the remote has) went through that branch's review, but that review vouched only for its bytes run on their own. So only the narrowest shape is allowed without a model call: the whole line is one command, and

- its verb is the script's own path (`./deploy.sh`, `../deploy.sh`, `/abs/deploy.sh`, `~/deploy.sh`), or a bare interpreter name followed straight by the script: `bash`, `sh`, `zsh`, `dash`, `ksh`, `python`, `python2`, `python3`, `node`, `perl` or `ruby`, resolved from `PATH`, never a path to one;
- its arguments are made only of letters, digits and `_-./:=,+@%`, and name no credential-looking path.

Anything else goes to the model with the script's content:

- an env assignment, `sudo` or another wrapper;
- any redirect (output, input, here-string or here-document, `2>&1` included);
- a pipe, `;`, `&&`, `||` or `&`;
- a `cd` prefix, or `source` or `.`;
- an interpreter flag (`bash -x`, `pwsh -File`), or an interpreter named by path (`./bin/bash x.sh`);
- an argument with a quote, `$`, glob or other shell metacharacter.

Arguments to a reviewed script are passed through: the script decides what they do, as its review saw. Trust covers only the script being run: a file it sources, imports or loads (another script, a module beside it, `node_modules`, a `sys.path` entry) is not compared with anything, so a reviewed script that loads a file the agent changed runs the changed file.

This is `policy.trustLandedScripts`, default on. It trusts whoever controls that remote, so turn it off for repositories you do not control. It also trusts the local copy of the remote's branch: the comparison is with the remote-tracking ref (such as `origin/main`), not the remote itself, so an agent that can repoint a remote or move that ref (`git remote set-url`, a fetch with a refspec, `git update-ref`) can make its own script count as landed.

Any other script's content goes to the model, with one line saying whether it is modified, unpushed, untracked or outside a repository. Files the command reads (`--body-file`, `-f`, a known extension) are attached as data. A file that is one of the gate's own (its config directory, a configured config file, or a link to one) or credential-looking (the list in [Fast allow](#fast-allow)) is never read: the model is told the command names it and that its contents were withheld. A script being run that is such a file counts as cut short, so the model's allow of it is not trusted ([Scripts](../README.md#scripts-are-judged-on-where-they-came-from-not-on-their-name)).
